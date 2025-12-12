#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <stdint.h>

// Windows에서 ssize_t 정의
#ifdef _WIN32
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <nghttp2/nghttp2.h>
#include "fetch.h"
#include "DB.h"

#pragma comment(lib, "ws2_32.lib")

// 이용할 서버 포트
#define SERVER_PORT 여기에 사용할 포트를 입력해주세요.
#define BUFFER_SIZE 8192
// 최대 접속자 수
#define MAX_CLIENTS 10

// SSL 인증서 경로 (필요시 여기서 수정)
// 기본은 certs/ 안에 위치해야합니다
#define CERT_FILE "certs/인증서 파일명을 입력해주세요.pem"
#define KEY_FILE  "certs/인증서 파일명을 입력해주세요.pem"

// 전방 선언
struct stream_data;
typedef struct stream_data stream_data;

// 클라이언트 세션 구조체
typedef struct {
    int fd;
    SSL* ssl;
    nghttp2_session* session;
    int want_io;
    struct stream_data* streams;  // 스트림 목록
} http2_session_data;

// 데이터 제공자 구조체
typedef struct {
    char* data;
    size_t length;
    size_t pos;
    int should_free;  // 메모리 해제 필요 여부
} data_provider_userdata;

// 스트림별 데이터 저장용
struct stream_data {
    int32_t stream_id;
    data_provider_userdata provider;
    char path[256];
    char method[8];
    char content_type[256];  // Content-Type 헤더 저장 (멀티파트 파싱용)
    // POST body 저장 (Content-Type에 따라 메모리 또는 파일)
    char* body;                  // 메모리 버퍼 (application/json 등)
    size_t body_capacity;        // 메모리 버퍼 용량
    FILE* body_file;             // 파일 포인터 (multipart/form-data)
    char body_file_path[256];    // 임시 파일 경로
    size_t body_length;          // 누적 크기
    int response_sent;
    // Range 요청 처리용
    int has_range;
    size_t range_start;
    size_t range_end;
    // 세션 연결 (메모리 누수 방지)
    http2_session_data* session_data;  // 이 스트림이 속한 세션
    struct stream_data* next;
};

// 함수 전방 선언
static stream_data* get_stream_data(http2_session_data* session_data, int32_t stream_id);
static void cleanup_all_streams(http2_session_data* session_data);
static ssize_t data_source_read_callback(nghttp2_session* session, int32_t stream_id,
    uint8_t* buf, size_t length, uint32_t* data_flags,
    nghttp2_data_source* source, void* user_data);
static char* read_file(const char* filepath, size_t* out_size);
static char* read_file_range(const char* filepath_utf8, size_t start, size_t end, size_t* out_size, size_t* total_size);
static const char* get_content_type(const char* path);
static int append_body(stream_data* sd, const uint8_t* data, size_t len);
static int handle_request(nghttp2_session* session, stream_data* sd, int32_t stream_id);
void handle_client(SOCKET client_sock, SSL_CTX* ssl_ctx);

// ==================== UTF-8 → UTF-16 변환 헬퍼 함수 ====================

/*
 * UTF-8 문자열을 UTF-16로 변환하는 함수
 * 반환된 포인터는 호출한 쪽에서 free() 해야 함
 */
static wchar_t* utf8_to_wide(const char* utf8)
{
    if (!utf8) return NULL;

    int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (len <= 0) {
        return NULL;
    }

    wchar_t* wide = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wide) {
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, len) <= 0) {
        free(wide);
        return NULL;
    }

    return wide;
}

// URL 퍼센트 인코딩 디코드 (UTF-8 경로 복원용)
static void url_decode_inplace(char* s) {
    char* dst = s;
    for (char* src = s; *src; ++src) {
        if (*src == '%') {
            if (src[1] && src[2]) {
                int hi = (src[1] <= '9') ? src[1] - '0' : (src[1] & ~0x20) - 'A' + 10;
                int lo = (src[2] <= '9') ? src[2] - '0' : (src[2] & ~0x20) - 'A' + 10;
                *dst++ = (char)((hi << 4) | lo);
                src += 2;
            }
        }
        else if (*src == '+') {
            *dst++ = ' ';
        }
        else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
}

// POST 바디 저장 (Content-Type에 따라 메모리 또는 파일)
static int append_body(stream_data* sd, const uint8_t* data, size_t len) {
    if (!sd || !data || len == 0) return 0;

    // 최대 요청 크기 제한 (4GB)
    #define MAX_REQUEST_SIZE (4ULL * 1024 * 1024 * 1024)

    size_t new_total = sd->body_length + len;
    if (new_total > MAX_REQUEST_SIZE) {
        printf("[에러] 요청 크기 초과: %zu bytes (최대 %llu bytes)\n", new_total, MAX_REQUEST_SIZE);
        return 0;
    }

    // Content-Type 체크: multipart/form-data면 파일 스트리밍
    if (strstr(sd->content_type, "multipart/form-data") != NULL) {
        // 파일 스트리밍 모드

        // 첫 데이터 도착 - 파일 생성
        if (!sd->body_file) {
            snprintf(sd->body_file_path, sizeof(sd->body_file_path),
                     "public/video/temp_upload_%d_%d.tmp", sd->stream_id, (int)time(NULL));

            sd->body_file = fopen(sd->body_file_path, "wb");
            if (!sd->body_file) {
                printf("[에러] 임시 파일 생성 실패: %s\n", sd->body_file_path);
                return 0;
            }

            printf("[스트리밍] 파일 저장 시작: %s\n", sd->body_file_path);
        }

        // 파일에 데이터 쓰기
        size_t written = fwrite(data, 1, len, sd->body_file);
        if (written != len) {
            printf("[에러] 파일 쓰기 실패: %zu/%zu bytes\n", written, len);
            return 0;
        }
    } else {
        // 메모리 버퍼 모드 (application/json 등)

        // 메모리 재할당 필요 시
        if (sd->body_length + len > sd->body_capacity) {
            size_t new_capacity = sd->body_capacity == 0 ? 4096 : sd->body_capacity * 2;
            while (new_capacity < sd->body_length + len) {
                new_capacity *= 2;
            }

            char* new_body = (char*)realloc(sd->body, new_capacity);
            if (!new_body) {
                printf("[에러] 메모리 할당 실패\n");
                return 0;
            }

            sd->body = new_body;
            sd->body_capacity = new_capacity;
        }

        // 메모리 버퍼에 복사
        memcpy(sd->body + sd->body_length, data, len);
    }

    sd->body_length += len;
    return 1;
}

// ALPN 콜백 - HTTP/2 프로토콜 협상
static int alpn_select_proto_cb(SSL* ssl, const unsigned char** out,
    unsigned char* outlen, const unsigned char* in,
    unsigned int inlen, void* arg) {
    int ret;
    (void)arg;
    (void)ssl;

    // h2 프로토콜 선택 시도
    ret = nghttp2_select_next_protocol((unsigned char**)out, outlen, in, inlen);

    if (ret == 1) {
        // [상세 로그] ALPN 협상 성공
        // printf("ALPN: HTTP/2 선택됨\n");
        return SSL_TLSEXT_ERR_OK;
    }

    printf("ALPN: HTTP/2를 협상할 수 없음\n");
    return SSL_TLSEXT_ERR_NOACK;
}

// nghttp2 전송 콜백 - 데이터를 SSL을 통해 전송
static ssize_t send_callback(nghttp2_session* session, const uint8_t* data,
    size_t length, int flags, void* user_data) {
    http2_session_data* session_data;
    int rv;
    int err;
    int sock_err;
    (void)session;
    (void)flags;

    session_data = (http2_session_data*)user_data;
    rv = SSL_write(session_data->ssl, data, (int)length);

    if (rv <= 0) {
        err = SSL_get_error(session_data->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }

        // SSL_ERROR_SYSCALL일 때 시스템 에러 확인
        if (err == SSL_ERROR_SYSCALL) {
            sock_err = WSAGetLastError();
            // 타임아웃이면 WOULDBLOCK 반환
            if (sock_err == WSAETIMEDOUT || sock_err == WSAEWOULDBLOCK) {
                return NGHTTP2_ERR_WOULDBLOCK;
            }
            printf("[에러] SSL 송신 시스템 에러: WSA=%d\n", sock_err);
        }
        else {
            printf("[에러] SSL 송신 에러: %d\n", err);
        }
        ERR_print_errors_fp(stderr);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    // [상세 로그] 송수신 바이트 수 확인용
    // printf("[DEBUG] %d bytes 전송\n", rv);
    return rv;
}

// nghttp2 수신 콜백 - SSL로부터 데이터 수신
static ssize_t recv_callback(nghttp2_session* session, uint8_t* buf,
    size_t length, int flags, void* user_data) {
    http2_session_data* session_data;
    int rv;
    int err;
    int sock_err;
    (void)session;
    (void)flags;

    session_data = (http2_session_data*)user_data;
    rv = SSL_read(session_data->ssl, buf, (int)length);

    if (rv < 0) {
        err = SSL_get_error(session_data->ssl, rv);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }

        // SSL_ERROR_SYSCALL일 때 시스템 에러 확인
        if (err == SSL_ERROR_SYSCALL) {
            sock_err = WSAGetLastError();
            // 타임아웃이면 WOULDBLOCK 반환
            if (sock_err == WSAETIMEDOUT || sock_err == WSAEWOULDBLOCK) {
                return NGHTTP2_ERR_WOULDBLOCK;
            }
            printf("[에러] SSL 수신 시스템 에러: WSA=%d\n", sock_err);
        }
        else {
            printf("[에러] SSL 수신 에러: %d\n", err);
        }
        ERR_print_errors_fp(stderr);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (rv == 0) {
        // [상세 로그] 연결 종료 확인용
        // printf("[DEBUG] EOF - 클라이언트 연결 종료\n");
        return NGHTTP2_ERR_EOF;
    }

    // [상세 로그] 수신 바이트 수 확인용
    // printf("[DEBUG] %d bytes 수신\n", rv);
    return rv;
}

// 프레임 수신 콜백
static int on_frame_recv_callback(nghttp2_session* session,
    const nghttp2_frame* frame, void* user_data) {
    http2_session_data* session_data = (http2_session_data*)user_data;
    stream_data* sd;

    if (!session_data) return 0;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
            // [상세 로그] HTTP/2 프레임 수신 상세 정보
            // printf("[DEBUG] HEADERS 프레임 수신 완료, stream_id=%d\n", frame->hd.stream_id);

            // 요청 헤더가 완료되었으므로 이제 응답 전송
            if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                sd = get_stream_data(session_data, frame->hd.stream_id);

                // [상세 로그] 요청 처리 상세 정보
                // printf("[DEBUG] 요청 처리: stream_id=%d, path=%s\n", frame->hd.stream_id, sd->path);

                // 라우팅 시스템을 사용하여 body 필요 여부 확인
                int needs_body = route_needs_body(sd->path, sd->method);

                if (!needs_body || (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
                    handle_request(session, sd, frame->hd.stream_id);
                }
            }
        }
        break;
    case NGHTTP2_DATA:
        // [상세 로그] DATA 프레임 수신 상세 정보
        // printf("[DEBUG] DATA 프레임 수신, stream_id=%d, length=%zu\n", frame->hd.stream_id, frame->hd.length);
        break;
    }

    return 0;
}

// 프레임 전송 콜백
static int on_frame_send_callback(nghttp2_session* session,
    const nghttp2_frame* frame, void* user_data) {
    (void)session;
    (void)user_data;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        // [상세 로그] HTTP/2 프레임 전송 상세 정보
        // printf("[DEBUG] HEADERS 프레임 전송, stream_id=%d\n", frame->hd.stream_id);
        break;
    case NGHTTP2_DATA:
        // [상세 로그] DATA 프레임 전송 상세 정보
        // printf("[DEBUG] DATA 프레임 전송, stream_id=%d, length=%zu\n", frame->hd.stream_id, frame->hd.length);
        break;
    }

    return 0;
}

// 스트림 리소스 정리 헬퍼 함수
static void cleanup_stream_resources(stream_data* sd) {
    if (!sd) return;

    // 메모리 버퍼 해제
    if (sd->body) {
        free(sd->body);
        sd->body = NULL;
    }

    // 파일 리소스 정리
    if (sd->body_file) {
        fclose(sd->body_file);
        sd->body_file = NULL;
    }

    // 임시 파일 삭제 (처리 완료되지 않은 경우)
    if (sd->body_file_path[0] != '\0') {
        remove(sd->body_file_path);
        sd->body_file_path[0] = '\0';
    }

    // 응답 데이터 버퍼 해제 (스트림 중단 시 누수 방지)
    if (sd->provider.should_free && sd->provider.data) {
        free(sd->provider.data);
        sd->provider.data = NULL;
        sd->provider.length = 0;
        sd->provider.pos = 0;
        sd->provider.should_free = 0;
    }
}

// 스트림 닫힘 콜백
static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
    uint32_t error_code, void* user_data) {
    http2_session_data* session_data = (http2_session_data*)user_data;
    stream_data* sd;
    stream_data* prev = NULL;
    (void)session;

    if (!session_data) return 0;

    // 세션의 스트림 리스트에서 찾기
    sd = session_data->streams;
    while (sd) {
        if (sd->stream_id == stream_id) {
            // 리소스 정리
            cleanup_stream_resources(sd);

            // 리스트에서 노드 제거
            if (prev) {
                prev->next = sd->next;
            } else {
                session_data->streams = sd->next;
            }

            // 노드 메모리 해제
            free(sd);
            // printf("[STREAM] 스트림 정리 완료: stream_id=%d (정상 종료)\n", stream_id);
            break;
        }
        prev = sd;
        sd = sd->next;
    }

    return 0;
}

// 헤더 수신 콜백
static int on_header_callback(nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name, size_t namelen,
    const uint8_t* value, size_t valuelen,
    uint8_t flags, void* user_data) {
    http2_session_data* session_data = (http2_session_data*)user_data;
    stream_data* sd;
    (void)session;
    (void)flags;

    if (!session_data) return 0;

    // [상세 로그] HTTP 헤더 수신 상세 정보
    // printf("[DEBUG] 헤더: %.*s: %.*s\n", (int)namelen, name, (int)valuelen, value);

    // :path 헤더 저장
    if (frame->hd.type == NGHTTP2_HEADERS &&
        frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        sd = get_stream_data(session_data, frame->hd.stream_id);
        if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            // 원본 경로 복사
            size_t copy_len = valuelen < sizeof(sd->path) ? valuelen : sizeof(sd->path) - 1;
            memcpy(sd->path, value, copy_len);
            sd->path[copy_len] = '\0';

            // 퍼센트 인코딩 해제 (UTF-8 파일명 대응)
            url_decode_inplace(sd->path);
        }
        else if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            size_t copy_len = valuelen < sizeof(sd->method) ? valuelen : sizeof(sd->method) - 1;
            memcpy(sd->method, value, copy_len);
            sd->method[copy_len] = '\0';
        }
        // Content-Type 헤더 저장 (멀티파트 파싱용)
        else if (namelen == 12 && memcmp(name, "content-type", 12) == 0) {
            size_t copy_len = valuelen < sizeof(sd->content_type) ? valuelen : sizeof(sd->content_type) - 1;
            memcpy(sd->content_type, value, copy_len);
            sd->content_type[copy_len] = '\0';
            // printf("[HDR] Content-Type: %s\n", sd->content_type);
        }
        // Range 헤더 파싱
        else if (namelen == 5 && memcmp(name, "range", 5) == 0) {
            // Range: bytes=start-end 형식 파싱
            char range_str[128];
            size_t copy_len = valuelen < sizeof(range_str) - 1 ? valuelen : sizeof(range_str) - 1;
            memcpy(range_str, value, copy_len);
            range_str[copy_len] = '\0';

            if (strncmp(range_str, "bytes=", 6) == 0) {
                const char* range_value = range_str + 6;
                char* dash = strchr(range_value, '-');

                if (dash) {
                    sd->has_range = 1;
                    sd->range_start = atoll(range_value);

                    if (*(dash + 1) != '\0') {
                        sd->range_end = atoll(dash + 1);
                    } else {
                        sd->range_end = (size_t)-1; // 끝까지
                    }

                    // [상세 로그] Range 요청 정보
                    // printf("Range 요청: %zu-%zu\n", sd->range_start, sd->range_end);
                }
            }
        }
    }

    return 0;
}

// DATA 청크 수신 콜백 (POST 바디 수집)
static int on_data_chunk_recv_callback(nghttp2_session* session,
    uint8_t flags,
    int32_t stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data) {
    http2_session_data* session_data = (http2_session_data*)user_data;
    stream_data* sd;

    if (!session_data) return NGHTTP2_ERR_CALLBACK_FAILURE;

    sd = get_stream_data(session_data, stream_id);
    if (!sd) return NGHTTP2_ERR_CALLBACK_FAILURE;

    if (!append_body(sd, data, len)) {
        printf("요청 바디 버퍼 확장 실패\n");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    // printf("---- [DATA] stream_id=%d, len=%zu, 누적=%zu, END_STREAM=%d\n",
    //     stream_id, len, sd->body_length, (flags & NGHTTP2_FLAG_END_STREAM) ? 1 : 0);

    if (flags & NGHTTP2_FLAG_END_STREAM) {
        // [상세 로그] 스트림 완료 정보
        // printf("*** 스트림 완료! stream_id=%d, 총 크기=%zu bytes ***\n", stream_id, sd->body_length);
        handle_request(session, sd, stream_id);
    }

    return 0;
}

// ==================== 파일 읽기 함수: UTF-8 경로 + _wfopen 사용 ====================

// 64비트 파일 위치 헬퍼 (2GB 이상 파일 대응)
static int64_t file_tell64(FILE* fp) {
#ifdef _WIN32
    return _ftelli64(fp);
#else
    return ftello(fp);
#endif
}

static int file_seek64(FILE* fp, int64_t offset, int origin) {
#ifdef _WIN32
    return _fseeki64(fp, offset, origin);
#else
    return fseeko(fp, offset, origin);
#endif
}

static char* read_file(const char* filepath_utf8, size_t* out_size) {
    FILE* fp;
    char* content;
    int64_t size64;
    size_t size;

    // UTF-8 → UTF-16 변환
    wchar_t* wide_path = utf8_to_wide(filepath_utf8);
    if (!wide_path) {
        printf("경로 변환 실패 (UTF-8 → UTF-16): %s\n", filepath_utf8);
        return NULL;
    }

    // 유니코드 경로로 파일 열기
    fp = _wfopen(wide_path, L"rb");
    free(wide_path);

    if (!fp) {
        printf("파일 열기 실패: %s\n", filepath_utf8);
        return NULL;
    }

    if (file_seek64(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    size64 = file_tell64(fp);
    if (size64 < 0) {
        fclose(fp);
        return NULL;
    }
    if (file_seek64(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    size = (size_t)size64;

    content = (char*)malloc(size + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }

    fread(content, 1, size, fp);
    content[size] = '\0';
    fclose(fp);

    *out_size = size;
    // [상세 로그] 파일 읽기 성공 정보
    // printf("파일 읽기 성공: %s (%zu bytes)\n", filepath_utf8, size);
    return content;
}

// Range 요청을 지원하는 파일 읽기 함수
static char* read_file_range(const char* filepath_utf8, size_t start, size_t end, size_t* out_size, size_t* total_size) {
    FILE* fp;
    char* content;
    int64_t file_size64;
    size_t file_size, read_size;

    // UTF-8 → UTF-16 변환
    wchar_t* wide_path = utf8_to_wide(filepath_utf8);
    if (!wide_path) {
        printf("경로 변환 실패 (UTF-8 → UTF-16): %s\n", filepath_utf8);
        return NULL;
    }

    // 유니코드 경로로 파일 열기
    fp = _wfopen(wide_path, L"rb");
    free(wide_path);

    if (!fp) {
        printf("파일 열기 실패: %s\n", filepath_utf8);
        return NULL;
    }

    // 파일 크기 확인
    if (file_seek64(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    file_size64 = file_tell64(fp);
    if (file_size64 < 0) {
        fclose(fp);
        return NULL;
    }
    file_size = (size_t)file_size64;
    *total_size = file_size;

    // range_end가 -1이거나 파일 크기를 넘으면 파일 끝까지
    if (end == (size_t)-1 || end >= file_size) {
        end = file_size - 1;
    }

    // start가 파일 크기를 넘으면 에러
    if (start >= file_size) {
        fclose(fp);
        return NULL;
    }

    read_size = end - start + 1;

    // 시작 위치로 이동
    if (file_seek64(fp, (int64_t)start, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    content = (char*)malloc(read_size + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }

    fread(content, 1, read_size, fp);
    content[read_size] = '\0';
    fclose(fp);

    *out_size = read_size;
    // [상세 로그] Range 파일 읽기 성공 정보
    // printf("Range 파일 읽기 성공: %s (%zu-%zu/%zu bytes)\n", filepath_utf8, start, end, file_size);
    return content;
}

// Content-Type 추론
static const char* get_content_type(const char* path) {
    const char* ext;

    ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";

    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html; charset=utf-8";
    if (strcmp(ext, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(ext, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcmp(ext, ".json") == 0) return "application/json; charset=utf-8";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcmp(ext, ".txt") == 0) return "text/plain; charset=utf-8";

    return "application/octet-stream";
}

// 쿼리 파라미터 파싱 헬퍼 함수
static int get_query_param_int(const char* query, const char* key) {
    if (!query || !key) return 0;

    char search[128];
    snprintf(search, sizeof(search), "%s=", key);

    const char* pos = strstr(query, search);
    if (!pos) return 0;

    return atoi(pos + strlen(search));
}

// API 라우팅 및 응답 전송
static int handle_api_routes(nghttp2_session* session, stream_data* sd, int32_t stream_id) {
    api_response* api_resp = NULL;
    nghttp2_nv hdrs[3];
    nghttp2_data_provider data_prd;
    char status_str[4];
    int rv;

    // 특수 처리: 쿼리 파라미터가 있는 API
    if (strncmp(sd->path, "/api/watch_history?", 19) == 0) {
        const char* query = sd->path + 19;
        int user_id = get_query_param_int(query, "user_id");
        int video_id = get_query_param_int(query, "video_id");

        if (user_id > 0 && video_id > 0) {
            api_resp = handle_watch_history(user_id, video_id);
        } else {
            api_resp = api_response_create(400, "application/json; charset=utf-8",
                "{\"error\":\"Missing user_id or video_id\"}");
        }
    }
    else if (strncmp(sd->path, "/api/video_details?", 19) == 0) {
        const char* query = sd->path + 19;
        int video_id = get_query_param_int(query, "id");

        if (video_id > 0) {
            api_resp = handle_video_details(video_id);
        } else {
            api_resp = api_response_create(400, "application/json; charset=utf-8",
                "{\"error\":\"Missing id parameter\"}");
        }
    }
    else if (strncmp(sd->path, "/api/video_search?", 18) == 0) {
        const char* query = sd->path + 18;
        int search_user_id = get_query_param_int(query, "user_id");

        // q= 파라미터 추출
        char search_query[256] = {0};
        const char* q_param = strstr(query, "q=");
        if (q_param) {
            q_param += 2;  // "q=" 건너뛰기

            // 다음 & 또는 문자열 끝까지 복사
            const char* end = strchr(q_param, '&');
            size_t len = end ? (size_t)(end - q_param) : strlen(q_param);
            if (len >= sizeof(search_query)) len = sizeof(search_query) - 1;

            memcpy(search_query, q_param, len);
            search_query[len] = '\0';

            // [상세 로그] 검색 쿼리
            // printf("[API] 검색어: '%s'\n", search_query);
            api_resp = handle_video_search(search_query, search_user_id);
        } else {
            // 검색어 없음 - 전체 목록 반환
            api_resp = handle_video_search("", search_user_id);
        }
    }
    else if (strncmp(sd->path, "/api/user_videos?", 17) == 0) {
        const char* query = sd->path + 17;
        int user_id = get_query_param_int(query, "user_id");

        if (user_id > 0) {
            api_resp = handle_user_videos(user_id);
        } else {
            api_resp = api_response_create(400, "application/json; charset=utf-8",
                "{\"error\":\"Missing user_id parameter\"}");
        }
    }
    else if (strncmp(sd->path, "/api/video_list", 15) == 0) {
        // /api/video_list 또는 /api/video_list?user_id=X
        int user_id = 0;
        if (sd->path[15] == '?') {
            const char* query = sd->path + 16;
            user_id = get_query_param_int(query, "user_id");
        }
        // user_id가 0이면 시청 기록 없이 반환
        api_resp = handle_video_list(user_id);
    }
    else if (strncmp(sd->path, "/api/recent_videos?", 19) == 0) {
        const char* query = sd->path + 19;
        int user_id = get_query_param_int(query, "user_id");
        int limit = get_query_param_int(query, "limit");

        // limit가 지정되지 않으면 기본값 2
        if (limit <= 0) limit = 2;

        if (user_id > 0) {
            api_resp = handle_recent_videos(user_id, limit);
        } else {
            api_resp = api_response_create(400, "application/json; charset=utf-8",
                "{\"error\":\"Missing user_id parameter\"}");
        }
    }
    // Content-Type 기반 라우팅
    else if (strstr(sd->content_type, "multipart/form-data") != NULL) {
        // 파일 스트리밍 모드 - 파일 경로 전달

        // 파일 닫기 (파싱을 위해)
        if (sd->body_file) {
            fclose(sd->body_file);
            sd->body_file = NULL;
        }

        // upload_video는 파일 경로로 처리
        if (strcmp(sd->path, "/api/upload_video") == 0 && strcmp(sd->method, "POST") == 0) {
            api_resp = handle_upload_video(NULL, sd->content_type, sd->body_length, sd->body_file_path);
            // handle_upload_video가 파일을 삭제하므로 경로 초기화
            sd->body_file_path[0] = '\0';
        } else {
            // 다른 multipart 요청도 여기서 처리 가능
            api_resp = api_response_create(404, "application/json; charset=utf-8",
                "{\"error\":\"Not found\"}");
        }
    }
    // 메모리 모드 - 메모리 버퍼 전달
    else {
        // body에 NULL 종료 문자 추가 (JSON 파싱을 위해)
        if (sd->body && sd->body_length > 0) {
            if (sd->body_length >= sd->body_capacity) {
                char* new_body = (char*)realloc(sd->body, sd->body_length + 1);
                if (new_body) {
                    sd->body = new_body;
                    sd->body_capacity = sd->body_length + 1;
                }
            }
            if (sd->body_length < sd->body_capacity) {
                sd->body[sd->body_length] = '\0';
            }
        }

        api_resp = route_request(sd->path, sd->method, sd->body);
    }

    // API 응답이 없으면 정적 파일로 처리
    if (!api_resp) {
        return 0;  // API가 아님
    }

    // API 응답 전송
    snprintf(status_str, sizeof(status_str), "%d", api_resp->status_code);

    hdrs[0].name = (uint8_t*)":status";
    hdrs[0].value = (uint8_t*)status_str;
    hdrs[0].namelen = 7;
    hdrs[0].valuelen = strlen(status_str);
    hdrs[0].flags = NGHTTP2_NV_FLAG_NONE;

    hdrs[1].name = (uint8_t*)"content-type";
    hdrs[1].value = (uint8_t*)api_resp->content_type;
    hdrs[1].namelen = 12;
    hdrs[1].valuelen = strlen(api_resp->content_type);
    hdrs[1].flags = NGHTTP2_NV_FLAG_NONE;

    hdrs[2].name = (uint8_t*)"server";
    hdrs[2].value = (uint8_t*)"nghttp2/QServer";
    hdrs[2].namelen = 6;
    hdrs[2].valuelen = 15;
    hdrs[2].flags = NGHTTP2_NV_FLAG_NONE;

    sd->provider.data = api_resp->body;
    sd->provider.length = api_resp->body_length;
    sd->provider.pos = 0;
    sd->provider.should_free = 1;

    api_resp->body = NULL;
    api_response_free(api_resp);

    data_prd.source.ptr = &sd->provider;
    data_prd.read_callback = data_source_read_callback;

    rv = nghttp2_submit_response(session, stream_id, hdrs, 3, &data_prd);
    if (rv != 0) {
        printf("응답 제출 실패: %s\n", nghttp2_strerror(rv));
    }
    else {
        // [상세 로그] 응답 제출 성공
        // printf("응답 제출 성공: stream_id=%d\n", stream_id);
    }

    sd->response_sent = 1;
    return 1;  // API 처리 완료
}

// 정적 파일 처리
static int handle_static_file(nghttp2_session* session, stream_data* sd, int32_t stream_id) {
    nghttp2_nv hdrs[6];  // Range 응답을 위해 헤더 개수 증가
    nghttp2_data_provider data_prd;
    char filepath[512];
    char* file_content;
    size_t file_size;
    size_t total_size;  // Range 요청용 전체 파일 크기
    const char* content_type;
    char content_range_str[128];  // Content-Range 헤더 문자열
    int rv;
    int hdr_count;

    // 정적 파일 경로 생성
    if (strcmp(sd->path, "/") == 0 || strlen(sd->path) == 0) {
        strcpy(filepath, "public/login.html");
    }
    else {
        // 쿼리 파라미터 제거 (? 이전까지만)
        char clean_path[256];
        strncpy(clean_path, sd->path, sizeof(clean_path) - 1);
        clean_path[sizeof(clean_path) - 1] = '\0';

        char* query_start = strchr(clean_path, '?');
        if (query_start) {
            *query_start = '\0';  // ? 위치에서 문자열 종료
        }

        // /public/으로 시작하면 그대로 사용 (이미 전체 경로)
        if (strncmp(clean_path, "/public/", 8) == 0) {
            // 소음 많은 정적 파일 로그는 생략
        if (strcmp(clean_path, "/public/logo.png") != 0 &&
            strstr(clean_path, "/public/thumb/") == NULL &&
            strcmp(clean_path, "/public/favicon.ico") != 0 &&
            strcmp(clean_path, "/favicon.ico") != 0) {
            // printf("[STATIC] %s\n", clean_path);
        }
            snprintf(filepath, sizeof(filepath), "%s", clean_path + 1);  // 앞의 / 제거
        }
        else {
            snprintf(filepath, sizeof(filepath), "public%s", clean_path);
        }
    }

    // Range 요청 처리
    if (sd->has_range) {
        file_content = read_file_range(filepath, sd->range_start, sd->range_end, &file_size, &total_size);
        if (!file_content) {
            // Range 요청 실패 - 416 Range Not Satisfiable
            const char* range_error = "<html><body><h1>416 Range Not Satisfiable</h1></body></html>";
            file_content = _strdup(range_error);
            file_size = strlen(range_error);
            content_type = "text/html; charset=utf-8";

            hdrs[0].name = (uint8_t*)":status";
            hdrs[0].value = (uint8_t*)"416";
            hdrs[0].namelen = 7;
            hdrs[0].valuelen = 3;
            hdrs[0].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[1].name = (uint8_t*)"content-type";
            hdrs[1].value = (uint8_t*)content_type;
            hdrs[1].namelen = 12;
            hdrs[1].valuelen = strlen(content_type);
            hdrs[1].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[2].name = (uint8_t*)"server";
            hdrs[2].value = (uint8_t*)"nghttp2/QServer";
            hdrs[2].namelen = 6;
            hdrs[2].valuelen = 15;
            hdrs[2].flags = NGHTTP2_NV_FLAG_NONE;

            hdr_count = 3;
        }
        else {
            // Range 응답 성공 - 206 Partial Content
            content_type = get_content_type(filepath);

            // range_end 재계산 (read_file_range에서 조정되었을 수 있음)
            size_t actual_end = sd->range_start + file_size - 1;

            snprintf(content_range_str, sizeof(content_range_str),
                     "bytes %zu-%zu/%zu", sd->range_start, actual_end, total_size);

            hdrs[0].name = (uint8_t*)":status";
            hdrs[0].value = (uint8_t*)"206";
            hdrs[0].namelen = 7;
            hdrs[0].valuelen = 3;
            hdrs[0].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[1].name = (uint8_t*)"content-type";
            hdrs[1].value = (uint8_t*)content_type;
            hdrs[1].namelen = 12;
            hdrs[1].valuelen = strlen(content_type);
            hdrs[1].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[2].name = (uint8_t*)"content-range";
            hdrs[2].value = (uint8_t*)content_range_str;
            hdrs[2].namelen = 13;
            hdrs[2].valuelen = strlen(content_range_str);
            hdrs[2].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[3].name = (uint8_t*)"accept-ranges";
            hdrs[3].value = (uint8_t*)"bytes";
            hdrs[3].namelen = 13;
            hdrs[3].valuelen = 5;
            hdrs[3].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[4].name = (uint8_t*)"server";
            hdrs[4].value = (uint8_t*)"nghttp2/QServer";
            hdrs[4].namelen = 6;
            hdrs[4].valuelen = 15;
            hdrs[4].flags = NGHTTP2_NV_FLAG_NONE;

            hdr_count = 5;
        }
    }
    else {
        // 일반 요청 (Range 없음)
        file_content = read_file(filepath, &file_size);
        if (!file_content) {
            const char* not_found = "<html><body><h1>404 Not Found</h1></body></html>";
            file_content = _strdup(not_found);
            file_size = strlen(not_found);
            content_type = "text/html; charset=utf-8";

            hdrs[0].name = (uint8_t*)":status";
            hdrs[0].value = (uint8_t*)"404";
            hdrs[0].namelen = 7;
            hdrs[0].valuelen = 3;
            hdrs[0].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[1].name = (uint8_t*)"content-type";
            hdrs[1].value = (uint8_t*)content_type;
            hdrs[1].namelen = 12;
            hdrs[1].valuelen = strlen(content_type);
            hdrs[1].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[2].name = (uint8_t*)"server";
            hdrs[2].value = (uint8_t*)"nghttp2/QServer";
            hdrs[2].namelen = 6;
            hdrs[2].valuelen = 15;
            hdrs[2].flags = NGHTTP2_NV_FLAG_NONE;

            hdr_count = 3;
        }
        else {
            content_type = get_content_type(filepath);

            hdrs[0].name = (uint8_t*)":status";
            hdrs[0].value = (uint8_t*)"200";
            hdrs[0].namelen = 7;
            hdrs[0].valuelen = 3;
            hdrs[0].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[1].name = (uint8_t*)"content-type";
            hdrs[1].value = (uint8_t*)content_type;
            hdrs[1].namelen = 12;
            hdrs[1].valuelen = strlen(content_type);
            hdrs[1].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[2].name = (uint8_t*)"accept-ranges";
            hdrs[2].value = (uint8_t*)"bytes";
            hdrs[2].namelen = 13;
            hdrs[2].valuelen = 5;
            hdrs[2].flags = NGHTTP2_NV_FLAG_NONE;

            hdrs[3].name = (uint8_t*)"server";
            hdrs[3].value = (uint8_t*)"nghttp2/QServer";
            hdrs[3].namelen = 6;
            hdrs[3].valuelen = 15;
            hdrs[3].flags = NGHTTP2_NV_FLAG_NONE;

            hdr_count = 4;
        }
    }

    sd->provider.data = file_content;
    sd->provider.length = file_size;
    sd->provider.pos = 0;
    sd->provider.should_free = 1;

    data_prd.source.ptr = &sd->provider;
    data_prd.read_callback = data_source_read_callback;

    rv = nghttp2_submit_response(session, stream_id, hdrs, hdr_count, &data_prd);

    if (rv != 0) {
        printf("응답 제출 실패: %s\n", nghttp2_strerror(rv));
    }
    else {
        // [상세 로그] 응답 제출 성공
        // printf("응답 제출 성공: stream_id=%d\n", stream_id);
    }

    sd->response_sent = 1;
    return 0;
}

// 요청 처리 메인 함수 (API와 정적 파일을 분기)
static int handle_request(nghttp2_session* session, stream_data* sd, int32_t stream_id) {
    if (!sd || sd->response_sent) return 0;

    // API 요청 처리
    if (handle_api_routes(session, sd, stream_id)) {
        return 0;  // API 처리 완료
    }

    // 정적 파일 처리
    return handle_static_file(session, sd, stream_id);
}

// 데이터 청크 읽기 콜백
static ssize_t data_source_read_callback(nghttp2_session* session,
    int32_t stream_id, uint8_t* buf, size_t length,
    uint32_t* data_flags, nghttp2_data_source* source,
    void* user_data) {
    data_provider_userdata* provider;
    size_t to_copy;
    (void)session;
    (void)user_data;

    provider = (data_provider_userdata*)source->ptr;
    to_copy = provider->length - provider->pos;

    if (to_copy > length) {
        to_copy = length;
    }

    memcpy(buf, provider->data + provider->pos, to_copy);
    provider->pos += to_copy;

    if (provider->pos >= provider->length) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        // 메모리 해제가 필요한 경우
        if (provider->should_free && provider->data) {
            free(provider->data);
            provider->data = NULL;
        }
    }

    // [상세 로그] 전송 데이터 정보
    // printf("데이터 전송: stream_id=%d, bytes=%zu, EOF=%d\n",
    //     stream_id, to_copy, (*data_flags & NGHTTP2_DATA_FLAG_EOF) ? 1 : 0);

    return (ssize_t)to_copy;
}

// 스트림 데이터 찾기/생성 (세션별 관리)
static stream_data* get_stream_data(http2_session_data* session_data, int32_t stream_id) {
    stream_data* sd;

    if (!session_data) return NULL;

    // 세션의 스트림 리스트에서 찾기
    sd = session_data->streams;
    while (sd) {
        if (sd->stream_id == stream_id) {
            return sd;
        }
        sd = sd->next;
    }

    // 새로 생성하여 세션의 리스트에 추가
    sd = (stream_data*)calloc(1, sizeof(stream_data));
    if (!sd) return NULL;

    sd->stream_id = stream_id;
    sd->session_data = session_data;  // 세션 연결
    sd->next = session_data->streams;
    session_data->streams = sd;

    return sd;
}

// 세션의 모든 스트림 강제 정리 (메모리 누수 방지)
static void cleanup_all_streams(http2_session_data* session_data) {
    stream_data* sd;
    stream_data* next;
    int count = 0;

    if (!session_data) return;

    sd = session_data->streams;
    while (sd) {
        next = sd->next;

        // 리소스 정리
        cleanup_stream_resources(sd);

        // 노드 메모리 해제
        free(sd);
        count++;

        sd = next;
    }

    session_data->streams = NULL;

    // if (count > 0) {
    //     printf("[CLEANUP] 세션 종료: %d개 스트림 강제 정리 (메모리 누수 방지)\n", count);
    // }
}

// 요청 시작 콜백 - 여기서 응답 전송
static int on_begin_headers_callback(nghttp2_session* session,
    const nghttp2_frame* frame, void* user_data) {
    http2_session_data* session_data = (http2_session_data*)user_data;
    stream_data* sd;
    (void)session;

    if (!session_data) return 0;

    // 요청 헤더가 시작될 때만 스트림 데이터 생성
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    // 스트림 데이터 초기화 (응답은 on_frame_recv_callback에서 처리)
    sd = get_stream_data(session_data, frame->hd.stream_id);
    if (!sd) return 0;

    sd->path[0] = '\0';
    sd->method[0] = '\0';
    sd->content_type[0] = '\0';
    sd->response_sent = 0;
    sd->provider.data = NULL;
    sd->provider.length = 0;
    sd->provider.pos = 0;
    sd->provider.should_free = 0;

    // Range 요청 초기화
    sd->has_range = 0;
    sd->range_start = 0;
    sd->range_end = 0;

    // Body 초기화 (모든 body는 파일로 저장)
    sd->body_length = 0;

    // 파일 스트리밍 초기화
    sd->body_file_path[0] = '\0';
    if (sd->body_file) {
        fclose(sd->body_file);
        sd->body_file = NULL;
    }

    // printf("[REQ] 새 요청 시작: stream_id=%d\n", frame->hd.stream_id);

    return 0;
}

// SSL 컨텍스트 초기화
SSL_CTX* create_ssl_ctx(void) {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // TLS 1.2 이상만 허용
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // ALPN 콜백 설정
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_proto_cb, NULL);

    return ctx;
}

// 인증서에서 도메인 이름(CN) 추출
static int get_cert_domain(SSL_CTX* ctx, char* domain_out, size_t domain_size) {
    X509* cert = NULL;
    X509_NAME* subject = NULL;
    BIO* bio = NULL;

    // BIO를 사용하여 인증서 파일 읽기 (AppLink 문제 회피)
    bio = BIO_new_file(CERT_FILE, "r");
    if (!bio) return 0;

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) return 0;

    subject = X509_get_subject_name(cert);
    if (subject) {
        int len = X509_NAME_get_text_by_NID(subject, NID_commonName,
                                             domain_out, (int)domain_size);
        X509_free(cert);
        return (len > 0) ? 1 : 0;
    }

    X509_free(cert);
    return 0;
}

// 로컬 IP 주소 가져오기
static int get_local_ip(char* ip_out, size_t ip_size) {
    char hostname[256];
    struct hostent* host_info;
    struct in_addr addr;

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return 0;
    }

    host_info = gethostbyname(hostname);
    if (!host_info || host_info->h_addr_list[0] == NULL) {
        return 0;
    }

    memcpy(&addr, host_info->h_addr_list[0], sizeof(struct in_addr));
    strncpy(ip_out, inet_ntoa(addr), ip_size - 1);
    ip_out[ip_size - 1] = '\0';

    return 1;
}

// 인증서 로드
int load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    // 인증서 로드
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 개인키 로드
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 개인키 검증
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "개인키가 인증서와 일치하지 않습니다\n");
        return -1;
    }

    printf("---- [OK] 인증서 로드 성공\n");
    return 0;
}

// nghttp2 세션 초기화
nghttp2_session* create_http2_session(http2_session_data* session_data) {
    nghttp2_session_callbacks* callbacks;
    nghttp2_session* session;
    nghttp2_settings_entry settings[2];
    int rv;

    // 콜백 설정
    rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        return NULL;
    }

    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

    // 서버 세션 생성
    rv = nghttp2_session_server_new(&session, callbacks, session_data);
    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0) {
        fprintf(stderr, "nghttp2 세션 생성 실패: %s\n", nghttp2_strerror(rv));
        return NULL;
    }

    // 초기 윈도우 크기 증가 (대용량 업로드 지원)
    rv = nghttp2_session_set_local_window_size(session, NGHTTP2_FLAG_NONE, 0, 100 * 1024 * 1024); // 100MB
    if (rv != 0) {
        fprintf(stderr, "윈도우 크기 설정 실패: %s\n", nghttp2_strerror(rv));
    }

    // 서버 설정 전송
    settings[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    settings[0].value = 100;

    settings[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
    settings[1].value = 100 * 1024 * 1024;  // 100MB

    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, 2);

    if (rv != 0) {
        fprintf(stderr, "설정 전송 실패: %s\n", nghttp2_strerror(rv));
        nghttp2_session_del(session);
        return NULL;
    }

    return session;
}

// 클라이언트 스레드용 데이터 구조체
typedef struct {
    SOCKET client_sock;
    SSL_CTX* ssl_ctx;
    struct sockaddr_in client_addr;
} client_thread_data;

// 클라이언트 처리 스레드 함수
unsigned __stdcall client_thread_func(void* arg) {
    client_thread_data* data = (client_thread_data*)arg;

    printf("[클라이언트] 연결: %s:%d\n",
        inet_ntoa(data->client_addr.sin_addr),
        ntohs(data->client_addr.sin_port));

    handle_client(data->client_sock, data->ssl_ctx);

    printf("[클라이언트] 연결 종료: %s:%d\n",
        inet_ntoa(data->client_addr.sin_addr),
        ntohs(data->client_addr.sin_port));

    free(data);
    return 0;
}

// 클라이언트 처리
void handle_client(SOCKET client_sock, SSL_CTX* ssl_ctx) {
    SSL* ssl;
    http2_session_data session_data;
    const unsigned char* alpn_proto;
    unsigned int alpn_len;
    int rv;

    memset(&session_data, 0, sizeof(session_data));

    // 소켓 타임아웃 설정 (100ms)
    {
        int timeout_ms = 100;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    }

    // SSL 객체 생성
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, (int)client_sock);

    // TLS 핸드셰이크
    // [상세 로그] TLS 핸드셰이크 시작
    // printf("TLS 핸드셰이크 시작...\n");
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(client_sock);
        return;
    }

    // [상세 로그] TLS 핸드셰이크 성공
    // printf("TLS 핸드셰이크 성공\n");

    // ALPN 협상 결과 확인
    alpn_proto = NULL;
    alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);

    if (alpn_proto) {
        // [상세 로그] ALPN 프로토콜
        // printf("ALPN 프로토콜: %.*s\n", alpn_len, alpn_proto);
    }

    // 세션 데이터 초기화
    session_data.fd = (int)client_sock;
    session_data.ssl = ssl;
    session_data.streams = NULL;  // 스트림 리스트 초기화

    // nghttp2 세션 생성
    session_data.session = create_http2_session(&session_data);
    if (!session_data.session) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client_sock);
        return;
    }

    // [상세 로그] HTTP/2 세션 생성 성공
    // printf("HTTP/2 세션 생성 완료\n");

    // 메인 루프 - 데이터 송수신
    while (1) {
        // 전송할 데이터 처리
        rv = nghttp2_session_send(session_data.session);
        if (rv != 0) {
            fprintf(stderr, "전송 실패: %s\n", nghttp2_strerror(rv));
            break;
        }

        // 수신 데이터 처리
        rv = nghttp2_session_recv(session_data.session);
        if (rv != 0) {
            // WOULDBLOCK은 정상 - 단순히 수신할 데이터가 없음
            if (rv == NGHTTP2_ERR_WOULDBLOCK) {
                // 계속 진행
            }
            else if (rv == NGHTTP2_ERR_EOF) {
                // [상세 로그] EOF 수신 정보
                // printf("[DEBUG] EOF 수신\n");
                break;
            }
            else {
                fprintf(stderr, "[에러] 수신 실패: %s\n", nghttp2_strerror(rv));
                break;
            }
        }

        // 세션이 종료되었는지 확인
        if (nghttp2_session_want_read(session_data.session) == 0 &&
            nghttp2_session_want_write(session_data.session) == 0) {
            // [상세 로그] 세션 종료 정보
            // printf("[DEBUG] 세션 종료\n");
            break;
        }

        // CPU 사용률 낮추기
        Sleep(1);
    }

    // 정리
    // [메모리 누수 방지] 세션의 모든 스트림 강제 정리
    cleanup_all_streams(&session_data);

    nghttp2_session_del(session_data.session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client_sock);
    // 클라이언트 연결 종료는 스레드 함수에서 출력됨
}

int main(void) {
    WSADATA wsa;
    SOCKET server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int client_len;
    SSL_CTX* ssl_ctx;
    int opt;

    // 콘솔 UTF-8 설정 (한글 출력용)
    SetConsoleOutputCP(65001);

    printf("\n========================================\n");
    printf("   HTTP/2 서버 시작\n");
    printf("========================================\n\n");

    // Winsock 초기화
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[에러] Winsock 초기화 실패: %d\n", WSAGetLastError());
        return 1;
    }
    printf("---- [OK] Winsock 초기화 완료\n");

    // DB 초기화
    if (!db_init()) {
        fprintf(stderr, "[에러] DB 초기화 실패\n");
        WSACleanup();
        return 1;
    }
    printf("---- [OK] DB 라이브러리 초기화 완료\n");

    // OpenSSL 초기화
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // SSL 컨텍스트 생성
    ssl_ctx = create_ssl_ctx();
    if (!ssl_ctx) {
        WSACleanup();
        return 1;
    }
    printf("---- [OK] SSL 컨텍스트 생성 완료\n");

    // 인증서 로드 (certs 디렉토리의 인증서 사용)
    if (load_certificates(ssl_ctx, CERT_FILE, KEY_FILE) < 0) {
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return 1;
    }
    printf("---- [OK] 인증서/키 로드 성공\n");

    // 서버 소켓 생성
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "[에러] 소켓 생성 실패: %d\n", WSAGetLastError());
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return 1;
    }

    // 주소 재사용 옵션
    opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    // 바인딩
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "바인딩 실패: %d\n", WSAGetLastError());
        closesocket(server_sock);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return 1;
    }

    printf("---- [OK] 포트 바인딩: %d\n", SERVER_PORT);

    // 리스닝
    if (listen(server_sock, MAX_CLIENTS) == SOCKET_ERROR) {
        fprintf(stderr, "리스닝 실패: %d\n", WSAGetLastError());
        closesocket(server_sock);
        SSL_CTX_free(ssl_ctx);
        WSACleanup();
        return 1;
    }

    // 서버 정보 출력 (도메인 + IP)
    char domain[256] = {0};
    char local_ip[64] = {0};

    printf("\n========================================\n\n");
    printf("   서버 시작 완료!\n");

    if (get_cert_domain(ssl_ctx, domain, sizeof(domain))) {
        printf("   외부 접속: https://%s:%d\n", domain, SERVER_PORT);
    }
    printf("\n========================================\n\n");

    // 클라이언트 연결 수락 루프
    while (1) {
        client_thread_data* thread_data;
        HANDLE hThread;

        client_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);

        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "[에러] 연결 수락 실패: %d\n", WSAGetLastError());
            continue;
        }

        // 클라이언트 연결 로그는 스레드에서 출력됨

        // 클라이언트 데이터 할당
        thread_data = (client_thread_data*)malloc(sizeof(client_thread_data));
        if (!thread_data) {
            fprintf(stderr, "[에러] 메모리 할당 실패\n");
            closesocket(client_sock);
            continue;
        }

        thread_data->client_sock = client_sock;
        thread_data->ssl_ctx = ssl_ctx;
        thread_data->client_addr = client_addr;

        // 새 스레드 생성하여 클라이언트 처리 (멀티 스레드)
        hThread = (HANDLE)_beginthreadex(NULL, 0, client_thread_func, thread_data, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);  // 스레드 핸들 즉시 닫기 (detached)
            // [상세 로그] 클라이언트 처리 스레드 생성
            // printf("클라이언트 처리 스레드 생성 완료\n");
        }
        else {
            fprintf(stderr, "스레드 생성 실패\n");
            free(thread_data);
            closesocket(client_sock);
        }
    }

    // 정리
    closesocket(server_sock);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    db_cleanup();
    WSACleanup();

    return 0;
}
