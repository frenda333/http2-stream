// fetch.c - API 엔드포인트 구현
#define _CRT_SECURE_NO_WARNINGS

#include "fetch.h"
#include "DB.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>

// x-www-form-urlencoded 디코더 (인플레이스)
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

// ==================== 공통 폼 파싱 헬퍼 ====================

// 폼 필드 구조체: 키-값 매핑
typedef struct {
    const char* key;    // 찾을 키 이름
    char* value;        // 값을 저장할 버퍼
    size_t value_size;  // 버퍼 크기
} form_field;

// application/x-www-form-urlencoded 파싱 (공통 함수)
static int parse_form_data(const char* body, form_field* fields, int field_count) {
    if (!body || !fields || field_count <= 0) return 0;

    char* copy = _strdup(body);
    if (!copy) return 0;

    char* ctx = NULL;
    char* token = strtok_s(copy, "&", &ctx);

    while (token) {
        char* eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            char* key = token;
            char* val = eq + 1;

            url_decode_inplace(key);
            url_decode_inplace(val);

            // 모든 필드를 순회하며 일치하는 키 찾기
            for (int i = 0; i < field_count; i++) {
                if (strcmp(key, fields[i].key) == 0) {
                    strncpy(fields[i].value, val, fields[i].value_size - 1);
                    fields[i].value[fields[i].value_size - 1] = '\0';
                    break;
                }
            }
        }
        token = strtok_s(NULL, "&", &ctx);
    }

    free(copy);
    return 1;
}

// 영상 파일 삭제 (video, thumb)
static void delete_video_files(int video_id) {
    char video_path[512];
    char thumb_path[512];
    snprintf(video_path, sizeof(video_path), "public/video/%d.mp4", video_id);
    snprintf(thumb_path, sizeof(thumb_path), "public/thumb/%d.jpg", video_id);

    if (remove(video_path) == 0) {
        printf("[파일] 삭제: %s\n", video_path);
    } else {
        printf("[에러] 파일 삭제 실패: %s\n", video_path);
    }

    if (remove(thumb_path) == 0) {
        printf("[파일] 삭제: %s\n", thumb_path);
    } else {
        printf("[에러] 파일 삭제 실패: %s\n", thumb_path);
    }
}

// API 응답 생성
api_response* api_response_create(int status_code, const char* content_type, const char* body) {
    api_response* resp;

    resp = (api_response*)malloc(sizeof(api_response));
    if (!resp) return NULL;

    resp->status_code = status_code;
    resp->content_type = content_type;

    if (body) {
        resp->body_length = strlen(body);
        resp->body = (char*)malloc(resp->body_length + 1);
        if (resp->body) {
            strcpy(resp->body, body);
        } else {
            free(resp);
            return NULL;
        }
    } else {
        resp->body = NULL;
        resp->body_length = 0;
    }

    return resp;
}

// API 응답 해제
void api_response_free(api_response* resp) {
    if (resp) {
        if (resp->body) {
            free(resp->body);
        }
        free(resp);
    }
}

// ==================== API 엔드포인트 구현 ====================

// POST /register - 회원가입
api_response* handle_register(const char* body) {
    printf("[API] POST /register\n");

    if (!body) body = "";

    // 폼 데이터 파싱
    char name[256] = { 0 };
    char username[128] = { 0 };
    char password[128] = { 0 };

    form_field fields[] = {
        {"name", name, sizeof(name)},
        {"username", username, sizeof(username)},
        {"password", password, sizeof(password)}
    };

    if (!parse_form_data(body, fields, 3)) {
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"status\":\"failure\",\"message\":\"memory error\"}");
    }

    // 필수 필드 검증
    if (strlen(name) == 0 || strlen(username) == 0 || strlen(password) == 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"status\":\"failure\",\"message\":\"missing fields\"}");
    }

    // DB 처리
    int result = db_register_user(name, username, password);
    if (result) {
        return api_response_create(200, "application/json; charset=utf-8",
            "{\"status\":\"success\"}");
    }
    else {
        return api_response_create(409, "application/json; charset=utf-8",
            "{\"status\":\"failure\",\"message\":\"duplicate or db error\"}");
    }
}

// POST /login - 로그인
api_response* handle_login(const char* body) {
    printf("[API] POST /login\n");
    if (!body) body = "";

    char username[128] = { 0 };
    char password[128] = { 0 };

    form_field fields[] = {
        {"username", username, sizeof(username)},
        {"password", password, sizeof(password)}
    };

    if (!parse_form_data(body, fields, 2)) {
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"status\":\"failure\",\"message\":\"memory error\"}");
    }

    if (strlen(username) == 0 || strlen(password) == 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"status\":\"failure\",\"message\":\"missing fields\"}");
    }

    // DB 로그인 확인 (user_id 반환)
    int user_id = db_login_user(username, password);
    if (user_id > 0) {
        // 로그인 성공 - user_id와 username 반환
        cJSON* success = cJSON_CreateObject();
        cJSON_AddStringToObject(success, "status", "success");
        cJSON_AddNumberToObject(success, "user_id", user_id);
        cJSON_AddStringToObject(success, "username", username);
        char* success_str = cJSON_PrintUnformatted(success);
        api_response* resp = api_response_create(200, "application/json; charset=utf-8", success_str);
        cJSON_free(success_str);
        cJSON_Delete(success);
        return resp;
    }
    else {
        // 로그인 실패 (아이디/비밀번호 불일치)
        return api_response_create(401, "application/json; charset=utf-8",
            "{\"status\":\"failure\",\"message\":\"invalid username or password\"}");
    }
}

// GET /video_list - 비디오 목록 (user_id 옵션)
api_response* handle_video_list(int user_id) {
    char json_buffer[8192];
    int result;

    printf("[API] GET /video_list (user_id=%d)\n", user_id);

    result = db_get_video_list(user_id, json_buffer, sizeof(json_buffer));

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        printf("[에러] /video_list - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Database error\"}");
    }
}

// 메모리에서 패턴 찾기 (memmem 대체)
static const char* find_in_mem(const char* haystack, size_t haystack_len, const char* needle, size_t needle_len) {
    if (needle_len == 0 || needle_len > haystack_len) return NULL;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

// ==================== 파일 스트리밍 멀티파트 파서 ====================

// 멀티파트 파싱 결과 구조체
typedef struct {
    char user_id_str[32];
    char videoname[256];
    char description[1024];
    char video_file_path[512];  // 추출된 비디오 파일 경로
    size_t video_size;
} multipart_parse_result;

// 파일에서 한 줄 읽기 (CRLF 또는 LF 처리)
static int read_line_from_file(FILE* fp, char* buffer, size_t buffer_size, size_t* line_len) {
    size_t i = 0;
    int ch;

    while (i < buffer_size - 1) {
        ch = fgetc(fp);
        if (ch == EOF) {
            if (i == 0) return 0;  // EOF
            break;
        }

        if (ch == '\n') {
            // LF 발견 - 줄 끝
            break;
        }

        if (ch == '\r') {
            // CR 발견 - 다음이 LF인지 확인
            int next = fgetc(fp);
            if (next != '\n' && next != EOF) {
                ungetc(next, fp);  // LF 아니면 되돌리기
            }
            break;
        }

        buffer[i++] = (char)ch;
    }

    buffer[i] = '\0';
    *line_len = i;
    return 1;
}

// 64비트 파일 위치 헬퍼 (2GB 이상 업로드 대응)
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

// 파일 스트리밍 방식으로 멀티파트 파싱 (메모리 재로드 없음)
static int parse_multipart_from_file(const char* file_path, const char* boundary,
                                      multipart_parse_result* result) {
    FILE* fp = NULL;
    char line_buffer[2048];
    size_t line_len;
    char boundary_line[256];
    char boundary_end[256];
    int found_video = 0;
    FILE* video_fp = NULL;

    memset(result, 0, sizeof(multipart_parse_result));

    // boundary 구분자 생성
    snprintf(boundary_line, sizeof(boundary_line), "--%s", boundary);
    snprintf(boundary_end, sizeof(boundary_end), "--%s--", boundary);

    fp = fopen(file_path, "rb");
    if (!fp) {
        printf("[에러] 멀티파트 파일 열기 실패: %s\n", file_path);
        return 0;
    }

    // 각 파트를 순회
    while (read_line_from_file(fp, line_buffer, sizeof(line_buffer), &line_len)) {
        // boundary 체크
        if (strncmp(line_buffer, boundary_line, strlen(boundary_line)) != 0) {
            continue;  // boundary 찾을 때까지 스킵
        }

        // 종료 boundary 체크
        if (strcmp(line_buffer, boundary_end) == 0) {
            break;
        }

        // Content-Disposition 헤더 읽기
        if (!read_line_from_file(fp, line_buffer, sizeof(line_buffer), &line_len)) {
            break;
        }

        // name 추출
        char field_name[64] = {0};
        const char* name_start = strstr(line_buffer, "name=\"");
        if (!name_start) continue;
        name_start += 6;

        const char* name_end = strchr(name_start, '"');
        if (!name_end) continue;

        size_t name_len = name_end - name_start;
        if (name_len >= sizeof(field_name)) continue;
        memcpy(field_name, name_start, name_len);
        field_name[name_len] = '\0';

        // Content-Type 헤더가 있으면 읽기 (videoFile의 경우)
        int64_t content_start_pos = file_tell64(fp);
        int has_content_type = 0;
        if (read_line_from_file(fp, line_buffer, sizeof(line_buffer), &line_len)) {
            if (strncmp(line_buffer, "Content-Type:", 13) == 0) {
                has_content_type = 1;
            } else {
                // Content-Type 없으면 되돌리기
                file_seek64(fp, content_start_pos, SEEK_SET);
            }
        }

        // 빈 줄 읽기 (헤더와 본문 구분)
        if (!read_line_from_file(fp, line_buffer, sizeof(line_buffer), &line_len)) {
            break;
        }

        // 본문 시작 위치
        int64_t body_start = file_tell64(fp);

        // 다음 boundary까지 읽기
        if (strcmp(field_name, "videoFile") == 0) {
            // 비디오 파일: 직접 파일로 스트리밍 복사
            snprintf(result->video_file_path, sizeof(result->video_file_path),
                     "public/video/temp_stream_%d.mp4", (int)time(NULL));

            video_fp = fopen(result->video_file_path, "wb");
            if (!video_fp) {
                printf("[에러] 비디오 임시 파일 생성 실패: %s\n", result->video_file_path);
                fclose(fp);
                return 0;
            }

            // 청크 단위로 복사 (boundary 찾을 때까지)
            char chunk[8192];
            char boundary_check[256];
            size_t boundary_check_len = 0;

            while (1) {
                size_t read_size = fread(chunk, 1, sizeof(chunk), fp);
                if (read_size == 0) break;

                // boundary 검색을 위한 버퍼
                for (size_t i = 0; i < read_size; i++) {
                    if (chunk[i] == '\r' || chunk[i] == '\n') {
                        // 줄바꿈 발견 - boundary 체크
                        if (boundary_check_len > 0) {
                            boundary_check[boundary_check_len] = '\0';
                            if (strncmp(boundary_check, boundary_line, strlen(boundary_line)) == 0) {
                                // boundary 발견!
                                // 이전까지 쓴 데이터에서 CRLF 제거
                                if (result->video_size >= 2) {
                                    file_seek64(video_fp, -2, SEEK_END);
                                    result->video_size -= 2;
                                }

                                // 현재 위치를 boundary 시작으로 되돌리기
                                int64_t current = file_tell64(fp);
                                file_seek64(fp, current - (int64_t)read_size + (int64_t)i - (int64_t)boundary_check_len, SEEK_SET);
                                found_video = 1;
                                goto video_done;
                            }

                            // boundary 아니면 버퍼 내용 쓰기
                            fwrite(boundary_check, 1, boundary_check_len, video_fp);
                            result->video_size += boundary_check_len;

                            // CRLF도 쓰기
                            fputc(chunk[i], video_fp);
                            result->video_size++;

                            boundary_check_len = 0;
                        } else {
                            fputc(chunk[i], video_fp);
                            result->video_size++;
                        }
                    } else {
                        // 일반 문자
                        if (boundary_check_len < sizeof(boundary_check) - 1) {
                            boundary_check[boundary_check_len++] = chunk[i];
                        } else {
                            // 버퍼 오버플로우 방지 - 기존 버퍼 쓰기
                            fwrite(boundary_check, 1, boundary_check_len, video_fp);
                            result->video_size += boundary_check_len;
                            boundary_check_len = 0;
                            boundary_check[boundary_check_len++] = chunk[i];
                        }
                    }
                }
            }

video_done:
            fclose(video_fp);
            video_fp = NULL;

            if (!found_video) {
                printf("[에러] 비디오 파일 boundary를 찾지 못함\n");
                remove(result->video_file_path);
                fclose(fp);
                return 0;
            }

            printf("[스트리밍] 비디오 파일 추출 완료: %s (%zu bytes)\n",
                   result->video_file_path, result->video_size);
        } else {
            // 작은 필드: 메모리에 저장
            char field_buffer[1024] = {0};
            size_t field_len = 0;

            while (read_line_from_file(fp, line_buffer, sizeof(line_buffer), &line_len)) {
                // boundary 체크
                if (strncmp(line_buffer, boundary_line, strlen(boundary_line)) == 0) {
                    // 되돌리기
                    file_seek64(fp, -(int64_t)(line_len + 2), SEEK_CUR);  // CRLF 포함
                    break;
                }

                // 필드 데이터 누적
                if (field_len + line_len >= sizeof(field_buffer) - 1) {
                    printf("[에러] 필드 길이 초과: %s (현재: %zu, 추가: %zu, 최대: %zu)\n",
                           field_name, field_len, line_len, sizeof(field_buffer) - 1);
                    fclose(fp);
                    if (found_video) remove(result->video_file_path);
                    return 0;
                }
                memcpy(field_buffer + field_len, line_buffer, line_len);
                field_len += line_len;
            }

            field_buffer[field_len] = '\0';

            // 필드별 저장
            if (strcmp(field_name, "user_id") == 0) {
                if (field_len >= sizeof(result->user_id_str)) {
                    printf("[에러] user_id 길이 초과: %zu\n", field_len);
                    fclose(fp);
                    if (found_video) remove(result->video_file_path);
                    return 0;
                }
                strcpy(result->user_id_str, field_buffer);
            } else if (strcmp(field_name, "videoname") == 0) {
                if (field_len >= sizeof(result->videoname)) {
                    printf("[에러] videoname 길이 초과: %zu\n", field_len);
                    fclose(fp);
                    if (found_video) remove(result->video_file_path);
                    return 0;
                }
                strcpy(result->videoname, field_buffer);
            } else if (strcmp(field_name, "description") == 0) {
                if (field_len >= sizeof(result->description)) {
                    printf("[에러] description 길이 초과: %zu\n", field_len);
                    fclose(fp);
                    if (found_video) remove(result->video_file_path);
                    return 0;
                }
                strcpy(result->description, field_buffer);
            }
        }
    }

    fclose(fp);

    // 유효성 검사
    if (!found_video || strlen(result->user_id_str) == 0 || strlen(result->videoname) == 0) {
        printf("[에러] 필수 필드 누락\n");
        if (found_video) remove(result->video_file_path);
        return 0;
    }

    printf("[파싱 완료] user_id=%s, videoname=%s, video_size=%zu\n",
           result->user_id_str, result->videoname, result->video_size);

    return 1;
}

// FFmpeg를 사용하여 영상 길이 추출 (초 단위로 반환)
static int get_video_duration(int video_id) {
    char video_path[512];
    char command[1024];
    char temp_file[512];

    // 파일 경로 생성
    snprintf(video_path, sizeof(video_path), "public/video/%d.mp4", video_id);
    snprintf(temp_file, sizeof(temp_file), "temp_duration_%d.txt", video_id);

    // FFmpeg 명령어: duration을 파일로 출력
    snprintf(command, sizeof(command),
             "ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 \"%s\" > \"%s\" 2>NUL",
             video_path, temp_file);

    // FFmpeg 실행
    int result = system(command);

    if (result != 0) {
        printf("[DURATION] FFprobe 실행 실패 (error code: %d)\n", result);
        return 0;
    }

    // 파일에서 duration 읽기
    FILE* fp = fopen(temp_file, "r");
    if (!fp) {
        printf("[DURATION] 임시 파일 열기 실패: %s\n", temp_file);
        return 0;
    }

    char duration_str[64] = {0};
    if (fgets(duration_str, sizeof(duration_str), fp) == NULL) {
        printf("[DURATION] 파일 읽기 실패\n");
        fclose(fp);
        remove(temp_file);
        return 0;
    }
    fclose(fp);

    // 임시 파일 삭제
    remove(temp_file);

    // 문자열을 초 단위 정수로 변환
    double duration_seconds = atof(duration_str);
    int duration_int = (int)(duration_seconds + 0.5); // 반올림

    printf("[DURATION] 영상 길이: %d초 (video_id=%d)\n", duration_int, video_id);
    return duration_int;
}

// FFmpeg를 사용하여 영상에서 썸네일 추출
static int generate_thumbnail(int video_id) {
    char video_path[512];
    char thumb_path[512];
    char command[1024];

    // 파일 경로 생성
    snprintf(video_path, sizeof(video_path), "public/video/%d.mp4", video_id);
    snprintf(thumb_path, sizeof(thumb_path), "public/thumb/%d.jpg", video_id);

    // FFmpeg 명령어 생성 (1초 지점에서 1프레임 추출)
    snprintf(command, sizeof(command),
             "ffmpeg -i \"%s\" -ss 00:00:01 -vframes 1 -y \"%s\" 2>NUL",
             video_path, thumb_path);

    // [상세 로그] FFmpeg 명령어
    // printf("[THUMB] FFmpeg 명령어: %s\n", command);

    // FFmpeg 실행
    int result = system(command);

    if (result == 0) {
        printf("[THUMB] 썸네일 생성 성공: %s\n", thumb_path);
        return 1;
    } else {
        printf("[THUMB] 썸네일 생성 실패 (error code: %d)\n", result);

        // 기본 썸네일 생성 실패 시 빈 파일 생성 (선택사항)
        // 또는 기본 이미지 복사

        return 0;
    }
}

// POST /upload_video - 비디오 업로드 (파일 스트리밍 전용)
api_response* handle_upload_video(const char* body, const char* content_type, size_t body_length, const char* file_path) {
    printf("[API] POST /upload_video (%zu bytes)\n", body_length);

    if (!content_type || body_length == 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Missing body or content-type\"}");
    }

    // 파일 경로 필수 (모든 업로드는 파일 스트리밍으로 처리)
    if (!file_path) {
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Internal error: file streaming required\"}");
    }

    // boundary 추출
    const char* boundary_prefix = "boundary=";
    const char* boundary_start = strstr(content_type, boundary_prefix);
    if (!boundary_start) {
        remove(file_path);
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Missing boundary in content-type\"}");
    }

    const char* boundary = boundary_start + strlen(boundary_prefix);

    // ==================== 파일 스트리밍 파싱 (모든 업로드 통일) ====================
    multipart_parse_result parse_result;

    // 파일 스트리밍 파서 호출 - 메모리에 전체 로드하지 않음!
    if (!parse_multipart_from_file(file_path, boundary, &parse_result)) {
        printf("[에러] 멀티파트 파싱 실패\n");
        remove(file_path);  // 원본 멀티파트 파일 삭제
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Multipart parsing failed\"}");
    }

    // 원본 멀티파트 파일 삭제 (더 이상 필요 없음)
    remove(file_path);

    // 파싱된 데이터
    int user_id = atoi(parse_result.user_id_str);
    const char* videoname = parse_result.videoname;
    const char* description = parse_result.description;
    const char* temp_video_path = parse_result.video_file_path;
    size_t video_size = parse_result.video_size;

    printf("[업로드] user_id=%d, videoname=%s, video_size=%zu\n",
           user_id, videoname, video_size);

    // FFmpeg로 영상 길이 추출
    int duration = 0;
    {
        char command[1024];
        char temp_duration_file[512];
        snprintf(temp_duration_file, sizeof(temp_duration_file),
                 "temp_dur_%d_%d.txt", user_id, (int)time(NULL));

        snprintf(command, sizeof(command),
                 "ffprobe -v error -show_entries format=duration "
                 "-of default=noprint_wrappers=1:nokey=1 \"%s\" > \"%s\" 2>NUL",
                 temp_video_path, temp_duration_file);

        if (system(command) == 0) {
            FILE* dur_fp = fopen(temp_duration_file, "r");
            if (dur_fp) {
                char duration_str[64] = {0};
                if (fgets(duration_str, sizeof(duration_str), dur_fp)) {
                    duration = (int)(atof(duration_str) + 0.5);
                }
                fclose(dur_fp);
            }
            remove(temp_duration_file);
        }
    }

    printf("[DURATION] 추출된 영상 길이: %d초\n", duration);

    // DB에 메타데이터 저장
    int video_id = db_add_video(user_id, videoname, description, duration);
    if (video_id <= 0) {
        remove(temp_video_path);
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Failed to save video metadata\"}");
    }

    // 임시 파일을 정식 파일명으로 이동
    char final_filepath[512];
    snprintf(final_filepath, sizeof(final_filepath), "public/video/%d.mp4", video_id);

    if (rename(temp_video_path, final_filepath) != 0) {
        printf("[에러] 파일 이동 실패: %s -> %s\n", temp_video_path, final_filepath);
        remove(temp_video_path);
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Failed to move video file\"}");
    }

    printf("[파일] 업로드 성공: %s (%zu bytes, %d초)\n",
           final_filepath, video_size, duration);

    // 썸네일 생성
    generate_thumbnail(video_id);

    // 성공 응답
    char response[256];
    snprintf(response, sizeof(response),
             "{\"status\":\"success\",\"video_id\":%d}", video_id);
    return api_response_create(200, "application/json; charset=utf-8", response);
}

// GET /video_details?id=123 - 비디오 상세정보
api_response* handle_video_details(int video_id) {
    char json_buffer[4096];
    int result;

    printf("[API] GET /video_details?id=%d\n", video_id);

    result = db_get_video_details(video_id, json_buffer, sizeof(json_buffer));

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        printf("[에러] /video_details - 비디오 없음 (id=%d)\n", video_id);
        return api_response_create(404, "application/json; charset=utf-8",
            "{\"error\":\"Video not found\"}");
    }
}

// GET /watch_history?user_id=1&video_id=2 - 시청 기록 조회
api_response* handle_watch_history(int user_id, int video_id) {
    char json_buffer[1024];
    int result;

    printf("[API] GET /watch_history?user_id=%d&video_id=%d\n", user_id, video_id);

    result = db_get_watch_history(user_id, video_id, json_buffer, sizeof(json_buffer));

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        // [상세 로그] 시청 기록 없음 (정상 케이스)
        // printf("[DEBUG] /watch_history: 기록 없음\n");
        return api_response_create(200, "application/json; charset=utf-8",
            "{\"record\":0,\"last_watch\":null}");
    }
}

// POST /update_history - 시청 기록 업데이트
api_response* handle_update_history(const char* body) {
    // [상세 로그] 시청 기록 업데이트 호출 (주기적 호출로 기본 비활성화)
    // printf("[API] POST /update_history\n");
    // [상세 로그] 요청 body 내용
    // printf("[DEBUG] body: %s\n", body ? body : "(null)");

    if (!body) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Missing request body\"}");
    }

    // body 파싱: user_id=1&video_id=2&record=123 형식
    int user_id = 0, video_id = 0, record = 0;

    char body_copy[1024];
    strncpy(body_copy, body, sizeof(body_copy) - 1);
    body_copy[sizeof(body_copy) - 1] = '\0';

    // user_id 추출
    char* token = strstr(body_copy, "user_id=");
    if (token) {
        user_id = atoi(token + 8);
    }

    // video_id 추출
    token = strstr(body_copy, "video_id=");
    if (token) {
        video_id = atoi(token + 9);
    }

    // record 추출
    token = strstr(body_copy, "record=");
    if (token) {
        record = atoi(token + 7);
    }

    // [상세 로그] 파싱 결과
    // printf("[DEBUG] user_id=%d, video_id=%d, record=%d\n", user_id, video_id, record);

    // 유효성 검사
    if (user_id <= 0 || video_id <= 0 || record < 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid parameters\"}");
    }

    // DB 업데이트
    int result = db_update_watch_history(user_id, video_id, record);

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8",
            "{\"success\":true}");
    } else {
        printf("[에러] /update_history - DB 업데이트 실패\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"DB update failed\"}");
    }
}

// GET /video_search?q=검색어 - 영상 검색 (제목 부분 일치, 사용자 기록 포함)
api_response* handle_video_search(const char* search_query, int user_id) {
    char json_buffer[8192];
    int result;

    printf("[API] GET /video_search?q=%s, user_id=%d\n", search_query ? search_query : "(empty)", user_id);

    // 검색어가 비어있거나 NULL인 경우, 모든 영상을 반환 (video_list와 동일)
    if (!search_query || strlen(search_query) == 0) {
        result = db_get_video_list(user_id, json_buffer, sizeof(json_buffer));
    } else {
        result = db_search_videos(search_query, user_id, json_buffer, sizeof(json_buffer));
    }

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        printf("[에러] /video_search - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Database error\"}");
    }
}

// GET /user_videos?user_id=1 - 특정 사용자의 영상 목록
api_response* handle_user_videos(int user_id) {
    char json_buffer[8192];
    int result;

    printf("[API] GET /user_videos?user_id=%d\n", user_id);

    if (user_id <= 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid user_id\"}");
    }

    result = db_get_user_videos(user_id, json_buffer, sizeof(json_buffer));

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        printf("[에러] /user_videos - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Database error\"}");
    }
}

// POST /update_video - 영상 정보 수정
api_response* handle_update_video(const char* body) {
    printf("[API] POST /update_video\n");
    if (!body) body = "";

    char video_id_str[32] = { 0 };
    char user_id_str[32] = { 0 };
    char videoname[256] = { 0 };
    char description[1024] = { 0 };

    form_field fields[] = {
        {"video_id", video_id_str, sizeof(video_id_str)},
        {"user_id", user_id_str, sizeof(user_id_str)},
        {"videoname", videoname, sizeof(videoname)},
        {"description", description, sizeof(description)}
    };

    if (!parse_form_data(body, fields, 4)) {
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Memory error\"}");
    }

    int video_id = atoi(video_id_str);
    int user_id = atoi(user_id_str);

    // 유효성 검사
    if (video_id <= 0 || user_id <= 0 || strlen(videoname) == 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid parameters\"}");
    }

    // DB 업데이트
    int result = db_update_video(video_id, user_id, videoname, description);

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8",
            "{\"success\":true}");
    } else {
        printf("[에러] /update_video - 권한 없음 또는 DB 오류\n");
        return api_response_create(403, "application/json; charset=utf-8",
            "{\"error\":\"Permission denied or DB error\"}");
    }
}

// POST /delete_video - 영상 삭제 (DB + 파일)
api_response* handle_delete_video(const char* body) {
    printf("[API] POST /delete_video\n");
    if (!body) body = "";

    char video_id_str[32] = { 0 };
    char user_id_str[32] = { 0 };

    form_field fields[] = {
        {"video_id", video_id_str, sizeof(video_id_str)},
        {"user_id", user_id_str, sizeof(user_id_str)}
    };

    if (!parse_form_data(body, fields, 2)) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Missing request body\"}");
    }

    int video_id = atoi(video_id_str);
    int user_id = atoi(user_id_str);

    // 유효성 검사
    if (video_id <= 0 || user_id <= 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid parameters\"}");
    }

    // DB에서 삭제 (권한 확인 포함)
    int result = db_delete_video(video_id, user_id);

    if (!result) {
        printf("[에러] /delete_video - 권한 없음 또는 DB 오류\n");
        return api_response_create(403, "application/json; charset=utf-8",
            "{\"error\":\"Permission denied or DB error\"}");
    }

    // 로컬 파일 삭제
    delete_video_files(video_id);

    return api_response_create(200, "application/json; charset=utf-8",
        "{\"success\":true}");
}

// GET /admin_videos - 관리자: 모든 영상 목록
api_response* handle_admin_videos(void) {
    char json_buffer[8192];
    int result;

    printf("[API] GET /admin_videos\n");

    result = db_get_all_videos(json_buffer, sizeof(json_buffer));

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        printf("[에러] /admin_videos - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Database error\"}");
    }
}

// POST /admin_update_video - 관리자: 영상 수정 (권한 확인 없음)
api_response* handle_admin_update_video(const char* body) {
    printf("[API] POST /admin_update_video\n");
    if (!body) body = "";

    char video_id_str[32] = { 0 };
    char videoname[256] = { 0 };
    char description[1024] = { 0 };

    form_field fields[] = {
        {"video_id", video_id_str, sizeof(video_id_str)},
        {"videoname", videoname, sizeof(videoname)},
        {"description", description, sizeof(description)}
    };

    if (!parse_form_data(body, fields, 3)) {
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Memory error\"}");
    }

    int video_id = atoi(video_id_str);

    if (video_id <= 0 || strlen(videoname) == 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid parameters\"}");
    }

    int result = db_admin_update_video(video_id, videoname, description);

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8",
            "{\"success\":true}");
    } else {
        printf("[에러] /admin_update_video - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"DB error\"}");
    }
}

// POST /admin_delete_video - 관리자: 영상 삭제 (권한 확인 없음)
api_response* handle_admin_delete_video(const char* body) {
    printf("[API] POST /admin_delete_video\n");
    if (!body) body = "";

    char video_id_str[32] = { 0 };

    form_field fields[] = {
        {"video_id", video_id_str, sizeof(video_id_str)}
    };

    if (!parse_form_data(body, fields, 1)) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Missing request body\"}");
    }

    int video_id = atoi(video_id_str);

    if (video_id <= 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid parameters\"}");
    }

    int result = db_admin_delete_video(video_id);

    if (!result) {
        printf("[에러] /admin_delete_video - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"DB error\"}");
    }

    // 로컬 파일 삭제
    delete_video_files(video_id);

    return api_response_create(200, "application/json; charset=utf-8",
        "{\"success\":true}");
}

// POST /increment_view - 조회수 증가
api_response* handle_increment_view(const char* body) {
    // [상세 로그] 조회수 증가 호출 (주기적 호출 가능성 있음)
    // printf("[API] POST /increment_view\n");
    // [상세 로그] 요청 body 내용
    // printf("[DEBUG] body: %s\n", body ? body : "(null)");

    if (!body) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Missing request body\"}");
    }

    // body 파싱: video_id=123 형식
    int video_id = 0;

    char body_copy[1024];
    strncpy(body_copy, body, sizeof(body_copy) - 1);
    body_copy[sizeof(body_copy) - 1] = '\0';

    // video_id 추출
    char* token = strstr(body_copy, "video_id=");
    if (token) {
        video_id = atoi(token + 9);
    }

    // [상세 로그] 파싱 결과
    // printf("[DEBUG] video_id=%d\n", video_id);

    // 유효성 검사
    if (video_id <= 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid video_id\"}");
    }

    // DB 조회수 증가
    int result = db_increment_view_count(video_id);

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8",
            "{\"success\":true}");
    } else {
        printf("[에러] /increment_view - DB 업데이트 실패 (video_id=%d)\n", video_id);
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"DB update failed\"}");
    }
}

// GET /recent_videos?user_id=1&limit=2 - 최근 시청 영상 목록
api_response* handle_recent_videos(int user_id, int limit) {
    char json_buffer[8192];
    int result;

    printf("[API] GET /recent_videos?user_id=%d&limit=%d\n", user_id, limit);

    // 유효성 검사
    if (user_id <= 0 || limit <= 0) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid parameters\"}");
    }

    // DB에서 최근 시청 영상 가져오기
    result = db_get_recent_videos(user_id, limit, json_buffer, sizeof(json_buffer));

    if (result) {
        return api_response_create(200, "application/json; charset=utf-8", json_buffer);
    } else {
        printf("[에러] /recent_videos - DB 오류\n");
        return api_response_create(500, "application/json; charset=utf-8",
            "{\"error\":\"Database error\"}");
    }
}

// ==================== 라우팅 시스템 ====================

// 라우팅 테이블 - 모든 엔드포인트를 한 곳에서 관리
static const api_route routes[] = {
    // 경로, 메서드, body필요, body핸들러, no-body핸들러
    { "/register",              "POST", 1, handle_register, NULL },
    { "/login",                 "POST", 1, handle_login, NULL },
    // /api/video_list는 QServer.c에서 쿼리 파라미터로 처리
    { "/api/update_history",    "POST", 1, handle_update_history, NULL },
    { "/api/update_video",      "POST", 1, handle_update_video, NULL },
    { "/api/delete_video",      "POST", 1, handle_delete_video, NULL },
    { "/api/admin_videos",      "GET",  0, NULL, handle_admin_videos },
    { "/api/admin_update_video", "POST", 1, handle_admin_update_video, NULL },
    { "/api/admin_delete_video", "POST", 1, handle_admin_delete_video, NULL },
    { "/api/increment_view",    "POST", 1, handle_increment_view, NULL },
    // 마지막 엔트리 - NULL로 끝 표시
    { NULL, NULL, 0, NULL, NULL }
};

// 특정 경로가 POST body를 필요로 하는지 확인
int route_needs_body(const char* path, const char* method) {
    if (!path || !method) return 0;

    // 업로드는 별도 라우팅이지만 body 필요
    if (strcmp(path, "/api/upload_video") == 0 && _stricmp(method, "POST") == 0) {
        return 1;
    }

    for (int i = 0; routes[i].path != NULL; i++) {
        if (strcmp(routes[i].path, path) == 0 &&
            _stricmp(routes[i].method, method) == 0) {
            return routes[i].needs_body;
        }
    }

    return 0; // 매칭되는 라우트 없으면 body 불필요
}

// 라우트 매칭 및 처리
api_response* route_request(const char* path, const char* method, const char* body) {
    if (!path || !method) {
        return api_response_create(400, "application/json; charset=utf-8",
            "{\"error\":\"Invalid request\"}");
    }

    // 소음 많은 정적/특정 엔드포인트는 로그 생략
    int should_log = 0;
    if (strncmp(path, "/api", 4) == 0 ||
        strcmp(path, "/login") == 0 ||
        strcmp(path, "/register") == 0) {
        should_log = 1;
    }
    if (should_log && strcmp(path, "/api/update_history") != 0) {
        printf("[ROUTER] %s %s\n", method, path);
    }

    // 라우팅 테이블에서 매칭되는 라우트 찾기
    for (int i = 0; routes[i].path != NULL; i++) {
        if (strcmp(routes[i].path, path) == 0 &&
            _stricmp(routes[i].method, method) == 0) {

            // 핸들러 호출
            if (routes[i].needs_body && routes[i].handler_with_body) {
                return routes[i].handler_with_body(body ? body : "");
            }
            else if (!routes[i].needs_body && routes[i].handler_no_body) {
                return routes[i].handler_no_body();
            }
            else {
                return api_response_create(500, "application/json; charset=utf-8",
                    "{\"error\":\"Handler not configured\"}");
            }
        }
    }

    // 404 - 라우트를 찾지 못함
    return NULL; // NULL을 반환하면 QServer에서 정적 파일로 처리
}
