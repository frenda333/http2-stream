// DB 관련 함수

#define _CRT_SECURE_NO_WARNINGS
#include "DB.h"
#include <mysql.h>
#include <stdio.h>
#include <string.h>
#include <windows.h> // FindFirstFileW 등을 사용하기 위해 포함

#pragma comment(lib, "libmysql.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

// 현재 DB 접속 정보 - 필요시 수정
static const char* DB_HOST = "localhost";
static const char* DB_USER = "root";
static const char* DB_PASS = "0000";     // serverdb password
static const char* DB_NAME = "serverdb"; // use db

// ==================== DB 연결 관리 매크로 ====================
// DB 연결 시작 (자동 에러 처리)
#define DB_CONNECT() \
    MYSQL* conn = db_open(); \
    if (!conn) { \
        fprintf(stderr, "[DB ERROR] 데이터베이스 연결 실패\n"); \
        return 0; \
    }

// DB 연결 종료
#define DB_DISCONNECT() \
    db_close(&conn);

// DB 연결 자동 관리 (함수 시작 시 사용)
#define DB_AUTO_CONNECT() DB_CONNECT()

// DB 연결 자동 해제 (함수 끝 시 사용)
#define DB_AUTO_DISCONNECT() DB_DISCONNECT()

// ==================== 공통 연결 헬퍼 (DB.c 내부 전용) ====================
static MYSQL* db_open(void) {
    MYSQL* conn = mysql_init(NULL);
    if (!conn) {
        fprintf(stderr, "mysql_init() failed\n");
        return NULL;
    }

    unsigned int ssl_mode = SSL_MODE_DISABLED;
    mysql_options(conn, MYSQL_OPT_SSL_MODE, &ssl_mode);

    if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, NULL, 0) == NULL) {
        fprintf(stderr, "DB connect failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }

    if (mysql_set_character_set(conn, "utf8mb4") != 0) {
        fprintf(stderr, "mysql_set_character_set(utf8mb4) failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }

    return conn;
}

static void db_close(MYSQL** pconn) {
    if (pconn && *pconn) {
        mysql_close(*pconn);
        *pconn = NULL;
    }
}

// ==================== 공통 영상 목록 조회 헬퍼 ====================

// 콜백 함수 타입: MYSQL_ROW를 cJSON 객체로 변환
typedef cJSON* (*row_to_json_callback)(MYSQL_ROW row);

// 공통 영상 목록 조회 함수 (쿼리 + 콜백 패턴)
static int execute_video_list_query(
    const char* query,
    row_to_json_callback callback,
    char* out_json,
    size_t max_size
) {
    // DB 연결
    MYSQL* conn = db_open();
    if (!conn) return 0;

    // cJSON 배열 생성
    cJSON* root = cJSON_CreateArray();
    if (!root) {
        fprintf(stderr, "cJSON_CreateArray failed\n");
        db_close(&conn);
        return 0;
    }

    // 쿼리 실행
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Worker query failed: %s\n", mysql_error(conn));
        cJSON_Delete(root);
        db_close(&conn);
        return 0;
    }

    // 결과 파싱
    MYSQL_RES* res = mysql_store_result(conn);
    if (res) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(res))) {
            cJSON* item = callback(row);  // 콜백 호출
            if (item) {
                cJSON_AddItemToArray(root, item);
            }
        }
        mysql_free_result(res);
    }

    // JSON 문자열로 변환
    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        fprintf(stderr, "cJSON_PrintUnformatted failed\n");
        db_close(&conn);
        return 0;
    }

    // 버퍼에 복사
    if (strlen(json_str) >= max_size) {
        fprintf(stderr, "JSON buffer overflow in execute_video_list_query\n");
        cJSON_free(json_str);
        db_close(&conn);
        return 0;
    }

    strcpy(out_json, json_str);
    cJSON_free(json_str);

    // 연결 해제
    db_close(&conn);
    return 1;
}

// 콜백 함수: video_list용 (10개 필드)
static cJSON* video_list_row_to_json(MYSQL_ROW row) {
    if (!row[0] || !row[1] || !row[2] || !row[3] || !row[4] || !row[6]) return NULL;

    cJSON* item = cJSON_CreateObject();
    if (!item) return NULL;

    cJSON_AddNumberToObject(item, "id", atoi(row[0]));
    cJSON_AddStringToObject(item, "videoname", row[1]);
    cJSON_AddStringToObject(item, "filename", row[2]);
    cJSON_AddStringToObject(item, "uploader", row[3]);
    cJSON_AddStringToObject(item, "uploaded_day", row[4]);
    cJSON_AddStringToObject(item, "description", row[5] ? row[5] : "");
    cJSON_AddStringToObject(item, "thumbnail", row[6]);
    cJSON_AddNumberToObject(item, "view_count", row[7] ? atoi(row[7]) : 0);
    cJSON_AddNumberToObject(item, "duration", row[8] ? atoi(row[8]) : 0);
    cJSON_AddNumberToObject(item, "watch_record", row[9] ? atoi(row[9]) : 0);

    return item;
}

// 콜백 함수: search_videos용 (10개 필드, video_list와 동일)
static cJSON* search_videos_row_to_json(MYSQL_ROW row) {
    return video_list_row_to_json(row);  // 구조가 동일하므로 재사용
}

// 콜백 함수: user_videos용 (8개 필드)
static cJSON* user_videos_row_to_json(MYSQL_ROW row) {
    if (!row[0] || !row[1] || !row[2] || !row[3] || !row[4] || !row[6]) return NULL;

    cJSON* item = cJSON_CreateObject();
    if (!item) return NULL;

    cJSON_AddNumberToObject(item, "id", atoi(row[0]));
    cJSON_AddStringToObject(item, "videoname", row[1]);
    cJSON_AddStringToObject(item, "filename", row[2]);
    cJSON_AddStringToObject(item, "uploader", row[3]);
    cJSON_AddStringToObject(item, "uploaded_day", row[4]);
    cJSON_AddStringToObject(item, "description", row[5] ? row[5] : "");
    cJSON_AddStringToObject(item, "thumbnail", row[6]);
    cJSON_AddNumberToObject(item, "view_count", row[7] ? atoi(row[7]) : 0);

    return item;
}

// 콜백 함수: all_videos용 (9개 필드, uploader_id 포함)
static cJSON* all_videos_row_to_json(MYSQL_ROW row) {
    if (!row[0] || !row[1] || !row[2] || !row[3] || !row[4] || !row[6]) return NULL;

    cJSON* item = cJSON_CreateObject();
    if (!item) return NULL;

    cJSON_AddNumberToObject(item, "id", atoi(row[0]));
    cJSON_AddStringToObject(item, "videoname", row[1]);
    cJSON_AddStringToObject(item, "filename", row[2]);
    cJSON_AddStringToObject(item, "uploader", row[3]);
    cJSON_AddStringToObject(item, "uploaded_day", row[4]);
    cJSON_AddStringToObject(item, "description", row[5] ? row[5] : "");
    cJSON_AddStringToObject(item, "thumbnail", row[6]);
    cJSON_AddNumberToObject(item, "uploader_id", row[7] ? atoi(row[7]) : 0);
    cJSON_AddNumberToObject(item, "view_count", row[8] ? atoi(row[8]) : 0);

    return item;
}

// 콜백 함수: recent_videos용 (11개 필드, last_watch_date 포함)
static cJSON* recent_videos_row_to_json(MYSQL_ROW row) {
    if (!row[0] || !row[1] || !row[2] || !row[3] || !row[4] || !row[6]) return NULL;

    cJSON* item = cJSON_CreateObject();
    if (!item) return NULL;

    cJSON_AddNumberToObject(item, "id", atoi(row[0]));
    cJSON_AddStringToObject(item, "videoname", row[1]);
    cJSON_AddStringToObject(item, "filename", row[2]);
    cJSON_AddStringToObject(item, "uploader", row[3]);
    cJSON_AddStringToObject(item, "uploaded_day", row[4]);
    cJSON_AddStringToObject(item, "description", row[5] ? row[5] : "");
    cJSON_AddStringToObject(item, "thumbnail", row[6]);
    cJSON_AddNumberToObject(item, "view_count", row[7] ? atoi(row[7]) : 0);
    cJSON_AddNumberToObject(item, "duration", row[8] ? atoi(row[8]) : 0);
    cJSON_AddNumberToObject(item, "watch_record", row[9] ? atoi(row[9]) : 0);

    // last_watch_date 처리 (날짜 부분만 추출)
    if (row[10] && strlen(row[10]) >= 10) {
        char date_only[11];
        memcpy(date_only, row[10], 10);
        date_only[10] = '\0';
        cJSON_AddStringToObject(item, "last_watch_date", date_only);
    } else {
        cJSON_AddStringToObject(item, "last_watch_date", "");
    }

    return item;
}


int db_init(void) {
    if (mysql_library_init(0, NULL, NULL)) {
        fprintf(stderr, "mysql_library_init() failed\n");
        return 0;
    }
    return 1;
}

void db_cleanup(void) {
    mysql_library_end();
}

// ==================== 회원가입 기능 구현 ====================
int db_register_user(const char* name, const char* username, const char* password) {
    DB_AUTO_CONNECT();

    // 아이디 중복 검사
    char query_check[512];
    char escaped_username[41]; // max length 20 * 2 + 1

    // 이스케이프 처리 (SQL Injection 방지)
    mysql_real_escape_string(conn, escaped_username, username, (unsigned long)strlen(username));

    _snprintf_s(query_check, sizeof(query_check), _TRUNCATE,
        "SELECT username FROM users WHERE username = '%s'",
        escaped_username);

    if (mysql_query(conn, query_check)) {
        fprintf(stderr, "register2: SELECT query failed: %s\n", mysql_error(conn));
        DB_AUTO_DISCONNECT();
        return 0;
    }

    MYSQL_RES* res = mysql_store_result(conn);
    if (res && mysql_num_rows(res) > 0) {
        fprintf(stderr, "register: ID already exists : (%s)\n", username);
        mysql_free_result(res);
        DB_AUTO_DISCONNECT();
        return 0; // 아이디 중복
    }
    if (res) mysql_free_result(res);

    // 사용자 정보 삽입 (id, 이름, 유저이름, 패스워드)
    char query_insert[1024];
    char escaped_name[81];     // 적절한 크기
    char escaped_password[41];

    // 모든 매개변수 이스케이프 처리
    // escaped_username은 이미 위에서 처리됨
    mysql_real_escape_string(conn, escaped_name, name, (unsigned long)strlen(name));
    mysql_real_escape_string(conn, escaped_password, password, (unsigned long)strlen(password));

    // 평문 비밀번호 저장 (주의: 운영 시에는 해시/솔트 사용 권장)
    _snprintf_s(query_insert, sizeof(query_insert), _TRUNCATE,
        "INSERT INTO users (name, username, password) VALUES ('%s', '%s', '%s')",
        escaped_name, escaped_username, escaped_password);

    if (mysql_query(conn, query_insert)) {
        fprintf(stderr, "register: INSERT query failed: %s\n", mysql_error(conn));
        DB_AUTO_DISCONNECT();
        return 0;
    }

    printf("[DB] 회원가입 성공: %s\n", username);
    DB_AUTO_DISCONNECT();
    return 1;
}

// ==================== 로그인 기능 구현 ====================
int db_login_user(const char* username, const char* password) {
    DB_AUTO_CONNECT();

    // 이스케이프 처리
    char query_check[512];
    char escaped_username[41]; // max length 20 * 2 + 1
    char escaped_password[41]; // max length 20 * 2 + 1

    mysql_real_escape_string(conn, escaped_username, username, (unsigned long)strlen(username));
    mysql_real_escape_string(conn, escaped_password, password, (unsigned long)strlen(password));

    // 아이디와 비밀번호가 일치하는 레코드 확인 (수정: 'SELECT 1' -> 'SELECT id')
    _snprintf_s(query_check, sizeof(query_check), _TRUNCATE,
        "SELECT id FROM users WHERE username = '%s' AND password = '%s'",
        escaped_username, escaped_password);

    if (mysql_query(conn, query_check)) {
        fprintf(stderr, "login: SELECT query failed: %s\n", mysql_error(conn));
        DB_AUTO_DISCONNECT();
        return 0; // DB 오류
    }

    // 결과 확인 (수정: user_id를 직접 가져옴)
    MYSQL_RES* res = mysql_store_result(conn);
    int user_id = 0; // 0은 로그인 실패를 의미

    if (res) {
        if (mysql_num_rows(res) == 1) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) {
                user_id = atoi(row[0]); // user_id (1 이상)
            }
        }
        mysql_free_result(res);
    }

    // 연결 해제 및 결과 반환
    if (user_id > 0) {
        printf("login success - username : %s, user_id: %d\n", username, user_id);
    }
    else {
        fprintf(stderr, "login: Invalid username or password: (%s)\n", username);
    }

    DB_AUTO_DISCONNECT();
    return user_id; // 성공 시 user_id, 실패 시 0 반환
}

// ==================== 영상 업로드 기능 구현 (video 테이블) ====================
int db_add_video(
    int user_id,
    const char* videoname,
    const char* description,
    int duration
) {
    MYSQL* conn = db_open();
    if (!conn) return 0; // 0은 실패

    // 이스케이프-처리를-위한-버퍼
    char esc_videoname[512];
    char* esc_description = malloc(strlen(description) * 2 + 1);

    if (!esc_description) {
        fprintf(stderr, "db_add_video: malloc failed\n");
        db_close(&conn);
        return 0; // 0은 실패
    }

    mysql_real_escape_string(conn, esc_videoname, videoname, (unsigned long)strlen(videoname));
    mysql_real_escape_string(conn, esc_description, description, (unsigned long)strlen(description));

    char query[8192]; // 쿼리-버퍼

    // video 테이블의-구조에-맞게-INSERT (duration 포함)
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "INSERT INTO video (uploader_id, videoname, description, duration) "
        "VALUES (%d, '%s', '%s', %d)",
        user_id, esc_videoname, esc_description, duration);

    free(esc_description); // 쿼리-생성-후-해제

    if (mysql_query(conn, query)) {
        fprintf(stderr, "db_add_video: INSERT query failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0; // 0은 실패
    }

    // (중요) 방금-삽입된-레코드의-Auto-Increment ID를-가져옵니다.
    my_ulonglong new_id_long = mysql_insert_id(conn);
    int new_id = (int)new_id_long;

    if (new_id == 0) {
        fprintf(stderr, "db_add_video: mysql_insert_id() returned 0\n");
        db_close(&conn);
        return 0; // 0은 실패
    }

    printf("Video metadata added to DB - uploader: %d, new_id: %d\n", user_id, new_id);
    db_close(&conn);
    return new_id; // 성공-시-ID 반환
}

// ==================== 영상 목록 API (main.html 용) ====================
int db_get_video_list(int user_id, char* out_json, size_t max_size) {
    char query[2048];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "SELECT "
        "  v.id, "
        "  v.videoname, "
        "  CONCAT('public/video/', v.id, '.mp4') AS filename, "
        "  COALESCE(u.username, 'System') AS uploader, "
        "  DATE_FORMAT(v.uploaded_day, '%%Y-%%m-%%d') AS uploaded_day, "
        "  COALESCE(v.description, '') AS description, "
        "  CONCAT('public/thumb/', v.id, '.jpg') AS thumbnail, "
        "  v.view_count, "
        "  v.duration, "
        "  COALESCE(wh.record, 0) AS watch_record "
        "FROM video v "
        "LEFT JOIN users u ON v.uploader_id = u.id "
        "LEFT JOIN watch_history wh ON v.id = wh.video_id AND wh.user_id = %d "
        "ORDER BY v.uploaded_day DESC",
        user_id);

    return execute_video_list_query(query, video_list_row_to_json, out_json, max_size);
}

// ==================== 단일 영상 상세정보 (viewer.html 용) ====================
int db_get_video_details(int video_id, char* out_json, size_t max_size) {
    // DB 연결
    MYSQL* conn = db_open();
    if (!conn) {
        cJSON* error = cJSON_CreateObject();
        cJSON_AddStringToObject(error, "error", "DB connection failed");
        char* error_str = cJSON_PrintUnformatted(error);
        if (error_str) {
            strncpy(out_json, error_str, max_size - 1);
            out_json[max_size - 1] = '\0';
            cJSON_free(error_str);
        }
        cJSON_Delete(error);
        return 0;
    }

    // 쿼리 생성
    char query[1024];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "SELECT "
        "  v.id, "
        "  v.videoname, "
        "  CONCAT('public/video/', v.id, '.mp4') AS filename, "
        "  COALESCE(u.username, 'System') AS uploader, "
        "  COALESCE(DATE_FORMAT(v.uploaded_day, '%%Y-%%m-%%d'), '날짜 없음') AS uploaded_day, "
        "  COALESCE(v.description, '') AS description, "
        "  v.view_count "
        "FROM video v "
        "LEFT JOIN users u ON v.uploader_id = u.id "
        "WHERE v.id = %d",
        video_id);

    // 쿼리 실행
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Worker query (get_video_details) failed: %s\n", mysql_error(conn));
        cJSON* error = cJSON_CreateObject();
        cJSON_AddStringToObject(error, "error", "DB query failed");
        char* error_str = cJSON_PrintUnformatted(error);
        if (error_str) {
            strncpy(out_json, error_str, max_size - 1);
            out_json[max_size - 1] = '\0';
            cJSON_free(error_str);
        }
        cJSON_Delete(error);
        db_close(&conn);
        return 0;
    }

    // 결과 파싱
    MYSQL_RES* res = mysql_store_result(conn);
    int found = 0;
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        if (row) {
            const char* id_str = row[0];
            const char* videoname = row[1];
            const char* filename = row[2];
            const char* uploader = row[3];
            const char* uploaded_day = row[4];
            const char* description = row[5];
            const char* view_count_str = row[6];

            if (id_str && videoname && filename && uploader && uploaded_day && description) {
                // cJSON 객체 생성 (자동 이스케이프!)
                cJSON* video = cJSON_CreateObject();
                cJSON_AddNumberToObject(video, "id", atoi(id_str));
                cJSON_AddStringToObject(video, "videoname", videoname);
                cJSON_AddStringToObject(video, "filename", filename);
                cJSON_AddStringToObject(video, "uploader", uploader);
                cJSON_AddStringToObject(video, "uploaded_day", uploaded_day);
                cJSON_AddStringToObject(video, "description", description);
                cJSON_AddNumberToObject(video, "view_count", view_count_str ? atoi(view_count_str) : 0);

                char* json_str = cJSON_PrintUnformatted(video);
                cJSON_Delete(video);

                if (json_str) {
                    if (strlen(json_str) < max_size) {
                        strcpy(out_json, json_str);
                        found = 1;
                    }
                    cJSON_free(json_str);
                }
            }
        }
        mysql_free_result(res);
    }

    // 연결 해제 및 결과 반환
    db_close(&conn);

    if (!found) {
        fprintf(stderr, "Video not found: id %d\n", video_id);
        cJSON* error = cJSON_CreateObject();
        cJSON_AddStringToObject(error, "error", "Video not found");
        char* error_str = cJSON_PrintUnformatted(error);
        if (error_str) {
            strncpy(out_json, error_str, max_size - 1);
            out_json[max_size - 1] = '\0';
            cJSON_free(error_str);
        }
        cJSON_Delete(error);
    }

    return found;
}

// ==================== 단일 시청 기록 조회 (main.html -> viewer.html) ====================
int db_get_watch_history(int user_id, int video_id, char* out_json, size_t max_size) {
    //  DB 연결
    MYSQL* conn = db_open();
    if (!conn) {
        cJSON* error = cJSON_CreateObject();
        cJSON_AddStringToObject(error, "error", "DB connection failed");
        char* error_str = cJSON_PrintUnformatted(error);
        if (error_str) {
            strncpy(out_json, error_str, max_size - 1);
            out_json[max_size - 1] = '\0';
            cJSON_free(error_str);
        }
        cJSON_Delete(error);
        return 0;
    }

    //  쿼리 생성
    char query[1024];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "SELECT "
        "  record, "
        "  DATE_FORMAT(last_watch_time, '%%Y-%%m-%%d %%H:%%i') AS last_watch "
        "FROM watch_history "
        "WHERE user_id = %d AND video_id = %d",
        user_id, video_id);

    // 쿼리 실행
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Worker query (get_watch_history) failed: %s\n", mysql_error(conn));
        cJSON* error = cJSON_CreateObject();
        cJSON_AddStringToObject(error, "error", "DB query failed");
        char* error_str = cJSON_PrintUnformatted(error);
        if (error_str) {
            strncpy(out_json, error_str, max_size - 1);
            out_json[max_size - 1] = '\0';
            cJSON_free(error_str);
        }
        cJSON_Delete(error);
        db_close(&conn);
        return 0;
    }

    // 결과 파싱
    MYSQL_RES* res = mysql_store_result(conn);
    int found = 0;
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        if (row) {
            const char* record_str = row[0];
            const char* last_watch = row[1];

            if (record_str && last_watch) {
                // cJSON 객체 생성
                cJSON* history = cJSON_CreateObject();
                cJSON_AddNumberToObject(history, "record", atoi(record_str));
                cJSON_AddStringToObject(history, "last_watch", last_watch);

                char* json_str = cJSON_PrintUnformatted(history);
                cJSON_Delete(history);

                if (json_str) {
                    if (strlen(json_str) < max_size) {
                        strcpy(out_json, json_str);
                        found = 1;
                    }
                    cJSON_free(json_str);
                }
            }
        }
        mysql_free_result(res);
    }

    // 연결 해제 및 결과 반환
    db_close(&conn);

    if (!found) {
        //  기록이 없는 것도 오류 X
        cJSON* error = cJSON_CreateObject();
        cJSON_AddStringToObject(error, "error", "History not found");
        char* error_str = cJSON_PrintUnformatted(error);
        if (error_str) {
            strncpy(out_json, error_str, max_size - 1);
            out_json[max_size - 1] = '\0';
            cJSON_free(error_str);
        }
        cJSON_Delete(error);
    }

    return found; // 1 (찾음), 0 (못 찾음)
}

// ==================== 시청 기록 업데이트 (viewer.html에서 호출) ====================
int db_update_watch_history(int user_id, int video_id, int record) {
    MYSQL* conn = db_open();
    if (!conn) return 0; // 0은 실패

    char query[1024];

    // PRIMARY KEY (user_id, video_id)
    // ON DUPLICATE KEY UPDATE를 사용하면
    // 1. 레코드가 없으면: INSERT
    // 2. 레코드가 있으면: UPDATE (record 값 갱신, last_watch_time은 자동 갱신)
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "INSERT INTO watch_history (user_id, video_id, record) "
        "VALUES (%d, %d, %d) "
        "ON DUPLICATE KEY UPDATE record = VALUES(record)",
        user_id, video_id, record);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "db_update_watch_history: query failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0; // 0은 실패
    }

    // (디버깅용) 영향 받은 행 수 확인 (1 = Insert, 2 = Update)
    // my_ulonglong affected_rows = mysql_affected_rows(conn);
    // printf("Watch history updated (User: %d, Video: %d, Record: %d, Rows: %llu)\n",
    //        user_id, video_id, record, affected_rows);

    // ==================== 30개 제한 로직 ====================
    // 해당 사용자의 시청 기록이 30개를 초과하면 가장 오래된 것 삭제
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "DELETE FROM watch_history "
        "WHERE user_id = %d "
        "AND (user_id, video_id) NOT IN ("
        "  SELECT user_id, video_id FROM ("
        "    SELECT user_id, video_id FROM watch_history "
        "    WHERE user_id = %d "
        "    ORDER BY last_watch_time DESC "
        "    LIMIT 30"
        "  ) AS recent"
        ")",
        user_id, user_id);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "db_update_watch_history: cleanup failed: %s\n", mysql_error(conn));
        // 정리 실패해도 메인 작업은 성공했으므로 계속 진행
    }

    db_close(&conn);
    return 1; // 성공
}

// ==================== 영상 검색 기능 (제목 부분 일치) ====================
int db_search_videos(const char* search_query, int user_id, char* out_json, size_t max_size) {
    // 검색어 이스케이프 처리 (SQL Injection 방지)
    MYSQL* conn = db_open();
    if (!conn) return 0;

    char escaped_query[512];
    mysql_real_escape_string(conn, escaped_query, search_query, (unsigned long)strlen(search_query));
    db_close(&conn);

    // 쿼리 생성
    char query[1280];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "SELECT "
        "  v.id, "
        "  v.videoname, "
        "  CONCAT('public/video/', v.id, '.mp4') AS filename, "
        "  COALESCE(u.username, 'System') AS uploader, "
        "  DATE_FORMAT(v.uploaded_day, '%%Y-%%m-%%d') AS uploaded_day, "
        "  COALESCE(v.description, '') AS description, "
        "  CONCAT('public/thumb/', v.id, '.jpg') AS thumbnail, "
        "  v.view_count, "
        "  v.duration, "
        "  COALESCE(wh.record, 0) AS watch_record "
        "FROM video v "
        "LEFT JOIN users u ON v.uploader_id = u.id "
        "LEFT JOIN watch_history wh ON v.id = wh.video_id AND wh.user_id = %d "
        "WHERE v.videoname LIKE '%%%s%%' "
        "ORDER BY v.uploaded_day DESC",
        user_id, escaped_query);

    return execute_video_list_query(query, search_videos_row_to_json, out_json, max_size);
}

// ==================== 영상 관리 기능 ====================

// 특정 사용자가 업로드한 영상 목록 조회 (날짜순 정렬)
int db_get_user_videos(int user_id, char* out_json, size_t max_size) {
    char query[1024];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "SELECT "
        "  v.id, "
        "  v.videoname, "
        "  CONCAT('public/video/', v.id, '.mp4') AS filename, "
        "  COALESCE(u.username, 'System') AS uploader, "
        "  DATE_FORMAT(v.uploaded_day, '%%Y-%%m-%%d') AS uploaded_day, "
        "  COALESCE(v.description, '') AS description, "
        "  CONCAT('public/thumb/', v.id, '.jpg') AS thumbnail, "
        "  v.view_count "
        "FROM video v "
        "LEFT JOIN users u ON v.uploader_id = u.id "
        "WHERE v.uploader_id = %d "
        "ORDER BY v.uploaded_day DESC",
        user_id);

    return execute_video_list_query(query, user_videos_row_to_json, out_json, max_size);
}

// 영상 정보 수정 (제목, 설명)
int db_update_video(int video_id, int user_id, const char* videoname, const char* description) {
    MYSQL* conn = db_open();
    if (!conn) return 0;

    // 권한 확인 (해당 영상의 uploader_id가 user_id와 일치하는지)
    char check_query[256];
    _snprintf_s(check_query, sizeof(check_query), _TRUNCATE,
        "SELECT uploader_id FROM video WHERE id = %d", video_id);

    if (mysql_query(conn, check_query)) {
        fprintf(stderr, "db_update_video: check query failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    MYSQL_RES* res = mysql_store_result(conn);
    if (!res) {
        db_close(&conn);
        return 0;
    }

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row || atoi(row[0]) != user_id) {
        // 영상이 없거나 권한 없음
        fprintf(stderr, "db_update_video: permission denied (video_id=%d, user_id=%d)\n", video_id, user_id);
        mysql_free_result(res);
        db_close(&conn);
        return 0;
    }
    mysql_free_result(res);

    // 업데이트 실행
    char esc_videoname[512];
    char* esc_description = malloc(strlen(description) * 2 + 1);
    if (!esc_description) {
        db_close(&conn);
        return 0;
    }

    mysql_real_escape_string(conn, esc_videoname, videoname, (unsigned long)strlen(videoname));
    mysql_real_escape_string(conn, esc_description, description, (unsigned long)strlen(description));

    char update_query[8192];
    _snprintf_s(update_query, sizeof(update_query), _TRUNCATE,
        "UPDATE video SET videoname = '%s', description = '%s' WHERE id = %d",
        esc_videoname, esc_description, video_id);

    free(esc_description);

    if (mysql_query(conn, update_query)) {
        fprintf(stderr, "db_update_video: UPDATE failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    printf("Video updated: video_id=%d, new_title='%s'\n", video_id, videoname);
    db_close(&conn);
    return 1;
}

// 영상 삭제 (DB에서만 삭제)
int db_delete_video(int video_id, int user_id) {
    MYSQL* conn = db_open();
    if (!conn) return 0;

    // 권한 확인
    char check_query[256];
    _snprintf_s(check_query, sizeof(check_query), _TRUNCATE,
        "SELECT uploader_id FROM video WHERE id = %d", video_id);

    if (mysql_query(conn, check_query)) {
        fprintf(stderr, "db_delete_video: check query failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    MYSQL_RES* res = mysql_store_result(conn);
    if (!res) {
        db_close(&conn);
        return 0;
    }

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row || atoi(row[0]) != user_id) {
        // 영상이 없거나 권한 없음
        fprintf(stderr, "db_delete_video: permission denied (video_id=%d, user_id=%d)\n", video_id, user_id);
        mysql_free_result(res);
        db_close(&conn);
        return 0;
    }
    mysql_free_result(res);

    // 삭제 실행
    char delete_query[256];
    _snprintf_s(delete_query, sizeof(delete_query), _TRUNCATE,
        "DELETE FROM video WHERE id = %d", video_id);

    if (mysql_query(conn, delete_query)) {
        fprintf(stderr, "db_delete_video: DELETE failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    printf("Video deleted from DB: video_id=%d\n", video_id);
    db_close(&conn);
    return 1;
}

// ==================== 관리자 기능 ====================

// 모든 사용자의 영상 목록 조회 (관리자용)
int db_get_all_videos(char* out_json, size_t max_size) {
    const char* query =
        "SELECT "
        "  v.id, "
        "  v.videoname, "
        "  CONCAT('public/video/', v.id, '.mp4') AS filename, "
        "  COALESCE(u.username, 'System') AS uploader, "
        "  DATE_FORMAT(v.uploaded_day, '%Y-%m-%d') AS uploaded_day, "
        "  COALESCE(v.description, '') AS description, "
        "  CONCAT('public/thumb/', v.id, '.jpg') AS thumbnail, "
        "  v.uploader_id, "
        "  v.view_count "
        "FROM video v "
        "LEFT JOIN users u ON v.uploader_id = u.id "
        "ORDER BY v.uploaded_day DESC";

    return execute_video_list_query(query, all_videos_row_to_json, out_json, max_size);
}

// 관리자 권한으로 영상 정보 수정 (권한 확인 없음)
int db_admin_update_video(int video_id, const char* videoname, const char* description) {
    MYSQL* conn = db_open();
    if (!conn) return 0;

    // 이스케이프 처리
    char esc_videoname[512];
    char* esc_description = malloc(strlen(description) * 2 + 1);
    if (!esc_description) {
        db_close(&conn);
        return 0;
    }

    mysql_real_escape_string(conn, esc_videoname, videoname, (unsigned long)strlen(videoname));
    mysql_real_escape_string(conn, esc_description, description, (unsigned long)strlen(description));

    char update_query[8192];
    _snprintf_s(update_query, sizeof(update_query), _TRUNCATE,
        "UPDATE video SET videoname = '%s', description = '%s' WHERE id = %d",
        esc_videoname, esc_description, video_id);

    free(esc_description);

    if (mysql_query(conn, update_query)) {
        fprintf(stderr, "db_admin_update_video: UPDATE failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    printf("Video updated (admin): video_id=%d, new_title='%s'\n", video_id, videoname);
    db_close(&conn);
    return 1;
}

// 관리자 권한으로 영상 삭제 (권한 확인 없음)
int db_admin_delete_video(int video_id) {
    MYSQL* conn = db_open();
    if (!conn) return 0;

    char delete_query[256];
    _snprintf_s(delete_query, sizeof(delete_query), _TRUNCATE,
        "DELETE FROM video WHERE id = %d", video_id);

    if (mysql_query(conn, delete_query)) {
        fprintf(stderr, "db_admin_delete_video: DELETE failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    printf("Video deleted from DB (admin): video_id=%d\n", video_id);
    db_close(&conn);
    return 1;
}

// ==================== 조회수 기능 ====================
int db_increment_view_count(int video_id) {
    MYSQL* conn = db_open();
    if (!conn) return 0;

    char query[256];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "UPDATE video SET view_count = view_count + 1 WHERE id = %d",
        video_id);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "db_increment_view_count: UPDATE failed: %s\n", mysql_error(conn));
        db_close(&conn);
        return 0;
    }

    // 영향받은 행 수 확인 (영상이 존재하는지 확인)
    my_ulonglong affected_rows = mysql_affected_rows(conn);
    if (affected_rows == 0) {
        fprintf(stderr, "db_increment_view_count: video not found (id=%d)\n", video_id);
        db_close(&conn);
        return 0;
    }

    // [상세 로그] 조회수 증가 성공
    // printf("View count incremented: video_id=%d\n", video_id);
    db_close(&conn);
    return 1;
}

// ==================== 최근 시청 영상 ====================
int db_get_recent_videos(int user_id, int limit, char* out_json, size_t max_size) {
    char query[1024];
    _snprintf_s(query, sizeof(query), _TRUNCATE,
        "SELECT "
        "  v.id, "
        "  v.videoname, "
        "  CONCAT('public/video/', v.id, '.mp4') AS filename, "
        "  COALESCE(u.username, 'System') AS uploader, "
        "  DATE_FORMAT(v.uploaded_day, '%%Y-%%m-%%d') AS uploaded_day, "
        "  COALESCE(v.description, '') AS description, "
        "  CONCAT('public/thumb/', v.id, '.jpg') AS thumbnail, "
        "  v.view_count, "
        "  v.duration, "
        "  COALESCE(wh.record, 0) AS watch_record, "
        "  wh.last_watch_time "
        "FROM watch_history wh "
        "INNER JOIN video v ON wh.video_id = v.id "
        "LEFT JOIN users u ON v.uploader_id = u.id "
        "WHERE wh.user_id = %d "
        "ORDER BY wh.last_watch_time DESC "
        "LIMIT %d",
        user_id, limit);

    return execute_video_list_query(query, recent_videos_row_to_json, out_json, max_size);
}

