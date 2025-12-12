/* fetch.h - API 엔드포인트 핸들러 */
#pragma once

#include <stddef.h>

/* API 응답 구조체 */
typedef struct {
    int status_code;           /* HTTP 상태 코드 (200, 404, 500 등) */
    const char* content_type;  /* Content-Type */
    char* body;                /* 응답 본문 (동적 할당) */
    size_t body_length;        /* 본문 길이 */
} api_response;

/* 라우트 핸들러 함수 포인터 타입 */
typedef api_response* (*route_handler_with_body)(const char* body);
typedef api_response* (*route_handler_no_body)(void);

/* 라우트 정보 구조체 */
typedef struct {
    const char* path;          /* 경로 (예: "/login") */
    const char* method;        /* HTTP 메서드 ("GET", "POST") */
    int needs_body;            /* POST body 필요 여부 (0=불필요, 1=필요) */
    route_handler_with_body handler_with_body;  /* body를 받는 핸들러 */
    route_handler_no_body handler_no_body;      /* body 없는 핸들러 */
} api_route;

/* API 응답 생성 */
api_response* api_response_create(int status_code, const char* content_type, const char* body);

/* API 응답 해제 */
void api_response_free(api_response* resp);

/* ==================== API 엔드포인트 핸들러 ==================== */

/* POST /register - 회원가입 */
api_response* handle_register(const char* body);

/* POST /login - 로그인 */
api_response* handle_login(const char* body);

/* GET /video_list - 비디오 목록 (user_id 옵션) */
api_response* handle_video_list(int user_id);

/* POST /upload_video - 비디오 업로드 (멀티파트) */
api_response* handle_upload_video(const char* body, const char* content_type, size_t body_length, const char* file_path);

/* GET /video_details?id=123 - 비디오 상세정보 */
api_response* handle_video_details(int video_id);

/* GET /watch_history?user_id=1&video_id=2 - 시청 기록 조회 */
api_response* handle_watch_history(int user_id, int video_id);

/* POST /update_history - 시청 기록 업데이트 */
api_response* handle_update_history(const char* body);

/* GET /video_search?q=검색어 - 영상 검색 (제목 부분 일치) */
api_response* handle_video_search(const char* search_query, int user_id);

/* GET /user_videos?user_id=1 - 특정 사용자의 영상 목록 */
api_response* handle_user_videos(int user_id);

/* POST /update_video - 영상 정보 수정 */
api_response* handle_update_video(const char* body);

/* POST /delete_video - 영상 삭제 */
api_response* handle_delete_video(const char* body);

/* GET /admin_videos - 관리자: 모든 영상 목록 */
api_response* handle_admin_videos(void);

/* POST /admin_update_video - 관리자: 영상 수정 */
api_response* handle_admin_update_video(const char* body);

/* POST /admin_delete_video - 관리자: 영상 삭제 */
api_response* handle_admin_delete_video(const char* body);

/* POST /increment_view - 조회수 증가 */
api_response* handle_increment_view(const char* body);

/* GET /recent_videos?user_id=1&limit=2 - 최근 시청 영상 목록 */
api_response* handle_recent_videos(int user_id, int limit);

/* ==================== 라우팅 시스템 ==================== */

/* 라우트 매칭 및 처리 */
api_response* route_request(const char* path, const char* method, const char* body);

/* 특정 경로가 POST body를 필요로 하는지 확인 */
int route_needs_body(const char* path, const char* method);
