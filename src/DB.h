// DB.h
#pragma once

#include <stdio.h> // size_t를 위해 포함
#include <cjson/cJSON.h> // cJSON 라이브러리

int db_init(void);
void db_cleanup(void);

// ==================== 회원가입/로그인 기능 ====================
int db_register_user(const char* name, const char* username, const char* password);
int db_login_user(const char* username, const char* password);

// ==================== 영상 업로드 기능 ====================
/*
 * @brief 'video' 테이블용 (main.html 용)
 * '[{"videoname":...}]' JSON 생성
 * @param user_id 사용자 ID (시청 기록 조회용, 0이면 시청 기록 없이 반환)
 * @param out_json [out] JSON 결과를 저장할 버퍼
 * @param max_size 버퍼의 최대 크기
 */
int db_get_video_list(int user_id, char* out_json, size_t max_size);

/*
 * @brief 'video' 테이블에 메타데이터 저장
 * @param user_id 업로드한 사용자의 ID
 * @param videoname 사용자가 입력한 영상 제목
 * @param description 영상 설명
 * @param duration 영상 길이 (초 단위)
 */
int db_add_video(
    int user_id,
    const char* videoname,
    const char* description,
    int duration
);

/*
 * @brief 'watch_history' 테이블에서 특정 시청 기록 조회 (main.html 클릭 시)
 * @param user_id 조회할 사용자 ID
 * @param video_id 조회할 영상 ID
 * @param out_json [out] {"record": 초, "last_watch": "YYYY-MM-DD HH:MM"} JSON
 * @param max_size 버퍼 크기
 */
int db_get_watch_history(int user_id, int video_id, char* out_json, size_t max_size);

/*
 * @brief 'watch_history' 테이블 업데이트 (viewer.html에서 주기적 호출)
 * @param user_id 사용자 ID
 * @param video_id 영상 ID
 * @param record 현재 재생 시간 (초)
 */
int db_update_watch_history(int user_id, int video_id, int record);

// ==================== 단일 영상 상세정보 ====================
/*
 * @brief 'video' 테이블에서 단일 영상의 상세 정보 (JSON)
 * @param video_id 조회할 영상의 ID
 * @param out_json [out] JSON 결과를 저장할 버퍼
 * @param max_size 버퍼의 최대 크기
 */
int db_get_video_details(int video_id, char* out_json, size_t max_size);

// ==================== 영상 검색 기능 ====================
/*
 * @brief 'video' 테이블에서 제목으로 영상 검색 (부분 일치)
 * @param search_query 검색어 (영상 제목에서 부분 일치 검색)
 * @param out_json [out] 검색 결과 JSON 배열을 저장할 버퍼
 * @param max_size 버퍼의 최대 크기
 */
int db_search_videos(const char* search_query, int user_id, char* out_json, size_t max_size);

// ==================== 영상 관리 기능 ====================
/*
 * @brief 특정 사용자가 업로드한 영상 목록 조회 (날짜순 정렬)
 * @param user_id 사용자 ID
 * @param out_json [out] 영상 목록 JSON 배열을 저장할 버퍼
 * @param max_size 버퍼의 최대 크기
 */
int db_get_user_videos(int user_id, char* out_json, size_t max_size);

/*
 * @brief 영상 정보 수정 (제목, 설명)
 * @param video_id 영상 ID
 * @param user_id 사용자 ID (권한 확인용)
 * @param videoname 새로운 영상 제목
 * @param description 새로운 영상 설명
 */
int db_update_video(int video_id, int user_id, const char* videoname, const char* description);

/*
 * @brief 영상 삭제 (DB에서만 삭제, 파일은 API에서 처리)
 * @param video_id 영상 ID
 * @param user_id 사용자 ID (권한 확인용)
 */
int db_delete_video(int video_id, int user_id);

// ==================== 관리자 기능 ====================
/*
 * @brief 모든 사용자의 영상 목록 조회 (관리자용, 날짜순 정렬)
 * @param out_json [out] 영상 목록 JSON 배열을 저장할 버퍼
 * @param max_size 버퍼의 최대 크기
 */
int db_get_all_videos(char* out_json, size_t max_size);

/*
 * @brief 관리자 권한으로 영상 정보 수정 (권한 확인 없음)
 * @param video_id 영상 ID
 * @param videoname 새로운 영상 제목
 * @param description 새로운 영상 설명
 */
int db_admin_update_video(int video_id, const char* videoname, const char* description);

/*
 * @brief 관리자 권한으로 영상 삭제 (권한 확인 없음)
 * @param video_id 영상 ID
 */
int db_admin_delete_video(int video_id);

// ==================== 조회수 기능 ====================
/*
 * @brief 영상 조회수 증가 (video.view_count += 1)
 * @param video_id 영상 ID
 */
int db_increment_view_count(int video_id);

// ==================== 최근 시청 영상 ====================
/*
 * @brief 특정 사용자의 최근 시청 영상 목록 조회 (최대 limit개)
 * @param user_id 사용자 ID
 * @param limit 가져올 최대 개수 (보통 2개)
 * @param out_json [out] 영상 목록 JSON 배열을 저장할 버퍼
 * @param max_size 버퍼의 최대 크기
 */
int db_get_recent_videos(int user_id, int limit, char* out_json, size_t max_size);
