-- 데이터베이스 스키마
-- MySQL Workbench 또는 mysql 커맨드라인에서 실행

-- 1. 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS serverdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE serverdb;

-- 2. 기존 테이블 삭제 (재설치 시)
DROP TABLE IF EXISTS watch_history;
DROP TABLE IF EXISTS video;
DROP TABLE IF EXISTS user;

-- 3. 사용자 테이블
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL COMMENT '사용자 이름',
    username VARCHAR(50) NOT NULL UNIQUE COMMENT '로그인 ID',
    password VARCHAR(255) NOT NULL COMMENT '비밀번호',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '가입일시',
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='사용자 정보';

-- 4. 영상 테이블
CREATE TABLE video (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL COMMENT '업로더 ID',
    videoname VARCHAR(255) NOT NULL COMMENT '영상 제목',
    description TEXT COMMENT '영상 설명',
    duration INT DEFAULT 0 COMMENT '영상 길이 (초 단위)',
    view_count INT DEFAULT 0 COMMENT '조회수',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '업로드일시',
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='영상 정보';

-- 5. 시청 기록 테이블
CREATE TABLE watch_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL COMMENT '사용자 ID',
    video_id INT NOT NULL COMMENT '영상 ID',
    record INT DEFAULT 0 COMMENT '시청 위치 (초 단위)',
    last_watch TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '마지막 시청 시간',
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (video_id) REFERENCES video(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_video (user_id, video_id),
    INDEX idx_user_id (user_id),
    INDEX idx_last_watch (last_watch)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='시청 기록';

--6. 관리자 ID 생성 ( id = 1 )

INSERT INTO users (name, username, password)
VALUES ('admin', 'admin', 'admin');
