CREATE DATABASE twofa;

USE twofa:

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

ALTER TABLE users 
ADD COLUMN registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN last_login TIMESTAMP NULL,
ADD COLUMN last_2fa TIMESTAMP NULL,
ADD COLUMN last_device VARCHAR(255) NULL;

CREATE TABLE sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id INT,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE otp (
    session_id VARCHAR(255),
    otp_code VARCHAR(6),
    expiry_time DATETIME,
    PRIMARY KEY (session_id, otp_code),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Insert a test user
INSERT INTO users (username, password) VALUES ('admin', 'Shaina071199');
ALTER TABLE users ADD COLUMN secret VARCHAR(255);
