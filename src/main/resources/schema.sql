-- ===============================
-- DROP EXISTING TABLES (if any)
-- ===============================
-- This removes old tables so we start fresh every time
DROP TABLE IF EXISTS authorities;
DROP TABLE IF EXISTS users;

-- ===============================
-- CREATE USERS TABLE
-- ===============================
-- Stores login credentials for Spring Security JDBC
CREATE TABLE users (
    username VARCHAR(50) NOT NULL PRIMARY KEY,   -- unique username
    password VARCHAR(500) NOT NULL,               -- encrypted password
    enabled BOOLEAN NOT NULL                      -- user active or not
);

-- ===============================
-- CREATE AUTHORITIES TABLE
-- ===============================
-- Stores roles/permissions for each user
CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,                -- reference to users table
    authority VARCHAR(50) NOT NULL,               -- role (ROLE_USER, ROLE_ADMIN)

    -- foreign key ensures username exists in users table
    CONSTRAINT fk_authorities_users
        FOREIGN KEY (username) REFERENCES users(username)
);

-- ===============================
-- UNIQUE INDEX
-- ===============================
-- Prevents duplicate role assignment to the same user
CREATE UNIQUE INDEX ix_auth_username
ON authorities (username, authority);
