CREATE DATABASE hss;
USE hss;

CREATE TABLE autn_info (
    imsi BIGINT PRIMARY KEY,
    key_id BIGINT,
    rand_num BIGINT
);

CREATE TABLE loc_info (
    imsi BIGINT PRIMARY KEY,
    mmei INT
);