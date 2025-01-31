CREATE DATABASE encrypted_db;

\c encrypted_db;

CREATE TABLE encrypted_data (
                                id SERIAL PRIMARY KEY,
                                encrypted_int BYTEA,  -- Зашифрованные целые числа (BGV)
                                encrypted_float BYTEA -- Зашифрованные дробные числа (CKKS)
);

CREATE USER client WITH PASSWORD '123456';
GRANT SELECT (encrypted_int, encrypted_float) ON encrypted_data TO client;