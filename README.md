# Простой пример гомоморфного шифрования

## Предварительная настройка
Нужно создать БД(в данном случае локально). Код ниже создает таблицу, которая 
будет содержать в себе два зашифрованных столбца типа BYTEA(байты). Так же создается
пользователь `client`, с правами только на чтение(select) из этой таблицы:


```commandline
sudo -u postgres psql
```

```sql
CREATE DATABASE encrypted_db;

\c encrypted_db;

CREATE TABLE encrypted_data (
    id SERIAL PRIMARY KEY,
    encrypted_int BYTEA,
    encrypted_float BYTEA
);

CREATE USER client WITH PASSWORD '123456';
GRANT SELECT (encrypted_int, encrypted_float) ON encrypted_data TO client;
```
Далее в программе будет выполняться подключение от пользователя с именем `postgres`, что
будет олицетворять подключения админа aka владельца сервера. Его пароль нужно либо задать
в коде в графе `password_server`, либо поменять сам пароль, на какой-нибудь простенький
(в примере используется 123456):
```commandline
sudo -u postgres psql
```
```sql
\password
```


## Запуск
На данный моент нет разделения на клиент и сервер, поэтому все выполняется в рамках одного
приложения


```
go run main.go
```
