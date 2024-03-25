# dpdecrypt

Support custom encryption and decryption functions for PostgreSQL for supporting search and sort on encrypted data within the database. The Keyring is expected to be stored in a secure location and passed in as a sql parameter as not to end up in the query log.

Supports bytea (byte array) data type to to support all database data types.
`pgcrypto` does not support `AES-GCM`.
Supports AES-GCM and AES-CBC encryption modes.
Only supports decryption of AES-GCM and AES-CBC encrypted data.
Encryption is expected to be done in the application layer.

## Field Format
AES-GCM: `{version(4)|| master_key_uuid(16) || iv(12) || encrypted_data(data||tag)}`
AES-CBC: `{version(4)|| master_key_uuid(16) || iv(16) || encrypted_data}`

## Dependencies
- PostgreSQL 16
- Openssl 1.1.1

## Getting started

### Building

Clone
```shell
$ git clone https://github.com/abartrimcmg/dpdecrypt.git
```

Build
Use Dockerfile to build the extension
  See Dockerfile for more details

### AES GCM/CBC decrypt function AES 256 (only) bit encryption function
- dp_decrypt (keyring bytea, data bytea) RETURNS bytea

### Key Ring
- AES 256: key length should be 32 bytes/char
- Keyring is a bytea field, expected to be in the format
     `masterkey_uuid(16)||key(32)||...` - repeating, this supports multiple keys and rotation
     The application is expected to order the provided guys in the fastest order, i.e. most used key first
     It is expect that the keyring is stored in a secure location and passed in as a sql parameter as not to end up in the query log

### Install to Database

Drop extensions
```shell
$ DROP EXTENSION IF EXISTS dpdecrypt;
```

Create extensions
```shell
$ CREATE EXTENSION IF NOT EXISTS dpdecrypt;
```

### Run test
```shell
postgres=# \i /home/user/pgcrypsi/test.sql
```

### Performance
-- Native Extension functions are significantly faster than UDF/PL/pgSQL functions
-- Testing on large datasets has show that GCM is not faster than CBC

