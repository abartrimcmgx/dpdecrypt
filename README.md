# dpdecrypt

PostgreSQL Extension for AES-GCM and AES-CBC decryption

Used pgcrypsi https://github.com/telkomdev/pgcrypsi as an example when creating this extension.

Majority of this POC was written by [@nanoguy0](https://github.com/nanoguy0)

The purpose of this extension is to provide a way to enable equality, like and sorting on encrypted data within a Postgres database. The extension is expected to be used in conjunction with application layer encryption and decryption. For example Microsoft's Data Protection API (DPAPI) and AWS Key Management Service (KMS) or Google Cloud Key Management Service (KMS) or Azure Key Vault.
The application layer will encrypt and decrypt the data and the extension will be used to search and sort on the encrypted data.
The Field storage format supports versioning and multiple keys for key rotation. Therefore Authentication processes and alike are not necessary as the application layer is expected to handle the responsibility of encryption and decryption and will reveal data corruption if the data has been tampered with.

It is implemented as custom decryption functions. A Keyring is used to support multiple keys. The Keyring is expected to be stored in a secure location and passed in as a sql parameter as not to end up in the query log. Only AES-GCM and AES-CBC with 256 bit keys are supported at this time. 

- Supports bytea (byte array) data type to to support all database data types.
- `pgcrypto` does not support `AES-GCM`.
- Supports AES-GCM and AES-CBC encryption modes.
- Only supports decryption of AES-GCM and AES-CBC encrypted data.
- Encryption is expected to be done in the application layer.

This Extension is half of the process and should allow for experimentation with different encryption and decryption methods including non-revealing approaches that produce results that are not equal to the original data, however would still be searchable and sortable. 

## Field Format
```
AES-GCM: {version(4)|| master_key_uuid(16) || iv(12) || encrypted_data(data||tag)}
AES-CBC: {version(4)|| master_key_uuid(16) || iv(16) || encrypted_data}
```

### AES GCM/CBC decrypt function AES 256 (only) bit encryption function
- dp_decrypt (keyring bytea, data bytea) RETURNS bytea

### Key Ring
- AES 256: key length should be 32 bytes/char
- Keyring is a bytea field, expected to be in the format
     `masterkey_uuid(16)||key(32)||...` - repeating, this supports multiple keys and rotation
     The application is expected to order the provided guys in the fastest order, i.e. most used key first
     It is expect that the keyring is stored in a secure location and passed in as a sql parameter as not to end up in the query log

## Dependencies
- PostgreSQL 16
- Openssl 1.1.1

## Getting started

### Building

#### Clone
```shell
$ git clone https://github.com/abartrimcmg/dpdecrypt.git
```

#### Build
Use Dockerfile to build the extension
  
```shell
$ docker build -t dpdecrypt .
```

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
postgres=# \i /home/user/dpdecrypt/test.sql
```

#### 100% SQL
The ```dpdecrypt_udf.sql``` file contains a UDF (User defined functions) implementation for AES-GCM and AES-CBC decryption. These functions are written in SQL and are slower than the native extension functions, The AES-CBC utilizes the pgcrypto extension for the CBC version and is snignificantly faster, however it is still 2x slower than this native extension implementation.

### Performance
-- Native Extension functions are significantly faster than UDF/PL/pgSQL functions
-- Testing on large datasets has show that GCM is not faster than CBC

