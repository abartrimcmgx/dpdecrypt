#ifndef DP_DECRYPT_H
#define DP_DECRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define AES_GCM_IV_SIZE 12
#define AES_CBC_IV_SIZE 16
#define AES_GCM_TAG_SIZE 16

typedef enum
{
    DP_GCM,
    DP_CBC
} dp_mode_t;

#define DP_OPENSSL_ERROR_NONE 0
#define DP_OPENSSL_ERROR_MODE 1

#define FAIL_DECRYPT(error_no) \
    do                         \
    {                          \
        ret = error_no;        \
        goto cleanup;          \
    } while (0);

enum DP_CIPHER_VERSION
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    DP_AES256_GCM = 0xdef0271e,
    DP_AES256_CBC = 0xdff0271e,
    #else
    DP_AES256_GCM = 0x1e27f0de,
    DP_AES256_CBC = 0x1e27f0df,
    #endif
};

typedef struct dp_cipher_header {
    unsigned int version;
    char uuid[16];
} dp_cipher_header;

typedef struct dp_keyring {
    char uuid[16];
    char key[32];
} dp_keyring;

unsigned char * search_dp_keyring(
    char *uuid, 
    dp_keyring *keyring, 
    size_t keyring_size);

static long dp_aes_decrypt(
    dp_mode_t mode, 
    const unsigned char *key, 
    const unsigned char *data, 
    size_t data_len, 
    unsigned char **dst, 
    unsigned int *dst_len);

#endif // DP_DECRYPT_H