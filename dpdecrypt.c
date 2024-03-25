#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include <string.h>
#include <openssl/err.h>
#include "dpdecrypt.h"

#if PG_VERSION_NUM >= 160000
    #include "varatt.h"
#endif


PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(dp_decrypt);
Datum dp_decrypt(PG_FUNCTION_ARGS)
{
    long ret = 0;
    unsigned int dst_size = 0;
    int key_ring_size = 0;
    int cipher_size = 0;

    unsigned char *key_ring = NULL;
    unsigned char *cipher = NULL;

    unsigned char *key = NULL;

    int cipher_version = -1;

    unsigned char *dst_buffer = NULL;
    bytea *result = NULL;

    bytea *key_ring_bp = (bytea *)PG_GETARG_BYTEA_PP(0);
    bytea *cipher_bp = (bytea *)PG_GETARG_BYTEA_PP(1);

    if ((key_ring_size = VARSIZE_ANY_EXHDR(key_ring_bp)) == 0)
        PG_RETURN_NULL();
    if ((cipher_size = VARSIZE_ANY_EXHDR(cipher_bp)) == 0)
        PG_RETURN_NULL();

    if (key_ring_size % sizeof(dp_keyring) != 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("Invalid keyring size, must be multiple of %d", (int)sizeof(dp_keyring))));

    cipher = (unsigned char *)VARDATA_ANY(cipher_bp);
    cipher_version = ((dp_cipher_header *)cipher)->version;

    key_ring = (unsigned char *)VARDATA_ANY(key_ring_bp);
    key = search_dp_keyring(((dp_cipher_header *)cipher)->uuid, (dp_keyring*)key_ring, key_ring_size / sizeof(dp_keyring));

    if (key == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("Key not found in keyring")));

    cipher += sizeof(dp_cipher_header);
    cipher_size -= sizeof(dp_cipher_header);

    switch (cipher_version)
    {
        case DP_AES256_GCM:
            ret = dp_aes_decrypt(DP_GCM ,key, cipher, cipher_size, &dst_buffer, &dst_size);
            break;
        case DP_AES256_CBC:
            ret = dp_aes_decrypt(DP_CBC ,key, cipher, cipher_size, &dst_buffer, &dst_size);
            break;
        default:
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_EXCEPTION),
                    errmsg("Invalid cipher version: %u", cipher_version)));
    }

    if (ret != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("error openssl with dp_decrypt, openssl error: %s", ERR_error_string(ret, NULL))));
    }

    result = (bytea *)palloc(dst_size + VARHDRSZ);
    SET_VARSIZE(result, dst_size + VARHDRSZ);

    memcpy(VARDATA_ANY(result), dst_buffer, dst_size);
    pfree(dst_buffer);

    // free the passed in from postgres data
    PG_FREE_IF_COPY(key_ring_bp, 0);
    PG_FREE_IF_COPY(cipher_bp, 1);

    PG_RETURN_BYTEA_P(result);
}

static long dp_aes_decrypt(
    dp_mode_t mode, 
    const unsigned char *key, 
    const unsigned char *data, 
    size_t data_len, 
    unsigned char **dst, 
    unsigned int *dst_len)
{
    // hardcode to 256 for now testing
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    long ret = -1;
    int dst_len_tmp = 0;
    int plaintext_len = 0;
    int raw_ciphertext_len = 0;
    unsigned char *ciphertext_raw = NULL;
    // unsigned char *dst_tmp = NULL;

    // If we are are not GCM, we prob should not put this on the stack
    unsigned char tag[AES_GCM_TAG_SIZE];

    unsigned char *dst_decode = (unsigned char *)data;
    unsigned int dst_decode_len = data_len;

    // GCM and CBC have different IV sizes
    unsigned int iv_size = 0;
    unsigned char *iv = dst_decode;  
    switch (mode)
    {
        case DP_GCM:
            cipher = (EVP_CIPHER *)EVP_aes_256_gcm();
            iv_size = AES_GCM_IV_SIZE;
            raw_ciphertext_len = dst_decode_len - (iv_size + sizeof(tag));
            break;
        case DP_CBC:
            cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
            iv_size = AES_CBC_IV_SIZE;
            raw_ciphertext_len = dst_decode_len - iv_size;
            break;
        default:
            FAIL_DECRYPT(DP_OPENSSL_ERROR_MODE);
    }
    ciphertext_raw = dst_decode + iv_size;

    // copy tag
    if (mode == DP_GCM) {
        memcpy(tag, dst_decode + raw_ciphertext_len + iv_size, sizeof(tag));
    }
    
    if ((*dst = (unsigned char *)palloc(raw_ciphertext_len)) == NULL)
        goto cleanup;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        FAIL_DECRYPT(ERR_get_error());
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        FAIL_DECRYPT(ERR_get_error());

    if (mode == DP_GCM)
    {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1)
            FAIL_DECRYPT(ERR_get_error());
    }

    if (EVP_DecryptUpdate(ctx, *dst, &dst_len_tmp, ciphertext_raw, raw_ciphertext_len) != 1)
        FAIL_DECRYPT(ERR_get_error());

    plaintext_len = dst_len_tmp;

    if (EVP_DecryptFinal_ex(ctx, *dst + dst_len_tmp, &dst_len_tmp) != 1)
        FAIL_DECRYPT(ERR_get_error());

    plaintext_len += dst_len_tmp;
    (*dst)[plaintext_len] = 0x0;
    *dst_len = plaintext_len;
    ret = 0;
/* Clean up */
cleanup:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    return ret;
}

unsigned char * search_dp_keyring(
    char *uuid, 
    dp_keyring *keyring, 
    size_t keyring_size)
{
    char *resolved_key = NULL;
    for (int i = 0; i < keyring_size; i++)
    {
        if (memcmp(uuid, keyring[i].uuid, 16) == 0)
        {
            resolved_key = keyring[i].key;
            break;
        }
    }
    return (unsigned char *)resolved_key;
}
