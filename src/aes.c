#include <string.h>

#include "aes.h"

int aes_encode(__const__ char *indata, __const__ int len, char *outdata, __const__ unsigned char *key)
{
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY aes;
    memset(iv, '\0', AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, GS_AES_KEY_LEN, &aes);
    AES_cbc_encrypt(indata, outdata, len, &aes, iv, AES_ENCRYPT);
}

int aes_decode(__const__ char *indata, __const__ int len, char *outdata, __const__ unsigned char *key)
{
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY aes;
    memset(iv, '\0', AES_BLOCK_SIZE);
    AES_set_decrypt_key(key, GS_AES_KEY_LEN, &aes);
    AES_cbc_encrypt(indata, outdata, len, &aes, iv, AES_DECRYPT);
}
