#include "base64.h"
#include "openssl/evp.h"

int b64_encode(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata)
{
    return EVP_EncodeBlock(outdata, indata, len);
}

int b64_decode(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata)
{
    return EVP_DecodeBlock(outdata, indata, len);
}
