#ifndef _BASE64_H
#define _BASE64_H

#define B64_ENCODE_LEN(s) (((s - 1) / 3 + 1) * 4);

int b64_encode(__const__ char *indata, __const__ int len, char *outdata);

int b64_decode(__const__ char *indata, __const__ int len, char *outdata);

#endif
