#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "base64.h"
#include "aes.h"

int main(int argc, char **argv)
{
    int el;
    int l = GS_AES_KEY_LEN / 8;
    unsigned char key[l];
    unsigned char *b64d;
    srand((unsigned) time(NULL));
    for(int i = 0; i < l; i++)
        key[i] = rand() % 256;
    el = B64_ENCODE_LEN(l);
    b64d = (unsigned char *) malloc(sizeof(char) * el);
    b64_encode(key, l, b64d);
    printf("key = %s\n", b64d);
    fflush(stdout);
    free(b64d);
    return 0;
}
