#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>

#include "openssl_ciphers.h"

/* gcc test.c -L/opt/local/lib -lssl -lcrypto -o test_run */

int main(int argc, char **argv) {
    unsigned char *ciphers = (unsigned char *)malloc(sizeof(unsigned char) * 2);
    unsigned short x = 0;
    const SSL_CIPHER *cipher = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Invalid arguments given.\n");
        exit(1);
    }
    else
    {
        sscanf(argv[1], "%x", &x);
        ciphers [0] = (unsigned char)(x >> 8);
        ciphers [1] = (unsigned char)(x % 256);
    }

    cipher = ssl3_get_cipher_by_char(ciphers);

    if (!cipher)
    {
        fprintf(stderr, "Cipher is null\n");
        exit(0);
    }

    printf("Cipher name is %s: \n", cipher->name);
    return 0;
}
