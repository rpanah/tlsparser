#include "wireshark_ciphers.h"
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
    unsigned int x = 0;
    if (argc != 2)
    {
        fprintf(stderr, "Invalid arguments given.\n");
        exit(1);
    }

    sscanf(argv[1], "%x", &x);
    printf("Name of cipher %.04x is %s\n", x, get_cipher_name(x));

    return 0;
}