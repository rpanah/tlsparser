/*
* Filename:     main.c
*
* Comments:     TLS parser driver.
*
* Author:       Abbas Razaghpanah (August 2016)
*/

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include "tls_constants.h"
#include "tls_handshake.h"
#include "utils.h"

int main(int argc, char **argv)
{
    FILE *f;
    unsigned char *raw_buffer = (unsigned char *)malloc(sizeof(unsigned char) * 10000);
    guchar *decoded = NULL;
    gsize *decoded_len = (gsize *)malloc(sizeof(gsize));
    unsigned long raw_buffer_size = 0;
    unsigned char *buffer = NULL;
    unsigned long buffer_size = 0;
    int i;
    int version = 0;
    int record_type = 0;
    unsigned int record_length = 0;
    unsigned int handshake_type = 0;

    if (argc < 2)
    {
        printf("No input file given, using standard input.\n");
        //exit(1);
        f = stdin;
    }
    else
        f = fopen(argv[1], "rb");

    if (!f)
    {
        printf("Can't open input file.\n");
        exit(1);
    }

    raw_buffer_size = fread(raw_buffer, 1, 10000, f);

    decoded = g_base64_decode((const char *)raw_buffer, decoded_len);
    if (decoded == NULL || *decoded_len <= 0)
    {
        //printf("Input not base64.\n");
        buffer = raw_buffer;
        buffer_size = raw_buffer_size;
    }
    else
    {
        printf("Base64 decoded (len: %lu).\n", *decoded_len);
        buffer = (unsigned char *)decoded;
        buffer_size = *decoded_len;
    }

    printf("Input read (%lu bytes): \n", buffer_size);
    for(i = 0; i < buffer_size; i++)
        printf("%c", buffer[i]);
    printf("\n");

    record_type = buffer[RECORD_TYPE_OFFSET];
    version = read_uint(buffer, VERSION_OFFSET, 2);
    record_length = read_uint(buffer, RECORD_LENGTH_OFFSET, 2);

    printf("TLS version: ");
    switch (version)
    {
        case SSL_3_0:
            printf("SSLv3");
            break;
        case TLS_1_0:
            printf("TLSv1.0");
            break;
        case TLS_1_1:
            printf("TLSv1.1");
            break;
        case TLS_1_2:
            printf("TLSv1.2");
            break;
        default:
            printf("unknown (%d)", version);
    }
    printf("\n");


    printf("Record length: %d\n", record_length);

    if (record_length != buffer_size - TLS_HEADER_LEN)
    {
        fprintf(stderr, "ERROR: Record length (%d) doesn't match the data (%lu).\n", record_length, buffer_size - TLS_HEADER_LEN);
        exit(1);
    }

    printf("Message type: ");
    switch (record_type)
    {
        case CHANGE_CIPHER_SPEC:
            printf("CHANGE_CIPHER_SPEC");
            break;
        case ALERT:
            printf("ALERT");
            break;
        case HANDSHAKE:
            printf("HANDSHAKE\n");
            process_handshake(buffer, buffer_size);
            break;
        case APPLICATION_DATA:
            printf("APPLICATION_DATA");
            break;
        default:
            printf("unknown (%d)", record_type);
    }
    printf("\n");

    return 0;
}
