/*
* Filename:     main.c
*
* Comments:     TLS parser driver.
*
* Author:       Abbas Razaghpanah (August 2016)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "tls_constants.h"
#include "tls_handshake.h"
#include "utils.h"
#include "x509_cert.h"

int main(int argc, char **argv)
{
    FILE *f = NULL;
    unsigned char *raw_buffer = (unsigned char *)malloc(sizeof(unsigned char) * 10000);
    guchar *decoded = NULL;
    gsize *decoded_len = (gsize *)malloc(sizeof(gsize));
    unsigned long raw_buffer_size = 0;
    unsigned char *buffer = NULL;
    unsigned long buffer_size = 0;
    int i;
    int json = 0;
    int version = 0;
    int record_type = 0;
    unsigned int record_length = 0;
    unsigned int handshake_type = 0;

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0)
        {
            json = 1;
            fprintf(stderr, "JSON output selected\n");
        }
        else
            f = fopen(argv[i], "rb");
    }

    if (f == NULL)
    {
        fprintf(stderr, "No input file given, using standard input.\n");
        f = stdin;
    }
    else
        f = fopen(argv[1], "rb");

    if (!f)
    {
        fprintf(stderr, "Can't open input file.\n");
        exit(1);
    }

    raw_buffer_size = fread(raw_buffer, 1, 10000, f);

    if (print_x509_cert(raw_buffer, raw_buffer_size) == TRUE)
    {
        return 0;
    }

    decoded = g_base64_decode((const char *)raw_buffer, decoded_len);
    if (decoded == NULL || *decoded_len <= 0)
    {
        //printf("Input not base64.\n");
        buffer = raw_buffer;
        buffer_size = raw_buffer_size;
    }
    else
    {
        fprintf(stderr, "Base64 decoded (len: %lu).\n", *decoded_len);
        buffer = (unsigned char *)decoded;
        buffer_size = *decoded_len;
    }


    record_type = buffer[RECORD_TYPE_OFFSET];
    version = read_uint(buffer, VERSION_OFFSET, 2);
    record_length = read_uint(buffer, RECORD_LENGTH_OFFSET, 2);

    if (json)
        printf("{\n");

    if (json)
    {
        printf("\"raw\": \"");
        print_hex_blob(buffer, 0, buffer_size, 0, 0);
        printf("\",\n");
    }
    else
    {
        printf("Input read (%lu bytes): \n", buffer_size);
        for(i = 0; i < buffer_size; i++)
            printf("%c", buffer[i]);
        printf("\n");
    }

    if (json)
        printf("\"tls_version\": \"");
    else
        printf("TLS version: ");

    switch (version)
    {
        case SSL_3_0:
            printf("SSLv3");
            if (json)
                printf("\"");
            break;
        case TLS_1_0:
            printf("TLSv1.0");
            if (json)
                printf("\"");
            break;
        case TLS_1_1:
            printf("TLSv1.1");
            if (json)
                printf("\"");
            break;
        case TLS_1_2:
            printf("TLSv1.2");
            if (json)
                printf("\"");
            break;
        default:
            printf("unknown (%d)", version);
            if (json)
                printf("\"");
    }


    if (!json)
        printf("\nRecord length: %d\n", record_length);

    if (record_length != buffer_size - TLS_HEADER_LEN)
    {
        fprintf(stderr, "ERROR: Record length (%d) doesn't match the data (%lu).\n", record_length, buffer_size - TLS_HEADER_LEN);
        if (json)
            printf("}");
        exit(1);
    }

    if (json)
        printf(",\n\"record_type\" : \"");
    else
        printf("Record type: ");

    switch (record_type)
    {
        case CHANGE_CIPHER_SPEC:
            printf("CHANGE_CIPHER_SPEC");
            if (json)
                printf("\"");
            break;
        case ALERT:
            printf("ALERT");
            if (json)
                printf("\"");
            break;
        case HANDSHAKE:
            printf("HANDSHAKE");
            if (json)
                printf("\",\n\"record_data\": {");
            else
                printf("\n");
            process_handshake(buffer, buffer_size, json);
            if (json)
                printf("}");
            break;
        case APPLICATION_DATA:
            printf("APPLICATION_DATA");
            if (json)
                printf("\"");
            break;
        default:
            printf("unknown (%d)", record_type);
            if (json)
                printf("\"");
    }
    if (json)
        printf("}");
    printf("\n");

    return 0;
}
