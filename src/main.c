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
#include "tls_extensions.h"
#include "tls_handshake.h"
#include "utils.h"
#include "x509_cert.h"

#define MAX_SIZE 65536

int main(int argc, char **argv)
{
    FILE *f = NULL;
    unsigned char *raw_buffer = (unsigned char *)malloc(sizeof(unsigned char) * MAX_SIZE);
    guchar *decoded = NULL;
    gsize *decoded_len = (gsize *)malloc(sizeof(gsize));
    unsigned long raw_buffer_size = 0;
    unsigned char *buffer = NULL;
    unsigned long buffer_size = 0;
    int i;
    int json = 0;
    int raw = 0;
    int multiple = 0;
    int version = 0;
    int record_type = 0;
    unsigned int record_length = 0;
    unsigned int handshake_type = 0;
    unsigned int offset = 0;
    const char *tls_version_string = NULL;

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0)
        {
            json = 1;
        }
        else if (strcmp(argv[i], "--raw") == 0 || strcmp(argv[i], "-r") == 0)
        {
            raw = 1;
        }
        else if (strcmp(argv[i], "--multiple") == 0 || strcmp(argv[i], "-m") == 0)
        {
            multiple = 1;
        }
        else if (f == NULL) 
        {
            f = fopen(argv[i], "rb");
        }
        else
        {
          fprintf(stderr, "Command line argument \"%s\" not recognized!\n", argv[i]);
        }
    }

    if (f == NULL)
    {
        if (!json)
            fprintf(stderr, "No input file given, using standard input.\n");
        f = stdin;
    }

    if (!f)
    {
        fprintf(stderr, "Can't open input file %s\n", argv[1]);
        exit(1);
    }

    raw_buffer_size = fread(raw_buffer, 1, MAX_SIZE, f);

    if (print_x509_cert(raw_buffer, raw_buffer_size) == TRUE)
    {
        return 0;
    }

    decoded = g_base64_decode((const char *)raw_buffer, decoded_len);
    if (decoded == NULL || *decoded_len <= 0)
    {
        buffer = raw_buffer;
        buffer_size = raw_buffer_size;
    }
    else
    {
        if (!json)
            fprintf(stderr, "Base64 decoded (len: %lu).\n", *decoded_len);
        buffer = (unsigned char *)decoded;
        buffer_size = *decoded_len;
    }

    i = 0;
    while(offset < buffer_size)
    {
        i++;
        if (i > 1)
        {
            if (!multiple)
            {
              fprintf(stderr, "Trailing data past the first record, but only asked to read one record (record length: %u data length: %lu).\n", record_length, buffer_size);
              exit(0);
            }
            if (json)
                printf("\n");
            else
                printf("\n----------------\n");
        }
        record_type = buffer[offset + RECORD_TYPE_OFFSET];
        version = read_uint(buffer, offset + VERSION_OFFSET, 2);
        record_length = read_uint(buffer, offset + RECORD_LENGTH_OFFSET, 2);

        if (json)
            printf("{\n");
    
        if (raw)
        {
            if (json)
            {
                printf("\"raw\": \"");
                print_hex_blob(buffer, offset, record_length, 0, 0, json);
                printf("\",\n");
            }
            else
            {
                printf("Input read (%u bytes): \n", record_length);
                for(i = offset; i < offset + record_length; i++)
                    printf("%c", buffer[i]);
                printf("\n");
            }
        }

        if (json)
            printf("\"tls_version\": \"");
        else
            printf("TLS version: ");

        tls_version_string = version_name(version);
        if (tls_version_string != NULL)
        {
            printf("%s", tls_version_string);
        }
        else
        {
            printf("unknown (%d)", version);
        }

        if (json)
            printf("\"");

        if (!json)
            printf("\nRecord length: %u\n", record_length);

        if (offset + record_length + TLS_HEADER_LEN > buffer_size)
        {
            fprintf(stderr, "ERROR: Record length + offset + header length (%d + %d + %d) exceeds data length (%lu).\n", record_length, offset, TLS_HEADER_LEN, buffer_size);
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
                process_handshake(buffer, offset, record_length + TLS_HEADER_LEN, json, raw);
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
                break;
        }
        if (json)
            printf("}");
        offset += record_length + TLS_HEADER_LEN;
    }

    printf("\n");

    return 0;
}
