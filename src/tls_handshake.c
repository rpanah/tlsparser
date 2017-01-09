#include "tls_ciphers.h"
#include "tls_compressions.h"
#include "tls_constants.h"
#include "tls_extensions.h"
#include "tls_handshake.h"
#include "utils.h"

#include <stdio.h>

struct handshake_message *process_handshake(void *data, int buffer_length)
{
    unsigned char *buffer = data;
    unsigned handshake_type = 0;
    unsigned handshake_length = 0;

    handshake_type = read_uint(buffer, HANDSHAKE_TYPE_OFFSET, HANDSHAKE_TYPE_LEN);
    handshake_length = read_uint(buffer, HANDSHAKE_LENGTH_OFFSET, HANDSHAKE_LENGTH_LEN);
    printf("Handshake length: %d\n", handshake_length);
    printf("Handshake type: ");
    switch (handshake_type)
    {
        default:
            fprintf(stderr, "ERROR: Unknown handshake type %d", handshake_type);
            break;
        case HELLO_REQUEST:
            printf("HELLO_REQUEST");
            break;
        case CLIENT_HELLO:
            printf("CLIENT_HELLO\n");
            process_handshake_client_hello(buffer, buffer_length);
            break;
        case SERVER_HELLO:
            printf("SERVER_HELLO\n");
            process_handshake_server_hello(buffer, buffer_length);
            break;
        case NEW_SESSION_TICKET:
            printf("NEW_SESSION_TICKET");
            break;
        case CERTIFICATE:
            printf("CERTIFICATE");
            break;
        case SERVER_KEY_EXCHANGE:
            printf("SERVER_KEY_EXCHANGE");
            break;
        case CERTIFICATE_REQUEST:
            printf("CERTIFICATE_REQUEST");
            break;
        case SERVER_DONE:
            printf("SERVER_DONE");
            break;
        case CERTIFICATE_VERIFY:
            printf("CERTIFICATE_VERIFY");
            break;
        case CLIENT_KEY_EXCHANGE:
            printf("CLIENT_KEY_EXCHANGE");
            break;
        case FINISHED:
            printf("FINISHED");
            break;
        case CERTIFICATE_URL:
            printf("CERTIFICATE_URL");
            break;
        case CERTIFICATE_STATUS:
            printf("CERTIFICATE_STATUS");
            break;
    }

    return 0;
}

struct hadnshake_client_hello *process_handshake_client_hello(void *data, int buffer_length)
{
    unsigned char *buffer = data;
    unsigned tls_version = 0;
    unsigned session_id_length = 0;
    unsigned cipher_suites_pos = 0;
    unsigned cipher_suites_length = 0;
    unsigned cipher_suites_start = 0;
    unsigned cipher_suites_end = 0;
    unsigned pos = 0;

    unsigned compression_methods_pos = 0;
    unsigned compression_methods_length = 0;
    unsigned compression_methods_start = 0;
    unsigned compression_methods_end = 0;

    unsigned extensions_pos = 0;
    unsigned extensions_length = 0;
    unsigned extensions_start = 0;
    unsigned extensions_end = 0;

    tls_version = read_uint(buffer, HANDSHAKE_CH_VERSION_OFFSET, HANDSHAKE_CH_VERSION_LEN);
    printf("Random:");
    print_hex_blob(buffer, HANDSHAKE_CH_RANDOM_OFFSET, HANDSHAKE_CH_RANDOM_LEN, 1, 1);
    session_id_length = read_uint(buffer, HANDSHAKE_CH_SESSION_ID_LENGTH_OFFSET, HANDSHAKE_CH_SESSION_ID_LENGTH_LEN);
    if (session_id_length)
    {
        printf("Session ID length: %d\n", session_id_length);
        printf("Session ID:");
        print_hex_blob(buffer, HANDSHAKE_CH_SESSION_ID_OFFSET, session_id_length, 1, 1);
    }
    else
    {
        printf("No session ID specified.\n");
    }
    cipher_suites_pos = HANDSHAKE_CH_SESSION_ID_OFFSET + session_id_length;
    cipher_suites_length = read_uint(buffer, cipher_suites_pos, HANDSHAKE_CH_CIPHERS_LENGTH_LEN);

    printf("TLS version: ");
    switch (tls_version)
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
            printf("unknown (%d)", tls_version);
    }
    printf("\n");


    printf("Cipher suites length: %d\n", cipher_suites_length);
    cipher_suites_start = cipher_suites_pos + HANDSHAKE_CH_CIPHERS_LENGTH_LEN;
    cipher_suites_end = cipher_suites_start + cipher_suites_length;

    printf("Cipher suites:\n");
    for (pos = cipher_suites_start; pos < cipher_suites_end; pos += HANDSHAKE_CH_CIPHER_LEN)
    {
        unsigned cipher = read_uint(buffer, pos, HANDSHAKE_CH_CIPHER_LEN);
        /* printf("%#04x ", cipher); */
        char *name = cipher_name(cipher);
        if(!name)
        {
            fprintf(stderr, "WARNING: Unknown cipher suite %#04x!\n", cipher);
            continue;
        }
        printf("\t%s (%#.04x)\n", name, cipher);
    }

    compression_methods_pos = pos;
    compression_methods_length = read_uint(buffer, compression_methods_pos, HANDSHAKE_CH_COMP_LENGTH_LEN);
    if (compression_methods_length)
    {
        printf("Compression methods length: %d\n", compression_methods_length);
    
        compression_methods_start = compression_methods_pos + HANDSHAKE_CH_COMP_LENGTH_LEN;
        compression_methods_end = compression_methods_start + compression_methods_length;

        printf("Compression methods:\n");
        for (pos = compression_methods_start; pos < compression_methods_end; pos += HANDSHAKE_CH_COMP_METHOD_LEN)
        {
            unsigned compression = read_uint(buffer, pos, HANDSHAKE_CH_COMP_METHOD_LEN);
            switch (compression)
            {
                default:
                    fprintf(stderr, "WARNING: Unknown compression method %#04x!\n", compression);
                    break;
                case COMP_NULL:
                    printf("\tNo compression (NULL).\n");
                    break;
                case COMP_DEFLATE:
                    printf("\tDEFLATE\n");
                    break;
                case COMP_LZS:
                    printf("\tLZS\n");
                    break;
            }
        }
    }
    else
    {
        printf("No compression methods specified.\n");
        pos = compression_methods_pos + HANDSHAKE_CH_COMP_LENGTH_LEN;
    }

    extensions_pos = pos;
    extensions_length = read_uint(buffer, extensions_pos, HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN);
    extensions_start = extensions_pos + HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN;
    extensions_end = extensions_start + extensions_length;

    printf("Extensions length: %d\n", extensions_length);
    printf("Extensions:\n");
    for (pos = extensions_start; pos < extensions_end; )
    {
        unsigned extension_id = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_ID_LEN);
        pos += HANDSHAKE_CH_EXTENSION_ID_LEN;
        unsigned extension_data_length = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN);
        pos += HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN + extension_data_length;
        /* printf("%#04x ", cipher); */
        char *name = extension_name(extension_id);
        printf("\t%s (id = %d len = %d))\n", name, extension_id, extension_data_length);
        switch (extension_id)
        {
            default:
                fprintf(stderr, "WARNING: Unknown extension %#04x!\n", extension_id);
                continue;

            case EXT_SERVER_NAME:
                /* parse_sni((char *)buffer, pos - extension_data_length, extension_data_length); */
                break;

            case EXT_MAX_FRAGMENT_LENGTH:
                break;

            case EXT_CLIENT_CERTIFICATE_URL:
                break;

            case EXT_TRUSTED_CA_KEYS:
                break;

            case EXT_TRUNCATED_HMAC:
                break;

            case EXT_STATUS_REQUEST:
                break;

            case EXT_USER_MAPPING:
                break;

            case EXT_CLIENT_AUTHZ:
                break;

            case EXT_SERVER_AUTHZ:
                break;

            case EXT_CERT_TYPE:
                break;

            case EXT_SUPPORTED_GROUPS:
                break;

            case EXT_EC_POINT_FORMATS:
                break;

            case EXT_SRP:
                break;

            case EXT_SIGNATURE_ALGORITHMS:
                break;

            case EXT_USE_SRTP:
                break;

            case EXT_HEARTBEAT:
                break;

            case EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                break;

            case EXT_STATUS_REQUEST_V2:
                break;

            case EXT_SIGNED_CERTIFICATE_TIMESTAMP:
                break;

            case EXT_CLIENT_CERTIFICATE_TYPE:
                break;

            case EXT_SERVER_CERTIFICATE_TYPE:
                break;

            case EXT_PADDING:
                break;

            case EXT_ENCRYPT_THEN_MAC:
                break;

            case EXT_EXTENDED_MASTER_SECRET:
                break;

            case EXT_TOKEN_BINDING:
                break;

            case EXT_CACHED_INFO:
                break;

            case EXT_SESSION_TICKET_TLS:
                break;

            case EXT_RENEGOTIATION_INFO:
                break;
        }
    }

    return 0;
}

struct hadnshake_server_hello *process_handshake_server_hello(void *data, int buffer_length)
{
    unsigned char *buffer = data;
    unsigned tls_version = 0;
    unsigned session_id_length = 0;
    unsigned cipher_suites_pos = 0;
    unsigned pos = 0;

    unsigned compression_methods_pos = 0;
    unsigned compression_methods_length = 0;
    unsigned compression_methods_start = 0;
    unsigned compression_methods_end = 0;

    unsigned extensions_pos = 0;
    unsigned extensions_length = 0;
    unsigned extensions_start = 0;
    unsigned extensions_end = 0;

    tls_version = read_uint(buffer, HANDSHAKE_CH_VERSION_OFFSET, HANDSHAKE_CH_VERSION_LEN);
    printf("Random:");
    print_hex_blob(buffer, HANDSHAKE_CH_RANDOM_OFFSET, HANDSHAKE_CH_RANDOM_LEN, 1, 1);
    session_id_length = read_uint(buffer, HANDSHAKE_CH_SESSION_ID_LENGTH_OFFSET, HANDSHAKE_CH_SESSION_ID_LENGTH_LEN);
    if (session_id_length)
    {
        printf("Session ID length: %d\n", session_id_length);
        printf("Session ID:");
        print_hex_blob(buffer, HANDSHAKE_CH_SESSION_ID_OFFSET, session_id_length, 1, 1);
    }
    else
    {
        printf("No session ID specified.\n");
    }
    cipher_suites_pos = HANDSHAKE_CH_SESSION_ID_OFFSET + session_id_length;

    printf("TLS version: ");
    switch (tls_version)
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
            printf("unknown (%d)", tls_version);
    }
    printf("\n");
    pos = HANDSHAKE_CH_SESSION_ID_OFFSET + session_id_length;

    printf("Cipher suite:");
    unsigned cipher = read_uint(buffer, pos, HANDSHAKE_CH_CIPHER_LEN);
    /* printf("%#04x ", cipher); */
    char *name = cipher_name(cipher);
    if(!name)
    {
        fprintf(stderr, "WARNING: Unknown cipher suite %#04x!\n", cipher);
    }
    printf("\t%s (%#.04x)\n", name, cipher);
    pos = pos + HANDSHAKE_CH_CIPHER_LEN;

    compression_methods_pos = pos;
    printf("Compression method:\n");
    unsigned compression = read_uint(buffer, pos, HANDSHAKE_CH_COMP_METHOD_LEN);
    switch (compression)
    {
        default:
            fprintf(stderr, "WARNING: Unknown compression method %#04x!\n", compression);
            break;
        case COMP_NULL:
            printf("\tNo compression (NULL).\n");
            break;
        case COMP_DEFLATE:
            printf("\tDEFLATE\n");
            break;
        case COMP_LZS:
            printf("\tLZS\n");
            break;
    }

    pos = pos + HANDSHAKE_CH_COMP_METHOD_LEN;

    extensions_pos = pos;
    extensions_length = read_uint(buffer, extensions_pos, HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN);
    extensions_start = extensions_pos + HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN;
    extensions_end = extensions_start + extensions_length;

    printf("Extensions length: %d\n", extensions_length);
    printf("Extensions:\n");
    for (pos = extensions_start; pos < extensions_end; )
    {
        unsigned extension_id = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_ID_LEN);
        pos += HANDSHAKE_CH_EXTENSION_ID_LEN;
        unsigned extension_data_length = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN);
        pos += HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN + extension_data_length;
        /* printf("%#04x ", cipher); */
        char *name = extension_name(extension_id);
        printf("\t%s (id = %d len = %d))\n", name, extension_id, extension_data_length);
        switch (extension_id)
        {
            default:
                fprintf(stderr, "WARNING: Unknown extension %#04x!\n", extension_id);
                continue;

            case EXT_SERVER_NAME:
                /* parse_sni((char *)buffer, pos - extension_data_length, extension_data_length); */
                break;

            case EXT_MAX_FRAGMENT_LENGTH:
                break;

            case EXT_CLIENT_CERTIFICATE_URL:
                break;

            case EXT_TRUSTED_CA_KEYS:
                break;

            case EXT_TRUNCATED_HMAC:
                break;

            case EXT_STATUS_REQUEST:
                break;

            case EXT_USER_MAPPING:
                break;

            case EXT_CLIENT_AUTHZ:
                break;

            case EXT_SERVER_AUTHZ:
                break;

            case EXT_CERT_TYPE:
                break;

            case EXT_SUPPORTED_GROUPS:
                break;

            case EXT_EC_POINT_FORMATS:
                break;

            case EXT_SRP:
                break;

            case EXT_SIGNATURE_ALGORITHMS:
                break;

            case EXT_USE_SRTP:
                break;

            case EXT_HEARTBEAT:
                break;

            case EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                break;

            case EXT_STATUS_REQUEST_V2:
                break;

            case EXT_SIGNED_CERTIFICATE_TIMESTAMP:
                break;

            case EXT_CLIENT_CERTIFICATE_TYPE:
                break;

            case EXT_SERVER_CERTIFICATE_TYPE:
                break;

            case EXT_PADDING:
                break;

            case EXT_ENCRYPT_THEN_MAC:
                break;

            case EXT_EXTENDED_MASTER_SECRET:
                break;

            case EXT_TOKEN_BINDING:
                break;

            case EXT_CACHED_INFO:
                break;

            case EXT_SESSION_TICKET_TLS:
                break;

            case EXT_RENEGOTIATION_INFO:
                break;
        }
    }

    return 0;
}
