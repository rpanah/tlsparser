#include "tls_ciphers.h"
#include "tls_compressions.h"
#include "tls_constants.h"
#include "tls_extensions.h"
#include "tls_handshake.h"
#include "utils.h"

#include <stdio.h>

struct handshake_message *process_handshake(void *data, int offset, int record_length, int json, int raw)
{
    unsigned char *buffer = data;
    unsigned handshake_type = 0;
    unsigned handshake_length = 0;

    handshake_type = read_uint(buffer, offset + HANDSHAKE_TYPE_OFFSET, HANDSHAKE_TYPE_LEN);
    handshake_length = read_uint(buffer, offset + HANDSHAKE_LENGTH_OFFSET, HANDSHAKE_LENGTH_LEN);
    if (!json)
    {
        printf("Handshake length: %d\n", handshake_length);
    }

    if (json)
        printf("\"handshake_type\": \"");
    else
        printf("Handshake type: ");

    switch (handshake_type)
    {
        default:
            fprintf(stderr, "ERROR: Unknown handshake type %d", handshake_type);
            break;
        case HELLO_REQUEST:
            printf("HELLO_REQUEST");
            if (json)
                printf("\"\n");
            break;
        case CLIENT_HELLO:
            printf("CLIENT_HELLO");
            if (json)
                printf("\", \"handshake_data\": {\n");
            process_handshake_client_hello(buffer, offset, record_length, handshake_length, json, raw);
            if (json)
                printf("}\n");
            break;
        case SERVER_HELLO:
            printf("SERVER_HELLO");
            if (json)
                printf("\", \"handshake_data\": {\n");
            process_handshake_server_hello(buffer, offset, record_length, handshake_length, json, raw);
            if (json)
                printf("}\n");
            break;
        case NEW_SESSION_TICKET:
            printf("NEW_SESSION_TICKET");
            if (json)
                printf("\"\n");
            break;
        case CERTIFICATE:
            printf("CERTIFICATE");
            if (json)
                printf("\"\n");
            break;
        case SERVER_KEY_EXCHANGE:
            printf("SERVER_KEY_EXCHANGE");
            if (json)
                printf("\"\n");
            break;
        case CERTIFICATE_REQUEST:
            printf("CERTIFICATE_REQUEST");
            if (json)
                printf("\"\n");
            break;
        case SERVER_DONE:
            printf("SERVER_DONE");
            if (json)
                printf("\"\n");
            break;
        case CERTIFICATE_VERIFY:
            printf("CERTIFICATE_VERIFY");
            if (json)
                printf("\"\n");
            break;
        case CLIENT_KEY_EXCHANGE:
            printf("CLIENT_KEY_EXCHANGE");
            if (json)
                printf("\"\n");
            break;
        case FINISHED:
            printf("FINISHED");
            if (json)
                printf("\"\n");
            break;
        case CERTIFICATE_URL:
            printf("CERTIFICATE_URL");
            if (json)
                printf("\"\n");
            break;
        case CERTIFICATE_STATUS:
            printf("CERTIFICATE_STATUS");
            if (json)
                printf("\"\n");
            break;
    }
    return 0;
}

struct hadnshake_client_hello *process_handshake_client_hello(void *data, int offset, int record_length, int handshake_length, int json, int raw)
{
    unsigned char *buffer = data;
    unsigned tls_version = 0;
    unsigned session_id_length = 0;
    unsigned cipher_suites_pos = 0;
    unsigned cipher_suites_length = 0;
    unsigned cipher_suites_start = 0;
    unsigned cipher_suites_end = 0;
    unsigned pos = offset;
    unsigned i = 0;

    unsigned compression_methods_pos = 0;
    unsigned compression_methods_length = 0;
    unsigned compression_methods_start = 0;
    unsigned compression_methods_end = 0;

    unsigned extensions_pos = 0;
    unsigned extensions_length = 0;
    unsigned extensions_start = 0;
    unsigned extensions_end = 0;

    tls_version = read_uint(buffer, offset + HANDSHAKE_CH_VERSION_OFFSET, HANDSHAKE_CH_VERSION_LEN);

    if (json)
    {
        printf("\"random\": \"");
        print_hex_blob(buffer, offset + HANDSHAKE_CH_RANDOM_OFFSET, HANDSHAKE_CH_RANDOM_LEN, 0, 0, json);
        printf("\"");
    }
    else
    {
        printf("\nRandom: ");
        print_hex_blob(buffer, offset + HANDSHAKE_CH_RANDOM_OFFSET, HANDSHAKE_CH_RANDOM_LEN, 0, 0, json);
        printf("\n");
    }

    session_id_length = read_uint(buffer, offset + HANDSHAKE_CH_SESSION_ID_LENGTH_OFFSET, HANDSHAKE_CH_SESSION_ID_LENGTH_LEN);
    if (session_id_length)
    {
        if (json)
        {
            printf(",\n\"session_id\": \"");
            print_hex_blob(buffer, offset + HANDSHAKE_CH_SESSION_ID_OFFSET, session_id_length, 0, 0, json);
            printf("\"");
        }
        else
        {
            printf("Session ID length: %d\n", session_id_length);
            printf("Session ID: ");
            print_hex_blob(buffer, offset + HANDSHAKE_CH_SESSION_ID_OFFSET, session_id_length, 0, 0, json);
            printf("\n");
        }
    }
    else
    {
        if (!json)
            printf("No session ID specified.\n");
    }

    cipher_suites_pos = offset + HANDSHAKE_CH_SESSION_ID_OFFSET + session_id_length;
    cipher_suites_length = read_uint(buffer, cipher_suites_pos, HANDSHAKE_CH_CIPHERS_LENGTH_LEN);

    if (json)
        printf(",\n\"tls_version\": \"");
    else
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
        case TLS_1_3:
            printf("TLSv1.3");
        default:
            printf("unknown (%d)", tls_version);
    }
    if (json)
        printf("\"");
    else
        printf("\n");

    if (!json)
        printf("Cipher suites length: %d\n", cipher_suites_length);

    cipher_suites_start = cipher_suites_pos + HANDSHAKE_CH_CIPHERS_LENGTH_LEN;
    cipher_suites_end = cipher_suites_start + cipher_suites_length;

    if (json)
        printf(",\n\"ciphers\": [\n");
    else
        printf("Cipher suites:\n");

    i = 0;
    for (pos = cipher_suites_start; pos < cipher_suites_end; pos += HANDSHAKE_CH_CIPHER_LEN)
    {
        if (json && i != 0)
            printf(",\n");

        unsigned cipher = read_uint(buffer, pos, HANDSHAKE_CH_CIPHER_LEN);
        /* printf("%#04x ", cipher); */
        char *name = cipher_name(cipher);
        if(!name)
        {
            if (json)
                printf("\t{\"name\": \"unknown\", \"id\": \"%#.4x\"}", cipher);
            i++;
            fprintf(stderr, "WARNING: Unknown cipher suite %#4x!\n", cipher);
            continue;
        }
        if (json)
            printf("\t{\"name\": \"%s\", \"id\": \"%#.4x\"}", name, cipher);
        else
            printf("\t%s (%#.4x)\n", name, cipher);
        i++;
    }

    if (json)
        printf("]");

    compression_methods_pos = pos;
    compression_methods_length = read_uint(buffer, compression_methods_pos, HANDSHAKE_CH_COMP_LENGTH_LEN);
    if (compression_methods_length)
    {
        if (!json)
            printf("Compression methods length: %d\n", compression_methods_length);

        compression_methods_start = compression_methods_pos + HANDSHAKE_CH_COMP_LENGTH_LEN;
        compression_methods_end = compression_methods_start + compression_methods_length;

        if (json)
            printf(",\n\"compression_methods\": [\n");
        else
            printf("Compression methods:\n");

        i = 0;
        for (pos = compression_methods_start; pos < compression_methods_end; pos += HANDSHAKE_CH_COMP_METHOD_LEN)
        {
            unsigned compression = read_uint(buffer, pos, HANDSHAKE_CH_COMP_METHOD_LEN);

            if (json)
            {
                if (i != 0)
                    printf(",\n");
            }
            switch (compression)
            {
                default:
                    fprintf(stderr, "WARNING: Unknown compression method %#4x!\n", compression);
                    break;
                case COMP_NULL:
                    if (json)
                        printf("\t\"NULL\"");
                    else
                        printf("\tNo compression (NULL).\n");
                    break;
                case COMP_DEFLATE:
                    if (json)
                        printf("\t\"DEFLATE\"");
                    else
                        printf("\tDEFLATE\n");
                    break;
                case COMP_LZS:
                    if (json)
                        printf("\t\"LZS\"");
                    else
                        printf("\tLZS\n");
                    break;
            }
            i++;
        }
        if (json)
            printf("]");
    }
    else
    {
        if (!json)
            printf("No compression methods specified.\n");
        pos = compression_methods_pos + HANDSHAKE_CH_COMP_LENGTH_LEN;
    }

    extensions_pos = pos;
    if (pos - offset == record_length)
    {
        return NULL;
    }

    if (pos - offset + HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN > record_length)
    {
        fprintf(stderr, "No extensions.\n");
        extensions_length = 0;
    }
    else
        extensions_length = read_uint(buffer, extensions_pos, HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN);

    extensions_start = extensions_pos + HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN;
    extensions_end = extensions_start + extensions_length;

    if (extensions_end - offset != record_length)
    {
        fprintf(stderr, "WARNING! Extensions end doesn't match buffer end (pos: %u, extensions_end: %u, record_length: %u, handshake_length: %u).\n", pos, extensions_end, record_length, handshake_length);
        extensions_length = 0;
        extensions_start = 0;
        extensions_end = 0;
        if (json)
            printf(", \"trailing_data\": \"");
        else
            printf("Trailing data: \n");

        print_hex_blob(buffer, extensions_pos, (record_length - (extensions_pos + 1)), 0, 0, json);

        if (json)
            printf("\"\n");
    }

    if (!json)
    {
        printf("Extensions length: %d\n", extensions_length);
    }

    if (extensions_length)
    {
        if (json)
            printf(",\n\"extensions\": [\n");
        else
            printf("Extensions:\n");
    }

    i = 0;
    for (pos = extensions_start; pos < extensions_end; )
    {
        unsigned extension_id = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_ID_LEN);
        pos += HANDSHAKE_CH_EXTENSION_ID_LEN;
        unsigned extension_data_length = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN);
        pos += HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN;
        /* printf("%#04x ", cipher); */
        const char *name = extension_name(extension_id);

        if (json)
        {
            if (i != 0)
                printf(",\n");
            printf("\t{ \"name\": \"%s\", \"id\": \"%#.4x\", \"length\": %u", name, extension_id, extension_data_length);
            if (raw)
            {
                printf(", \"raw\": \"");
                print_hex_blob((char *)buffer, pos, extension_data_length, 0, 0, json);
                printf("\"");
            }
            printf(", \"data\": {");
        }
        else
            printf("\t%s (id = %u len = %u))\n", name, extension_id, extension_data_length);

        switch (extension_id)
        {
            default:
                if (name == NULL)
                    fprintf(stderr, "WARNING: Unknown extension %#4x!\n", extension_id);
                break;

            case EXT_SERVER_NAME:
                parse_sni((char *)buffer, pos, extension_data_length, json);
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
                parse_supported_groups((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_EC_POINT_FORMATS:
                parse_point_formats((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_SRP:
                break;

            case EXT_SIGNATURE_ALGORITHMS:
                parse_signature_algorithms((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_USE_SRTP:
                break;

            case EXT_HEARTBEAT:
                break;

            case EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                parse_alpns((char *) buffer, pos, extension_data_length, json);
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

            case OLD_EXT_NEXT_PROTOCOL_NEGOTIATION:
                break;

            case OLD_EXT_CHANNEL_ID:
                break;

            case EXT_CHANNEL_ID:
                break;

            case EXT_RENEGOTIATION_INFO:
                break;

            case EXT_SUPPORTED_VERSIONS:
                parse_ch_supported_versions((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_KEY_SHARE:
                parse_ch_key_share((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_PSK_KEY_EXCHANGE_MODES:
                parse_ch_psk_key_exchange_modes((char *) buffer, pos, extension_data_length, json);
                break;
        }
        if (json)
            printf("}}");
        i++;
        pos += extension_data_length;
    }
    if (json)
    {
        if (i != 0)
            printf("\n]");
    }

    return 0;
}

struct hadnshake_server_hello *process_handshake_server_hello(void *data, int offset, int record_length, int handshake_length, int json, int raw)
{
    unsigned char *buffer = data;
    unsigned tls_version = 0;
    unsigned session_id_length = 0;
    unsigned cipher_suites_pos = 0;
    unsigned pos = offset;
    unsigned i = 0;

    unsigned compression_methods_pos = 0;
    unsigned compression_methods_length = 0;
    unsigned compression_methods_start = 0;
    unsigned compression_methods_end = 0;

    unsigned extensions_pos = 0;
    unsigned extensions_length = 0;
    unsigned extensions_start = 0;
    unsigned extensions_end = 0;
    int hello_retry_request = 1;

    tls_version = read_uint(buffer, offset + HANDSHAKE_CH_VERSION_OFFSET, HANDSHAKE_CH_VERSION_LEN);

    if (json)
    {
        printf("\"random\": \"");
        print_hex_blob(buffer, offset + HANDSHAKE_CH_RANDOM_OFFSET, HANDSHAKE_CH_RANDOM_LEN, 0, 0, json);
        printf("\"");
    }
    else
    {
        printf("\nRandom: ");
        print_hex_blob(buffer, offset + HANDSHAKE_CH_RANDOM_OFFSET, HANDSHAKE_CH_RANDOM_LEN, 0, 0, json);
        printf("\n");
    }

    for(i = 0; i < HANDSHAKE_CH_RANDOM_LEN; i++)
    {
        if ((char)buffer[offset + HANDSHAKE_CH_RANDOM_OFFSET + i] != TLS13_HELLO_RETRY_REQUEST_MAGIC[i])
        {
            hello_retry_request = 0;
            break;
        }
    }

    if (hello_retry_request)
    {
        if (json)
            printf(",\n\"hello_retry_request\": \"1\"");
        else
            printf("Hello Retry Request Found\n");
    }
    else
    {
        if (json)
            printf(",\n\"hello_retry_request\": \"0\"");
    }

    session_id_length = read_uint(buffer, offset + HANDSHAKE_CH_SESSION_ID_LENGTH_OFFSET, HANDSHAKE_CH_SESSION_ID_LENGTH_LEN);
    if (session_id_length)
    {
        if (json)
        {
            printf(",\n\"session_id\": \"");
            print_hex_blob(buffer, offset + HANDSHAKE_CH_SESSION_ID_OFFSET, session_id_length, 0, 0, json);
            printf("\"");
        }
        else
        {
            printf("Session ID length: %d\n", session_id_length);
            printf("Session ID: ");
            print_hex_blob(buffer, offset + HANDSHAKE_CH_SESSION_ID_OFFSET, session_id_length, 0, 0, json);
            printf("\n");
        }
    }
    else
    {
        if (!json)
            printf("No session ID specified.\n");
    }

    cipher_suites_pos = offset + HANDSHAKE_CH_SESSION_ID_OFFSET + session_id_length;

    if (json)
        printf(",\n\"tls_version\": \"");
    else
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
    if (json)
        printf("\",");
    else
        printf("\n");

    pos = offset + HANDSHAKE_CH_SESSION_ID_OFFSET + session_id_length;

    if (json)
        printf("\n\"cipher\": ");
    else
        printf("Cipher suite:");

    unsigned cipher = read_uint(buffer, pos, HANDSHAKE_CH_CIPHER_LEN);
    /* printf("%#04x ", cipher); */
    char *name = cipher_name(cipher);
    if(!name)
    {
        fprintf(stderr, "WARNING: Unknown cipher suite %#4x!\n", cipher);
        if (json)
            printf("\t{\"name\": \"unknown\", \"id\": \"%#.4x\"}", cipher);
    }
    else
    {
        if (json)
            printf("{\"name\": \"%s\", \"id\": \"%#.4x\"}", name, cipher);
        else
            printf("\t%s (%#.4x)\n", name, cipher);
    }

    pos = pos + HANDSHAKE_CH_CIPHER_LEN;

    compression_methods_pos = pos;
    if (json)
        printf(",\n\"compression_method\": ");
    else
        printf("Compression method:\n");

    unsigned compression = read_uint(buffer, pos, HANDSHAKE_CH_COMP_METHOD_LEN);
    switch (compression)
    {
        default:
            fprintf(stderr, "WARNING: Unknown compression method %#4x!\n", compression);
            if (json)
                printf("\"UNKNOWN (%#.4x)\"", compression);
            break;
        case COMP_NULL:
            if (json)
                printf("\"NULL\"");
            else
                printf("\tNo compression (NULL).\n");
            break;
        case COMP_DEFLATE:
            if (json)
                printf("\"DEFLATE\"");
            else
                printf("\tDEFLATE\n");
            break;
        case COMP_LZS:
            if (json)
                printf("\"LZS\"");
            else
                printf("\tLZS\n");
            break;
    }

    pos = pos + HANDSHAKE_CH_COMP_METHOD_LEN;

    extensions_pos = pos;

    if (pos - offset == record_length)
    {
        return NULL;
    }

    if (pos - offset + HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN > record_length)
    {
        fprintf(stderr, "No extensions.\n");
        extensions_length = 0;
    }
    else
        extensions_length = read_uint(buffer, extensions_pos, HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN);

    extensions_start = extensions_pos + HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN;
    extensions_end = extensions_start + extensions_length;

    if (extensions_end - offset != record_length)
    {
        fprintf(stderr, "WARNING! Extensions end doesn't match buffer end (pos: %u, extensions_end: %u, record_length: %u, handshake_length: %u).\n", pos, extensions_end, record_length, handshake_length);
        extensions_length = 0;
        extensions_start = 0;
        extensions_end = 0;
        if (json)
            printf(", \"trailing_data\": \"");
        else
            printf("Trailing data: \n");

        print_hex_blob(buffer, extensions_pos, (record_length - (extensions_pos + 1)), 0, 0, json);

        if (json)
            printf("\"\n");
    }

    if (!json)
    {
        printf("Extensions length: %d\n", extensions_length);
    }

    if (extensions_length)
    {
        if (json)
            printf(",\n\"extensions\": [\n");
        else
            printf("Extensions:\n");
    }

    i = 0;
    for (pos = extensions_start; pos < extensions_end; )
    {
        unsigned extension_id = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_ID_LEN);
        pos += HANDSHAKE_CH_EXTENSION_ID_LEN;
        unsigned extension_data_length = read_uint(buffer, pos, HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN);
        pos += HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN;
        /* printf("%#4x ", cipher); */
        const char *name = extension_name(extension_id);

        if (json)
        {
            if (i != 0)
                printf(",\n");
            printf("\t{ \"name\": \"%s\", \"id\": \"%#.4x\", \"length\": %u", name, extension_id, extension_data_length);
            if (raw)
            {
                printf(", \"raw\": \"");
                print_hex_blob((char *)buffer, pos, extension_data_length, 0, 0, json);
                printf("\"");
            }
            printf(", \"data\": {");
        }
        else
            printf("\t%s (id = %u len = %u))\n", name, extension_id, extension_data_length);

        switch (extension_id)
        {
            default:
                if (name == NULL)
                    fprintf(stderr, "WARNING: Unknown extension %#4x!\n", extension_id);
                break;

            case EXT_SERVER_NAME:
                parse_sni((char *)buffer, pos, extension_data_length, json);
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
                parse_supported_groups((char *)buffer, pos, extension_data_length, json);
                break;

            case EXT_EC_POINT_FORMATS:
                parse_point_formats((char *)buffer, pos, extension_data_length, json);
                break;

            case EXT_SRP:
                break;

            case EXT_SIGNATURE_ALGORITHMS:
                parse_signature_algorithms((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_USE_SRTP:
                break;

            case EXT_HEARTBEAT:
                break;

            case EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                parse_alpns((char *)buffer, pos, extension_data_length, json);
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

            case OLD_EXT_NEXT_PROTOCOL_NEGOTIATION:
                break;

            case OLD_EXT_CHANNEL_ID:
                break;

            case EXT_CHANNEL_ID:
                break;

            case EXT_RENEGOTIATION_INFO:
                break;

            case EXT_SUPPORTED_VERSIONS:
                parse_sh_supported_versions((char *) buffer, pos, extension_data_length, json);
                break;

            case EXT_KEY_SHARE:
                parse_sh_key_share((char *) buffer, pos, extension_data_length, json);
                break;
        }
        if (json)
            printf("}}");
        i++;
        pos += extension_data_length;
    }

    if (json)
    {
        if (i != 0)
            printf("\n]");
    }
    return 0;
}
