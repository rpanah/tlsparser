#include "tls_constants.h"
#include "tls_extensions.h"
#include "ec_extensions.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

const char *extension_name(unsigned code)
{
    switch (code)
    {
        default:
            return "unknown";
            break;

        case EXT_SERVER_NAME:
            return "SERVER_NAME";
            break;

        case EXT_MAX_FRAGMENT_LENGTH:
            return "MAX_FRAGMENT_LENGTH";
            break;

        case EXT_CLIENT_CERTIFICATE_URL:
            return "CLIENT_CERTIFICATE_URL";
            break;

        case EXT_TRUSTED_CA_KEYS:
            return "TRUSTED_CA_KEYS";
            break;

        case EXT_TRUNCATED_HMAC:
            return "TRUNCATED_HMAC";
            break;

        case EXT_STATUS_REQUEST:
            return "STATUS_REQUEST";
            break;

        case EXT_USER_MAPPING:
            return "USER_MAPPING";
            break;

        case EXT_CLIENT_AUTHZ:
            return "CLIENT_AUTHZ";
            break;

        case EXT_SERVER_AUTHZ:
            return "SERVER_AUTHZ";
            break;

        case EXT_CERT_TYPE:
            return "CERT_TYPE";
            break;

        case EXT_SUPPORTED_GROUPS:
            return "SUPPORTED_GROUPS";
            break;

        case EXT_EC_POINT_FORMATS:
            return "EC_POINT_FORMATS";
            break;

        case EXT_SRP:
            return "SRP";
            break;

        case EXT_SIGNATURE_ALGORITHMS:
            return "SIGNATURE_ALGORITHMS";
            break;

        case EXT_USE_SRTP:
            return "USE_SRTP";
            break;

        case EXT_HEARTBEAT:
            return "HEARTBEAT";
            break;

        case EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
            return "APPLICATION_LAYER_PROTOCOL_NEGOTIATION";
            break;

        case EXT_STATUS_REQUEST_V2:
            return "STATUS_REQUEST_V2";
            break;

        case EXT_SIGNED_CERTIFICATE_TIMESTAMP:
            return "SIGNED_CERTIFICATE_TIMESTAMP";
            break;

        case EXT_CLIENT_CERTIFICATE_TYPE:
            return "CLIENT_CERTIFICATE_TYPE";
            break;

        case EXT_SERVER_CERTIFICATE_TYPE:
            return "SERVER_CERTIFICATE_TYPE";
            break;

        case EXT_PADDING:
            return "PADDING";
            break;

        case EXT_ENCRYPT_THEN_MAC:
            return "ENCRYPT_THEN_MAC";
            break;

        case EXT_EXTENDED_MASTER_SECRET:
            return "EXTENDED_MASTER_SECRET";
            break;

        case EXT_TOKEN_BINDING:
            return "TOKEN_BINDING";
            break;

        case EXT_CACHED_INFO:
            return "CACHED_INFO";
            break;

        case EXT_SESSION_TICKET_TLS:
            return "SESSION_TICKET_TLS";
            break;

        case OLD_EXT_NEXT_PROTOCOL_NEGOTIATION:
            return "NEXT_PROTOCOL_NEGOTIATION";
            break;

        case OLD_EXT_CHANNEL_ID:
            return "OLD_CHANNEL_ID";
            break;

        case EXT_CHANNEL_ID:
            return "CHANNEL_ID";
            break;

        case EXT_RENEGOTIATION_INFO:
            return "RENEGOTIATION_INFO";
            break;

        case EXT_SHORT_HEADER:
            return "SHORT_HEADER";
            break;
    }
}

struct tls_sni *parse_sni(char *data, unsigned offset, unsigned length, int json)
{
    unsigned i = offset;
    unsigned j = 0;
    unsigned name_list_length = read_uint(data, offset, HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN);
    unsigned name_index = 0;
    unsigned name_type;
    unsigned name_length;

    i += HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN;

    if (json)
        printf("\"sni_list\": [");

    for (; i < offset + length;)
    {
        if (json)
        {
            if (name_index != 0)
                printf(", ");
            printf("{");
        }

        name_type = read_uint(data, i, SNI_TYPE_LENGTH);
        i += SNI_TYPE_LENGTH;

        name_length = read_uint(data, i, SNI_NAME_LENGTH_LEN);
        i+= SNI_NAME_LENGTH_LEN;

        if (json)
            printf("\"sni_type_name\": \"%s\", \"name_length\": %d, \"name\": \"", sni_type_name(name_type), name_length);
        else
            printf("\t\t[%d]: (type: %s, length: %u) ", name_index, sni_type_name(name_type), name_length);

        for (j = 0; j < name_length; j++, i++)
            printf("%c", data[i]);

        name_index++;
        if (json)
            printf("\"}");
        else
            printf("\n");
    }
    if (json)
        printf("]");
    return 0;
}

const char *sni_type_name(unsigned code)
{
    switch (code)
    {
        default:
            return "SNI_UNKNOWN_TYPE";
            break;

        case SNI_TYPE_HOSTNAME:
            return "SNI_HOSTNAME";
            break;
    }
}
