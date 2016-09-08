#include "tls_extensions.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *extension_name(unsigned code)
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

        case EXT_RENEGOTIATION_INFO:
            return "RENEGOTIATION_INFO";
            break;
    }
}

struct tls_sni *parse_sni(char *data, unsigned offset, unsigned length)
{
    char *sni = (char *)(malloc(length + 1));
    unsigned i = 0;
    printf("\t\tSNI: ");
    for (i = offset; i < offset + length; i++)
    {
        sni[i] = data[i];
        printf("%c", data[i]);
    }
    sni[length] = '\0';
    printf("\n");
    return 0;
}
