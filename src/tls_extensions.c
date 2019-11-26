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

        case EXT_COMPRESS_CERTIFICATE:
            return "COMPRESS_CERTIFICATE";
            break;

        case EXT_SESSION_TICKET_TLS:
            return "SESSION_TICKET_TLS";
            break;

        case  EXT_EXTENDED_RANDOM:
            return "EXTENDED_RANDOM";
            break;

        case  EXT_PRE_SHARED_KEY:
            return "PRE_SHARED_KEY";
            break;

        case  EXT_EARLY_DATA:
            return "EARLY_DATA";
            break;

        case  EXT_SUPPORTED_VERSIONS:
            return "SUPPORTED_VERSIONS";
            break;

        case  EXT_COOKIE:
            return "COOKIE";
            break;

        case  EXT_PSK_KEY_EXCHANGE_MODES:
            return "PSK_KEY_EXCHANGE_MODES";
            break;

        case  EXT_TICKET_EARLY_DATA_INFO:
            return "TICKET_EARLY_DATA_INFO";
            break;

        case  EXT_CERTIFICATE_AUTHORITIES:
            return "CERTIFICATE_AUTHORITIES";
            break;

        case  EXT_OID_FILTERS:
            return "OID_FILTERS";
            break;

        case  EXT_POST_HANDSHAKE_AUTH:
            return "POST_HANDSHAKE_AUTH";
            break;

        case  EXT_SIGNATURE_ALGORITHMS_CERT:
            return "SIGNATURE_ALGORITHMS_CERT";
            break;

        case  EXT_KEY_SHARE:
            return "KEY_SHARE";
            break;

        case OLD_EXT_NEXT_PROTOCOL_NEGOTIATION:
            return "NEXT_PROTOCOL_NEGOTIATION";
            break;

        case EXT_ORIGIN_BOUND_CERTIFICATES:
            return "ORIGIN_BOUND_CERTIFICATES";
            break;

        case EXT_ENCRYPTED_CLIENT_CERTIFICATES:
            return "ENCRYPTED_CLIENT_CERTIFICATES";
            break;

        case EXT_TOKEN_BINDING_TEST:
            return "TOKEN_BINDING_TEST";
            break;

        case OLD_EXT_CHANNEL_ID:
            return "OLD_CHANNEL_ID";
            break;

        case EXT_CHANNEL_ID:
            return "CHANNEL_ID";
            break;

        case EXT_NEW_PADDING:
            return "NEW_PADDING";
            break;

        case EXT_RENEGOTIATION_INFO:
            return "RENEGOTIATION_INFO";
            break;

        case EXT_TLS_DRAFT:
            return "TLS_DRAFT";
            break;

        case EXT_SHORT_HEADER:
            return "SHORT_HEADER";
            break;

        case 0x0a0a:
        case 0x1a1a:
        case 0x2a2a:
        case 0x3a3a:
        case 0x4a4a:
        case 0x5a5a:
        case 0x6a6a:
        case 0x7a7a:
        case 0x8a8a:
        case 0x9a9a:
        case 0xaaaa:
        case 0xbaba:
        case 0xcaca:
        case 0xdada:
        case 0xeaea:
        case 0xfafa:
            return "GOOGLE_GREASE";
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

void parse_ch_psk_key_exchange_modes(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned psk_key_exchange_modes_length = read_uint(data, pos, PSK_MODES_LENGTH);
    unsigned mode_code = 0;
    const char *name = NULL;
    int i = 0;
    pos += PSK_MODES_LENGTH;
    if (json)
        printf("\"psk_key_exchange_mode_list\": [");
    for(; pos < offset + length; pos += PSK_MODES_LENGTH)
    {
        if (json && i != 0)
            printf(", ");
        mode_code = read_uint(data, pos, PSK_MODES_LENGTH);
        name = psk_key_exchange_mode_name(mode_code);

        if (name == NULL)
        {
            name = "unknown";
            fprintf(stderr, "WARNING! Unknown PSK key exchange mode code (%#.4x)\n", mode_code);
        }
        if (json)
        {
            printf("{\"name\": \"%s\", \"id\": \"%#.4x\"}", name, mode_code);
        }
        else
        {
            printf("\t\tpsk key exchange mode: %s (id = %#.4x)\n", name, mode_code);
        }
        i++;
    }
    if(json)
        printf("]");
}

const char *psk_key_exchange_mode_name(unsigned code)
{
    switch (code)
    {
        default:
            return "UNKNOWN_PSK_EXCHANGE_MODE";
            break;
        case TLSEXT_PSK_KE:
            return "PSK_KE";
            break;
        case TLSEXT_PSK_DHE_KE:
            return "PSK_DHE_KE";
            break;
    }
}

void parse_ch_key_share(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned key_share_length = read_uint(data, pos, KEY_SHARE_LENGTH);
    unsigned group_code = 0;
    unsigned key_exchange_length = 0;
    const char *name = NULL;
    int i = 0;
    pos += KEY_SHARE_LENGTH;
    if (json)
        printf("\"key_share_list\": [");
    for(; pos < offset + length; pos += key_exchange_length)
    {
        if (json && i != 0)
            printf(", ");
        group_code = read_uint(data, pos, KEY_SHARE_GROUP_CODE_LENGTH);
        name = key_share_group_name(group_code);
        pos += KEY_SHARE_GROUP_CODE_LENGTH;
        key_exchange_length = read_uint(data, pos, KEY_SHARE_KEY_EXCHANGE_LENGTH);
        pos += KEY_SHARE_KEY_EXCHANGE_LENGTH;

        if (name == NULL)
        {
            name = "unknown";
            fprintf(stderr, "WARNING! Unknown group code (%#.4x)\n", group_code);
        }
        if (json)
        {
            printf("{\"name\": \"%s\", \"id\": \"%#.4x\", \"key_exchange_length\": \"%d\",", name, group_code, key_exchange_length);
            printf("\"key_exchange\": \"");
            print_hex_blob(data, pos, key_exchange_length, 0, 0, json);
            printf("\"}");
        }
        else
        {
            printf("\t\tgroup: %s (id = %#.4x) key_exchange_length: %d\n", name, group_code, key_exchange_length);
            printf("\t\t\tkey_exchange: ");
            print_hex_blob(data, pos, key_exchange_length, 0, 0, 0);
            printf("\n");
        }
        i++;
    }
    if(json)
        printf("]");
}

void parse_sh_key_share(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned group_code = 0;
    unsigned key_exchange_length = 0;
    const char *name = NULL;
    int i = 0;
    if (json)
      printf("\"key_share\": ");
    group_code = read_uint(data, pos, KEY_SHARE_GROUP_CODE_LENGTH);
    name = key_share_group_name(group_code);
    pos += KEY_SHARE_GROUP_CODE_LENGTH;
    key_exchange_length = read_uint(data, pos, KEY_SHARE_KEY_EXCHANGE_LENGTH);
    pos += KEY_SHARE_KEY_EXCHANGE_LENGTH;
    if (name == NULL)
    {
        name = "unknown";
        fprintf(stderr, "WARNING! Unknown group code (%#.4x)\n", group_code);
    }
    if (json)
    {
        printf("{\"name\": \"%s\", \"id\": \"%#.4x\", \"key_exchange_length\": \"%d\",", name, group_code, key_exchange_length);
        printf("\"key_exchange\": \"");
        print_hex_blob(data, pos, key_exchange_length, 0, 0, json);
        printf("\"}");
    }
    else
    {
        printf("\t\tgroup: %s (id = %#.4x) key_exchange_length: %d\n", name, group_code, key_exchange_length);
        printf("\t\t\tkey_exchange: ");
        print_hex_blob(data, pos, key_exchange_length, 0, 0, 0);
        printf("\n");
    }
}

const char *key_share_group_name(unsigned code)
{
    switch (code)
    {
        default:
            return "KEY_SHARE_UNKNOWN_GROUP";
            break;
        case TLSEXT_GROUP_sect163k1:
            return "sect163k1 (K-163)";
            break;
        case TLSEXT_GROUP_sect163r1:
            return "sect163r1";
            break;
        case TLSEXT_GROUP_sect163r2:
            return "sect163r2 (B-163)";
            break;
        case TLSEXT_GROUP_sect193r1:
            return "sect193r1";
            break;
        case TLSEXT_GROUP_sect193r2:
            return "sect193r2";
            break;
        case TLSEXT_GROUP_sect233k1:
            return "sect233k1 (K-233)";
            break;
        case TLSEXT_GROUP_sect233r1:
            return "sect233r1 (B-233)";
            break;
        case TLSEXT_GROUP_sect239k1:
            return "sect239k1";
            break;
        case TLSEXT_GROUP_sect283k1:
            return "sect283k1 (K-283)";
            break;
        case TLSEXT_GROUP_sect283r1:
            return "sect283r1 (B-283)";
            break;
        case TLSEXT_GROUP_sect409k1:
            return "sect409k1 (K-409)";
            break;
        case TLSEXT_GROUP_sect409r1:
            return "sect409r1 (B-409)";
            break;
        case TLSEXT_GROUP_sect571k1:
            return "sect571k1 (K-571)";
            break;
        case TLSEXT_GROUP_sect571r1:
            return "sect571r1 (B-571)";
            break;
        case TLSEXT_GROUP_secp160k1:
            return "secp160k1";
            break;
        case TLSEXT_GROUP_secp160r1:
            return "secp160r1";
            break;
        case TLSEXT_GROUP_secp160r2:
            return "secp160r2";
            break;
        case TLSEXT_GROUP_secp192k1:
            return "secp192k1";
            break;
        case TLSEXT_GROUP_secp192r1:
            return "secp192r1 (P-192)";
            break;
        case TLSEXT_GROUP_secp224k1:
            return "secp224k1";
            break;
        case TLSEXT_GROUP_secp224r1:
            return "secp224r1 (P-224)";
            break;
        case TLSEXT_GROUP_secp256k1:
            return "secp256k1";
            break;
        case TLSEXT_GROUP_secp256r1:
            return "secp256r1 (P-256)";
            break;
        case TLSEXT_GROUP_secp384r1:
            return "secp384r1 (P-384)";
            break;
        case TLSEXT_GROUP_secp521r1:
            return "secp521r1 (P-521)";
            break;
        case TLSEXT_GROUP_brainpoolP256r1:
            return "brainpoolP256r1";
            break;
        case TLSEXT_GROUP_brainpoolP384r1:
            return "brainpoolP384r1";
            break;
        case TLSEXT_GROUP_brainpoolP512r1:
            return "brainpoolP512r1";
            break;
        case TLSEXT_GROUP_ecdh_x25519:
            return "ecdh_x25519";
            break;
        case TLSEXT_GROUP_ffdhe2048:
            return "ffdhe2048";
            break;
        case TLSEXT_GROUP_ffdhe3072:
            return "ffdhe3072";
            break;
        case TLSEXT_GROUP_ffdhe4096:
            return "ffdhe4096";
            break;
        case TLSEXT_GROUP_ffdhe6144:
            return "ffdhe6144";
            break;
        case TLSEXT_GROUP_ffdhe8192:
            return "ffdhe8192";
            break;
        case TLSEXT_GROUP_arbitrary_explicit_prime_curves:
            return "arbitrary_explicit_prime_curves";
            break;
        case TLSEXT_GROUP_arbitrary_explicit_char2_curves:
            return "arbitrary_explicit_char2_curves";
            break;
        case 0x0a0a:
        case 0x1a1a:
        case 0x2a2a:
        case 0x3a3a:
        case 0x4a4a:
        case 0x5a5a:
        case 0x6a6a:
        case 0x7a7a:
        case 0x8a8a:
        case 0x9a9a:
        case 0xaaaa:
        case 0xbaba:
        case 0xcaca:
        case 0xdada:
        case 0xeaea:
        case 0xfafa:
            return "GOOGLE_GREASE";
    }
}

void parse_ch_supported_versions(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned versions_length = read_uint(data, pos, VERSION_SET_LENGTH);
    unsigned version_code;
    const char *name = NULL;
    int i = 0;
    pos += VERSION_SET_LENGTH;

    if (json)
        printf("\"version_list\": [");
    for(; pos < offset + length; pos += VERSION_LENGTH)
    {
        if (json && i != 0)
            printf(", ");
        version_code = read_uint(data, pos, VERSION_LENGTH);
        name = version_name(version_code);
        if (name == NULL)
        {
            name = "unknown";
            fprintf(stderr, "WARNING! Unknown version (%#.4x)\n", version_code);
        }
        if (json)
            printf("{\"name\": \"%s\", \"id\": \"%#.4x\"}", name, version_code);
        else
            printf("\t\t%s\n", name);
        i++;
    }
    if(json)
        printf("]");
}

void parse_sh_supported_versions(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned version_code;
    const char *name = NULL;

    if (json)
        printf("\"version\": ");
    version_code = read_uint(data, pos, VERSION_LENGTH);
    name = version_name(version_code);
    if (name == NULL)
    {
        name = "unknown";
        fprintf(stderr, "WARNING! Unknown version (%#.4x)\n", version_code);
    }
    if (json)
        printf("{\"name\": \"%s\", \"id\": \"%#.4x\"}", name, version_code);
    else
        printf("\t\t%s\n", name);
}

const char *version_name(unsigned code) {
    switch (code)
    {
        default:
            return NULL;
            break;
        case SSL_3_0:
            return "SSL_3_0";
            break;
        case TLS_1_0:
            return "TLS_1_0";
            break;
        case TLS_1_1:
            return "TLS_1_1";
            break;
        case TLS_1_2:
            return "TLS_1_2";
            break;
        case TLS_1_3:
            return "TLS_1_3";
            break;
        case TLS_1_3_DRAFT0:
            return "TLS_1_3_DRAFT0";
            break;
        case TLS_1_3_DRAFT1:
            return "TLS_1_3_DRAFT1";
            break;
        case TLS_1_3_DRAFT2:
            return "TLS_1_3_DRAFT2";
            break;
        case TLS_1_3_DRAFT3:
            return "TLS_1_3_DRAFT3";
            break;
        case TLS_1_3_DRAFT4:
            return "TLS_1_3_DRAFT4";
            break;
        case TLS_1_3_DRAFT5:
            return "TLS_1_3_DRAFT5";
            break;
        case TLS_1_3_DRAFT6:
            return "TLS_1_3_DRAFT6";
            break;
        case TLS_1_3_DRAFT7:
            return "TLS_1_3_DRAFT7";
            break;
        case TLS_1_3_DRAFT8:
            return "TLS_1_3_DRAFT8";
            break;
        case TLS_1_3_DRAFT9:
            return "TLS_1_3_DRAFT9";
            break;
        case TLS_1_3_DRAFT10:
            return "TLS_1_3_DRAFT10";
            break;
        case TLS_1_3_DRAFT11:
            return "TLS_1_3_DRAFT11";
            break;
        case TLS_1_3_DRAFT12:
            return "TLS_1_3_DRAFT12";
            break;
        case TLS_1_3_DRAFT13:
            return "TLS_1_3_DRAFT13";
            break;
        case TLS_1_3_DRAFT14:
            return "TLS_1_3_DRAFT14";
            break;
        case TLS_1_3_DRAFT15:
            return "TLS_1_3_DRAFT15";
            break;
        case TLS_1_3_DRAFT16:
            return "TLS_1_3_DRAFT16";
            break;
        case TLS_1_3_DRAFT17:
            return "TLS_1_3_DRAFT17";
            break;
        case TLS_1_3_DRAFT18:
            return "TLS_1_3_DRAFT18";
            break;
        case TLS_1_3_DRAFT19:
            return "TLS_1_3_DRAFT19";
            break;
        case TLS_1_3_DRAFT20:
            return "TLS_1_3_DRAFT20";
            break;
        case TLS_1_3_DRAFT21:
            return "TLS_1_3_DRAFT21";
            break;
        case TLS_1_3_DRAFT22:
            return "TLS_1_3_DRAFT22";
            break;
        case TLS_1_3_DRAFT23:
            return "TLS_1_3_DRAFT23";
            break;
        case TLS_1_3_DRAFT24:
            return "TLS_1_3_DRAFT24";
            break;
        case TLS_1_3_DRAFT25:
            return "TLS_1_3_DRAFT25";
            break;
        case TLS_1_3_DRAFT26:
            return "TLS_1_3_DRAFT26";
            break;
        case TLS_1_3_DRAFT27:
            return "TLS_1_3_DRAFT27";
            break;
        case TLS_1_3_DRAFT28:
            return "TLS_1_3_DRAFT28";
            break;
        case TLS_1_3_FB22:
            return "TLS_1_3_FB22";
            break;
        case TLS_1_3_FB23:
            return "TLS_1_3_FB23";
            break;
        case TLS_1_3_FB26:
            return "TLS_1_3_FB26";
            break;
        case TLS_1_3_FB40:
            return "TLS_1_3_FB40";
            break;
        case DTLS_1_0:
            return "DTLS_1_0";
            break;
        case DTLS_1_1:
            return "DTLS_1_1";
            break;
        case TLS_1_3_7E01:
            return "TLS_1_3_7E01";
            break;
        case TLS_1_3_7E02:
            return "TLS_1_3_7E02";
            break;
        case 0x0a0a:
        case 0x1a1a:
        case 0x2a2a:
        case 0x3a3a:
        case 0x4a4a:
        case 0x5a5a:
        case 0x6a6a:
        case 0x7a7a:
        case 0x8a8a:
        case 0x9a9a:
        case 0xaaaa:
        case 0xbaba:
        case 0xcaca:
        case 0xdada:
        case 0xeaea:
        case 0xfafa:
            return "GOOGLE_GREASE";
    }
}

void parse_signature_algorithms(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned sigalgs_length = read_uint(data, pos, SIGALG_SET_LENGTH);
    unsigned sigalg_code;
    const char *name = NULL;
    int i = 0;
    pos += SIGALG_SET_LENGTH;

    if (json)
        printf("\"sigalg_list\": [");
    for(; pos < offset + length; pos += SIGALG_LENGTH)
    {
        if (json && i != 0)
            printf(", ");
        sigalg_code = read_uint(data, pos, SIGALG_LENGTH);
        name = sigalg_name(sigalg_code);
        if (name == NULL)
        {
            name = "unknown";
            fprintf(stderr, "WARNING! Unknown signature algorithm (%#.4x)\n", sigalg_code);
        }
        if (json)
            printf("{\"name\": \"%s\", \"id\": \"%#.4x\"}", name, sigalg_code);
        else
            printf("\t\t%s\n", name);
        i++;
    }
    if(json)
        printf("]");
}

const char *sigalg_name(unsigned code) {
    switch (code)
    {
        default:
            return NULL;
            break;
        case TLSEXT_SIGALG_ECDSA_SECP224R1_SHA224:
            return "ECDSA_SECP224R1_SHA224";
            break;

        case TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256:
            return "ECDSA_SECP256R1_SHA256";
            break;

        case TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384:
            return "ECDSA_SECP384R1_SHA384";
            break;

        case TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512:
            return "ECDSA_SECP521R1_SHA512";
            break;

        case TLSEXT_SIGALG_ECDSA_MD5:
            return "ECDSA_MD5";
            break;

        case TLSEXT_SIGALG_ECDSA_SHA1:
            return "ECDSA_SHA1";
            break;

        case  TLSEXT_SIGALG_TLS13_RSA_PSS_SHA256:
            return "TLS13_RSA_PSS_SHA256";
            break;

        case  TLSEXT_SIGALG_TLS13_RSA_PSS_SHA384:
            return "TLS13_RSA_PSS_SHA384";
            break;

        case TLSEXT_SIGALG_TLS13_RSA_PSS_SHA512:
            return "TLS13_RSA_PSS_SHA512";
            break;

        case TLSEXT_SIGALG_TLS13_ED25519:
            return "TLS13_ED25519";
            break;

        case TLSEXT_SIGALG_TLS13_ED448:
            return "TLS13_ED448";
            break;

        case TLSEXT_SIGALG_RSA_PSS_PSS_SHA256:
            return "RSA_PSS_PSS_SHA256";
            break;

        case TLSEXT_SIGALG_RSA_PSS_PSS_SHA384:
            return "RSA_PSS_PSS_SHA384";
            break;

        case TLSEXT_SIGALG_RSA_PSS_PSS_SHA512:
            return "RSA_PSS_PSS_SHA512";
            break;

        case  TLSEXT_SIGALG_RSA_PSS_SHA256:
            return "RSA_PSS_SHA256";
            break;

        case  TLSEXT_SIGALG_RSA_PSS_SHA384:
            return "RSA_PSS_SHA384";
            break;

        case TLSEXT_SIGALG_RSA_PSS_SHA512:
            return "RSA_PSS_SHA512";
            break;

        case TLSEXT_SIGALG_ED25519:
            return "ED25519";
            break;

        case TLSEXT_SIGALG_ED448:
            return "ED448";
            break;

        case TLSEXT_SIGALG_RSA_PKCS1_SHA224:
            return "RSA_PKCS1_SHA224";
            break;

        case TLSEXT_SIGALG_RSA_PKCS1_SHA256:
            return "RSA_PKCS1_SHA256";
            break;

        case TLSEXT_SIGALG_RSA_PKCS1_SHA384:
            return "RSA_PKCS1_SHA384";
            break;

        case  TLSEXT_SIGALG_RSA_PKCS1_SHA512:
            return "RSA_PKCS1_SHA512";
            break;

        case  TLSEXT_SIGALG_RSA_PKCS1_MD5:
            return "RSA_PKCS1_MD5";
            break;

        case  TLSEXT_SIGALG_RSA_PKCS1_SHA1:
            return "RSA_PKCS1_SHA1";
            break;

        case  TLSEXT_SIGALG_DSA_SHA224:
            return "DSA_SHA224";
            break;

        case  TLSEXT_SIGALG_DSA_SHA256:
            return "DSA_SHA256";
            break;

        case  TLSEXT_SIGALG_DSA_SHA384:
            return "DSA_SHA384";
            break;

        case  TLSEXT_SIGALG_DSA_SHA512:
            return "DSA_SHA512";
            break;

        case  TLSEXT_SIGALG_DSA_SHA1:
            return "DSA_SHA1";
            break;

        case  TLSEXT_SIGALG_GOSTR34102012_256_GOSTR34112012_256:
            return "GOSTR34102012_256_GOSTR34112012_256";
            break;

        case  TLSEXT_SIGALG_GOSTR34102012_512_GOSTR34112012_512:
            return "GOSTR34102012_512_GOSTR34112012_512";
            break;

        case  TLSEXT_SIGALG_GOSTR34102001_GOSTR3411:
            return "GOSTR34102001_GOSTR3411";
            break;
    }
}
