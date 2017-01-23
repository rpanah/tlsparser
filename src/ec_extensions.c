#include "ec_extensions.h"
#include "utils.h"
#include <stdio.h>

void parse_supported_groups(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned curves_length = read_uint(data, pos, EC_CURVE_SET_LENGTH);
    unsigned curve_code;
    int i = 0;
    pos += EC_CURVE_SET_LENGTH;

    if (json)
        printf("\"supported_group_list\": [");
    for(; pos < offset + length; pos += EC_CURVE_LENGTH)
    {
        if (json && i != 0)
            printf(", ");
        curve_code = read_uint(data, pos, EC_CURVE_LENGTH);
        if (json)
            printf("{\"name\": \"%s\", \"code\": \"%#.04x\"}", ec_named_curve_name(curve_code), curve_code);
        else
            printf("\t\t%s\n", ec_named_curve_name(curve_code));
        i++;
    }
    if (json)
        printf("]");
}

const char *ec_named_curve_name(unsigned code)
{
    switch (code)
    {
        default:
            return "RESERVED";
            break;

        case EC_NAMED_CURVE_SECT163K1:
            return "EC_NAMED_CURVE_SECT163K1";
            break;
        case EC_NAMED_CURVE_SECT163R1:
            return "EC_NAMED_CURVE_SECT163R1";
            break;
        case EC_NAMED_CURVE_SECT163R2:
            return "EC_NAMED_CURVE_SECT163R2";
            break;
        case EC_NAMED_CURVE_SECT193R1:
            return "EC_NAMED_CURVE_SECT193R1";
            break;
        case EC_NAMED_CURVE_SECT193R2:
            return "EC_NAMED_CURVE_SECT193R2";
            break;
        case EC_NAMED_CURVE_SECT233K1:
            return "EC_NAMED_CURVE_SECT233K1";
            break;
        case EC_NAMED_CURVE_SECT233R1:
            return "EC_NAMED_CURVE_SECT233R1";
            break;
        case EC_NAMED_CURVE_SECT239K1:
            return "EC_NAMED_CURVE_SECT239K1";
            break;
        case EC_NAMED_CURVE_SECT283K1:
            return "EC_NAMED_CURVE_SECT283K1";
            break;
        case EC_NAMED_CURVE_SECT283R1:
            return "EC_NAMED_CURVE_SECT283R1";
            break;
        case EC_NAMED_CURVE_SECT409K1:
            return "EC_NAMED_CURVE_SECT409K1";
            break;
        case EC_NAMED_CURVE_SECT409R1:
            return "EC_NAMED_CURVE_SECT409R1";
            break;
        case EC_NAMED_CURVE_SECT571K1:
            return "EC_NAMED_CURVE_SECT571K1";
            break;
        case EC_NAMED_CURVE_SECT571R1:
            return "EC_NAMED_CURVE_SECT571R1";
            break;
        case EC_NAMED_CURVE_SECP160K1:
            return "EC_NAMED_CURVE_SECP160K1";
            break;
        case EC_NAMED_CURVE_SECP160R1:
            return "EC_NAMED_CURVE_SECP160R1";
            break;
        case EC_NAMED_CURVE_SECP160R2:
            return "EC_NAMED_CURVE_SECP160R2";
            break;
        case EC_NAMED_CURVE_SECP192K1:
            return "EC_NAMED_CURVE_SECP192K1";
            break;
        case EC_NAMED_CURVE_SECP192R1:
            return "EC_NAMED_CURVE_SECP192R1";
            break;
        case EC_NAMED_CURVE_SECP224K1:
            return "EC_NAMED_CURVE_SECP224K1";
            break;
        case EC_NAMED_CURVE_SECP224R1:
            return "EC_NAMED_CURVE_SECP224R1";
            break;
        case EC_NAMED_CURVE_SECP256K1:
            return "EC_NAMED_CURVE_SECP256K1";
            break;
        case EC_NAMED_CURVE_SECP256R1:
            return "EC_NAMED_CURVE_SECP256R1";
            break;
        case EC_NAMED_CURVE_SECP384R1:
            return "EC_NAMED_CURVE_SECP384R1";
            break;
        case EC_NAMED_CURVE_SECP521R1:
            return "EC_NAMED_CURVE_SECP521R1";
            break;
        case EC_NAMED_CURVE_BRAINPOOLP256R1:
            return "EC_NAMED_CURVE_BRAINPOOLP256R1";
            break;
        case EC_NAMED_CURVE_BRAINPOOLP384R1:
            return "EC_NAMED_CURVE_BRAINPOOLP384R1";
            break;
        case EC_NAMED_CURVE_BRAINPOOLP512R1:
            return "EC_NAMED_CURVE_BRAINPOOLP512R1";
            break;
        case EC_NAMED_CURVE_ECDH_X25519:
            return "EC_NAMED_CURVE_ECDH_X25519";
            break;
        case EC_NAMED_CURVE_ECDH_X448:
            return "EC_NAMED_CURVE_ECDH_X448";
            break;
        case EC_NAMED_CURVE_FFDHE2048:
            return "EC_NAMED_CURVE_FFDHE2048";
            break;
        case EC_NAMED_CURVE_FFDHE3072:
            return "EC_NAMED_CURVE_FFDHE3072";
            break;
        case EC_NAMED_CURVE_FFDHE4096:
            return "EC_NAMED_CURVE_FFDHE4096";
            break;
        case EC_NAMED_CURVE_FFDHE6144:
            return "EC_NAMED_CURVE_FFDHE6144";
            break;
        case EC_NAMED_CURVE_FFDHE8192:
            return "EC_NAMED_CURVE_FFDHE8192";
            break;
        case EC_NAMED_CURVE_ARBITRARY_EXPLICIT_PRIME_CURVES:
            return "EC_NAMED_CURVE_ARBITRARY_EXPLICIT_PRIME_CURVES";
            break;
        case EC_NAMED_CURVE_ARBITRARY_EXPLICIT_CHAR2_CURVES:
            return "EC_NAMED_CURVE_ARBITRARY_EXPLICIT_CHAR2_CURVES";
            break;

    }
}

void parse_point_formats(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned point_formats_length = read_uint(data, pos, EC_POINT_FORMAT_SET_LENGTH);
    unsigned point_format_code;
    int i = 0;
    pos += EC_POINT_FORMAT_SET_LENGTH;

    if (json)
        printf("\"point_format_list\": [");
    for(; pos < offset + length; pos += EC_POINT_FORMAT_LENGTH)
    {
        if (json && i != 0)
            printf(", ");
        point_format_code = read_uint(data, pos, EC_POINT_FORMAT_LENGTH);
        if (json)
            printf("{\"name\": \"%s\", \"code\": \"%#.02x\"}", ec_point_format_name(point_format_code), point_format_code);
        else
            printf("\t\t%s\n", ec_point_format_name(point_format_code));
        i++;
    }
    if(json)
        printf("]");
}

const char *ec_point_format_name(unsigned code)
{
    switch (code)
    {
        default:
            return "RESERVED";
            break;

        case EC_POINT_FORMAT_UNCOMPRESSED:
            return "EC_POINT_FORMAT_UNCOMPRESSED";
            break;
        case EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME:
            return "EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME";
            break;
        case EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2:
            return "EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2";
            break;
    }
}