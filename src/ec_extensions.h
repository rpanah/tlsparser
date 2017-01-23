#ifndef __EC_EXTENSIONS_H
#define __EC_EXTENSIONS_H

void parse_supported_groups(char *data, unsigned offset, unsigned length, int json);
const char *ec_named_curve_name(unsigned code);

void parse_point_formats(char *data, unsigned offset, unsigned length, int json);
const char *ec_point_format_name(unsigned code);

#define EC_CURVE_SET_LENGTH             2
#define EC_CURVE_LENGTH                 2

#define EC_NAMED_CURVE_SECT163K1        1
#define EC_NAMED_CURVE_SECT163R1        2
#define EC_NAMED_CURVE_SECT163R2        3
#define EC_NAMED_CURVE_SECT193R1        4
#define EC_NAMED_CURVE_SECT193R2        5
#define EC_NAMED_CURVE_SECT233K1        6
#define EC_NAMED_CURVE_SECT233R1        7
#define EC_NAMED_CURVE_SECT239K1        8
#define EC_NAMED_CURVE_SECT283K1        9
#define EC_NAMED_CURVE_SECT283R1        10
#define EC_NAMED_CURVE_SECT409K1        11
#define EC_NAMED_CURVE_SECT409R1        12
#define EC_NAMED_CURVE_SECT571K1        13
#define EC_NAMED_CURVE_SECT571R1        14
#define EC_NAMED_CURVE_SECP160K1        15
#define EC_NAMED_CURVE_SECP160R1        16
#define EC_NAMED_CURVE_SECP160R2        17
#define EC_NAMED_CURVE_SECP192K1        18
#define EC_NAMED_CURVE_SECP192R1        19
#define EC_NAMED_CURVE_SECP224K1        20
#define EC_NAMED_CURVE_SECP224R1        21
#define EC_NAMED_CURVE_SECP256K1        22
#define EC_NAMED_CURVE_SECP256R1        23
#define EC_NAMED_CURVE_SECP384R1        24
#define EC_NAMED_CURVE_SECP521R1        25
#define EC_NAMED_CURVE_BRAINPOOLP256R1  26
#define EC_NAMED_CURVE_BRAINPOOLP384R1  27
#define EC_NAMED_CURVE_BRAINPOOLP512R1  28
#define EC_NAMED_CURVE_ECDH_X25519      29  //(TEMPORARY - registered 2016-02-29, expires 2017-03-01)
#define EC_NAMED_CURVE_ECDH_X448        30  //(TEMPORARY - registered 2016-02-29, expires 2017-03-01)
#define EC_NAMED_CURVE_FFDHE2048        256
#define EC_NAMED_CURVE_FFDHE3072        257
#define EC_NAMED_CURVE_FFDHE4096        258
#define EC_NAMED_CURVE_FFDHE6144        259
#define EC_NAMED_CURVE_FFDHE8192        260
#define EC_NAMED_CURVE_ARBITRARY_EXPLICIT_PRIME_CURVES  0xff01
#define EC_NAMED_CURVE_ARBITRARY_EXPLICIT_CHAR2_CURVES  0xff02

#define EC_POINT_FORMAT_UNCOMPRESSED                    0
#define EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME       1
#define EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2       2

#define EC_POINT_FORMAT_SET_LENGTH                      1
#define EC_POINT_FORMAT_LENGTH                          1

#endif /* __EC_EXTENSIONS_H */
