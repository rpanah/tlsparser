#ifndef __TLS_EXTENSIONS_H
#define __TLS_EXTENSIONS_H

#include "ec_extensions.h"
#include "alpn_extension.h"

const char *extension_name(unsigned extension_id);
const char *sni_type_name(unsigned code);
struct tls_sni *parse_sni(char *data, unsigned offset, unsigned length, int json);

void parse_signature_algorithms(char *data, unsigned offset, unsigned length, int json);
const char *sigalg_name(unsigned code);

#define EXT_SERVER_NAME                                 0
#define EXT_MAX_FRAGMENT_LENGTH                         1
#define EXT_CLIENT_CERTIFICATE_URL                      2
#define EXT_TRUSTED_CA_KEYS                             3
#define EXT_TRUNCATED_HMAC                              4
#define EXT_STATUS_REQUEST                              5
#define EXT_USER_MAPPING                                6
#define EXT_CLIENT_AUTHZ                                7
#define EXT_SERVER_AUTHZ                                8
#define EXT_CERT_TYPE                                   9
#define EXT_SUPPORTED_GROUPS                            10
#define EXT_EC_POINT_FORMATS                            11
#define EXT_SRP                                         12
#define EXT_SIGNATURE_ALGORITHMS                        13
#define EXT_USE_SRTP                                    14
#define EXT_HEARTBEAT                                   15
#define EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION      16
#define EXT_STATUS_REQUEST_V2                           17
#define EXT_SIGNED_CERTIFICATE_TIMESTAMP                18
#define EXT_CLIENT_CERTIFICATE_TYPE                     19
#define EXT_SERVER_CERTIFICATE_TYPE                     20
#define EXT_PADDING                                     21
#define EXT_ENCRYPT_THEN_MAC                            22
#define EXT_EXTENDED_MASTER_SECRET                      23
#define EXT_TOKEN_BINDING                               24
#define EXT_CACHED_INFO                                 25
#define EXT_SESSION_TICKET_TLS                          35
#define EXT_EXTENDED_RANDOM                             40
#define EXT_PRE_SHARED_KEY                              41
#define EXT_EARLY_DATA                                  42
#define EXT_SUPPORTED_VERSIONS                          43
#define EXT_COOKIE                                      44
#define EXT_PSK_KEY_EXCHANGE_MODES                      45
#define EXT_TICKET_EARLY_DATA_INFO                      46
#define EXT_CERTIFICATE_AUTHORITIES                     47
#define EXT_OID_FILTERS                                 48
#define EXT_POST_HANDSHAKE_AUTH                         49
#define EXT_SIGNATURE_ALGORITHMS_CERT                   50
#define EXT_KEY_SHARE                                   51
#define OLD_EXT_NEXT_PROTOCOL_NEGOTIATION               13172
#define EXT_ORIGIN_BOUND_CERTIFICATES                   13175
#define EXT_ENCRYPTED_CLIENT_CERTIFICATES               13180
#define EXT_TOKEN_BINDING_TEST                          21760
#define OLD_EXT_CHANNEL_ID                              30031
#define EXT_CHANNEL_ID                                  30032
#define EXT_NEW_PADDING                                 35655
#define EXT_RENEGOTIATION_INFO                          65281
#define EXT_TLS_DRAFT                                   65282
#define EXT_SHORT_HEADER                                65283 // https://nss-review.dev.mozaws.net/D122

#define SNI_TYPE_LENGTH                                 1
#define SNI_NAME_LENGTH_LEN                             2
#define SNI_TYPE_HOSTNAME                               0

/* Signature algorithms */

#define SIGALG_SET_LENGTH                               2
#define SIGALG_LENGTH                                   2

#define TLSEXT_SIGALG_ECDSA_SECP224R1_SHA224                    0x0303
#define TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256                    0x0403
#define TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384                    0x0503
#define TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512                    0x0603
#define TLSEXT_SIGALG_ECDSA_MD5                                 0x0103
#define TLSEXT_SIGALG_ECDSA_SHA1                                0x0203

#define TLSEXT_SIGALG_TLS13_RSA_PSS_SHA256                      0x0700
#define TLSEXT_SIGALG_TLS13_RSA_PSS_SHA384                      0x0701
#define TLSEXT_SIGALG_TLS13_RSA_PSS_SHA512                      0x0702

#define TLSEXT_SIGALG_TLS13_ED25519                             0x0703
#define TLSEXT_SIGALG_TLS13_ED448                               0x0704

#define TLSEXT_SIGALG_RSA_PSS_SHA256                            0x0804
#define TLSEXT_SIGALG_RSA_PSS_SHA384                            0x0805
#define TLSEXT_SIGALG_RSA_PSS_SHA512                            0x0806

#define TLSEXT_SIGALG_ED25519                                   0x0807
#define TLSEXT_SIGALG_ED448                                     0x0808

#define TLSEXT_SIGALG_RSA_PKCS1_SHA224                          0x0301
#define TLSEXT_SIGALG_RSA_PKCS1_SHA256                          0x0401
#define TLSEXT_SIGALG_RSA_PKCS1_SHA384                          0x0501
#define TLSEXT_SIGALG_RSA_PKCS1_SHA512                          0x0601
#define TLSEXT_SIGALG_RSA_PKCS1_MD5                             0x0101
#define TLSEXT_SIGALG_RSA_PKCS1_SHA1                            0x0201

#define TLSEXT_SIGALG_DSA_SHA224                                0x0302
#define TLSEXT_SIGALG_DSA_SHA256                                0x0402
#define TLSEXT_SIGALG_DSA_SHA384                                0x0502
#define TLSEXT_SIGALG_DSA_SHA512                                0x0602
#define TLSEXT_SIGALG_DSA_SHA1                                  0x0202

#define TLSEXT_SIGALG_GOSTR34102012_256_GOSTR34112012_256       0xeeee
#define TLSEXT_SIGALG_GOSTR34102012_512_GOSTR34112012_512       0xefef
#define TLSEXT_SIGALG_GOSTR34102001_GOSTR3411                   0xeded

#endif /* __TLS_EXTENSIONS_H */
