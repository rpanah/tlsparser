#ifndef __TLS_EXTENSIONS_H
#define __TLS_EXTENSIONS_H

#include "ec_extensions.h"

const char *extension_name(unsigned extension_id);
const char *sni_type_name(unsigned code);
struct tls_sni *parse_sni(char *data, unsigned offset, unsigned length);

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
#define EXT_RENEGOTIATION_INFO                          65281

#define SNI_TYPE_LENGTH                                 1
#define SNI_NAME_LENGTH_LEN                             2
#define SNI_TYPE_HOSTNAME                               0

#endif /* __TLS_EXTENSIONS_H */
