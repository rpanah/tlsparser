#ifndef __TLS_CONSTANTS_H
#define __TLS_CONSTANTS_H

#define TLS_HEADER_LEN 5


/* Byte offsets */

#define RECORD_TYPE_OFFSET      0

#define VERSION_OFFSET          1

#define VERSION_MAJOR_OFFSET    1
#define VERSION_MINOR_OFFSET    2

#define RECORD_LENGTH_OFFSET    3

/* TLSv1.3 Magic    */

#define TLS13_HELLO_RETRY_REQUEST_MAGIC \
"\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C"
#define TLS13_TLS12_DOWNGRADE_MARKER_MAGIC \
"\x44\x4F\x57\x4E\x47\x52\x44\x01"
#define TLS13_TLS10_DOWNGRADE_MARKER_MAGIC \
"\x44\x4F\x57\x4E\x47\x52\x44\x00"


/* TLS record types */

#define CHANGE_CIPHER_SPEC      0x14    /* 20 */
#define ALERT                   0x15    /* 21 */
#define HANDSHAKE               0x16    /* 22 */
#define APPLICATION_DATA        0x17    /* 23 */

/* Handshake offsets */

#define HANDSHAKE_TYPE_OFFSET           TLS_HEADER_LEN
#define HANDSHAKE_TYPE_LEN              1
#define HANDSHAKE_LENGTH_OFFSET         HANDSHAKE_TYPE_OFFSET + HANDSHAKE_TYPE_LEN
#define HANDSHAKE_LENGTH_LEN            3
#define HANDSHAKE_MESSAGE_OFFSET        HANDSHAKE_LENGTH_OFFSET + HANDSHAKE_LENGTH_LEN

#define HANDSHAKE_CH_VERSION_OFFSET             HANDSHAKE_MESSAGE_OFFSET
#define HANDSHAKE_CH_VERSION_LEN                2
#define HANDSHAKE_CH_RANDOM_OFFSET              HANDSHAKE_CH_VERSION_OFFSET + HANDSHAKE_CH_VERSION_LEN
#define HANDSHAKE_CH_RANDOM_LEN                 32
#define HANDSHAKE_CH_SESSION_ID_LENGTH_OFFSET   HANDSHAKE_CH_RANDOM_OFFSET + HANDSHAKE_CH_RANDOM_LEN
#define HANDSHAKE_CH_SESSION_ID_LENGTH_LEN      1
#define HANDSHAKE_CH_SESSION_ID_OFFSET          HANDSHAKE_CH_SESSION_ID_LENGTH_OFFSET + HANDSHAKE_CH_SESSION_ID_LENGTH_LEN
#define HANDSHAKE_CH_SESSION_ID_LEN_MAX         4
#define HANDSHAKE_CH_CIPHERS_LENGTH_LEN         2
#define HANDSHAKE_CH_CIPHER_LEN                 2
#define HANDSHAKE_CH_COMP_LENGTH_LEN            1
#define HANDSHAKE_CH_COMP_METHOD_LEN            1
#define HANDSHAKE_CH_EXTENSIONS_LENGTH_LEN      2
#define HANDSHAKE_CH_EXTENSION_ID_LEN           2
#define HANDSHAKE_CH_EXTENSION_DATA_LENGTH_LEN  2

/* Handshake type */

#define HELLO_REQUEST           0x00    /* 0 */
#define CLIENT_HELLO            0x01    /* 1 */
#define SERVER_HELLO            0x02    /* 2 */
#define NEW_SESSION_TICKET      0x04    /* 4 */
#define CERTIFICATE             0x0b    /* 11 */
#define SERVER_KEY_EXCHANGE     0x0c    /* 12 */
#define CERTIFICATE_REQUEST     0x0d    /* 13 */
#define SERVER_DONE             0x0e    /* 14 */
#define CERTIFICATE_VERIFY      0x0f    /* 15 */
#define CLIENT_KEY_EXCHANGE     0x10    /* 16 */
#define FINISHED                0x14    /* 20 */
#define CERTIFICATE_URL         0x15    /* 21 */
#define CERTIFICATE_STATUS      0x16    /* 22 */

/* TLS versions */

#define SSL_3_0                 0x0300  /* 3,0 */
#define TLS_1_0                 0x0301  /* 3,1 */
#define TLS_1_1                 0x0302  /* 3,2 */
#define TLS_1_2                 0x0303  /* 3,3 */
#define TLS_1_3                 0x0304  /* 3,4 */
#define TLS_1_3_DRAFT23         0x7f17
#define TLS_1_3_DRAFT23_FB      0xfb17
#define TLS_1_3_DRAFT26         0x7f1a
#define TLS_1_3_DRAFT26_FB      0xfb1a
#define TLS_1_3_DRAFT28         0x7f1c
#define TLS_1_3_DRAFT28_FB      0xfb1c

#endif
