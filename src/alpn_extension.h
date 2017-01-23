#ifndef __ALPN_EXTENSION_H
#define __ALPN_EXTENSION_H

void parse_alpns(char *data, unsigned offset, unsigned length, int json);
const char *alpn_desc(char *code);

#define ALPN_SET_LENGTH                 2
#define ALPN_LENGTH                     1

#define ALPN_HTTP_1_1                   "http/1.1"
#define ALPN_SPDY_1                     "spdy/1"
#define ALPN_SPDY_2                     "spdy/2"
#define ALPN_SPDY_3                     "spdy/3"
#define ALPN_SPDY_3_1                   "spdy/3.1"
#define ALPN_STUN_TURN                  "stun.turn"
#define ALPN_STUN_NAT_DISCOVERY         "stun.nat-discovery"
#define ALPN_HTTP2_TLS                  "h2"
#define ALPN_HTTP2_TCP                  "h2c"
#define ALPN_WEBRTC                     "webrtc"
#define ALPN_CONFIDENTIAL_WEBRTC        "c-webrtc"
#define ALPN_FTP                        "ftp"


#define ALPN_DESC_HTTP_1_1                   "HTTP/1.1"
#define ALPN_DESC_SPDY_1                     "SPDY/1"
#define ALPN_DESC_SPDY_2                     "SPDY/2"
#define ALPN_DESC_SPDY_3                     "SPDY/3"
#define ALPN_DESC_SPDY_3_1                   "SPDY/3.1"
#define ALPN_DESC_STUN_TURN                  "Traversal Using Relays around NAT (TURN)"
#define ALPN_DESC_STUN_NAT_DISCOVERY         "NAT discovery using Session Traversal Utilities for NAT (STUN)"
#define ALPN_DESC_HTTP2_TLS                  "HTTP/2 over TLS"
#define ALPN_DESC_HTTP2_TCP                  "HTTP/2 over TCP"
#define ALPN_DESC_WEBRTC                     "WebRTC Media and Data"
#define ALPN_DESC_CONFIDENTIAL_WEBRTC        "Confidential WebRTC Media and Data"
#define ALPN_DESC_FTP                        "FTP"

#endif /* __ALPN_EXTENSION_H */
