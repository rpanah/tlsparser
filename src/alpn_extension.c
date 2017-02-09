#include "alpn_extension.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_alpns(char *data, unsigned offset, unsigned length, int json)
{
    unsigned pos = offset;
    unsigned alpns_length = read_uint(data, pos, ALPN_SET_LENGTH);
    unsigned alpn_code_length;
    int i = 0;
    pos += ALPN_SET_LENGTH;

    if (json)
        printf("\"alpn_list\": [");
    for(; pos < offset + length;)
    {
        alpn_code_length = read_uint(data, pos, ALPN_LENGTH);
        pos += ALPN_LENGTH;
        char *alpn_code = (char *)malloc(sizeof(char) * alpn_code_length + 1);
        memcpy(alpn_code, data + pos, alpn_code_length);
        alpn_code[alpn_code_length] = '\0';
        if (json)
        {
            if (i != 0)
                printf(", ");
            printf("{\"id\": \"%s\"", alpn_code);
        }
        else
            printf("\t\t%s", alpn_code);//alpn_name(alpn_code));

        if (alpn_desc(alpn_code))
        {
            if (json)
                printf(", \"description\": \"%s\"", alpn_desc(alpn_code));
            else
                printf(" (%s)", alpn_desc(alpn_code));
        }
        if (json)
            printf("}");
        else
            printf("\n");
        pos += alpn_code_length;
        i++;
    }
    if (json)
        printf("]");
}

const char *alpn_desc(char *code)
{
    if(strcmp(code, ALPN_HTTP_1_1) == 0)
        return ALPN_DESC_HTTP_1_1;
    else if (strcmp(code, ALPN_SPDY_1) == 0)
        return ALPN_DESC_SPDY_1;
    else if (strcmp(code, ALPN_SPDY_2) == 0)
        return ALPN_DESC_SPDY_2;
    else if (strcmp(code, ALPN_SPDY_3) == 0)
        return ALPN_DESC_SPDY_3;
    else if (strcmp(code, ALPN_SPDY_3_1) == 0)
        return ALPN_DESC_SPDY_3_1;
    else if (strcmp(code, ALPN_STUN_TURN) == 0)
        return ALPN_DESC_STUN_TURN;
    else if (strcmp(code, ALPN_STUN_NAT_DISCOVERY) == 0)
        return ALPN_DESC_STUN_NAT_DISCOVERY;
    else if (strcmp(code, ALPN_HTTP2_TLS) == 0)
        return ALPN_DESC_HTTP2_TLS;
    else if (strcmp(code, ALPN_HTTP2_TCP) == 0)
        return ALPN_DESC_HTTP2_TCP;
    else if (strcmp(code, ALPN_WEBRTC) == 0)
        return ALPN_DESC_WEBRTC;
    else if (strcmp(code, ALPN_CONFIDENTIAL_WEBRTC) == 0)
        return ALPN_DESC_CONFIDENTIAL_WEBRTC;
    else if (strcmp(code, ALPN_FTP) == 0)
        return ALPN_DESC_FTP;
    else
        return "";
}
