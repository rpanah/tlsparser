#ifndef __TLS_HANDSHAKE_H
#define __TLS_HANDSHAKE_H

struct handshake_message
{
    void *raw_packet;
    int raw_size;
    int handshake_type;
    void *handshake_contents;
};

struct handshake_message *process_handshake(void *buffer, int buffer_length, int json, int raw);
struct hadnshake_client_hello *process_handshake_client_hello(void *data, int buffer_length, int handshake_length, int json, int raw);
struct hadnshake_server_hello *process_handshake_server_hello(void *data, int buffer_length, int handshake_length, int json, int raw);

#endif /* __TLS_HANDSHAKE_H */
