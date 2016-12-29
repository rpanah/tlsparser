#ifndef __TLS_HANDSHAKE_H
#define __TLS_HANDSHAKE_H

struct handshake_message
{
    void *raw_packet;
    int raw_size;
    int handshake_type;
    void *handshake_contents;
};

struct handshake_message *process_handshake(void *buffer, int buffer_length);
struct hadnshake_client_hello *process_handshake_client_hello(void *data, int buffer_length);
struct hadnshake_server_hello *process_handshake_server_hello(void *data, int buffer_length);

#endif /* __TLS_HANDSHAKE_H */
