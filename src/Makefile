BINARY=tlsparser
#INCLUDE=-I/opt/local/include/glib-2.0/
CFLAGS=`pkg-config --cflags glib-2.0`
LIBS=-L/opt/local/lib/ -lglib-2.0.0
CC=gcc

main: main.c tls_constants.h tls_handshake.o tls_handshake.h utils.o utils.h tls_ciphers.o tls_ciphers.h tls_extensions.o tls_extensions.h
	$(CC) -o $(BINARY) $(CFLAGS) main.c tls_handshake.o tls_ciphers.o utils.o tls_extensions.o $(LIBS)

tls_handshake.o: tls_handshake.c tls_handshake.h utils.h tls_ciphers.h tls_compressions.h tls_extensions.h
	$(CC) -c $(CFLAGS) -o tls_handshake.o tls_handshake.c

utils.o: utils.c utils.h
	$(CC) -c $(CFLAGS) -o utils.o utils.c

tls_ciphers.o: tls_ciphers.c tls_ciphers.h
	$(CC) -c $(CFLAGS) -o tls_ciphers.o tls_ciphers.c

tls_extensions.o: tls_extensions.c tls_extensions.h
	$(CC) -c $(CFLAGS) -o tls_extensions.o tls_extensions.c

clean:
	rm *.o $(BINARY)
