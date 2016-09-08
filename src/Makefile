BINARY=tlsparser

main: main.c tls_constants.h tls_handshake.o tls_handshake.h utils.o utils.h tls_ciphers.o tls_ciphers.h tls_extensions.o tls_extensions.h
	gcc -o $(BINARY) main.c tls_handshake.o tls_ciphers.o utils.o tls_extensions.o

tls_handshake.o: tls_handshake.c tls_handshake.h utils.h tls_ciphers.h tls_compressions.h tls_extensions.h
	gcc -c -o tls_handshake.o tls_handshake.c

utils.o: utils.c utils.h
	gcc -c -o utils.o utils.c

tls_ciphers.o: tls_ciphers.c tls_ciphers.h
	gcc -c -o tls_ciphers.o tls_ciphers.c

tls_extensions.o: tls_extensions.c tls_extensions.h
	gcc -c -o tls_extensions.o tls_extensions.c

clean:
	rm *.o $(BINARY)
