BINARY=tlsparser
CFLAGS=`pkg-config --cflags glib-2.0` `pkg-config --cflags openssl`
LIBS=`pkg-config --libs glib-2.0` `pkg-config --libs openssl`
CC=gcc
PYTHON=python

main: main.c tls_constants.h tls_handshake.o tls_handshake.h utils.o utils.h tls_ciphers.o tls_ciphers.h tls_extensions.o tls_extensions.h alpn_extension.o alpn_extension.h ec_extensions.o ec_extensions.h x509_cert.o x509_cert.h
	$(CC) -o $(BINARY) $(CFLAGS) main.c tls_handshake.o tls_ciphers.o utils.o alpn_extension.o ec_extensions.o tls_extensions.o x509_cert.o $(LIBS)

tls_handshake.o: tls_handshake.c tls_handshake.h utils.h tls_ciphers.h tls_compressions.h tls_extensions.h alpn_extension.h ec_extensions.h
	$(CC) -c $(CFLAGS) -o tls_handshake.o tls_handshake.c

utils.o: utils.c utils.h
	$(CC) -c $(CFLAGS) -o utils.o utils.c

tls_ciphers.o: tls_ciphers.c tls_ciphers.h
	$(CC) -c $(CFLAGS) -o tls_ciphers.o tls_ciphers.c

tls_extensions.o: tls_extensions.c tls_extensions.h ec_extensions.h tls_constants.h
	$(CC) -c $(CFLAGS) -o tls_extensions.o tls_extensions.c

ec_extensions.o: ec_extensions.c ec_extensions.h tls_constants.h utils.h
	$(CC) -c $(CFLAGS) -o ec_extensions.o ec_extensions.c

alpn_extension.o: alpn_extension.c tls_constants.h utils.h
	$(CC) -c $(CFLAGS) -o alpn_extension.o alpn_extension.c

x509_cert.o: x509_cert.c x509_cert.h
	$(CC) -c $(CFLAGS) -o x509_cert.o x509_cert.c

tls_ciphers.c: cipher_list produce_cipher_c_code.py
	$(PYTHON) produce_cipher_c_code.py

tls_ciphers.h: tls_ciphers.c

clean:
	rm *.o $(BINARY)
