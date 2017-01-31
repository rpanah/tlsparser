#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/ssl3.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>

/* gcc test.c -L/opt/local/lib -lssl -lcrypto -o test_run */

int main() {
    unsigned char ciphers[] = { 0xba, 0xba };
    const SSL_METHOD *meth = TLSv1_2_method();
    SSL_CTX *ctx = NULL;
    SSL_CIPHER *cipher = NULL;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(meth);

    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!meth)
    {
        fprintf(stderr, "Method is null\n");
        ERR_print_errors(bio_err);
    }

    if (!ctx)
    {
        fprintf(stderr, "CTX is null\n");
        ERR_print_errors(bio_err);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "SSL is null\n");
        ERR_print_errors(bio_err);
    }

    cipher = ssl->method->get_cipher_by_char(ciphers);
    if (!cipher)
    {
        fprintf(stderr, "Cipher is null\n");
        ERR_print_errors(bio_err);
        exit(0);
    }

    printf("Cipher name is %s: \n", cipher->name);
    return 0;
}
