#include "x509_cert.h"

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <stdio.h>

int print_x509_cert(const unsigned char *data, unsigned length)
{
    BIO *bio;
    X509 *certificate = NULL;
    bio = BIO_new(BIO_s_mem());
    BIO_write(bio, (const void*)data, length);
    certificate = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (certificate != NULL)
    {
        X509_print_fp(stdout, certificate);
        return 1;
    }
    else
    {
        return 0;
    }
}
