#include <stdio.h>
#include "tls_ciphers.h"
#include <stdlib.h>

char *cipher_name(unsigned code)
{
    switch(code)
    {
        default:
            return 0;
            break;


        case TLS_NULL_WITH_NULL_NULL:
            return "TLS_NULL_WITH_NULL_NULL";
            break;
    

        case TLS_RSA_WITH_NULL_MD5:
            return "TLS_RSA_WITH_NULL_MD5";
            break;
    

        case TLS_RSA_WITH_NULL_SHA:
            return "TLS_RSA_WITH_NULL_SHA";
            break;
    

        case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
            return "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
            break;
    

        case TLS_RSA_WITH_RC4_128_MD5:
            return "TLS_RSA_WITH_RC4_128_MD5";
            break;
    

        case TLS_RSA_WITH_RC4_128_SHA:
            return "TLS_RSA_WITH_RC4_128_SHA";
            break;
    

        case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
            return "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
            break;
    

        case TLS_RSA_WITH_IDEA_CBC_SHA:
            return "TLS_RSA_WITH_IDEA_CBC_SHA";
            break;
    

        case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
            return "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA";
            break;
    

        case TLS_RSA_WITH_DES_CBC_SHA:
            return "TLS_RSA_WITH_DES_CBC_SHA";
            break;
    

        case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
            return "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_DES_CBC_SHA:
            return "TLS_DH_DSS_WITH_DES_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
            return "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_DES_CBC_SHA:
            return "TLS_DH_RSA_WITH_DES_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
            return "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_DES_CBC_SHA:
            return "TLS_DHE_DSS_WITH_DES_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
            return "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_DES_CBC_SHA:
            return "TLS_DHE_RSA_WITH_DES_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
            return "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5";
            break;
    

        case TLS_DH_anon_WITH_RC4_128_MD5:
            return "TLS_DH_anon_WITH_RC4_128_MD5";
            break;
    

        case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
            return "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_DES_CBC_SHA:
            return "TLS_DH_anon_WITH_DES_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_KRB5_WITH_DES_CBC_SHA:
            return "TLS_KRB5_WITH_DES_CBC_SHA";
            break;
    

        case TLS_KRB5_WITH_3DES_EDE_CBC_SHA:
            return "TLS_KRB5_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_KRB5_WITH_RC4_128_SHA:
            return "TLS_KRB5_WITH_RC4_128_SHA";
            break;
    

        case TLS_KRB5_WITH_IDEA_CBC_SHA:
            return "TLS_KRB5_WITH_IDEA_CBC_SHA";
            break;
    

        case TLS_KRB5_WITH_DES_CBC_MD5:
            return "TLS_KRB5_WITH_DES_CBC_MD5";
            break;
    

        case TLS_KRB5_WITH_3DES_EDE_CBC_MD5:
            return "TLS_KRB5_WITH_3DES_EDE_CBC_MD5";
            break;
    

        case TLS_KRB5_WITH_RC4_128_MD5:
            return "TLS_KRB5_WITH_RC4_128_MD5";
            break;
    

        case TLS_KRB5_WITH_IDEA_CBC_MD5:
            return "TLS_KRB5_WITH_IDEA_CBC_MD5";
            break;
    

        case TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA:
            return "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA";
            break;
    

        case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA:
            return "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA";
            break;
    

        case TLS_KRB5_EXPORT_WITH_RC4_40_SHA:
            return "TLS_KRB5_EXPORT_WITH_RC4_40_SHA";
            break;
    

        case TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5:
            return "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5";
            break;
    

        case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5:
            return "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5";
            break;
    

        case TLS_KRB5_EXPORT_WITH_RC4_40_MD5:
            return "TLS_KRB5_EXPORT_WITH_RC4_40_MD5";
            break;
    

        case TLS_PSK_WITH_NULL_SHA:
            return "TLS_PSK_WITH_NULL_SHA";
            break;
    

        case TLS_DHE_PSK_WITH_NULL_SHA:
            return "TLS_DHE_PSK_WITH_NULL_SHA";
            break;
    

        case TLS_RSA_PSK_WITH_NULL_SHA:
            return "TLS_RSA_PSK_WITH_NULL_SHA";
            break;
    

        case TLS_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_RSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
            return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
            return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_AES_128_CBC_SHA:
            return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_RSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
            return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
            return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_AES_256_CBC_SHA:
            return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_RSA_WITH_NULL_SHA256:
            return "TLS_RSA_WITH_NULL_SHA256";
            break;
    

        case TLS_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_RSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_RSA_WITH_AES_256_CBC_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
            return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
            return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
            break;
    

        case TLS_DH_anon_WITH_AES_128_CBC_SHA256:
            return "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
            return "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
            break;
    

        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA";
            break;
    

        case TLS_PSK_WITH_RC4_128_SHA:
            return "TLS_PSK_WITH_RC4_128_SHA";
            break;
    

        case TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_PSK_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_PSK_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_DHE_PSK_WITH_RC4_128_SHA:
            return "TLS_DHE_PSK_WITH_RC4_128_SHA";
            break;
    

        case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_RSA_PSK_WITH_RC4_128_SHA:
            return "TLS_RSA_PSK_WITH_RC4_128_SHA";
            break;
    

        case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_RSA_WITH_SEED_CBC_SHA:
            return "TLS_RSA_WITH_SEED_CBC_SHA";
            break;
    

        case TLS_DH_DSS_WITH_SEED_CBC_SHA:
            return "TLS_DH_DSS_WITH_SEED_CBC_SHA";
            break;
    

        case TLS_DH_RSA_WITH_SEED_CBC_SHA:
            return "TLS_DH_RSA_WITH_SEED_CBC_SHA";
            break;
    

        case TLS_DHE_DSS_WITH_SEED_CBC_SHA:
            return "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
            break;
    

        case TLS_DHE_RSA_WITH_SEED_CBC_SHA:
            return "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
            break;
    

        case TLS_DH_anon_WITH_SEED_CBC_SHA:
            return "TLS_DH_anon_WITH_SEED_CBC_SHA";
            break;
    

        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_RSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_RSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
            return "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
            return "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
            return "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
            return "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
            return "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
            return "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_PSK_WITH_AES_128_GCM_SHA256:
            return "TLS_PSK_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_PSK_WITH_AES_256_GCM_SHA384:
            return "TLS_PSK_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
            return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
            return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
            return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
            return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_PSK_WITH_AES_128_CBC_SHA256:
            return "TLS_PSK_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_PSK_WITH_AES_256_CBC_SHA384:
            return "TLS_PSK_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_PSK_WITH_NULL_SHA256:
            return "TLS_PSK_WITH_NULL_SHA256";
            break;
    

        case TLS_PSK_WITH_NULL_SHA384:
            return "TLS_PSK_WITH_NULL_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
            return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
            return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_NULL_SHA256:
            return "TLS_DHE_PSK_WITH_NULL_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_NULL_SHA384:
            return "TLS_DHE_PSK_WITH_NULL_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
            return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
            return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_NULL_SHA256:
            return "TLS_RSA_PSK_WITH_NULL_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_NULL_SHA384:
            return "TLS_RSA_PSK_WITH_NULL_SHA384";
            break;
    

        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
            return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
            break;
    

        case TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
            return "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256";
            break;
    

        case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
            return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
            break;
    

        case TLS_FALLBACK_SCSV:
            return "TLS_FALLBACK_SCSV";
            break;
    

        case TLS_ECDH_ECDSA_WITH_NULL_SHA:
            return "TLS_ECDH_ECDSA_WITH_NULL_SHA";
            break;
    

        case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
            return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
            break;
    

        case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
            return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
            return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
            return "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
            return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_ECDH_RSA_WITH_NULL_SHA:
            return "TLS_ECDH_RSA_WITH_NULL_SHA";
            break;
    

        case TLS_ECDH_RSA_WITH_RC4_128_SHA:
            return "TLS_ECDH_RSA_WITH_RC4_128_SHA";
            break;
    

        case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_ECDHE_RSA_WITH_NULL_SHA:
            return "TLS_ECDHE_RSA_WITH_NULL_SHA";
            break;
    

        case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
            return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
            break;
    

        case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_ECDH_anon_WITH_NULL_SHA:
            return "TLS_ECDH_anon_WITH_NULL_SHA";
            break;
    

        case TLS_ECDH_anon_WITH_RC4_128_SHA:
            return "TLS_ECDH_anon_WITH_RC4_128_SHA";
            break;
    

        case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
            return "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
            return "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
            return "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            return "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            return "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            return "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            return "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
            break;
    

        case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_PSK_WITH_RC4_128_SHA:
            return "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
            break;
    

        case TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
            break;
    

        case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
            break;
    

        case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
            break;
    

        case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_PSK_WITH_NULL_SHA:
            return "TLS_ECDHE_PSK_WITH_NULL_SHA";
            break;
    

        case TLS_ECDHE_PSK_WITH_NULL_SHA256:
            return "TLS_ECDHE_PSK_WITH_NULL_SHA256";
            break;
    

        case TLS_ECDHE_PSK_WITH_NULL_SHA384:
            return "TLS_ECDHE_PSK_WITH_NULL_SHA384";
            break;
    

        case TLS_RSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_RSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_RSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_RSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
            return "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
            return "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
            return "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
            return "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
            return "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
            return "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
            return "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_RSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_RSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_RSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_RSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
            return "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
            return "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
            return "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
            return "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
            return "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
            return "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
            return "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
            return "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_PSK_WITH_ARIA_128_CBC_SHA256:
            return "TLS_PSK_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_PSK_WITH_ARIA_256_CBC_SHA384:
            return "TLS_PSK_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
            return "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
            return "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
            return "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
            return "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_PSK_WITH_ARIA_128_GCM_SHA256:
            return "TLS_PSK_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_PSK_WITH_ARIA_256_GCM_SHA384:
            return "TLS_PSK_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
            return "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
            return "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
            return "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
            return "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
            return "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
            return "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            return "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            return "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384";
            break;
    

        case TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            return "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
            break;
    

        case TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            return "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
            break;
    

        case TLS_RSA_WITH_AES_128_CCM:
            return "TLS_RSA_WITH_AES_128_CCM";
            break;
    

        case TLS_RSA_WITH_AES_256_CCM:
            return "TLS_RSA_WITH_AES_256_CCM";
            break;
    

        case TLS_DHE_RSA_WITH_AES_128_CCM:
            return "TLS_DHE_RSA_WITH_AES_128_CCM";
            break;
    

        case TLS_DHE_RSA_WITH_AES_256_CCM:
            return "TLS_DHE_RSA_WITH_AES_256_CCM";
            break;
    

        case TLS_RSA_WITH_AES_128_CCM_8:
            return "TLS_RSA_WITH_AES_128_CCM_8";
            break;
    

        case TLS_RSA_WITH_AES_256_CCM_8:
            return "TLS_RSA_WITH_AES_256_CCM_8";
            break;
    

        case TLS_DHE_RSA_WITH_AES_128_CCM_8:
            return "TLS_DHE_RSA_WITH_AES_128_CCM_8";
            break;
    

        case TLS_DHE_RSA_WITH_AES_256_CCM_8:
            return "TLS_DHE_RSA_WITH_AES_256_CCM_8";
            break;
    

        case TLS_PSK_WITH_AES_128_CCM:
            return "TLS_PSK_WITH_AES_128_CCM";
            break;
    

        case TLS_PSK_WITH_AES_256_CCM:
            return "TLS_PSK_WITH_AES_256_CCM";
            break;
    

        case TLS_DHE_PSK_WITH_AES_128_CCM:
            return "TLS_DHE_PSK_WITH_AES_128_CCM";
            break;
    

        case TLS_DHE_PSK_WITH_AES_256_CCM:
            return "TLS_DHE_PSK_WITH_AES_256_CCM";
            break;
    

        case TLS_PSK_WITH_AES_128_CCM_8:
            return "TLS_PSK_WITH_AES_128_CCM_8";
            break;
    

        case TLS_PSK_WITH_AES_256_CCM_8:
            return "TLS_PSK_WITH_AES_256_CCM_8";
            break;
    

        case TLS_PSK_DHE_WITH_AES_128_CCM_8:
            return "TLS_PSK_DHE_WITH_AES_128_CCM_8";
            break;
    

        case TLS_PSK_DHE_WITH_AES_256_CCM_8:
            return "TLS_PSK_DHE_WITH_AES_256_CCM_8";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8";
            break;
    

        case OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return "OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256";
            break;
    

        case 0x0a0a:
        case 0x1a1a:
        case 0x2a2a:
        case 0x3a3a:
        case 0x4a4a:
        case 0x5a5a:
        case 0x6a6a:
        case 0x7a7a:
        case 0x8a8a:
        case 0x9a9a:
        case 0xaaaa:
        case 0xbaba:
        case 0xcaca:
        case 0xdada:
        case 0xeaea:
        case 0xfafa:
            return "GOOGLE_GREASE";
    }
}
