input_file_name = "cipher_list"
c_out = "tls_ciphers.c"
h_out = "tls_ciphers.h"

c = open(c_out, "w")
h = open(h_out, "w")

c_header = """#include <stdio.h>
#include "tls_ciphers.h"
#include <stdlib.h>

// AUTO-GENERATED CODE. Use the python script to re-generate this list

char *cipher_name(unsigned code)
{
    switch(code)
    {
        default:
            return 0;
            break;
"""

c.write(c_header)

h_header = """#ifndef __TLS_CIPHERS_H
#define __TLS_CIPHERS_H
// AUTO-GENERATED CODE. Use the python script to re-generate this list

char *cipher_name(unsigned cipher);

"""
h.write(h_header)

with open(input_file_name) as f:
    for line in f:
        key, val = line.rstrip().split(' ')
        c.write("        case %s:\n            return \"%s\";\n" % (key, val))
        h.write("#define %s %s\n" % (val, key))

c_footer = """        case 0x0a0a:
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
"""
c.write(c_footer)
c.close()

h_footer = """
#endif /* __TLS_CIPHERS_H */
"""
h.write(h_footer)
h.close()
