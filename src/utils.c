#include "utils.h"
#include <stdio.h>

unsigned read_uint(void *_buffer, unsigned offset, unsigned size)
{
    unsigned i = 0;
    unsigned result = 0;
    unsigned char *buffer = _buffer;
    if (sizeof(result) < size)
    {
        fprintf(stderr, "ERROR: requested size (%d) larger than sizeof(unsigned) = %lu.\n", size, sizeof(result));
    }

    for (i = offset; i < offset + size; i++)
        result = (result << 8) | buffer[i];
    return result;
}

unsigned read_int(void *_buffer, unsigned offset, unsigned size)
{
    unsigned i = 0;
    int result = 0;
    unsigned char *buffer = _buffer;
    if (sizeof(result) < size)
    {
        fprintf(stderr, "ERROR: requested size (%d) larger than sizeof(unsigned) = %lu.\n", size, sizeof(result));
    }

    for (i = offset; i < offset + size; i++)
        result = (result << 8) | buffer[i];
    return result;
}
