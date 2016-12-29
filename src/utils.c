#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned read_uint(void *_buffer, unsigned offset, unsigned size)
{
    unsigned i = 0;
    unsigned result = 0;
    unsigned char *buffer = _buffer;
    if (sizeof(result) < size)
    {
        fprintf(stderr, "ERROR: requested size (%d) larger than sizeof(unsigned int) = %lu.\n", size, sizeof(result));
    }

    for (i = offset; i < offset + size; i++)
        result = (result << 8) | buffer[i];
    return result;
}

unsigned long read_ulong(void *_buffer, unsigned offset, unsigned size)
{
    unsigned i = 0;
    unsigned long result = 0;
    unsigned char *buffer = _buffer;
    if (sizeof(result) < size)
    {
        fprintf(stderr, "ERROR: requested size (%d) larger than sizeof(unsigned long) = %lu.\n", size, sizeof(result));
    }

    for (i = offset; i < offset + size; i++)
        result = (result << 8) | buffer[i];
    return result;
}

unsigned long long read_ulonglong(void *_buffer, unsigned offset, unsigned size)
{
    unsigned i = 0;
    unsigned long long result = 0;
    unsigned char *buffer = _buffer;
    if (sizeof(result) < size)
    {
        fprintf(stderr, "ERROR: requested size (%d) larger than sizeof(unsigned long long) = %lu.\n", size, sizeof(result));
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
        fprintf(stderr, "ERROR: requested size (%d) larger than sizeof(int) = %lu.\n", size, sizeof(result));
    }

    for (i = offset; i < offset + size; i++)
        result = (result << 8) | buffer[i];
    return result;
}

const char *epoch_to_string(time_t in_time)
{
    char *result = (char *)malloc(sizeof(char)*100);
    struct tm ts;
    ts = *localtime(&in_time);
    strftime(result, sizeof(char) * 100, "%a %Y-%m-%d %H:%M:%S %Z", &ts);

    return result;
}
