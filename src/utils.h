#ifndef __UTILS_H
#define __UTILS_H

#include <time.h>

unsigned read_uint(void *buffer, unsigned offset, unsigned size);
unsigned long read_ulong(void *buffer, unsigned offset, unsigned size);
unsigned long long read_ulonglong(void *buffer, unsigned offset, unsigned size);
unsigned read_int(void *buffer, unsigned offset, unsigned size);
void print_hex_blob(void *buffer, unsigned offset, unsigned size, unsigned short tabs, unsigned short spacing);
void print_tabs(unsigned tabs);
const char *epoch_to_string(time_t time);

#endif /* __UTILS_H */
