#ifndef _CRC32_H
#define _CRC32_H

#include <zlib.h>

#define CRC32(buf, len) \
    crc32(0L, buf, len)

#endif
