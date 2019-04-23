#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

#define LOG_INFO(fmt, ...)                      \
    {                                           \
        fprintf(stdout, "INFO: ");              \
        fprintf(stdout, fmt, ## __VA_ARGS__);   \
        fflush(stdout);                         \
    }

#define LOG_ERR(fmt, ...)                       \
    {                                           \
        fprintf(stderr, "ERROR: ");             \
        fprintf(stderr, fmt, ## __VA_ARGS__);   \
        fflush(stderr);                         \
    }

#define LOG_WARN(fmt, ...)                      \
    {                                           \
        fprintf(stdout, "WARNING: ");           \
        fprintf(stdout, fmt, ## __VA_ARGS__);   \
        fflush(stdout);                         \
    }

#ifdef DEBUG
# define LOG_DEBUG(fmt, ...)                    \
    {                                           \
        fprintf(stderr, "DEBUG: ");             \
        fprintf(stderr, fmt, ## __VA_ARGS__);   \
        fflush(stderr);                         \
    }
#else
# define LOG_DEBUG(fmt, ...)
#endif

#endif
