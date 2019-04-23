#ifndef _SOCKMNR_H
#define _SOCKMNR_H

#include "uv.h"
#include "time.h"

typedef struct gs_socket_s
{
    union
    {
        uv_tcp_t uv_tcp;
        uv_udp_t uv_udp;
        uv_stream_t uv_stream;
        uv_handle_t uv_handle;
    };
    struct gs_socket_s* next;
    char is_closed;
    int count;
    char *buf;
    time_t act_time;
    unsigned int len;
} gs_socket_t;

typedef void (*gs_timeout_f)(gs_socket_t *);

void manager_bind_loop(uv_loop_t *loop);

void manager_register(gs_socket_t *s);

void manager_reference(gs_socket_t *s);

void manager_unreference(gs_socket_t *s);

void manager_close(gs_socket_t *s);

char manager_isclosed(__const__ gs_socket_t *s);

void manager_timeout(uv_loop_t *loop, __const__ gs_socket_t *s, int timeout_sec, gs_timeout_f cb);

#endif
