#ifndef _COMMON_H
#define _COMMON_H

#include <stddef.h>

#include "uv.h"
#include "sockmnr.h"

#define DEFAULT_BACKLOG 128
#define GS_RANDOM_LEN 1024
#define BUFFER_SIZE 40960

typedef void (*gs_handle_f)(gs_socket_t *, __const__ char*, __const__ size_t);

typedef void (*gs_parse_f)(gs_socket_t *, __const__ char*, __const__ size_t, __const__ int status);

typedef void (*gs_getaddrinfo_cb_f)(gs_socket_t *, __const__ int, __const__ struct sockaddr *);

typedef struct
{
    union
    {
        uv_write_t tcp_req;
        uv_udp_send_t udp_req;
    };
    uv_buf_t *buf;
    size_t len;
} write_req_t;

typedef struct
{
    char atyp;
    char* addr;
    char len;
    uint16_t port;
} gs_addr_t;


int do_bind(char *host6, char *host4, int port, uv_tcp_t **tcp, uv_connection_cb tcp_cb, uv_udp_t **udp, uv_udp_recv_cb udp_cb);

void chrswt(char *a, char *b);

void reverse(char *buf, size_t len);

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr);

int getipv4hostbyname(__const__ char *hostname, struct sockaddr_in *addr);

int getipv6hostbyname(__const__ char *hostname, struct sockaddr_in6 *addr);

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

void free_buffer(write_req_t *wr);

void after_tcp_write(uv_write_t *req, int status);

void after_udp_write(uv_udp_send_t *req, int status);

void gs_parse(gs_socket_t *s, __const__ char *buf, __const__ size_t len, gs_parse_f on_conn_cb, gs_parse_f on_read_cb, char *aes_key, char net);

int gs_enc_write(__const__ gs_socket_t *s, __const__ struct sockaddr *addr, __const__ char *buf, __const__ size_t len, char *aes_key, char act, char net, char status);

int gs_udp_send(uv_udp_t *server, __const__ char *buf, __const__ size_t len, __const__ struct sockaddr* client);

int gs_write(uv_stream_t *client, __const__ char *buf, __const__ size_t len);

int gs_getaddrinfo(uv_loop_t *loop, gs_socket_t *s, __const__ gs_addr_t *gsaddr, gs_getaddrinfo_cb_f cb);

#endif
