#ifndef _COMMON_H
#define _COMMON_H

#include "pipe.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>

#define GS_RANDOM_LEN 1024

typedef struct gs_socket_s gs_socket_t;
typedef struct gs_socket_s gs_tcp_t;
typedef struct gs_socket_s gs_udp_t;

struct gs_socket_s
{
    pp_socket_t s;
    unsigned char *aes_key;
    char *buf;
    int len;
    char tcp_flg;
    struct sockaddr* seraddr;
    struct sockaddr* dnsaddr;
    void *data;
};

typedef struct
{
    char status;
    char unsed[2];
} __attribute__((__packed__)) gs_header_t;

typedef int (*gs_parse_f)(gs_socket_t *, __const__ gs_header_t *, __const__ char *, uint32_t);

int do_bind(char *host6, char *host4, int port, pp_loop_t *loop, unsigned char *aes_key, struct sockaddr* seraddr, struct sockaddr* dnsaddr, void *data, int tcp_flags, int udp_flags, pp_tcp_accepted_f tcp_cb, pp_udp_read_f udp_cb);

int closing(pp_socket_t *s);

void chrswt(char *a, char *b);

void reverse(char *buf, size_t len);

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr);

int getipv4hostbyname(__const__ char *hostname, struct sockaddr_in *addr);

int getipv6hostbyname(__const__ char *hostname, struct sockaddr_in6 *addr);

int gs_parse(gs_socket_t *s, __const__ char *buf, __const__ size_t len, char istcp, gs_parse_f on_conn_cb, gs_parse_f on_read_cb);

int gs_enc_data(__const__ char *buf, __const__ int len, char **enc_buf, int *enc_len, char status, unsigned char *aes_key);

int parse_address(__const__ char *buf, __const__ int len, struct sockaddr* addr);

#endif
