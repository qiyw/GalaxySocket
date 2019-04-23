#ifndef _SOCKS5_H
#define _SOCKS5_H

#define S5_VERSION 0x05
#define S5_SUB_VERSION 0x01

#define S5_STATUS_BEGIN 0
#define S5_STATUS_AUTHENTICATION 1
#define S5_STATUS_END_AUTH 2
#define S5_STATUS_END_CONNECT 3

#include "common.h"
#include "time.h"

typedef struct
{
    char status;
    char needauth;
    char *user;
    char *passwd;
    //0: not connect
    //1: tcp
    //2: udp
    char type;
} gs_socks5_t;

typedef struct gs_s5_socket_s
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    gs_socks5_t *s5;
    struct sockaddr *server;
    char *addrbuf;
    int addrlen;
    struct gs_s5_socket_s *map;
} gs_s5_socket_t;

void socks5_parse(gs_s5_socket_t *s, __const__ char *buf, __const__ size_t len);

#endif
