#ifndef _PIPE_H
#define _PIPE_H

#include <sys/socket.h>
#include <time.h>

#define PP_TCP_IPV6ONLY 1

#define PP_UDP_IPV6ONLY 1
#define PP_UDP_TPROXY 2

#define PP_TYPE_TCP 1
#define PP_TYPE_UDP 2
#define PP_TYPE_UDP_FAKE 3

#define PP_ACTIVE_CLOSE 0x0F
#define PP_ACTIVE_NOTHING 0
#define PP_ACTIVE_EVENT 1

#define PP_BUFFER_SIZE 40960

typedef struct pp_loop_s pp_loop_t;
typedef struct pp_socket_s pp_socket_t;
typedef struct pp_socket_s pp_tcp_t;
typedef struct pp_socket_s pp_udp_t;

typedef int socket_t;

typedef int (*pp_tcp_accepting_f)(pp_tcp_t *srv, pp_tcp_t **);

typedef int (*pp_tcp_accepted_f)(pp_tcp_t *);

typedef int (*pp_tcp_read_f)(pp_tcp_t *, __const__ char *, __const__ int);

typedef int (*pp_closing_f)(pp_socket_t *);

typedef int (*pp_udp_accept_f)(pp_udp_t *srv, pp_udp_t **);

typedef int (*pp_udp_read_f)(pp_udp_t *, __const__ struct msghdr *, __const__ char *, __const__ int);

struct pp_socket_s
{
    pp_loop_t *loop;
    pp_socket_t *next;
    pp_socket_t *pipe_target;
    struct sockaddr_storage addr;
    time_t udp_timeout;
    socket_t fd;
    char type;
    char is_srv;
    char handling;
    char active;
    void *accepting_cb;
    void *accepted_cb;
    void *read_cb;
    pp_closing_f close_cb;
};

pp_loop_t *pp_loop_init();

int pp_tcp_init(pp_loop_t *loop, pp_tcp_t *tcp, pp_closing_f cb);

int pp_tcp_bind(pp_tcp_t *tcp, struct sockaddr *addr, int flags);

int pp_tcp_listen(pp_tcp_t *tcp, pp_tcp_accepting_f cb, pp_tcp_accepted_f rcb);

int pp_tcp_connect(pp_tcp_t *tcp, struct sockaddr *addr);

int pp_tcp_read_start(pp_tcp_t *tcp, pp_tcp_read_f cb);

int pp_tcp_pipe_bind(pp_tcp_t *stcp, pp_tcp_t *ttcp);

int pp_tcp_fast_write(pp_tcp_t *tcp, struct sockaddr *addr, __const__ char *buf, __const__ int len);

int pp_tcp_write(pp_tcp_t *tcp, __const__ char *buf, __const__ int len);

int pp_tcp_pipe_write(pp_tcp_t *tcp, __const__ char *buf, __const__ int len);

int pp_udp_init(pp_loop_t *loop, pp_udp_t *udp, pp_closing_f cb);

int pp_udp_bind(pp_udp_t *udp, struct sockaddr *addr, int flags);

int pp_udp_listen(pp_udp_t *udp, pp_udp_accept_f cb, pp_udp_read_f rcb);

int pp_udp_connect(pp_udp_t *udp, struct sockaddr *addr);

int pp_udp_read_start(pp_udp_t *udp, pp_udp_read_f cb);

int pp_udp_pipe_bind(pp_udp_t *sudp, pp_udp_t *tudp);

int pp_udp_write(pp_udp_t *udp, __const__ char *buf, __const__ int len);

int pp_udp_pipe_write(pp_udp_t *udp, __const__ char *buf, __const__ int len);

int pp_loop_run(pp_loop_t *loop);

int pp_socket_pipe_bind(pp_socket_t *ss, pp_socket_t *st);

int pp_close(pp_socket_t *socket);

socket_t pp_fileno(pp_socket_t *socket);

pp_socket_t *pp_pipe_socket(pp_socket_t *socket);

pp_loop_t *pp_get_loop(pp_socket_t *socket);

struct sockaddr *pp_address(pp_socket_t *socket);

#endif
