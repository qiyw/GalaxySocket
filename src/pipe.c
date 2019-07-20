#include "pipe.h"
#include "thrdpool.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>

#define SOCKET_LAZY_INIT -10
#define SOCKET_NULL -20
#define MAX_LISTEN 128
#define EPOLL_TIMEOUT 500
#define SOCKET_TIMEOUT 5
#define MAX_THREAD 30
#define CLOSE_TIMEOUT 1

#define EPOLL_ENEVTS_SERVER EPOLLIN
#define EPOLL_ENEVTS_CLIENT EPOLLIN | EPOLLONESHOT

struct pp_loop_s
{
    pp_socket_t *header;
    pp_socket_t *last;
    tpool_t *tpool;
    pthread_mutex_t lock;
    int epfd;
};

typedef struct
{
    pp_socket_t *s;
    char *buf;
    int size;
    struct msghdr *msg;
} __thread_param_t;

static void *__thread_read_handle(void *args)
{
    struct epoll_event ev;
    __thread_param_t *parm = (__thread_param_t *) args;
    if(parm->s->type == PP_TYPE_TCP)
    {
        if(((pp_tcp_read_f) parm->s->read_cb)((pp_tcp_t *) parm->s, parm->buf, parm->size) != 0)
        {
            pp_close(parm->s);
        }
        else
        {
            ev.data.fd = parm->s->fd;
            ev.data.ptr = parm->s;
            ev.events = EPOLL_ENEVTS_CLIENT;
            epoll_ctl(parm->s->loop->epfd, EPOLL_CTL_MOD, parm->s->fd, &ev);
        }
        parm->s->handling = 0;
        free(parm->buf);
        free(parm);
    }
    else
    {
        if(((pp_udp_read_f) parm->s->read_cb)((pp_tcp_t *) parm->s, parm->msg, parm->buf, parm->size) != 0)
        {
            pp_close(parm->s);
        }
        else
        {
            if(parm->s->type != PP_TYPE_UDP_FAKE)
            {
                ev.data.fd = parm->s->fd;
                ev.data.ptr = parm->s;
                ev.events = EPOLL_ENEVTS_CLIENT;
                epoll_ctl(parm->s->loop->epfd, EPOLL_CTL_MOD, parm->s->fd, &ev);
            }
        }
        parm->s->handling = 0;
        free(parm->msg->msg_iov);
        free(parm->msg->msg_control);
        free(parm->msg);
        free(parm->buf);
        free(parm);
    }
    return NULL;
}

static void *__thread_connect_handle(void *args)
{
    pp_socket_t *s = (pp_socket_t *) args;
    if(((pp_tcp_accepted_f) s->accepted_cb)((pp_tcp_t *) s) != 0)
        pp_close(s);
    s->handling = 0;
    return NULL;
}

static void __socket_handle(pp_socket_t *s)
{
    __thread_param_t *parm;
    socket_t fd;
    char *buf;
    int read;
    struct sockaddr_storage addr;
    unsigned int addrl = sizeof(addr);
    if(s->type == PP_TYPE_TCP)
    {
        if(s->is_srv == 1)
        {
            fd = accept(s->fd, (struct sockaddr *) &addr, &addrl);
            pp_socket_t *client = NULL;
            if(fd > 0)
            {
                if(((pp_tcp_accepting_f) s->accepting_cb)((pp_tcp_t *) s, (pp_tcp_t **) &client) == 0 && client != NULL)
                {
                    client->fd = fd;
                    memcpy(&client->addr, &addr, addrl);
                    client->handling = 1;
                    client->accepted_cb = s->accepted_cb;
                    if(tpool_add_task(s->loop->tpool, __thread_connect_handle, (void *) client) != 0)
                        abort();
                }
            }
        }
        else
        {
            buf = (char *) malloc(sizeof(char) * PP_BUFFER_SIZE);
            read = recv(s->fd, buf, PP_BUFFER_SIZE, MSG_NOSIGNAL);
            if(read <= 0)
            {
                free(buf);
                pp_close(s);
            }
            else
            {
                parm = (__thread_param_t *) malloc(sizeof(__thread_param_t));
                parm->s = s;
                parm->buf = buf;
                parm->size = read;
                s->handling = 1;
                if(tpool_add_task(s->loop->tpool, __thread_read_handle, (void *) parm) != 0)
                    abort();
            }
        }
    }
    else
    {
        buf = (char *) malloc(sizeof(char) * PP_BUFFER_SIZE);
        struct msghdr *msg = (struct msghdr *) malloc(sizeof(struct msghdr));
        char *cntrlbuf = (char *) malloc(sizeof(char) * 64);
        struct iovec *iov = (struct iovec *) malloc(sizeof(struct iovec));
        memset(cntrlbuf, '\0', 64);
        msg->msg_control = cntrlbuf;
        msg->msg_controllen = 64;
        msg->msg_name = &addr;
        msg->msg_namelen = addrl;
        iov[0].iov_base = buf;
        iov[0].iov_len = PP_BUFFER_SIZE;
        msg->msg_iov = iov;
        msg->msg_iovlen = 1;
        pp_socket_t *client = NULL;
        read = recvmsg(s->fd, msg, 0);
        if(read <= 0)
        {
            if(s->is_srv != 1)
                pp_close(client);
            free(iov);
            free(cntrlbuf);
            free(msg);
            free(buf);
        }
        else
        {
            if(s->is_srv == 1)
            {
                if(((pp_udp_accept_f) s->accepting_cb)((pp_udp_t *) s, (pp_udp_t **) &client) == 0 && client != NULL)
                {
                    client->type = PP_TYPE_UDP_FAKE;
                    client->fd = s->fd;
                    client->udp_timeout = time(NULL);
                    memcpy(&client->addr, &addr, addrl);
                    parm = (__thread_param_t *) malloc(sizeof(__thread_param_t));
                    parm->msg = msg;
                    parm->buf = buf;
                    parm->s = client;
                    parm->size = read;
                    client->read_cb = s->read_cb;
                    client->handling = 1;
                    if(tpool_add_task(s->loop->tpool, __thread_read_handle, (void *) parm) != 0)
                        abort();
                }
                else
                {
                    free(iov);
                    free(cntrlbuf);
                    free(msg);
                    free(buf);
                }
            }
            else
            {
                parm = (__thread_param_t *) malloc(sizeof(__thread_param_t));
                parm->msg = msg;
                parm->buf = buf;
                parm->s = s;
                parm->size = read;
                s->handling = 1;
                if(tpool_add_task(s->loop->tpool, __thread_read_handle, (void *) parm) != 0)
                    abort();
            }
        }
    }
}

static void __socket_close_event(pp_loop_t *loop)
{
    pp_socket_t *s, *p;
    pthread_mutex_lock(&loop->lock);
    s = loop->header;
    p = NULL;
    while(s != NULL)
    {
        if(s->active == PP_ACTIVE_CLOSE && s->handling == 0)
        {
            if(s->pipe_target != NULL && s->pipe_target->handling != 0)
            {
                p = s;
                s = s->next;
                continue;
            }
            if(p == NULL)
                loop->header = s->next;
            else
                p->next = s->next;
            if(s->next == NULL)
                loop->last = p;
            char type = s->type;
            socket_t fd = s->fd;
            pp_socket_t *c = s;
            s = s->next;
            if(c->close_cb != NULL)
            {
                c->close_cb(c);
            }
            else
            {
                printf("WARNING: you should free socket in closing call back!\n");
                free(c);
            }
            if(type != PP_TYPE_UDP_FAKE)
            {
                if(fd > 0)
                {
                    shutdown(fd, SHUT_RDWR);
                    close(fd);
                }
            }
            continue;
        }
        if(s->type == PP_TYPE_UDP_FAKE)
        {
            if(difftime(time(NULL), s->udp_timeout) > SOCKET_TIMEOUT)
                pp_close(s);
        }
        p = s;
        s = s->next;
    }
    pthread_mutex_unlock(&loop->lock);
}

static int __set_timeout(socket_t fd)
{
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT;
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) != 0)
        return 1;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
}

static int __set_reuseaddr(socket_t fd)
{
    int on = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

static int __set_non_blocking(socket_t fd)
{
//     int flags;
//     flags = fcntl(fd, F_GETFL, 0);
//     if(flags == -1)
//         return -1;
//     flags |= O_NONBLOCK;
//     if(fcntl(fd, F_SETFL, flags) == -1)
//         return -1;
    return 0;
}

pp_loop_t *pp_loop_init()
{
    pp_loop_t *loop = (pp_loop_t *) malloc(sizeof(pp_loop_t));
    loop->header = NULL;
    if(pthread_mutex_init(&loop->lock, NULL) != 0)
    {
        free(loop);
        return NULL;
    }
    loop->tpool = tpool_create(MAX_THREAD);
    if(loop->tpool == NULL)
    {
        free(loop);
        return NULL;
    }
    loop->epfd = epoll_create1(0);
    if(loop->epfd < 0)
    {
        free(loop);
        return NULL;
    }
    return loop;
}

int pp_tcp_init(pp_loop_t *loop, pp_tcp_t *tcp, pp_closing_f cb)
{
    pthread_mutex_lock(&loop->lock);
    if(loop->header == NULL)
    {
        loop->header = (pp_socket_t *) tcp;
        loop->last = (pp_socket_t *) tcp;
    }
    else
    {
        loop->last->next = (pp_socket_t *) tcp;
        loop->last = (pp_socket_t *) tcp;
    }
    pthread_mutex_unlock(&loop->lock);
    tcp->loop = loop;
    tcp->pipe_target = NULL;
    //we don't know ipv4 or ipv6
    //so not create socket in there
    tcp->fd = SOCKET_LAZY_INIT;
    tcp->type = PP_TYPE_TCP;
    tcp->is_srv = 0;
    tcp->handling = 0;
    tcp->active = PP_ACTIVE_NOTHING;
    tcp->accepting_cb = NULL;
    tcp->accepted_cb = NULL;
    tcp->read_cb = NULL;
    tcp->close_cb = cb;
    return 0;
}

int pp_tcp_bind(pp_tcp_t *tcp, struct sockaddr *addr, int flags)
{
    int on = 1;
    if(tcp->fd != SOCKET_LAZY_INIT)
        return 1;
    tcp->fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->fd <= 0)
        return 1;
    __set_timeout(tcp->fd);
    if(addr->sa_family == AF_INET6)
    {
        if(flags == PP_TCP_IPV6ONLY)
        {
            if(setsockopt(tcp->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(tcp->fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&tcp->addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(bind(tcp->fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&tcp->addr, addr, sizeof(struct sockaddr_in));
    }
    if(__set_reuseaddr(tcp->fd) != 0)
        return 1;
    if(__set_non_blocking(tcp->fd) != 0)
        return 1;
    return 0;
}

int pp_tcp_listen(pp_tcp_t *tcp, pp_tcp_accepting_f cb, pp_tcp_accepted_f rcb)
{
    struct epoll_event ev;
    int qlen = 5;
    int rtn = listen(tcp->fd, MAX_LISTEN);
    if(rtn != 0)
        return rtn;
    if(setsockopt(tcp->fd, 6, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0)
        return 1;
    tcp->is_srv = 1;
    tcp->accepting_cb = cb;
    tcp->accepted_cb = rcb;
    tcp->active = PP_ACTIVE_EVENT;
    ev.data.fd = tcp->fd;
    ev.data.ptr = tcp;
    ev.events = EPOLL_ENEVTS_SERVER;
    epoll_ctl(tcp->loop->epfd, EPOLL_CTL_ADD, tcp->fd, &ev);
    return 0;
}

int pp_tcp_connect(pp_tcp_t *tcp, struct sockaddr *addr)
{
    if(tcp->fd != SOCKET_LAZY_INIT)
        return 1;
    tcp->fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->fd <= 0)
        return 1;
    if(__set_non_blocking(tcp->fd) != 0)
        return 1;
    __set_timeout(tcp->fd);
    if(addr->sa_family == AF_INET6)
    {
        if(connect(tcp->fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&tcp->addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(connect(tcp->fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&tcp->addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int pp_tcp_read_start(pp_tcp_t *tcp, pp_tcp_read_f cb)
{
    struct epoll_event ev;
    if(tcp->is_srv == 1)
        return 1;
    if(tcp->fd <= 0)
        return 1;
    tcp->read_cb = cb;
    tcp->active = PP_ACTIVE_EVENT;
    ev.data.fd = tcp->fd;
    ev.data.ptr = tcp;
    ev.events = EPOLL_ENEVTS_CLIENT;
    epoll_ctl(tcp->loop->epfd, EPOLL_CTL_ADD, tcp->fd, &ev);
    return 0;
}
/*
int pp_tcp_accept(pp_tcp_t *server, pp_tcp_t *client)
{
    struct epoll_event ev;
    unsigned int s = sizeof(client->addr);
    if(client->is_srv != 0)
        return 1;
    socket_t fd = accept(server->fd, (struct sockaddr *) &client->addr, &s);
    if(fd <= 0)
    {
        ((pp_socket_t *) server)->handling = 0;
        ev.data.fd = server->fd;
        ev.data.ptr = server;
        ev.events = EPOLL_ENEVTS_CLIENT;
        epoll_ctl(server->loop->epfd, EPOLL_CTL_MOD, server->fd, &ev);
        return 1;
    }
    if(__set_non_blocking(fd) != 0)
        return 1;
    client->fd = fd;
    ((pp_socket_t *) server)->handling = 0;
    ev.data.fd = server->fd;
    ev.data.ptr = server;
    ev.events = EPOLL_ENEVTS_CLIENT;
    epoll_ctl(server->loop->epfd, EPOLL_CTL_MOD, server->fd, &ev);
    return 0;
}*/

int pp_tcp_pipe_bind(pp_tcp_t *stcp, pp_tcp_t *ttcp)
{
    return pp_socket_pipe_bind((pp_socket_t *) stcp, (pp_socket_t *) ttcp);
}

int pp_tcp_fast_write(pp_tcp_t *tcp, struct sockaddr *addr, __const__ char *buf, __const__ int len)
{
    if(tcp->fd != SOCKET_LAZY_INIT)
        return 1;
    tcp->fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->fd <= 0)
        return 1;
    if(__set_non_blocking(tcp->fd) != 0)
        return 1;
    __set_timeout(tcp->fd);
    if(addr->sa_family == AF_INET6)
    {
        if(sendto(tcp->fd, buf, len, MSG_FASTOPEN, addr, sizeof(struct sockaddr_in6)) <= 0)
            return 1;
        memcpy(&tcp->addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(sendto(tcp->fd, buf, len, MSG_FASTOPEN, addr, sizeof(struct sockaddr_in)) <= 0)
            return 1;
        memcpy(&tcp->addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int pp_tcp_write(pp_tcp_t *tcp, __const__ char *buf, __const__ int len)
{
    if(tcp->fd <= 0)
        return 1;
    if(tcp->active == PP_ACTIVE_CLOSE)
        return 1;
    return send(tcp->fd, buf, len, MSG_NOSIGNAL) <= 0;
}

int pp_tcp_pipe_write(pp_tcp_t *tcp, __const__ char *buf, __const__ int len)
{
    if(tcp->pipe_target == NULL)
        return 1;
    return pp_tcp_write(tcp->pipe_target, buf, len);
}

int pp_udp_init(pp_loop_t *loop, pp_udp_t *udp, pp_closing_f cb)
{
    pthread_mutex_lock(&loop->lock);
    if(loop->header == NULL)
    {
        loop->header = (pp_socket_t *) udp;
        loop->last = (pp_socket_t *) udp;
    }
    else
    {
        loop->last->next = (pp_socket_t *) udp;
        loop->last = (pp_socket_t *) udp;
    }
    pthread_mutex_unlock(&loop->lock);
    udp->loop = loop;
    udp->pipe_target = NULL;
    //we don't know ipv4 or ipv6
    //so not create socket in there
    udp->fd = SOCKET_LAZY_INIT;
    udp->type = PP_TYPE_UDP;
    udp->is_srv = 0;
    udp->handling = 0;
    udp->active = PP_ACTIVE_NOTHING;
    udp->accepting_cb = NULL;
    udp->accepted_cb = NULL;
    udp->read_cb = NULL;
    udp->close_cb = cb;
    return 0;
}

int pp_udp_bind(pp_udp_t *udp, struct sockaddr *addr, int flags)
{
    int on = 1;
    if(udp->fd != SOCKET_LAZY_INIT)
        return 1;
    udp->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if(udp->fd <= 0)
        return 1;
    __set_timeout(udp->fd);
    if(addr->sa_family == AF_INET6)
    {
        if((flags & 1) == 1)
        {
            if(setsockopt(udp->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return 1;
        }
        if(((flags >> 1) & 1) == 1)
        {
            //need root
            if(setsockopt(udp->fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
                return 1;
            if(setsockopt(udp->fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(udp->fd, addr, sizeof(struct sockaddr_in6)) != 0)
            return 1;
        memcpy(&udp->addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        if(((flags >> 1) & 1) == 1)
        {
            //need root
            if(setsockopt(udp->fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) != 0)
                return 1;
            if(setsockopt(udp->fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) != 0)
                return 1;
        }
        if(bind(udp->fd, addr, sizeof(struct sockaddr_in)) != 0)
            return 1;
        memcpy(&udp->addr, addr, sizeof(struct sockaddr_in));
    }
    if(__set_reuseaddr(udp->fd) != 0)
        return 1;
    if(__set_non_blocking(udp->fd) != 0)
        return 1;
    return 0;
}

int pp_udp_listen(pp_udp_t *udp, pp_udp_accept_f cb, pp_udp_read_f rcb)
{
    struct epoll_event ev;
    udp->is_srv = 1;
    udp->accepting_cb = cb;
    udp->read_cb = rcb;
    udp->active = PP_ACTIVE_EVENT;
    ev.data.fd = udp->fd;
    ev.data.ptr = udp;
    ev.events = EPOLL_ENEVTS_SERVER;
    epoll_ctl(udp->loop->epfd, EPOLL_CTL_ADD, udp->fd, &ev);
    return 0;
}

int pp_udp_connect(pp_udp_t *udp, struct sockaddr *addr)
{
    if(udp->fd != SOCKET_LAZY_INIT)
        return 1;
    udp->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if(udp->fd <= 0)
        return 1;
    if(__set_non_blocking(udp->fd) != 0)
        return 1;
    __set_timeout(udp->fd);
    if(addr->sa_family == AF_INET6)
    {
        memcpy(&udp->addr, addr, sizeof(struct sockaddr_in6));
    }
    else
    {
        memcpy(&udp->addr, addr, sizeof(struct sockaddr_in));
    }
    return 0;
}

int pp_udp_read_start(pp_udp_t *udp, pp_udp_read_f cb)
{
    struct epoll_event ev;
    if(udp->fd <= 0)
        return 1;
    udp->read_cb = cb;
    udp->active = PP_ACTIVE_EVENT;
    ev.data.fd = udp->fd;
    ev.data.ptr = udp;
    ev.events = EPOLL_ENEVTS_CLIENT;
    epoll_ctl(udp->loop->epfd, EPOLL_CTL_ADD, udp->fd, &ev);
    return 0;
}

int pp_udp_pipe_bind(pp_udp_t *sudp, pp_udp_t *tudp)
{
    return pp_socket_pipe_bind((pp_socket_t *) sudp, (pp_socket_t *) tudp);
}

int pp_udp_write(pp_udp_t *udp, __const__ char *buf, __const__ int len)
{
    if(udp->fd <= 0)
        return 1;
    if(udp->type == PP_TYPE_UDP_FAKE)
        udp->udp_timeout = time(NULL);
    return sendto(udp->fd, buf, len, 0, (struct sockaddr *) &udp->addr, sizeof(struct sockaddr_storage)) <= 0;
}

int pp_udp_pipe_write(pp_udp_t *udp, __const__ char *buf, __const__ int len)
{
    if(udp->pipe_target == NULL)
        return 1;
    return pp_udp_write(udp->pipe_target, buf, len);
}

int pp_loop_run(pp_loop_t *loop)
{
    struct epoll_event events[MAX_THREAD];
    int wait_count;
    if(loop->header == NULL)
        return 1;
    for(;;)
    {
        __socket_close_event(loop);
        wait_count = epoll_wait(loop->epfd, events, MAX_THREAD, EPOLL_TIMEOUT);
        for(int i = 0 ; i < wait_count; i++)
        {
            uint32_t events_flags = events[i].events;
            if ( events_flags & EPOLLERR || events_flags & EPOLLHUP || (! events_flags & EPOLLIN)) {
                pp_close((pp_socket_t *) events[i].data.ptr);
                continue;
            }
            __socket_handle((pp_socket_t *) events[i].data.ptr);
        }
    }
    return 0;
}

int pp_socket_pipe_bind(pp_socket_t *ss, pp_socket_t *st)
{
    ss->pipe_target = st;
    st->pipe_target = ss;
    return 0;
}

int pp_close(pp_socket_t *socket)
{
    if(socket->active == PP_ACTIVE_EVENT && socket->fd > 0)
        epoll_ctl(socket->loop->epfd, EPOLL_CTL_DEL, socket->fd, NULL);
    socket->active = PP_ACTIVE_CLOSE;
    if(socket->pipe_target != NULL)
    {
        socket->pipe_target->active = PP_ACTIVE_CLOSE;
    }
    return 0;
}

socket_t pp_fileno(pp_socket_t *socket)
{
    if(socket->fd > 0)
        return socket->fd;
    else
        return -1;
}

pp_socket_t *pp_pipe_socket(pp_socket_t *socket)
{
    return socket->pipe_target;
}

pp_loop_t *pp_get_loop(pp_socket_t *socket)
{
    return socket->loop;
}
