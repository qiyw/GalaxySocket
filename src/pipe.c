#include "pipe.h"
#include "thrdpool.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>

#define SOCKET_LAZY_INIT -10
#define SOCKET_NULL -20
#define MAX_LISTEN 128
#define SELECT_TIMEOUT 100000
#define SOCKET_TIMEOUT 5
#define MAX_THREAD 30

struct pp_loop_s
{
    pp_socket_t *header;
    pp_socket_t *last;
    tpool_t *tpool;
    pthread_mutex_t lock;
    int count;
};

static struct pp_loop_array_s
{
    int len;
    pp_loop_t **loops;
    pthread_mutex_t lock;
} __loop_array;

static void __sighandler(int signum)
{
    while(__loop_array.len--)
    {
        pp_loop_t *loop = __loop_array.loops[__loop_array.len];
        if(loop->header == NULL)
            continue;
        for(pp_socket_t *s = loop->header; s != NULL; s = s->next)
        {
            if(s->active != PP_ACTIVE_CLOSE && s->type != PP_TYPE_UDP_FAKE && s->fd > 0)
            {
                shutdown(s->fd, SHUT_RDWR);
                close(s->fd);
            }
        }
    }
    exit(0);
}

static void __add_loop(pp_loop_t *loop)
{
    pthread_mutex_lock(&__loop_array.lock);
    if(__loop_array.len == 0)
        __loop_array.loops = (pp_loop_t **) malloc(sizeof(pp_loop_t *));
    else
        __loop_array.loops = (pp_loop_t **) realloc(__loop_array.loops, sizeof(pp_loop_t *) * (__loop_array.len + 1));
    __loop_array.loops[__loop_array.len] = loop;
    __loop_array.len++;
    pthread_mutex_unlock(&__loop_array.lock);
}

static void *__thread_udp_read(void *args)
{
    pp_udp_t *client = (pp_udp_t *) ((void **) args)[0];
    struct msghdr *msg = (struct msghdr *) ((void **) args)[1];
    char *buf = (char *) ((void **) args)[2];
    int *len = (int *) ((void **) args)[3];
    if(((pp_udp_read_f) client->read_cb)((pp_udp_t *) client, msg, buf, *len) != 0)
        pp_close((pp_socket_t *) client);
    free(args);
    free(len);
    free(buf);
    free(msg->msg_iov);
    free(msg->msg_control);
    free(msg);
    return NULL;
}

static void *__thread_handle(void *args)
{
    pp_socket_t *s = (pp_socket_t *) args;
    char buf[PP_BUFFER_SIZE];
    int read;
    if(s->type == PP_TYPE_TCP)
    {
        if(s->is_srv == 1)
        {
            ((pp_tcp_connect_f) s->conn_cb)((pp_tcp_t *) s);
        }
        else
        {
            read = recv(s->fd, buf, PP_BUFFER_SIZE, MSG_NOSIGNAL);
            if(read <= 0)
            {
                pp_close(s);
            }
            else
            {
                if(((pp_tcp_read_f) s->read_cb)((pp_tcp_t *) s, buf, read) != 0)
                    pp_close(s);
            }
        }
    }
    else
    {
        struct msghdr *msg = (struct msghdr *) malloc(sizeof(struct msghdr));
        char cntrlbuf[64];
        struct iovec *iov = (struct iovec *) malloc(sizeof(struct iovec));
        memset(cntrlbuf, '\0', 64);
        struct sockaddr_storage addr;
        pp_socket_t *client = NULL;
        if(s->is_srv == 1)
        {
            if(((pp_udp_accept_f) s->conn_cb)((pp_udp_t *) s, (pp_udp_t **) &client) == 0 && client != NULL)
            {
                char *tbuf = (char *) malloc(sizeof(char) * PP_BUFFER_SIZE);
                int *tread = (int *) malloc(sizeof(int));
                char *tcntrlbuf = (char *) malloc(sizeof(char) * 64);
                client->type = PP_TYPE_UDP_FAKE;
                client->fd = s->fd;
                client->udp_timeout = time(NULL);
                msg->msg_name = &client->addr;
                msg->msg_namelen = sizeof(struct sockaddr_storage);
                msg->msg_control = tcntrlbuf;
                msg->msg_controllen = 64;
                iov[0].iov_base = tbuf;
                iov[0].iov_len = PP_BUFFER_SIZE;
                msg->msg_iov = iov;
                msg->msg_iovlen = 1;
                *tread = recvmsg(client->fd, msg, 0);
                if(*tread <= 0)
                {
                    pp_close(client);
                }
                else
                {
                    client->read_cb = s->read_cb;
                    void **args = malloc(sizeof(void *) * 4);
                    args[0] = client;
                    args[1] = msg;
                    args[2] = tbuf;
                    args[3] = tread;
                    if(tpool_add_task(client->loop->tpool, __thread_udp_read, (void *) args) != 0)
                        abort();
                }
            }
        }
        else
        {
            client = s;
            msg->msg_name = &addr;
            msg->msg_namelen = sizeof(struct sockaddr_storage);
            msg->msg_control = cntrlbuf;
            msg->msg_controllen = 64;
            iov[0].iov_base = buf;
            iov[0].iov_len = PP_BUFFER_SIZE;
            msg->msg_iov = iov;
            msg->msg_iovlen = 1;
            read = recvmsg(client->fd, msg, 0);
            if(read <= 0)
            {
                pp_close(client);
            }
            else
            {
                if(((pp_udp_read_f) s->read_cb)((pp_udp_t *) client, msg, buf, read) != 0)
                    pp_close(client);
            }
            free(iov);
            free(msg);
        }
    }
    s->handling = 0;
    return NULL;
}

static int __set_timeout(socket_t fd)
{
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT;
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) != 0)
        return 1;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
}

pp_loop_t *pp_loop_init()
{
    pp_loop_t *loop = (pp_loop_t *) malloc(sizeof(pp_loop_t));
    loop->header = NULL;
    loop->count = 0;
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
    loop->count++;
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
    tcp->conn_cb = NULL;
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
    return 0;
}

int pp_tcp_listen(pp_tcp_t *tcp, pp_tcp_connect_f cb)
{
    int qlen = 5;
    int rtn = listen(tcp->fd, MAX_LISTEN);
    if(rtn != 0)
        return rtn;
    if(setsockopt(tcp->fd, 6, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0)
        return 1;
    tcp->is_srv = 1;
    tcp->conn_cb = cb;
    tcp->active = PP_ACTIVE_EVENT;
    return 0;
}

int pp_tcp_connect(pp_tcp_t *tcp, struct sockaddr *addr)
{
    if(tcp->fd != SOCKET_LAZY_INIT)
        return 1;
    tcp->fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(tcp->fd <= 0)
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
    if(tcp->is_srv != 0)
        return 1;
    if(tcp->fd <= 0)
        return 1;
    tcp->read_cb = cb;
    tcp->active = PP_ACTIVE_EVENT;
    return 0;
}

int pp_tcp_accept(pp_tcp_t *server, pp_tcp_t *client)
{
    unsigned int s = sizeof(client->addr);
    if(client->is_srv != 0)
        return 1;
    socket_t fd = accept(server->fd, (struct sockaddr *) &client->addr, &s);
    if(fd <= 0)
        return 1;
    client->fd = fd;
    return 0;
}

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
    loop->count++;
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
    udp->conn_cb = NULL;
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
    return 0;
}

int pp_udp_listen(pp_udp_t *udp, pp_udp_accept_f cb, pp_udp_read_f rcb)
{
    udp->is_srv = 1;
    udp->conn_cb = cb;
    udp->read_cb = rcb;
    udp->active = PP_ACTIVE_EVENT;
    return 0;
}

int pp_udp_connect(pp_udp_t *udp, struct sockaddr *addr)
{
    if(udp->fd != SOCKET_LAZY_INIT)
        return 1;
    udp->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if(udp->fd <= 0)
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
    if(udp->fd <= 0)
        return 1;
    udp->read_cb = cb;
    udp->active = PP_ACTIVE_EVENT;
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
    fd_set fs;
    socket_t max_fd;
    int selrtn;
    struct timeval timeout;
    pp_socket_t **sock_lst;
    pp_socket_t **sock_lst_tmp;
    pp_socket_t *s, *p;
    static char shf = 0;
    if(shf == 0)
    {
        signal(SIGINT, __sighandler);
        signal(SIGTERM, __sighandler);
        pthread_mutex_init(&__loop_array.lock, NULL);
        __loop_array.len = 0;
        shf = 1;
    }
    __add_loop(loop);
    while(1)
    {
        FD_ZERO(&fs);
        max_fd = 0;
        timeout.tv_sec = 0;
        timeout.tv_usec = SELECT_TIMEOUT;
        pthread_mutex_lock(&loop->lock);
        sock_lst = malloc(sizeof(pp_socket_t *) * (loop->count + 1));
        sock_lst_tmp = sock_lst;
        s = loop->header;
        p = NULL;
        while(s != NULL)
        {
            if(s->active == PP_ACTIVE_CLOSE && s->handling == 0)
            {
                if(s->pipe_target != NULL && s->pipe_target->handling != 0)
                    continue;
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
                    shutdown(fd, SHUT_RDWR);
                    close(fd);
                }
                loop->count--;
                continue;
            }
            if(s->active == PP_ACTIVE_EVENT && s->handling == 0 && s->type != PP_TYPE_UDP_FAKE)
            {
                if(s->pipe_target == NULL || (s->pipe_target != NULL && s->pipe_target->active == PP_ACTIVE_EVENT))
                {
                    if(s->fd > max_fd)
                        max_fd = s->fd;
                    FD_SET(s->fd, &fs);
                    *sock_lst_tmp++ = s;
                }
            }
            if(s->type == PP_TYPE_UDP_FAKE)
            {
                if(difftime(time(NULL), s->udp_timeout) > SOCKET_TIMEOUT)
                    pp_close(s);
            }
            p = s;
            s = s->next;
        }
        *sock_lst_tmp = NULL;
        pthread_mutex_unlock(&loop->lock);
        if(max_fd != 0)
        {
            selrtn = select(max_fd + 1, &fs, NULL, NULL, &timeout);
            switch(selrtn)
            {
                case -1:
                    return 1;
                case 0:
                    break;
                default:
                    sock_lst_tmp = sock_lst;
                    while((s = *sock_lst_tmp++) != NULL)
                    {
                        if(FD_ISSET(s->fd, &fs))
                        {
                            s->handling = 1;
                            if(tpool_add_task(loop->tpool, __thread_handle, (void *) s) != 0)
                                abort();
                        }
                    }
                    break;
            }
        }
        else
        {
            usleep(SELECT_TIMEOUT);
        }
        free(sock_lst);
    }
}

int pp_socket_pipe_bind(pp_socket_t *ss, pp_socket_t *st)
{
    ss->pipe_target = st;
    st->pipe_target = ss;
    return 0;
}

int pp_close(pp_socket_t *socket)
{
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
