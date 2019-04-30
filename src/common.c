#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common.h"
#include "aes.h"
#include "time.h"
#include "log.h"

#define HEADER_SIGN 0xff

typedef struct
{
    unsigned char sign;
    char act;
    //0:tcp 1:udp
    char net;
    char status;
    uint16_t total_len;
    uint16_t data_len;
} __attribute__ ((__packed__)) s5_header_t;

typedef struct
{
    uv_getaddrinfo_t ug;
    uint16_t port;
    gs_socket_t *s;
    gs_getaddrinfo_cb_f cb;
} gs_getaddrinfo_t;

static struct addrinfo *__gethostbyname(__const__ char *hostname)
{
    struct addrinfo *result = NULL;
    struct addrinfo hints;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_flags = 0;
    if(getaddrinfo(hostname, NULL, &hints, &result) != 0)
        return NULL;
    return result;
}

static int __do_tcp_bind(struct sockaddr *addr, uv_tcp_t *server, uv_connection_cb cb, unsigned int flags)
{
    LOG_DEBUG("__do_tcp_bind start\n");
    int en;
    if((en = uv_tcp_bind(server, addr, flags)))
    {
        LOG_ERR("tcp bind failed: %s\n", uv_strerror(en));
        return 1;
    }
    if((en = uv_listen((uv_stream_t *) server, DEFAULT_BACKLOG, cb)))
    {
        LOG_ERR("tcp listen failed: %s\n", uv_strerror(en));
        return 1;
    }
    LOG_DEBUG("__do_tcp_bind end\n");
    return 0;
}

static int __do_udp_bind(struct sockaddr *addr, uv_udp_t *server, uv_udp_recv_cb cb, unsigned int flags)
{
    LOG_DEBUG("__do_udp_bind start\n");
    int en;
    if((en = uv_udp_bind(server, addr, flags)))
    {
        LOG_ERR("udp bind failed: %s\n", uv_strerror(en));
        return 1;
    }
    uv_udp_recv_start(server, alloc_buffer, cb);
    LOG_DEBUG("__do_udp_bind end\n");
    return 0;
}

static void __on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
    LOG_DEBUG("__on_resolved start\n");
    struct sockaddr_storage addr;
    gs_getaddrinfo_t *_r = (gs_getaddrinfo_t *) resolver;
    manager_unreference(_r->s);
    if(status != 0)
    {
        _r->cb(_r->s, status, NULL);
        free(resolver);
        return;
    }
    if(res == NULL)
    {
        _r->cb(_r->s, 1, NULL);
        free(resolver);
        return;
    }
    if(manager_isclosed(_r->s))
    {
        free(resolver);
        return;
    }
    if(res->ai_family == AF_INET)
    {
        memcpy(&addr, res->ai_addr, sizeof(struct sockaddr_in));
        ((struct sockaddr_in *) &addr)->sin_port = _r->port;
    }
    if(res->ai_family == AF_INET6)
    {
        memcpy(&addr, res->ai_addr, sizeof(struct sockaddr_in6));
        ((struct sockaddr_in6 *) &addr)->sin6_port = _r->port;
    }
    _r->cb(_r->s, 0, (struct sockaddr *) &addr);
    free(resolver);
    uv_freeaddrinfo(res);
    LOG_DEBUG("__on_resolved end\n");
}

int do_bind(char *host6, char *host4, int port, uv_tcp_t **tcp, uv_connection_cb tcp_cb, uv_udp_t **udp, uv_udp_recv_cb udp_cb)
{
    LOG_DEBUG("do_bind start\n");
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;

    //ipv6
    if(getipv6hostbyname(host6, &addr6) != 0)
    {
        LOG_ERR("unknown ip6 host name: %s\n", host6);
        return 1;
    }
    addr6.sin6_port = port;
    reverse((char *) &addr6.sin6_port, 2);
    if(tcp != NULL && tcp_cb != NULL)
    {
        if(__do_tcp_bind((struct sockaddr *) &addr6, *tcp, tcp_cb, UV_TCP_IPV6ONLY) != 0)
            return 1;
    }
    if(udp != NULL && udp_cb != NULL)
    {
        if(__do_udp_bind((struct sockaddr *) &addr6, *udp, udp_cb, UV_UDP_IPV6ONLY | UV_UDP_REUSEADDR) != 0)
            return 1;
    }
    LOG_INFO("server listen on %s:%d\n", host6, port);

    //ipv4
    if(getipv4hostbyname(host4, &addr) != 0)
    {
        LOG_ERR("unknown ip4 host name: %s\n", host4);
        return 1;
    }
    addr.sin_port = port;
    reverse((char *) &addr.sin_port, 2);
    if(tcp != NULL && tcp_cb != NULL)
    {
        tcp++;
        if(__do_tcp_bind((struct sockaddr *) &addr, *tcp, tcp_cb, 0) != 0)
            return 1;
    }
    if(udp != NULL && udp_cb != NULL)
    {
        udp++;
        if(__do_udp_bind((struct sockaddr *) &addr6, *udp, udp_cb, UV_UDP_REUSEADDR) != 0)
            return 1;
    }
    LOG_INFO("server listen on %s:%d\n", host4, port);

    LOG_DEBUG("do_bind end\n");
    return 0;
}

void chrswt(char *a, char *b)
{
    *a = *a ^ *b;
    *b = *a ^ *b;
    *a = *a ^ *b;
}

void reverse(char *buf, size_t len)
{
    int hl = len>>1;
    for(int i = 0; i < hl; i++)
    {
        chrswt(&buf[i], &buf[len - i - 1]);
    }
}

int getfirsthostbyname(__const__ char *hostname, struct sockaddr* addr)
{
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    if(result->ai_family == AF_INET)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
    }
    if(result->ai_family == AF_INET6)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in6));
    }
    freeaddrinfo(result);
    return 0;
}

int getipv4hostbyname(__const__ char *hostname, struct sockaddr_in *addr)
{
    struct addrinfo *p = NULL;
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    for(p = result; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET)
        {
            memcpy(addr, p->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(result);
            return 0;
        }
    }
    freeaddrinfo(result);
    return 1;
}

int getipv6hostbyname(__const__ char *hostname, struct sockaddr_in6 *addr)
{
    struct addrinfo *p = NULL;
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    for(p = result; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET6)
        {
            memcpy(addr, p->ai_addr, sizeof(struct sockaddr_in6));
            freeaddrinfo(result);
            return 0;
        }
    }
    freeaddrinfo(result);
    return 1;
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    size_t buff_size = BUFFER_SIZE;
    buf->base = (char*) malloc(buff_size);
    buf->len = buff_size;
}

void free_buffer(write_req_t *wr)
{
    for(int i = 0; i < wr->len; i++)
        free(wr->buf[i].base);
    free(wr->buf);
    free(wr);
}

void after_tcp_write(uv_write_t *req, int status)
{
    LOG_DEBUG("after_tcp_write start\n");
    if (status)
        LOG_INFO("tcp write failed: %s\n", uv_err_name(status));
    free_buffer((write_req_t *) req);
    LOG_DEBUG("after_tcp_write end\n");
}

void after_udp_write(uv_udp_send_t *req, int status)
{
    LOG_DEBUG("after_udp_write start\n");
    if (status)
        LOG_INFO("udp write failed: %s\n", uv_err_name(status));
    free_buffer((write_req_t *) req);
    LOG_DEBUG("after_udp_write end\n");
}

void gs_parse(gs_socket_t *s, __const__ char *buf, __const__ size_t len, gs_parse_f on_conn_cb, gs_parse_f on_read_cb, char *aes_key, char net)
{
    LOG_DEBUG("gs_parse start\n");
    s5_header_t header;
    char* tbuf;
    size_t tlen;
    gs_parse_f cb;
    if(s->len == 0)
    {
        s->buf = malloc(sizeof(char) * len);
        memcpy(s->buf, buf, len);
        s->len = len;
    }
    else
    {
        s->buf = (char *) realloc(s->buf, sizeof(char) * (len + s->len));
        char *t = (char *) s->buf;
        t += s->len;
        memcpy(t, buf, len);
        s->len += len;
    }
    tbuf = s->buf;
    tlen = s->len;
    while(1)
    {
        if(manager_isclosed(s))
            return;
        if(tlen < GS_AES_ENCODE_LEN(sizeof(s5_header_t)))
            break;
        aes_decode(tbuf, sizeof(s5_header_t), (char *) &header, aes_key);
        reverse((char *) &header.total_len, sizeof(uint16_t));
        reverse((char *) &header.data_len, sizeof(uint16_t));
        if(header.sign != HEADER_SIGN)
        {
            manager_close(s);
            return;
        }
        if(header.net != net)
        {
            manager_close(s);
            return;
        }
        if(tlen < sizeof(s5_header_t) + header.total_len)
            break;
        if(header.net == 0)
        {
            if(header.act == 0)
            {
                cb = on_conn_cb;
            }
            else if(header.act == 1)
            {
                cb = on_read_cb;
            }
            else
            {
                manager_close(s);
                return;
            }
        }
        else if(header.net == 1)
        {
            if(header.act == 1)
            {
                cb = on_read_cb;
            }
            else
            {
                manager_close(s);
                return;
            }
        }
        else
        {
            manager_close(s);
            return;
        }
        if(tlen < GS_AES_ENCODE_LEN(sizeof(s5_header_t) + header.data_len))
        {
            manager_close(s);
            return;
        }
        if(header.data_len != 0)
        {
            char *ucdata = (char *) malloc(sizeof(char) * (sizeof(s5_header_t) + header.data_len));
            aes_decode(tbuf, sizeof(s5_header_t) + header.data_len, ucdata, aes_key);
            cb(s, ucdata + sizeof(s5_header_t), header.data_len, header.status);
            free(ucdata);
        }
        else
        {
            cb(s, NULL, 0, header.status);
        }
        tbuf += sizeof(s5_header_t) + header.total_len;
        tlen -= sizeof(s5_header_t) + header.total_len;
    }
    if(tlen == 0)
    {
        free(s->buf);
        s->buf = NULL;
        s->len = 0;
    }
    else
    {
        char *c = malloc(sizeof(char) * tlen);
        memcpy(c, tbuf, tlen);
        free(s->buf);
        s->buf = c;
        s->len = tlen;
    }
    LOG_DEBUG("gs_parse end\n");
}


int gs_enc_write(__const__ gs_socket_t *s, __const__ struct sockaddr *addr, __const__ char *buf, __const__ size_t len, char *aes_key, char act, char net, char status)
{
    LOG_DEBUG("gs_enc_write start\n");
    static char f = 0;
    s5_header_t header;
    int mindatalen = GS_AES_ENCODE_LEN(sizeof(s5_header_t) + len) - sizeof(s5_header_t);
    int randlen;
    int totallen;
    unsigned char *tmp;
    if(manager_isclosed(s))
        return 1;
    if(f == 0)
    {
        srand((unsigned) time(NULL));
        f = 1;
    }
    randlen = rand() % GS_RANDOM_LEN + 1;
    header.sign = HEADER_SIGN;
    header.act = act;
    header.net = net;
    header.status = status;
    header.total_len = mindatalen + randlen;
    header.data_len = len;
    totallen = header.total_len;
    reverse((char *) &header.total_len, sizeof(uint16_t));
    reverse((char *) &header.data_len, sizeof(uint16_t));
    char *indata = malloc(sizeof(char) * (sizeof(s5_header_t) + len));
    memcpy(indata, &header, sizeof(s5_header_t));
    if(buf != NULL)
        memcpy(indata + sizeof(s5_header_t), buf, len);
    char *outdata = malloc(sizeof(char) * (sizeof(s5_header_t) + totallen));
    aes_encode(indata, sizeof(s5_header_t) + len, outdata, aes_key);
    tmp = &outdata[sizeof(s5_header_t) + mindatalen];
    while(randlen--)
        *tmp++ = rand() % 256;
    free(indata);
    write_req_t *req = (write_req_t*) malloc(sizeof(write_req_t));
    req->len = 1;
    req->buf = malloc(sizeof(uv_buf_t));
    *(req->buf) = uv_buf_init(outdata, sizeof(s5_header_t) + totallen);
    LOG_DEBUG("gs_enc_write end\n");
    if(net == 0)
        return uv_write((uv_write_t *) req, (uv_stream_t *) s, req->buf, 1, after_tcp_write);
    if(net == 1)
        return uv_udp_send((uv_udp_send_t *) req, (uv_udp_t *) s, req->buf, 1, addr, after_udp_write);
}

int gs_udp_send(uv_udp_t *server, __const__ char *buf, __const__ size_t len, __const__ struct sockaddr* client)
{
    LOG_DEBUG("gs_udp_send start\n");
    char *tbuf = malloc(sizeof(char) * len);
    memcpy(tbuf, buf, len);
    write_req_t *req = (write_req_t*) malloc(sizeof(write_req_t));
    req->len = 1;
    req->buf = malloc(sizeof(uv_buf_t));
    *(req->buf) = uv_buf_init(tbuf, len);
    return uv_udp_send((uv_udp_send_t *) req, server, req->buf, 1, client, after_udp_write);
    LOG_DEBUG("gs_udp_send end\n");
}

int gs_write(uv_stream_t *client, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("gs_write start\n");
    char *tbuf = malloc(sizeof(char) * len);
    memcpy(tbuf, buf, len);
    write_req_t *req = (write_req_t*) malloc(sizeof(write_req_t));
    req->len = 1;
    req->buf = malloc(sizeof(uv_buf_t));
    *(req->buf) = uv_buf_init(tbuf, len);
    return uv_write((uv_write_t *) req, client, req->buf, 1, after_tcp_write);
    LOG_DEBUG("gs_write end\n");
}

int gs_getaddrinfo(uv_loop_t *loop, gs_socket_t *s, __const__ gs_addr_t *gsaddr, gs_getaddrinfo_cb_f cb)
{
    LOG_DEBUG("gs_getaddrinfo start\n");
    int sts = 0;
    gs_getaddrinfo_t *resolver;
    struct sockaddr_storage addr;
    struct addrinfo hints;
    char hostname[256];
    switch(gsaddr->atyp)
    {
        case 0x01:
            ((struct sockaddr_in *) &addr)->sin_family = AF_INET;
            ((struct sockaddr_in *) &addr)->sin_port = gsaddr->port;
            memcpy(&((struct sockaddr_in *) &addr)->sin_addr, gsaddr->addr, gsaddr->len);
            cb(s, 0, (struct sockaddr *) &addr);
            break;
        case 0x03:
            resolver = (gs_getaddrinfo_t *) malloc(sizeof(gs_getaddrinfo_t));
            resolver->s = s;
            resolver->cb = cb;
            resolver->port = gsaddr->port;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = 0;
            hints.ai_protocol = 0;
            hints.ai_flags = 0;
            memcpy(hostname, gsaddr->addr, gsaddr->len);
            hostname[gsaddr->len] = '\0';
            manager_reference(s);
            sts = uv_getaddrinfo(loop, (uv_getaddrinfo_t *) resolver, __on_resolved, hostname, NULL, &hints);
            break;
        case 0x04:
            ((struct sockaddr_in6 *) &addr)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *) &addr)->sin6_port = gsaddr->port;
            memcpy(&((struct sockaddr_in6 *) &addr)->sin6_addr, gsaddr->addr, gsaddr->len);
            cb(s, 0, (struct sockaddr *) &addr);
            break;
    }
    LOG_DEBUG("gs_getaddrinfo end\n");
    return sts;
}
