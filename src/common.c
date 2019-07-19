#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <time.h>

#include "common.h"
#include "aes.h"
#include "log.h"
#include "crc32.h"

struct bind_args
{
    pp_loop_t *loop;
    unsigned char *aes_key;
    uint32_t crc32;
    struct sockaddr* seraddr;
    struct sockaddr* dnsaddr;
    void *data;
};

typedef struct
{
    uint32_t crc32;
    uint32_t data_total_len;
    uint32_t data_len;
    gs_header_t header;
} __attribute__((__packed__)) __header_t;

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

static int __udp_accepted(pp_udp_t *srv, pp_udp_t **client)
{
    LOG_DEBUG("__udp_accepted start\n");
    *client = (pp_udp_t *) malloc(sizeof(gs_udp_t));
    memset(*client, '\0', sizeof(gs_udp_t));
    gs_udp_t *udp = (gs_udp_t *) *client;
    udp->aes_key = ((gs_udp_t *) srv)->aes_key;
    udp->crc32 = ((gs_udp_t *) srv)->crc32;
    udp->seraddr = ((gs_udp_t *) srv)->seraddr;
    udp->dnsaddr = ((gs_udp_t *) srv)->dnsaddr;
    udp->data = NULL;
    pp_udp_init(pp_get_loop((pp_socket_t *) srv), *client, closing);
    LOG_DEBUG("__udp_accepted end\n");
    return 0;
}

static int __do_tcp_bind(struct sockaddr *addr, struct bind_args *ba, pp_tcp_connect_f cb, int flags)
{
    LOG_DEBUG("__do_tcp_bind start\n");
    gs_tcp_t *tcp = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
    memset(tcp, '\0', sizeof(gs_tcp_t));
    tcp->aes_key = ba->aes_key;
    tcp->crc32 = ba->crc32;
    tcp->seraddr = ba->seraddr;
    tcp->dnsaddr = ba->dnsaddr;
    tcp->data = ba->data;
    if(pp_tcp_init(ba->loop, (pp_tcp_t *) tcp, closing) != 0)
    {
        LOG_ERR("init socket failed\n");
        return 1;
    }
    if(pp_tcp_bind((pp_tcp_t *) tcp, addr, flags) != 0)
    {
        LOG_ERR("tcp bind failed\n");
        return 1;
    }
    if(pp_tcp_listen((pp_tcp_t *) tcp, cb))
    {
        LOG_ERR("tcp listen failed\n");
        return 1;
    }
    LOG_DEBUG("__do_tcp_bind end\n");
    return 0;
}

static int __do_udp_bind(struct sockaddr *addr, struct bind_args *ba, pp_udp_read_f cb, int flags)
{
    LOG_DEBUG("__do_udp_bind start\n");
    gs_udp_t *udp = (gs_udp_t *) malloc(sizeof(gs_udp_t));
    memset(udp, '\0', sizeof(gs_udp_t));
    udp->aes_key = ba->aes_key;
    udp->crc32 = ba->crc32;
    udp->seraddr = ba->seraddr;
    udp->dnsaddr = ba->dnsaddr;
    udp->data = ba->data;
    if(pp_udp_init(ba->loop, (pp_udp_t *) udp, closing) != 0)
    {
        LOG_ERR("init socket failed\n");
        return 1;
    }
    if(pp_udp_bind((pp_udp_t *) udp, addr, flags) != 0)
    {
        LOG_ERR("udp bind failed\n");
        return 1;
    }
    if(pp_udp_listen((pp_udp_t *) udp, __udp_accepted, cb))
    {
        LOG_ERR("udp listen failed\n");
        return 1;
    }
    LOG_DEBUG("__do_udp_bind end\n");
    return 0;
}

int do_bind(char *host6, char *host4, int port, pp_loop_t *loop, unsigned char *aes_key, uint32_t crc32, struct sockaddr* seraddr, struct sockaddr* dnsaddr, void *data, int tcp_flags, int udp_flags, pp_tcp_connect_f tcp_cb, pp_udp_read_f udp_cb)
{
    LOG_DEBUG("do_bind start\n");
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;

    struct bind_args ba;

    ba.loop = loop;
    ba.aes_key = aes_key;
    ba.data = data;
    ba.crc32 = crc32;
    ba.dnsaddr = dnsaddr;
    ba.seraddr = seraddr;

    //ipv6
    if(getipv6hostbyname(host6, &addr6) != 0)
    {
        LOG_ERR("unknown ip6 host name: %s\n", host6);
        return 1;
    }
    addr6.sin6_port = htons(port);

    if(tcp_cb != NULL)
    {
        if(__do_tcp_bind((struct sockaddr *) &addr6, &ba, tcp_cb, PP_TCP_IPV6ONLY | tcp_flags) != 0)
            return 1;
    }
    if(udp_cb != NULL)
    {
        if(__do_udp_bind((struct sockaddr *) &addr6, &ba, udp_cb, PP_UDP_IPV6ONLY | udp_flags) != 0)
            return 1;
    }
    LOG_INFO("server listen on %s:%d\n", host6, port);

    //ipv4
    if(getipv4hostbyname(host4, &addr) != 0)
    {
        LOG_ERR("unknown ip4 host name: %s\n", host4);
        return 1;
    }
    addr.sin_port = htons(port);

    if(tcp_cb != NULL)
    {
        if(__do_tcp_bind((struct sockaddr *) &addr, &ba, tcp_cb, tcp_flags) != 0)
            return 1;
    }
    if(udp_cb != NULL)
    {
        if(__do_udp_bind((struct sockaddr *) &addr, &ba, udp_cb, udp_flags) != 0)
            return 1;
    }
    LOG_INFO("server listen on %s:%d\n", host4, port);

    LOG_DEBUG("do_bind end\n");
    return 0;
}

int closing(pp_socket_t *s)
{
    LOG_DEBUG("closing start\n");
    gs_socket_t *gs = (gs_socket_t *) s;
    if(gs->data != NULL && gs->data)
        free(gs->data);
    if(gs->len != 0)
        free(gs->buf);
    free(gs);
    return 0;
    LOG_DEBUG("closing end\n");
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

int gs_parse(gs_socket_t *s, __const__ char *buf, __const__ size_t len, char istcp, gs_parse_f on_conn_cb, gs_parse_f on_read_cb)
{
    LOG_DEBUG("gs_parse start\n");
    char *tbuf;
    int tlen;
    __header_t header;
    uint32_t crc32_c = CRC32(s->aes_key, GS_AES_KEY_LEN / 8);
    int headerlen = GS_AES_ENCODE_LEN(sizeof(__header_t));
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
        if(tlen <= headerlen)
            break;
        aes_decode((unsigned char *) tbuf, sizeof(__header_t), (unsigned char *) &header, s->aes_key);
        reverse((char *) &header.data_total_len, sizeof(uint32_t));
        reverse((char *) &header.data_len, sizeof(uint32_t));
        if(header.crc32 != crc32_c)
            return 1;
        if(header.data_total_len < GS_AES_ENCODE_LEN(header.data_len))
            return 1;
        if(tlen < headerlen + header.data_total_len)
            break;
        char *ucdata;
        if(header.data_len == 0)
            ucdata = NULL;
        else
            ucdata = (char *) malloc(sizeof(char) * header.data_len);
        aes_decode((unsigned char *) tbuf + headerlen, header.data_len, (unsigned char *) ucdata, s->aes_key);
        if(istcp && s->tcp_flg == 0)
        {
            s->tcp_flg = 1;
            if(on_conn_cb(s, &header.header, ucdata, header.data_len) != 0)
            {
                if(ucdata != NULL)
                    free(ucdata);
                return 1;
            }
        }
        else
        {
            if(on_read_cb(s, &header.header, ucdata, header.data_len) != 0)
            {
                if(ucdata != NULL)
                    free(ucdata);
                return 1;
            }
        }
        if(ucdata != NULL)
            free(ucdata);
        tbuf += headerlen + header.data_total_len;
        tlen -= headerlen + header.data_total_len;
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
    return 0;
}

int gs_enc_data(__const__ char *buf, __const__ int len, char **enc_buf, int *enc_len, char status, unsigned char *aes_key)
{
    static char fst = 0;
    unsigned char *tmp;
    char *tmpdata;
    int tmplen;
    if(fst == 0)
    {
        srand((unsigned) time(NULL));
        fst = 1;
    }
    __header_t header;
    int headerlen = GS_AES_ENCODE_LEN(sizeof(__header_t));
    int mindatalen = GS_AES_ENCODE_LEN(len);
    int randlen = rand() % GS_RANDOM_LEN + 1;
    header.crc32 = CRC32(aes_key, GS_AES_KEY_LEN / 8);
    header.data_total_len = mindatalen + randlen;
    header.data_len = len;
    reverse((char *) &header.data_total_len, sizeof(uint32_t));
    reverse((char *) &header.data_len, sizeof(uint32_t));
    header.header.status = status;
    *enc_len = headerlen + mindatalen + randlen;
    *enc_buf = (char *) malloc(sizeof(char) * (*enc_len));
    tmpdata = (char *) malloc(sizeof(char) * mindatalen);
    memcpy(tmpdata, buf, len);
    tmplen = mindatalen - len;
    tmp = (unsigned char *) tmpdata + len;
    while(tmplen--)
        *tmp++ = rand() % 256;
    aes_encode((unsigned char *) &header, sizeof(__header_t), (unsigned char *) *enc_buf, aes_key);
    aes_encode((unsigned char *) tmpdata, mindatalen, (unsigned char *) (*enc_buf) + headerlen, aes_key);
    tmp = (unsigned char *) (*enc_buf) + headerlen + mindatalen;
    while(randlen--)
        *tmp++ = rand() % 256;
    free(tmpdata);
    return 0;
}

int parse_address(__const__ char *buf, __const__ int len, struct sockaddr* addr)
{
    uint16_t *port;
    char dlen;
    char atyp;
    if(len == 0)
        return -1;
    atyp = buf[0];
    switch(atyp)
    {
        case 0x01:
            //ipv4
            if(len < 7)
                return -1;
            port = (uint16_t *) &buf[5];
            ((struct sockaddr_in *) addr)->sin_family = AF_INET;
            ((struct sockaddr_in *) addr)->sin_port = *port;
            memcpy(&((struct sockaddr_in *) addr)->sin_addr, (char *) &buf[1], 4);
            return 7;
        case 0x03:
            //domian
            if(len < 2)
                return -1;
            dlen = buf[1];
            if(len < dlen + 4)
                return -1;
            port = (uint16_t *) &buf[2 + dlen];
            {
                char addrstr[dlen + 1];
                memcpy(addrstr, (char *) &buf[2], dlen);
                addrstr[(int) dlen] = '\0';
                if(getfirsthostbyname(addrstr, addr) != 0)
                    return -1;
                if(addr->sa_family == AF_INET)
                    ((struct sockaddr_in *) addr)->sin_port = *port;
                else
                    ((struct sockaddr_in6 *) addr)->sin6_port = *port;
            }
            return dlen + 4;
        case 0x04:
            //ipv6
            if(len < 19)
                return -1;
            port = (uint16_t *) &buf[17];
            ((struct sockaddr_in6 *) addr)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *) addr)->sin6_port = *port;
            memcpy(&((struct sockaddr_in6 *) addr)->sin6_addr, (char *) &buf[1], 16);
            return 19;
        default:
            return -1;
    }
}
