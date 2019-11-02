#include <stdlib.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "pipe.h"
#include "common.h"
#include "log.h"

#define SOCKS5_VERSION 0x05

typedef struct
{
    char ver;
    char cmd;
    char rsv;
    char atyp;
} __attribute__ ((__packed__)) s5_conn_header_t;

static int __tcp_connect(pp_tcp_t *srv);

static int __tcp_srv_read(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_auth(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_connect(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_tcp_forward(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __s5_udp_forward(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __tcp_clnt_read(pp_tcp_t *clnt, __const__ char *buf, __const__ int len);

static int __tcp_clnt_on_connect(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __tcp_clnt_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __udp_clnt_read(pp_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

static int __udp_clnt_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __usage(char *prog)
{
    printf("Usage: %s INI_FILE\n", prog);
    fflush(stdout);
    return 1;
}

int main(int argc, char** argv)
{
    LOG_DEBUG("main start\n");
    conf_t *conf;
    struct sockaddr_storage *srvaddr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    if(argc < 2)
        return __usage(argv[0]);
    conf_t **confs = conf_read(argv[1]);
    if(confs == NULL)
        return 1;
    pp_loop_t *loop = pp_loop_init();
    if(loop == NULL)
    {
        LOG_ERR("loop init failed\n");
        return 1;
    }
    while((conf = *confs++) != NULL)
    {
        int b64kl = strlen(conf->key);
        if(B64_DECODE_LEN(conf->key, b64kl) != GS_AES_KEY_LEN / 8)
        {
            LOG_ERR("invaild key length: %s\n", conf->key);
            continue;
        }
        unsigned char *aes_key = (unsigned char *) malloc(sizeof(char) * (GS_AES_KEY_LEN / 8));
        if(b64_decode((unsigned char *) conf->key, b64kl, aes_key) <= 0)
        {
            LOG_ERR("invaild key: %s\n", conf->key);
            free(aes_key);
            continue;
        }
        srvaddr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
        if(getfirsthostbyname(conf->server, (struct sockaddr *) srvaddr) != 0)
        {
            LOG_ERR("unknown server: %s\n", conf->server);
            continue;
        }
        if(srvaddr->ss_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) srvaddr;
            addr4->sin_port = htons(conf->port);
        }
        else
        {
            addr6 = (struct sockaddr_in6 *) srvaddr;
            addr6->sin6_port = htons(conf->port);
        }
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, loop, aes_key, (struct sockaddr *) srvaddr, NULL, NULL, 0, 0, __tcp_connect, NULL) != 0)
        {
            LOG_ERR("bind failed\n");
            return 1;
        }
    }
    pp_loop_run(loop);
    LOG_DEBUG("main end\n");
    return 0;
}

static int __tcp_connect(pp_tcp_t *srv)
{
    LOG_DEBUG("__tcp_connect start\n");
    ((gs_tcp_t *) srv)->data = malloc(sizeof(char));
    memset(((gs_tcp_t *) srv)->data, '\0', sizeof(char));
    pp_tcp_read_start((pp_tcp_t *) srv, __tcp_srv_read);
    LOG_DEBUG("__tcp_connect end\n");
    return 0;
}

static int __tcp_srv_read(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__tcp_srv_read start\n");
    switch(*((char *) ((gs_tcp_t *) srv)->data))
    {
        case 0x00:
            return __s5_auth(srv, buf, len);
        case 0x01:
            return __s5_connect(srv, buf, len);
        case 0x02:
            return __s5_tcp_forward(srv, buf, len);
        case 0x03:
            return __s5_udp_forward(srv, buf, len);
        default:
            return 1;
    }
    LOG_DEBUG("__tcp_srv_read end\n");
}

static int __s5_auth(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__s5_auth start\n");
    char dlen;
    char method;
    char ver;
    char resbuf[2];
    if(len <= 2)
        return 1;
    ver = buf[0];
    if(ver != SOCKS5_VERSION)
        return 1;
    dlen = buf[1];
    if(dlen != len - 2)
        return 1;
    char *tbuf = (char *) &buf[2];
    while(dlen--)
    {
        method = *tbuf++;
        if(method == 0x00)
        {
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x00;
            *((char *) ((gs_tcp_t *) srv)->data) = 0x01;
            return pp_tcp_write(srv, resbuf, 2);
        }
    }
    resbuf[0] = SOCKS5_VERSION;
    resbuf[1] = 0xff;
    *((char *) ((gs_tcp_t *) srv)->data) = 0x01;
    return pp_tcp_write(srv, resbuf, 2);
}

static int __s5_connect(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__s5_connect start\n");
    s5_conn_header_t *header;
    int headerlen = sizeof(s5_conn_header_t);
    int dlen;
    struct sockaddr_storage addr;
    char resbuf[10];
    memset(resbuf, '\0', 10);
    if(len <= headerlen)
        return 1;
    header = (s5_conn_header_t *) buf;
    if(header->ver != SOCKS5_VERSION)
        return 1;
    if((dlen = parse_address((char *) &header->atyp, len - 3, (struct sockaddr *) &addr)) != len - 3)
        return 1;
    switch(header->cmd)
    {
        case 0x01:
            {
                gs_tcp_t *tcp = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
                char *resbufc;
                int reslen;
                memset(tcp, '\0', sizeof(gs_tcp_t));
                if(pp_tcp_init(pp_get_loop((pp_socket_t *) srv), (pp_tcp_t *) tcp, closing) != 0)
                {
                    LOG_ERR("init socket failed\n");
                    return 1;
                }
                tcp->aes_key = ((gs_tcp_t *) srv)->aes_key;
                tcp->data = NULL;
                gs_enc_data((char *) &header->atyp, dlen, &resbufc, &reslen, 0, ((gs_tcp_t *) srv)->aes_key);
                int sts = pp_tcp_fast_write((pp_tcp_t *) tcp, (struct sockaddr *) ((gs_tcp_t *) srv)->seraddr, resbufc, reslen);
                free(resbufc);
                if(sts == 0)
                {
                    pp_tcp_read_start((pp_tcp_t *) tcp, __tcp_clnt_read);
                    pp_tcp_pipe_bind((pp_tcp_t *) srv, (pp_tcp_t *) tcp);
                }
                else
                {
                    pp_close((pp_tcp_t *) tcp);
                }
                return sts;
            }
            break;
        case 0x02:
            //bind not support
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            return pp_tcp_write(srv, resbuf, 10);
        case 0x03:
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x00;
            resbuf[3] = 0x01;
            *((char *) ((gs_tcp_t *) srv)->data) = 0x03;
            return pp_tcp_write(srv, resbuf, 10);
        default:
            resbuf[0] = SOCKS5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            return pp_tcp_write(srv, resbuf, 10);
    }
}

static int __s5_tcp_forward(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__s5_tcp_forward start\n");
    char *resbuf;
    int reslen;
    gs_enc_data(buf, len, &resbuf, &reslen, 0, ((gs_tcp_t *) srv)->aes_key);
    int r = pp_tcp_pipe_write((pp_tcp_t *) srv, resbuf, reslen);
    free(resbuf);
    LOG_DEBUG("__s5_tcp_forward end\n");
    return r;
}

static int __s5_udp_forward(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__s5_udp_forward start\n");
    int dlen;
    struct sockaddr_storage addr;
    char *resbuf;
    int reslen;
    if((dlen = parse_address(buf + 3, len - 3, (struct sockaddr *) &addr)) < 0)
        return 1;
    if(dlen == len + 3)
        return 1;
    gs_udp_t *client = (gs_udp_t *) malloc(sizeof(gs_udp_t));
    memset(client, '\0', sizeof(gs_udp_t));
    client->aes_key = ((gs_tcp_t *) srv)->aes_key;
    client->seraddr = ((gs_tcp_t *) srv)->seraddr;
    client->data = NULL;
    pp_udp_init(pp_get_loop((pp_socket_t *) srv), (pp_udp_t *) client, closing);
    pp_udp_connect((pp_udp_t *) client, (struct sockaddr *) client->seraddr);
    pp_socket_pipe_bind((pp_socket_t *) client, (pp_socket_t *) srv);
    pp_udp_read_start((pp_udp_t *) client, __udp_clnt_read);
    gs_enc_data(buf + 3, len - 3, &resbuf, &reslen, 0, ((gs_tcp_t *) client)->aes_key);
    int r = pp_udp_write((pp_udp_t *) client, resbuf, reslen);
    free(resbuf);
    LOG_DEBUG("__s5_udp_forward start\n");
    return r;
}

static int __tcp_clnt_read(pp_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__tcp_clnt_read start\n");
    return gs_parse((gs_socket_t *) clnt, buf, len, 1, __tcp_clnt_on_connect, __tcp_clnt_on_read);
}

static int __tcp_clnt_on_connect(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__tcp_clnt_on_connect start\n");
    char resbuf[10];
    memset(resbuf, '\0', 10);
    gs_tcp_t *srv = (gs_tcp_t *) pp_pipe_socket((pp_socket_t *) s);
    if(srv == NULL)
        return 1;
    if(header->status == 0)
    {
        resbuf[0] = SOCKS5_VERSION;
        resbuf[1] = 0x00;
        resbuf[3] = 0x01;
        *((char *) srv->data) = 0x02;
        return pp_tcp_write((pp_tcp_t *) srv, resbuf, 10);
    }
    return 1;
}

static int __tcp_clnt_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__tcp_clnt_on_read start\n");
    if(header->status == 0)
        return pp_tcp_pipe_write((pp_tcp_t *) s, buf, len);
    return 1;
    LOG_DEBUG("__tcp_clnt_on_read end\n");
}

static int __udp_clnt_read(pp_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__udp_clnt_read start\n");
    LOG_DEBUG("__udp_clnt_read end\n");
    return gs_parse((gs_socket_t *) clnt, buf, len, 0, NULL, __udp_clnt_on_read);
}

static int __udp_clnt_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__udp_clnt_on_read start\n");
    pp_tcp_t *srv = (pp_tcp_t *) pp_pipe_socket((pp_socket_t *) s);
    char resbuf[10 + len];
    memset(resbuf, '\0', 10 + len);
    resbuf[3] = 0x01;
    memcpy(resbuf + 10, buf, len);
    LOG_DEBUG("__udp_clnt_on_read end\n");
    return pp_tcp_write(srv, resbuf, 10 + len);
}
