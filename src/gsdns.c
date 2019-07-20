#include <stdlib.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "pipe.h"
#include "common.h"
#include "log.h"
#include "crc32.h"

static int __tcp_connect(pp_tcp_t *srv);

static int __tcp_srv_read(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __tcp_clnt_read(pp_tcp_t *clnt, __const__ char *buf, __const__ int len);

static int __tcp_clnt_on_connect(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __tcp_clnt_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __udp_srv_read(pp_udp_t *srv, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

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
    struct sockaddr_storage *dnsaddr;
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
        uint32_t crc = CRC32(aes_key, GS_AES_KEY_LEN / 8);
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
        dnsaddr = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
        if(getfirsthostbyname(conf->dns_server, (struct sockaddr *) dnsaddr) != 0)
        {
            LOG_ERR("unknown dns server: %s\n", conf->dns_server);
            continue;
        }
        if(dnsaddr->ss_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) dnsaddr;
            addr4->sin_port = htons(conf->dns_port);
        }
        else
        {
            addr6 = (struct sockaddr_in6 *) dnsaddr;
            addr6->sin6_port = htons(conf->dns_port);
        }
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, loop, aes_key, crc, (struct sockaddr *) srvaddr, (struct sockaddr *) dnsaddr, NULL, 0, 0, __tcp_connect, __udp_srv_read) != 0)
        {
            LOG_ERR("bind failed\n");
            continue;
        }
    }
    pp_loop_run(loop);
    LOG_DEBUG("main end\n");
    return 0;
}

static int __tcp_connect(pp_tcp_t *srv)
{
    LOG_DEBUG("__tcp_connect start\n");
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    int restmplen;
    char *restmpbuf;
    char *resbuf;
    int reslen;
    gs_tcp_t *client = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
    memset(client, '\0', sizeof(gs_tcp_t));
    if(pp_tcp_init(pp_get_loop((pp_socket_t *) srv), (pp_tcp_t *) client, closing) != 0)
    {
        LOG_ERR("init socket failed\n");
        return 1;
    }
    client->aes_key = ((gs_tcp_t *) srv)->aes_key;
    client->crc32 = ((gs_tcp_t *) srv)->crc32;
    client->seraddr = ((gs_tcp_t *) srv)->seraddr;
    client->dnsaddr = ((gs_tcp_t *) srv)->dnsaddr;
    client->data = NULL;
    if(client->dnsaddr->sa_family == AF_INET)
    {
        addr4 = (struct sockaddr_in *) client->dnsaddr;
        restmplen = 7;
        restmpbuf = malloc(sizeof(char) * (restmplen));
        restmpbuf[0] = 0x01;
        memcpy(restmpbuf + 1, &addr4->sin_addr, 4);
        memcpy(restmpbuf + 5, &addr4->sin_port, 2);
    }
    else
    {
        addr6 = (struct sockaddr_in6 *) client->dnsaddr;
        restmplen = 19;
        restmpbuf = malloc(sizeof(char) * (restmplen));
        restmpbuf[0] = 0x04;
        memcpy(restmpbuf + 1, &addr6->sin6_addr, 16);
        memcpy(restmpbuf + 17, &addr6->sin6_port, 2);
    }
    gs_enc_data(restmpbuf, restmplen, &resbuf, &reslen, 0, client->aes_key);
    int sts = pp_tcp_fast_write((pp_tcp_t *) client, client->seraddr, resbuf, reslen);
    free(restmpbuf);
    free(resbuf);
    if(sts == 0)
    {
        pp_tcp_pipe_bind((pp_tcp_t *) srv, (pp_tcp_t *) client);
        pp_tcp_read_start((pp_tcp_t *) client, __tcp_clnt_read);
    }
    else
    {
        pp_close((pp_tcp_t *) srv);
        pp_close((pp_tcp_t *) client);
    }
    LOG_DEBUG("__tcp_connect end\n");
    return sts;
}

static int __tcp_srv_read(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__tcp_srv_read start\n");
    char *resbuf;
    int reslen;
    gs_enc_data(buf, len, &resbuf, &reslen, 0, ((gs_socket_t *) srv)->aes_key);
    int sts = pp_tcp_pipe_write(srv, resbuf, reslen);
    free(resbuf);
    LOG_DEBUG("__tcp_srv_read end\n");
    return sts;
}

static int __tcp_clnt_read(pp_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__tcp_clnt_read start\n");
    LOG_DEBUG("__tcp_clnt_read end\n");
    return gs_parse((gs_socket_t *) clnt, buf, len, 1, __tcp_clnt_on_connect, __tcp_clnt_on_read);
}

static int __tcp_clnt_on_connect(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__tcp_clnt_on_connect start\n");
    gs_tcp_t *srv = (gs_tcp_t *) pp_pipe_socket((pp_socket_t *) s);
    if(srv == NULL)
        return 1;
    if(header->status == 0)
    {
        pp_tcp_read_start((pp_tcp_t *) srv, __tcp_srv_read);
        return 0;
    }
    return 1;
}

static int __tcp_clnt_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__tcp_clnt_on_read start\n");
    LOG_DEBUG("__tcp_clnt_on_read end\n");
    if(header->status == 0)
        return pp_tcp_pipe_write((pp_tcp_t *) s, buf, len);
    return 1;
}

static int __udp_srv_read(pp_udp_t *srv, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__udp_srv_read start\n");
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    int restmplen;
    char *restmpbuf;
    char *resbuf;
    int reslen;
    gs_udp_t *client = (gs_udp_t *) malloc(sizeof(gs_udp_t));
    memset(client, '\0', sizeof(gs_udp_t));
    client->aes_key = ((gs_udp_t *) srv)->aes_key;
    client->crc32 = ((gs_udp_t *) srv)->crc32;
    client->seraddr = ((gs_udp_t *) srv)->seraddr;
    client->dnsaddr = ((gs_udp_t *) srv)->dnsaddr;
    client->data = NULL;
    pp_udp_init(pp_get_loop((pp_socket_t *) srv), (pp_udp_t *) client, closing);
    pp_udp_connect((pp_udp_t *) client, (struct sockaddr *) client->seraddr);
    pp_udp_pipe_bind((pp_udp_t *) client, srv);
    pp_udp_read_start((pp_udp_t *) client, __udp_clnt_read);
    if(client->dnsaddr->sa_family == AF_INET)
    {
        addr4 = (struct sockaddr_in *) client->dnsaddr;
        restmplen = 7;
        restmpbuf = malloc(sizeof(char) * (restmplen + len));
        restmpbuf[0] = 0x01;
        memcpy(restmpbuf + 1, &addr4->sin_addr, 4);
        memcpy(restmpbuf + 5, &addr4->sin_port, 2);
    }
    else
    {
        addr6 = (struct sockaddr_in6 *) client->dnsaddr;
        restmplen = 19;
        restmpbuf = malloc(sizeof(char) * (restmplen + len));
        restmpbuf[0] = 0x04;
        memcpy(restmpbuf + 1, &addr6->sin6_addr, 16);
        memcpy(restmpbuf + 17, &addr6->sin6_port, 2);
    }
    memcpy(restmpbuf + restmplen, buf, len);
    restmplen += len;
    gs_enc_data(restmpbuf, restmplen, &resbuf, &reslen, 0, client->aes_key);
    int r = pp_udp_write((pp_udp_t *) client, resbuf, reslen);
    free(restmpbuf);
    free(resbuf);
    return r;
    LOG_DEBUG("__udp_srv_read end\n");
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
    LOG_DEBUG("__udp_clnt_on_read end\n");
    return pp_udp_pipe_write((pp_udp_t *) s, buf, len);
}
