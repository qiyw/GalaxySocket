#include <stdlib.h>
#include <stdint.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "common.h"
#include "log.h"

static int __tcp_connect(pp_tcp_t *srv);

static int __tcp_srv_read(pp_tcp_t *srv, __const__ char *buf, __const__ int len);

static int __tcp_srv_on_connect(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __tcp_srv_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __tcp_clnt_read(pp_tcp_t *clnt, __const__ char *buf, __const__ int len);

static int __udp_srv_read(pp_udp_t *srv, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

static int __udp_srv_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len);

static int __udp_clnt_read(pp_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

static int __usage(char *prog)
{
    printf("Usage: %s INI_FILE\n", prog);
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv)
{
    LOG_DEBUG("main start\n");
    conf_t *conf;
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
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, loop, aes_key, NULL, NULL, NULL, 0, 0, __tcp_connect, __udp_srv_read) != 0)
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
    pp_tcp_read_start((pp_tcp_t *) srv, __tcp_srv_read);
    LOG_DEBUG("__tcp_connect end\n");
    return 0;
}

static int __tcp_srv_read(pp_tcp_t *srv, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__tcp_srv_read start\n");
    return gs_parse((gs_socket_t *) srv, buf, len, 1, __tcp_srv_on_connect, __tcp_srv_on_read);
    LOG_DEBUG("__tcp_srv_read end\n");
}

static int __tcp_srv_on_connect(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__tcp_srv_on_connect start\n");
    struct sockaddr_storage addr;
    int dlen;
    char *resbuf;
    int reslen;
    char sts;
    if(header->status != 0)
        return 1;
    if((dlen = parse_address(buf, len, (struct sockaddr *) &addr)) < 0)
        return 1;
    if(dlen != len)
    {
        sts = 1;
    }
    else
    {
        gs_tcp_t *tcp = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
        memset(tcp, '\0', sizeof(gs_tcp_t));
        if(pp_tcp_init(pp_get_loop((pp_socket_t *) s), (pp_tcp_t *) tcp, closing) != 0)
        {
            LOG_ERR("init socket failed\n");
            return 1;
        }
        tcp->aes_key = ((gs_udp_t *) s)->aes_key;
        tcp->data = NULL;
        sts = pp_tcp_connect((pp_tcp_t *) tcp, (struct sockaddr *) &addr);
        if(sts == 0)
        {
            pp_tcp_read_start((pp_tcp_t *) tcp, __tcp_clnt_read);
            pp_tcp_pipe_bind((pp_tcp_t *) s, (pp_tcp_t *) tcp);
        }
        else
        {
            pp_close((pp_tcp_t *) tcp);
        }
    }
    gs_enc_data(NULL, 0, &resbuf, &reslen, sts, s->aes_key);
    int r = pp_tcp_write((pp_tcp_t *) s, resbuf, reslen);
    free(resbuf);
    LOG_DEBUG("__tcp_srv_on_connect end\n");
    return sts | r;
}

static int __tcp_srv_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__tcp_srv_on_read start\n");
    if(header->status != 0)
        return 1;
    LOG_DEBUG("__tcp_srv_on_read end\n");
    return pp_tcp_pipe_write((pp_tcp_t *) s, buf, len);
}

static int __tcp_clnt_read(pp_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__tcp_clnt_read start\n");
    char *resbuf;
    int reslen;
    gs_enc_data(buf, len, &resbuf, &reslen, 0, ((gs_tcp_t *) clnt)->aes_key);
    int r = pp_tcp_pipe_write((pp_tcp_t *) clnt, resbuf, reslen);
    free(resbuf);
    LOG_DEBUG("__tcp_clnt_read end\n");
    return r;
}

static int __udp_srv_read(pp_udp_t *srv, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__udp_srv_read start\n");
    LOG_DEBUG("__udp_srv_read end\n");
    return gs_parse((gs_socket_t *) srv, buf, len, 0, NULL, __udp_srv_on_read);
}

static int __udp_srv_on_read(gs_socket_t *s, __const__ gs_header_t *header, __const__ char *buf, uint32_t len)
{
    LOG_DEBUG("__udp_srv_on_read start\n");
    int dlen;
    struct sockaddr_storage addr;
    if(header->status != 0)
        return 1;
    if((dlen = parse_address(buf, len, (struct sockaddr *) &addr)) < 0)
        return 1;
    if(dlen == len)
        return 1;
    gs_udp_t *client = (gs_udp_t *) malloc(sizeof(gs_udp_t));
    memset(client, '\0', sizeof(gs_udp_t));
    client->aes_key = ((gs_udp_t *) s)->aes_key;
    client->data = NULL;
    pp_udp_init(pp_get_loop((pp_socket_t *) s), (pp_udp_t *) client, closing);
    if(pp_udp_connect((pp_udp_t *) client, (struct sockaddr *) &addr) != 0)
        return 1;
    pp_udp_pipe_bind((pp_udp_t *) client, (pp_udp_t *) s);
    pp_udp_read_start((pp_udp_t *) client, __udp_clnt_read);
    LOG_DEBUG("__udp_srv_on_read end\n");
    return pp_udp_write((pp_udp_t *) client, buf + dlen, len - dlen);
}

static int __udp_clnt_read(pp_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    LOG_DEBUG("__udp_clnt_read start\n");
    char *resbuf;
    int reslen;
    gs_enc_data(buf, len, &resbuf, &reslen, 0, ((gs_tcp_t *) clnt)->aes_key);
    int r = pp_udp_pipe_write((pp_udp_t *) clnt, resbuf, reslen);
    free(resbuf);
    LOG_DEBUG("__udp_clnt_read end\n");
    return r;
}
