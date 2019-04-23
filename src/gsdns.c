#include <stdlib.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "uv.h"
#include "common.h"
#include "sockmnr.h"
#include "log.h"

typedef struct gs_udp_s
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    struct sockaddr* addr;
    struct sockaddr* srvaddr;
    struct sockaddr* dnsaddr;
    char *dbuf;
    int dlen;
    struct gs_udp_s *server;
} gs_udp_t;

static void __on_udp_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

static void __on_udp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_udp_timeout(gs_socket_t *remote);

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
    struct sockaddr_storage *dnsaddr;
    struct sockaddr_storage *srvaddr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    if(argc < 2)
        return __usage(argv[0]);
    conf_t **confs = conf_read(argv[1]);
    gs_udp_t * udps[2];
    if(confs == NULL)
        return 1;
    uv_loop_t *loop = uv_default_loop();
    while((conf = *confs++) != NULL)
    {
        char *aes_key = (char *) malloc(sizeof(char) * (GS_AES_KEY_LEN / 8));
        if(b64_decode(conf->key, strlen(conf->key), aes_key) <= 0)
        {
            LOG_ERR("invaild key: %s\n", conf->key);
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
            addr4->sin_port = conf->port;
            reverse((char *) &addr4->sin_port, 2);
        }
        else
        {
            addr6 = (struct sockaddr_in6 *) srvaddr;
            addr6->sin6_port = conf->port;
            reverse((char *) &addr6->sin6_port, 2);
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
            addr4->sin_port = conf->dns_port;
            reverse((char *) &addr4->sin_port, 2);
        }
        else
        {
            addr6 = (struct sockaddr_in6 *) dnsaddr;
            addr6->sin6_port = conf->dns_port;
            reverse((char *) &addr6->sin6_port, 2);
        }
        gs_udp_t *udp = (gs_udp_t *) malloc(sizeof(gs_udp_t));
        memset(udp, '\0', sizeof(gs_udp_t));
        udp->loop = loop;
        udp->aes_key = aes_key;
        udp->srvaddr = (struct sockaddr *) srvaddr;
        udp->dnsaddr = (struct sockaddr *) dnsaddr;
        udps[0] = udp;
        udps[1] = malloc(sizeof(gs_udp_t));
        memcpy(udps[1], udps[0], sizeof(gs_udp_t));
        uv_udp_init(loop, (uv_udp_t *) udps[0]);
        uv_udp_init(loop, (uv_udp_t *) udps[1]);
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, NULL, NULL, (uv_udp_t **) udps, __on_udp_read) != 0)
            continue;
    }
    manager_bind_loop(loop);
    uv_run(loop, UV_RUN_DEFAULT);
    LOG_DEBUG("main end\n");
    return 0;
}

static void __on_udp_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags)
{
    gs_udp_t *server;
    struct sockaddr *dnsaddr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    int addrlen;
    char *resbuf;
    int resbuflen;
    LOG_DEBUG("__on_udp_read start\n");
    if (nread > 0)
    {
        server = (gs_udp_t *) handle;
        gs_udp_t *remote = (gs_udp_t *) malloc(sizeof(gs_udp_t));
        memset(remote, '\0', sizeof(gs_udp_t));
        manager_register((gs_socket_t *) remote);
        remote->loop = server->loop;
        remote->aes_key = server->aes_key;
        uv_udp_init(remote->loop, (uv_udp_t *) remote);
        remote->addr = (struct sockaddr*) malloc(sizeof(struct sockaddr_storage));
        memcpy(remote->addr, addr, sizeof(struct sockaddr_storage));
        remote->server = server;
        dnsaddr = server->dnsaddr;
        if(dnsaddr->sa_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) dnsaddr;
            addrlen = 7;
            resbuf = (char *) malloc(sizeof(char) * (addrlen + nread));
            resbuf[0] = 0x01;
            memcpy(&resbuf[1], &addr4->sin_addr, 4);
            memcpy(&resbuf[5], &addr4->sin_port, 2);
        }
        else
        {
            addr6 = (struct sockaddr_in6 *) dnsaddr;
            addrlen = 19;
            resbuf = (char *) malloc(sizeof(char) * (addrlen + nread));
            resbuf[0] = 0x04;
            memcpy(&resbuf[1], &addr6->sin6_addr, 16);
            memcpy(&resbuf[17], &addr6->sin6_port, 2);
        }
        memcpy(&resbuf[addrlen], buf->base, nread);
        if(gs_enc_write((gs_socket_t *) remote, server->srvaddr, resbuf, addrlen + nread, remote->aes_key, 1, 1, 0) != 0)
        {
            LOG_ERR("udp send failed\n");
            free(resbuf);
            free(remote->addr);
            manager_close((gs_socket_t *) remote);
            return;
        }
        uv_udp_recv_start((uv_udp_t *) remote, alloc_buffer, __on_udp_remote_read);
        ((gs_socket_t *) remote)->act_time = time(NULL);
        manager_timeout(remote->loop, (gs_socket_t *) remote, 10, __on_udp_timeout);
        free(resbuf);
    }
    if (nread < 0)
    {
        LOG_INFO("udp read error\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
    }
    free(buf->base);
    LOG_DEBUG("__on_udp_read end\n");
}

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags)
{
    gs_udp_t *remote = (gs_udp_t *) handle;
    LOG_DEBUG("__on_udp_remote_read start\n");
    if (nread > 0)
    {
        ((gs_socket_t *) remote)->act_time = time(NULL);
        gs_parse((gs_socket_t *) remote, buf->base, nread, NULL, __on_udp_handle_read, remote->aes_key, 1);
    }
    if (nread < 0)
    {
        LOG_INFO("udp read error\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
        gs_enc_write((gs_socket_t *) remote->server,remote->addr, NULL, 0, ((gs_udp_t *) remote)->aes_key, 1, 1, 2);
    }
    free(buf->base);
    LOG_DEBUG("__on_udp_remote_read end\n");
}

static void __on_udp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_udp_handle_read start\n");
    gs_udp_t *server = ((gs_udp_t *) remote)->server;
    if(status != 0)
    {
        manager_close(remote);
        return;
    }
    gs_udp_send((uv_udp_t *) server, buf, len, ((gs_udp_t *) remote)->addr);
    LOG_DEBUG("__on_udp_handle_read end\n");
}

static void __on_udp_timeout(gs_socket_t *remote)
{
    free(((gs_udp_t *) remote)->addr);
}
