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

typedef struct gs_tcp_s
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    char proc;
    struct sockaddr* srvaddr;
    struct sockaddr* dnsaddr;
    struct gs_tcp_s *map;
} gs_tcp_t;

static void __on_udp_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

static void __on_udp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_udp_timeout(gs_socket_t *remote);

static void __on_tcp_conn(uv_stream_t *stream, int status);

static void __on_tcp_remote_connected(uv_connect_t *conn,int status);

static void __on_tcp_remote_read(uv_stream_t *remote, ssize_t nread, __const__ uv_buf_t *buf);

static void __on_tcp_remote_handle_connect(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_tcp_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf);

static void __on_tcp_remote_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

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
    gs_udp_t *udps[2];
    gs_tcp_t *tcps[2];
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
        gs_tcp_t *tcp = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
        tcp->loop = loop;
        tcp->aes_key = aes_key;
        tcp->srvaddr = (struct sockaddr *) srvaddr;
        tcp->dnsaddr = (struct sockaddr *) dnsaddr;
        tcps[0] = tcp;
        tcps[1] = malloc(sizeof(gs_tcp_t));
        memcpy(tcps[1], tcps[0], sizeof(gs_tcp_t));
        uv_tcp_init(loop, (uv_tcp_t *) tcps[0]);
        uv_tcp_init(loop, (uv_tcp_t *) tcps[1]);
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, (uv_tcp_t **) tcps, __on_tcp_conn, (uv_udp_t **) udps, __on_udp_read) != 0)
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

static void __on_tcp_conn(uv_stream_t *stream, int status)
{
    int en;
    LOG_DEBUG("__on_tcp_conn start\n");
    if(status < 0)
    {
        LOG_ERR("client connect failed: %s\n", uv_strerror(status));
        return;
    }
    gs_tcp_t *server = (gs_tcp_t *) stream;
    gs_tcp_t *client = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
    memset(client, '\0', sizeof(gs_tcp_t));
    manager_register((gs_socket_t *) client);
    client->loop = server->loop;
    client->srvaddr = server->srvaddr;
    client->aes_key = server->aes_key;
    client->dnsaddr = server->dnsaddr;
    client->map = NULL;
    uv_tcp_init(client->loop, (uv_tcp_t *) client);
    if (uv_accept(stream, (uv_stream_t*) client) == 0)
    {
        gs_tcp_t *remote = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
        memset(remote, '\0', sizeof(gs_tcp_t));
        manager_register((gs_socket_t *) remote);
        uv_tcp_init(((gs_tcp_t *) client)->loop, (uv_tcp_t *) remote);
        remote->map = client;
        client->map = remote;
        uv_connect_t *connect = (uv_connect_t * ) malloc(sizeof(uv_connect_t));
        if((en = uv_tcp_connect(connect, (uv_tcp_t *) remote, client->srvaddr, __on_tcp_remote_connected)) != 0)
        {
            LOG_ERR("remote connteced failed: %s\n", uv_err_name(en));
            manager_close((gs_socket_t *) client);
            manager_close((gs_socket_t *) remote);
        }
        else
        {
            manager_reference((gs_socket_t *) client);
            manager_reference((gs_socket_t *) remote);
        }
    }
    else
    {
        LOG_ERR("client connect failed: %s\n", uv_strerror(status));
        manager_close((gs_socket_t *) client);
    }
    LOG_DEBUG("__on_tcp_conn end\n");
}

static void __on_tcp_remote_connected(uv_connect_t *conn,int status)
{
    LOG_DEBUG("__on_tcp_remote_connected start\n");
    int en;
    uv_os_fd_t fd;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    char *buf;
    int len;
    gs_tcp_t *remote = (gs_tcp_t *) conn->handle;
    gs_tcp_t *client = remote->map;
    manager_unreference((gs_socket_t *) client);
    manager_unreference((gs_socket_t *) remote);
    if(status != 0)
    {
        manager_close((gs_socket_t *) client);
        manager_close((gs_socket_t *) remote);
    }
    else
    {
        if(client->dnsaddr->sa_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) client->dnsaddr;
            len = 7;
            buf = (char *) malloc(sizeof(char) * len);
            buf[0] = 0x01;
            memcpy(&buf[1], &addr4->sin_addr, 4);
            memcpy(&buf[5], &addr4->sin_port, 2);
        }
        else
        {
            char s[INET6_ADDRSTRLEN];
            addr6 = (struct sockaddr_in6 *) client->dnsaddr;
            len = 19;
            buf = (char *) malloc(sizeof(char) * len);
            buf[0] = 0x04;
            memcpy(&buf[1], &addr6->sin6_addr, 16);
            memcpy(&buf[17], &addr6->sin6_port, 2);
        }
        gs_enc_write((gs_socket_t *) remote, NULL, buf, len, client->aes_key, 0, 0, 0);
        uv_read_start((uv_stream_t*) remote, alloc_buffer, __on_tcp_remote_read);
    }
    free(conn);
    LOG_DEBUG("__on_tcp_remote_connected end\n");
}

static void __on_tcp_remote_read(uv_stream_t *remote, ssize_t nread, __const__ uv_buf_t *buf)
{
    LOG_DEBUG("__on_tcp_remote_read start\n");
    gs_socket_t *client = (gs_socket_t *) ((gs_tcp_t *) remote)->map;
    if (nread > 0)
    {
        gs_parse((gs_socket_t *) remote, buf->base, nread, __on_tcp_remote_handle_connect, __on_tcp_remote_handle_read, ((gs_tcp_t *) client)->aes_key, 0);
    }
    if (nread < 0)
    {
        manager_close(client);
        manager_close((gs_socket_t *) remote);
        LOG_INFO("client closed\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
    }
    free(buf->base);
    LOG_DEBUG("__on_tcp_remote_read end\n");
}

static void __on_tcp_remote_handle_connect(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_tcp_remote_handle_connect start\n");
    gs_tcp_t *client = ((gs_tcp_t *) remote)->map;
    if(((gs_tcp_t *) remote)->proc != 0)
    {
        manager_close(remote);
        manager_close((gs_socket_t *) client);
        return;
    }
    ((gs_tcp_t *) remote)->proc = 1;
    if(status != 0)
    {
        manager_close(remote);
        manager_close((gs_socket_t *) client);
        return;
    }
    ((gs_tcp_t *) remote)->proc = 2;
    uv_read_start((uv_stream_t*) client, alloc_buffer, __on_tcp_read);
    LOG_DEBUG("__on_tcp_remote_handle_connect end\n");
}

static void __on_tcp_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf)
{
    LOG_DEBUG("__on_tcp_read start\n");
    gs_tcp_t *remote = ((gs_tcp_t *) client)->map;
    if (nread > 0)
    {
        gs_enc_write((gs_socket_t *) remote, NULL, buf->base, nread, ((gs_tcp_t *) client)->aes_key, 1, 0, 0);
    }
    if (nread < 0)
    {
        manager_close((gs_socket_t *) client);
        manager_close((gs_socket_t *) remote);
        LOG_INFO("client closed\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
    }
    free(buf->base);
    LOG_DEBUG("__on_tcp_read end\n");
}

static void __on_tcp_remote_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_tcp_remote_handle_read start\n");
    gs_tcp_t *client = ((gs_tcp_t *) remote)->map;
    if (len > 0 && status == 0 && ((gs_tcp_t *) remote)->proc == 2)
    {
        if(!manager_isclosed((gs_socket_t *) client))
            gs_write((uv_stream_t *) client, buf, len);
    }
    else
    {
        manager_close(remote);
        if(client != NULL)
            manager_close((gs_socket_t *) client);
    }
    LOG_DEBUG("__on_tcp_remote_handle_read end\n");
}
