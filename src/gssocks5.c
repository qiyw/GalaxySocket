#include <stdlib.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "uv.h"
#include "common.h"
#include "sockmnr.h"
#include "log.h"
#include "socks5.h"

static void __on_s5_server_conn(uv_stream_t *stream, int status);

static void __on_s5_client_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf);

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
    gs_s5_socket_t * tcps[2];
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
        gs_s5_socket_t *tcp = (gs_s5_socket_t *) malloc(sizeof(gs_s5_socket_t));
        memset(tcp, '\0', sizeof(gs_s5_socket_t));
        tcp->loop = loop;
        tcp->aes_key = aes_key;
        tcp->server = (struct sockaddr *) srvaddr;
        tcps[0] = tcp;
        tcps[1] = malloc(sizeof(gs_s5_socket_t));
        memcpy(tcps[1], tcps[0], sizeof(gs_s5_socket_t));
        uv_tcp_init(loop, (uv_tcp_t *) tcps[0]);
        uv_tcp_init(loop, (uv_tcp_t *) tcps[1]);
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, (uv_tcp_t **) tcps, __on_s5_server_conn, NULL, NULL) != 0)
            continue;
    }
    manager_bind_loop(loop);
    uv_run(loop, UV_RUN_DEFAULT);
    LOG_DEBUG("main end\n");
    return 0;
}

static void __on_s5_server_conn(uv_stream_t *stream, int status)
{
    LOG_DEBUG("__on_s5_server_conn start\n");
    struct sockaddr_storage addr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    int len;
    if(status < 0)
    {
        LOG_ERR("client connect failed: %s\n", uv_strerror(status));
        return;
    }
    gs_s5_socket_t *server = (gs_s5_socket_t *) stream;
    gs_socks5_t *s5 = (gs_socks5_t *) malloc(sizeof(gs_socks5_t));
    memset(s5, '\0', sizeof(gs_socks5_t));
    s5->needauth = 0;
    gs_s5_socket_t *client = (gs_s5_socket_t *) malloc(sizeof(gs_s5_socket_t));
    memset(client, '\0', sizeof(gs_s5_socket_t));
    manager_register((gs_socket_t *) client);
    client->loop = server->loop;
    client->aes_key = server->aes_key;
    client->map = NULL;
    client->s5 = s5;
    client->server = server->server;
    uv_tcp_init(client->loop, (uv_tcp_t *) client);
    if (uv_accept(stream, (uv_stream_t*) client) == 0)
    {
        uv_tcp_getpeername((uv_tcp_t *) client, (struct sockaddr *) &addr, &len);
        if(addr.ss_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) &addr;
            LOG_INFO("client %s:%d connected\n", inet_ntoa(addr4->sin_addr), ntohs(addr4->sin_port));
        }
        else
        {
            char s[INET6_ADDRSTRLEN];
            addr6 = (struct sockaddr_in6 *) &addr;
            inet_ntop(AF_INET6, &addr6->sin6_addr, s, sizeof s);
            LOG_INFO("client %s:%d connected\n", s, ntohs(addr6->sin6_port));
        }
        uv_read_start((uv_stream_t*) client, alloc_buffer, __on_s5_client_read);
    }
    else
    {
        LOG_ERR("client connect failed: %s\n", uv_strerror(status));
        manager_close((gs_socket_t *) client);
    }
    LOG_DEBUG("__on_s5_server_conn end\n");
}

static void __on_s5_client_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf)
{
    LOG_DEBUG("__on_s5_client_read start\n");
    gs_socket_t *remote = (gs_socket_t *) ((gs_s5_socket_t *) client)->map;
    if (nread > 0)
    {
        socks5_parse((gs_s5_socket_t *) client, buf->base, nread);
    }
    if (nread < 0)
    {
        manager_close((gs_socket_t *) client);
        if(remote != NULL)
            manager_close(remote);
        LOG_INFO("client closed\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
    }
    free(buf->base);
    LOG_DEBUG("__on_s5_client_read end\n");
}
