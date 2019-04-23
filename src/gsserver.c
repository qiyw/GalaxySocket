#include <stdlib.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "uv.h"
#include "common.h"
#include "sockmnr.h"
#include "log.h"
#include "time.h"

typedef struct gs_tcp_s
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    char proc;
    struct gs_tcp_s *map;
} gs_tcp_t;

typedef struct gs_udp_s
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    struct sockaddr* addr;
    char *dbuf;
    int dlen;
    struct gs_udp_s *server;
} gs_udp_t;

static int __parse_gs_addr(__const__ char *buf, __const__ size_t len, gs_addr_t *gsaddr);

static void __on_tcp_conn(uv_stream_t *stream, int status);

static void __on_tcp_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf);

static void __on_tcp_handle_connect(gs_socket_t *client, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_tcp_resolved(gs_socket_t *client, __const__ int status, __const__ struct sockaddr *addr);

static void __on_tcp_handle_read(gs_socket_t *client, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_tcp_remote_connected(uv_connect_t *conn,int status);

static void __on_tcp_remote_read(uv_stream_t *remote, ssize_t nread, __const__ uv_buf_t *buf);

static void __on_udp_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

static void __on_udp_resolved(gs_socket_t *remote, __const__ int status, __const__ struct sockaddr *addr);

static void __on_udp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

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
    gs_tcp_t * tcps[2];
    gs_udp_t * udps[2];
    conf_t *conf;
    if(argc < 2)
        return __usage(argv[0]);
    conf_t **confs = conf_read(argv[1]);
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
        gs_tcp_t *tcp = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
        memset(tcp, '\0', sizeof(gs_tcp_t));
        gs_udp_t *udp = (gs_udp_t *) malloc(sizeof(gs_udp_t));
        memset(udp, '\0', sizeof(gs_udp_t));
        tcp->loop = loop;
        tcp->aes_key = aes_key;
        udp->loop = loop;
        udp->aes_key = aes_key;
        tcps[0] = tcp;
        tcps[1] = malloc(sizeof(gs_tcp_t));
        memcpy(tcps[1], tcps[0], sizeof(gs_tcp_t));
        udps[0] = udp;
        udps[1] = malloc(sizeof(gs_udp_t));
        memcpy(udps[1], udps[0], sizeof(gs_udp_t));
        uv_tcp_init(loop, (uv_tcp_t *) tcps[0]);
        uv_tcp_init(loop, (uv_tcp_t *) tcps[1]);
        uv_udp_init(loop, (uv_udp_t *) udps[0]);
        uv_udp_init(loop, (uv_udp_t *) udps[1]);
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, (uv_tcp_t **) tcps, __on_tcp_conn, (uv_udp_t **) udps, __on_udp_read) != 0)
            continue;
    }
    manager_bind_loop(loop);
    uv_run(loop, UV_RUN_DEFAULT);
    LOG_DEBUG("main end\n");
    return 0;
}

static int __parse_gs_addr(__const__ char *buf, __const__ size_t len, gs_addr_t *gsaddr)
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
            gsaddr->atyp = atyp;
            gsaddr->addr = (char *) &buf[1];
            gsaddr->len = 4;
            gsaddr->port = *port;
            return 7;
        case 0x03:
            //domian
            if(len < 2)
                return -1;
            dlen = buf[1];
            if(len < dlen + 4)
                return -1;
            port = (uint16_t *) &buf[2 + dlen];
            gsaddr->atyp = atyp;
            gsaddr->addr = (char *) &buf[2];
            gsaddr->len = dlen;
            gsaddr->port = *port;
            return dlen + 4;
        case 0x04:
            //ipv6
            if(len < 19)
                return -1;
            port = (uint16_t *) &buf[17];
            gsaddr->atyp = atyp;
            gsaddr->addr = (char *) &buf[1];
            gsaddr->len = 16;
            gsaddr->port = *port;
            return 19;
        default:
            return -1;
    }
}

static void __on_tcp_conn(uv_stream_t *stream, int status)
{
    LOG_DEBUG("__on_tcp_conn start\n");
    struct sockaddr_storage addr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    int len;
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
    client->aes_key = server->aes_key;
    client->map = NULL;
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
        uv_read_start((uv_stream_t*) client, alloc_buffer, __on_tcp_read);
    }
    else
    {
        LOG_ERR("client connect failed: %s\n", uv_strerror(status));
        manager_close((gs_socket_t *) client);
    }
    LOG_DEBUG("__on_tcp_conn end\n");
}

static void __on_tcp_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf)
{
    LOG_DEBUG("__on_read start\n");
    if (nread > 0)
    {
        gs_parse((gs_socket_t *) client, buf->base, nread, __on_tcp_handle_connect, __on_tcp_handle_read, ((gs_tcp_t *) client)->aes_key, 0);
    }
    if (nread < 0)
    {
        manager_close((gs_socket_t *) client);
        if(((gs_tcp_t *) client)->map != NULL)
            manager_close((gs_socket_t *) ((gs_tcp_t *) client)->map);
        LOG_INFO("client closed\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
    }
    free(buf->base);
    LOG_DEBUG("__on_read end\n");
}

static void __on_tcp_handle_connect(gs_socket_t *client, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_tcp_handle_connect start\n");
    gs_addr_t gsaddr;
    if(((gs_tcp_t *) client)->map != NULL)
    {
        manager_close(client);
        manager_close((gs_socket_t *) ((gs_tcp_t *) client)->map);
        return;
    }
    if(((gs_tcp_t *) client)->proc != 0)
    {
        manager_close(client);
        return;
    }
    ((gs_tcp_t *) client)->proc = 1;
    if(status != 0)
    {
        manager_close(client);
        return;
    }
    if(__parse_gs_addr(buf, len, &gsaddr) != len)
    {
        manager_close(client);
        return;
    }
    if(gs_getaddrinfo(((gs_tcp_t *) client)->loop, client, &gsaddr, __on_tcp_resolved) != 0)
    {
        manager_close(client);
        return;
    }
    LOG_DEBUG("__on_tcp_handle_connect end\n");
}

static void __on_tcp_resolved(gs_socket_t *client, __const__ int status, __const__ struct sockaddr *addr)
{
    LOG_DEBUG("__on_tcp_resolved start\n");
    int en;
    if(status != 0)
    {
        gs_enc_write(client, NULL, NULL, 0, ((gs_tcp_t *) client)->aes_key, 0, 0, 1);
        return;
    }
    gs_tcp_t *remote = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
    memset(remote, '\0', sizeof(gs_tcp_t));
    manager_register((gs_socket_t *) remote);
    uv_tcp_init(((gs_tcp_t *) client)->loop, (uv_tcp_t *) remote);
    remote->map = (gs_tcp_t *) client;
    ((gs_tcp_t *) client)->map = remote;
    uv_connect_t *connect = (uv_connect_t * ) malloc(sizeof(uv_connect_t));
    if((en = uv_tcp_connect(connect, (uv_tcp_t *) remote, addr, __on_tcp_remote_connected)) != 0)
    {
        LOG_ERR("remote connteced failed: %s\n", uv_err_name(en));
        gs_enc_write(client, NULL, NULL, 0, ((gs_tcp_t *) client)->aes_key, 0, 0, 2);
    }
    else
    {
        manager_reference(client);
        manager_reference((gs_socket_t *) remote);
    }
    LOG_DEBUG("__on_tcp_resolved end\n");
}

static void __on_tcp_handle_read(gs_socket_t *client, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_tcp_handle_read start\n");
    gs_socket_t *remote = (gs_socket_t *) ((gs_tcp_t *) client)->map;
    if (len > 0 && status == 0 && ((gs_tcp_t *) client)->proc == 2)
    {
        if(!manager_isclosed(remote))
            gs_write((uv_stream_t *) remote, buf, len);
    }
    else
    {
        manager_close(client);
        if(remote != NULL)
            manager_close(remote);
    }
    LOG_DEBUG("__on_tcp_handle_read end\n");
}

static void __on_tcp_remote_connected(uv_connect_t *conn,int status)
{
    LOG_DEBUG("__on_tcp_remote_connected start\n");
    gs_tcp_t *remote = (gs_tcp_t *) conn->handle;
    gs_tcp_t *client = remote->map;
    manager_unreference((gs_socket_t *) client);
    manager_unreference((gs_socket_t *) remote);
    if(status != 0)
    {
        client->proc = -1;
        LOG_ERR("remote client connect failed: %s\n", uv_strerror(status));
        gs_enc_write((gs_socket_t *) client, NULL, NULL, 0, client->aes_key, 0, 0, 2);
    }
    else
    {
        client->proc = 2;
        gs_enc_write((gs_socket_t *) client, NULL, NULL, 0, client->aes_key, 0, 0, 0);
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
        gs_enc_write(client, NULL, buf->base, nread, ((gs_tcp_t *) client)->aes_key, 1, 0, 0);
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

static void __on_udp_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags)
{
    gs_udp_t *server;
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
        gs_parse((gs_socket_t *) remote, buf->base, nread, NULL, __on_udp_handle_read, remote->aes_key, 1);
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

static void __on_udp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_udp_handle_read start\n");
    gs_addr_t gsaddr;
    int gsaddrlen;
    if(status != 0)
    {
        manager_close(remote);
        return;
    }
    if((gsaddrlen = __parse_gs_addr(buf, len, &gsaddr)) == len)
    {
        manager_close(remote);
        return;
    }
    ((gs_udp_t *) remote)->dbuf = (char *) malloc(sizeof(char) * (len - gsaddrlen));
    ((gs_udp_t *) remote)->dlen = len - gsaddrlen;
    memcpy(((gs_udp_t *) remote)->dbuf, &(buf[gsaddrlen]), len - gsaddrlen);
    if(gs_getaddrinfo(((gs_udp_t *) remote)->loop, (gs_socket_t *) remote, &gsaddr, __on_udp_resolved) != 0)
    {
        free(((gs_udp_t *) remote)->dbuf);
        free(((gs_udp_t *) remote)->addr);
        manager_close((gs_socket_t *) remote);
    }
    remote->act_time = time(NULL);
    manager_timeout(((gs_udp_t *) remote)->loop, remote, 10, __on_udp_timeout);
    LOG_DEBUG("__on_udp_handle_read end\n");
}

static void __on_udp_resolved(gs_socket_t *remote, __const__ int status, __const__ struct sockaddr *addr)
{
    LOG_DEBUG("__on_udp_resolved start\n");
    int en;
    if(status != 0)
    {
        gs_enc_write((gs_socket_t *) ((gs_udp_t *) remote)->server,((gs_udp_t *) remote)->addr, NULL, 0, ((gs_udp_t *) remote)->aes_key, 1, 1, 1);
        free(((gs_udp_t *) remote)->dbuf);
        return;
    }
    if(gs_udp_send((uv_udp_t *) remote, ((gs_udp_t *) remote)->dbuf, ((gs_udp_t *) remote)->dlen, addr) != 0)
    {
        gs_enc_write((gs_socket_t *) ((gs_udp_t *) remote)->server,((gs_udp_t *) remote)->addr, NULL, 0, ((gs_udp_t *) remote)->aes_key, 1, 1, 1);
        free(((gs_udp_t *) remote)->dbuf);
        return;
    }
    uv_udp_recv_start((uv_udp_t *) remote, alloc_buffer, __on_udp_remote_read);
    free(((gs_udp_t *) remote)->dbuf);
    LOG_DEBUG("__on_udp_resolved end\n");
}

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags)
{
    gs_udp_t *remote = (gs_udp_t *) handle;
    LOG_DEBUG("__on_udp_remote_read start\n");
    if (nread > 0)
    {
        ((gs_socket_t *) remote)->act_time = time(NULL);
        gs_enc_write((gs_socket_t *) remote->server,remote->addr, buf->base, nread, ((gs_udp_t *) remote)->aes_key, 1, 1, 0);
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

static void __on_udp_timeout(gs_socket_t *remote)
{
    free(((gs_udp_t *) remote)->addr);
}
