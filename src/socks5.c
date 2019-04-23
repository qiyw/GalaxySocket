#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "socks5.h"
#include "log.h"
#include "time.h"

typedef struct
{
    char ver;
    char cmd;
    char rsv;
    char atyp;
} __attribute__ ((__packed__)) s5_conn_header_t;

typedef struct
{
    char rsv[2];
    char frag;
    char atyp;
} __attribute__ ((__packed__)) s5_trans_header_t;

typedef struct
{
    uv_timer_t timer;
    gs_s5_socket_t *s;
} s5_timer_t;

static void __s5_tcp_handle_connect(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    char resbuf[10];
    memset(resbuf, '\0', 10);
    gs_socket_t *client = (gs_socket_t *) ((gs_s5_socket_t *) remote)->map;
    if(manager_isclosed(client))
        return;
    if(status != 0)
    {
        resbuf[0] = S5_VERSION;
        resbuf[1] = 0x04;
        resbuf[3] = 0x01;
        gs_write((uv_stream_t *) client, resbuf, 10);
    }
    else
    {
        resbuf[0] = S5_VERSION;
        resbuf[1] = 0x00;
        resbuf[3] = 0x01;
        gs_write((uv_stream_t *) client, resbuf, 10);
        ((gs_s5_socket_t *) client)->s5->status = S5_STATUS_END_CONNECT;
        ((gs_s5_socket_t *) client)->s5->type = 1;
    }
}

static void __s5_tcp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    gs_socket_t *client = (gs_socket_t *) ((gs_s5_socket_t *) remote)->map;
    if(status != 0)
    {
        manager_close((gs_socket_t *) remote);
        manager_close(client);
    }
    else
    {
        if(!manager_isclosed(client))
            gs_write((uv_stream_t *) client, buf, len);
    }
}

static void __s5_tcp_on_read(uv_stream_t *remote, ssize_t nread, __const__ uv_buf_t *buf)
{
    LOG_DEBUG("__s5_tcp_on_read start\n");
    gs_socket_t *client = (gs_socket_t *) ((gs_s5_socket_t *) remote)->map;
    if (nread > 0)
    {
        gs_parse((gs_socket_t *) remote, buf->base, nread, __s5_tcp_handle_connect, __s5_tcp_handle_read, ((gs_s5_socket_t *) client)->aes_key, 0);
    }
    if (nread < 0)
    {
        manager_close((gs_socket_t *) remote);
        manager_close(client);
        LOG_INFO("remote server closed\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
    }
    free(buf->base);
    LOG_DEBUG("__s5_tcp_on_read end\n");
}

static void __on_remote_connected(uv_connect_t *conn,int status)
{
    LOG_DEBUG("__on_remote_connected start\n");
    char resbuf[10];
    gs_s5_socket_t *remote = (gs_s5_socket_t *) conn->handle;
    gs_s5_socket_t *client = remote->map;
    manager_unreference((gs_socket_t *) client);
    manager_unreference((gs_socket_t *) remote);
    memset(resbuf, '\0', 10);
    if(status != 0)
    {
        LOG_ERR("remote client connect failed: %s\n", uv_strerror(status));
        resbuf[0] = S5_VERSION;
        resbuf[1] = 0x04;
        resbuf[3] = 0x01;
        if(!manager_isclosed((gs_socket_t *) client))
            gs_write((uv_stream_t *) client, resbuf, 10);
    }
    else
    {
        if(!manager_isclosed((gs_socket_t *) remote) && !manager_isclosed((gs_socket_t *) client))
        {
            gs_enc_write((gs_socket_t *) remote, NULL, client->addrbuf, client->addrlen, client->aes_key, 0, 0, 0);
            uv_read_start((uv_stream_t*) remote, alloc_buffer, __s5_tcp_on_read);
        }
    }
    free(conn);
    free(client->addrbuf);
    LOG_DEBUG("__on_remote_connected end\n");
}

static void __s5_udp_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    gs_s5_socket_t *client = ((gs_s5_socket_t *) remote)->map;
    if(status != 0)
    {
        manager_close(remote);
        manager_close((gs_socket_t *) client);
        return;
    }
    if(!manager_isclosed((gs_socket_t *) client))
    {
        char resbuf[10 + len];
        resbuf[3] = 0x01;
        memcpy(&resbuf[10], buf, len);
        gs_write((uv_stream_t *) client, resbuf, 10 + len);
    }
}

static void __s5_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags)
{
    gs_s5_socket_t *remote = (gs_s5_socket_t *) handle;
    LOG_DEBUG("__on_udp_remote_read start\n");
    if (nread > 0)
    {
        ((gs_socket_t *) remote)->act_time = time(NULL);
        gs_parse((gs_socket_t *) remote, buf->base, nread, NULL, __s5_udp_handle_read, remote->aes_key, 1);
    }
    if (nread < 0)
    {
        printf("end\n");
        if (nread != UV_EOF)
            fprintf(stderr, "%s\n", uv_err_name(nread));
        manager_close((gs_socket_t *) remote);
        manager_close((gs_socket_t *) remote->map);
    }
    free(buf->base);
}

static void __do_authentication(gs_s5_socket_t *client, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("__do_authentication start\n");
    char dlen;
    char method;
    char ver;
    char resbuf[2];
    if(len <= 2)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    ver = buf[0];
    if(ver != S5_VERSION)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    dlen = buf[1];
    if(dlen != len - 2)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    char *tbuf = (char *) &buf[2];
    while(dlen--)
    {
        method = *tbuf++;
        if(client->s5->needauth == 0)
        {
            if(method == 0x00)
            {
                resbuf[0] = S5_VERSION;
                resbuf[1] = 0x00;
                client->s5->status = S5_STATUS_END_AUTH;
                gs_write((uv_stream_t *) client, resbuf, 2);
                return;
            }
        }
        else
        {
            if(method == 0x01)
            {
                resbuf[0] = S5_VERSION;
                resbuf[1] = 0x01;
                client->s5->status = S5_STATUS_AUTHENTICATION;
                gs_write((uv_stream_t *) client, resbuf, 2);
                return;
            }
        }
    }
    resbuf[0] = S5_VERSION;
    resbuf[1] = 0xff;
    gs_write((uv_stream_t *) client, resbuf, 2);
    LOG_DEBUG("__do_authentication end\n");
}

static void __do_auth_user(gs_s5_socket_t *client, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("__do_auth_user start\n");
    char ver, luser, *user, lpasswd, *passwd;
    char resbuf[2];
    if(len <= 2)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    ver = buf[0];
    if(ver != S5_SUB_VERSION)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    luser = buf[1];
    if(luser >= len - 2)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    user = (char *) malloc(sizeof(char) * (luser + 1));
    memcpy(user, buf + 2, luser);
    user[luser] = '\0';
    if(len <= 2 + luser)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    lpasswd = buf[2 + luser];
    if(lpasswd != len - luser - 3)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    passwd = (char *) malloc(sizeof(char) * (lpasswd + 1));
    memcpy(passwd, buf + luser + 3, lpasswd);
    passwd[lpasswd] = '\0';
    if(strcmp(client->s5->user, user) == 0
        && strcmp(client->s5->passwd, passwd) == 0)
    {
        resbuf[0] = S5_SUB_VERSION;
        resbuf[1] = 0x00;
        client->s5->status = S5_STATUS_END_AUTH;
        gs_write((uv_stream_t *) client, resbuf, 2);
        return;
    }
    else
    {
        resbuf[0] = S5_SUB_VERSION;
        resbuf[1] = 0x01;
        gs_write((uv_stream_t *) client, resbuf, 2);
    }
    LOG_DEBUG("__do_auth_user end\n");
}

static void __do_connect(gs_s5_socket_t *client, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("__do_connect start\n");
    int addrlen;
    char domainlen;
    s5_conn_header_t *header;
    int headerlen = sizeof(s5_conn_header_t);
    int en;
    char resbuf[10];
    memset(resbuf, '\0', 10);
    gs_s5_socket_t *remote;
    if(len <= headerlen)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    header = (s5_conn_header_t *) buf;
    if(header->ver != S5_VERSION)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    switch(header->atyp)
    {
        case 0x01:
            if(len != headerlen + 6)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            addrlen = 7;
            break;
        case 0x03:
            if(len <= headerlen)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            domainlen = buf[headerlen];
            if(len != domainlen + headerlen + 3)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            addrlen = domainlen + 4;
            break;
        case 0x04:
            if(len != headerlen + 18)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            addrlen = 19;
            break;
        default:
            resbuf[0] = S5_VERSION;
            resbuf[1] = 0x08;
            resbuf[3] = 0x01;
            gs_write((uv_stream_t *) client, resbuf, 10);
            return;
    }
    switch(header->cmd)
    {
        case 0x01:
            remote = (gs_s5_socket_t *) malloc(sizeof(gs_s5_socket_t));
            memset(remote, '\0', sizeof(gs_s5_socket_t));
            manager_register((gs_socket_t *) remote);
            uv_tcp_init(client->loop, (uv_tcp_t *) remote);
            remote->map = client;
            client->map = remote;
            uv_connect_t *connect = (uv_connect_t * ) malloc(sizeof(uv_connect_t));
            if((en = uv_tcp_connect(connect, (uv_tcp_t *) remote, client->server, __on_remote_connected)) != 0)
            {
                LOG_ERR("remote connteced failed: %s\n", uv_err_name(en));
                resbuf[0] = S5_VERSION;
                resbuf[1] = 0x03;
                resbuf[3] = 0x01;
                gs_write((uv_stream_t *) client, resbuf, 10);
            }
            else
            {
                client->addrbuf = (char *) malloc(sizeof(char) * addrlen);
                memcpy(client->addrbuf, &buf[3], addrlen);
                client->addrlen = addrlen;
                manager_reference((gs_socket_t *) client);
                manager_reference((gs_socket_t *) remote);
            }
            break;
        case 0x02:
            //bind not support
            resbuf[0] = S5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            gs_write((uv_stream_t *) client, resbuf, 10);
            return;
        case 0x03:
            resbuf[0] = S5_VERSION;
            resbuf[1] = 0x00;
            resbuf[3] = 0x01;
            gs_write((uv_stream_t *) client, resbuf, 10);
            client->s5->status = S5_STATUS_END_CONNECT;
            client->s5->type = 2;
            break;
        default:
            resbuf[0] = S5_VERSION;
            resbuf[1] = 0x07;
            resbuf[3] = 0x01;
            gs_write((uv_stream_t *) client, resbuf, 10);
            return;
    }
    LOG_DEBUG("__do_connect end\n");
}

static void __do_tcp_transfer(gs_s5_socket_t *client, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("__do_tcp_transfer start\n");
    gs_socket_t *remote = (gs_socket_t *) client->map;
    gs_enc_write(remote, NULL, buf, len, client->aes_key, 1, 0, 0);
    LOG_DEBUG("__do_tcp_transfer end\n");
}

static void __do_udp_transfer(gs_s5_socket_t *client, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("__do_udp_transfer start\n");
    s5_trans_header_t *header;
    int headerlen = sizeof(s5_trans_header_t);
    int addrlen;
    char domainlen;
    if(len <= headerlen)
    {
        manager_close((gs_socket_t *) client);
        return;
    }
    header = (s5_trans_header_t *) buf;
    switch(header->atyp)
    {
        case 0x01:
            if(len <= headerlen + 6)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            addrlen = 7;
            break;
        case 0x03:
            if(len <= headerlen)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            domainlen = buf[headerlen];
            if(len <= domainlen + headerlen + 3)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            addrlen = domainlen + 4;
            break;
        case 0x04:
            if(len <= headerlen + 18)
            {
                manager_close((gs_socket_t *) client);
                return;
            }
            addrlen = 19;
            break;
        default:
            manager_close((gs_socket_t *) client);
            return;
    }
    gs_s5_socket_t *remote = (gs_s5_socket_t *) malloc(sizeof(gs_s5_socket_t));
    memset(remote, '\0', sizeof(gs_s5_socket_t));
    manager_register((gs_socket_t *) remote);
    remote->aes_key = client->aes_key;
    remote->map = client;
    client->map = remote;
    uv_udp_init(client->loop, (uv_udp_t *) remote);
    gs_enc_write((gs_socket_t *) remote, client->server, &buf[3], len - 3, client->aes_key, 1, 1, 0);
    uv_udp_recv_start((uv_udp_t *) remote, alloc_buffer, __s5_udp_remote_read);
    ((gs_socket_t *) remote)->act_time = time(NULL);
    manager_timeout(client->loop, (gs_socket_t *) remote, 10, NULL);
    LOG_DEBUG("__do_udp_transfer end\n");
}

void socks5_parse(gs_s5_socket_t *s, __const__ char *buf, __const__ size_t len)
{
    LOG_DEBUG("socks5_parse start\n");
    switch(s->s5->status)
    {
        case S5_STATUS_BEGIN:
            __do_authentication(s, buf, len);
            break;
        case S5_STATUS_AUTHENTICATION:
            __do_auth_user(s, buf, len);
            break;
        case S5_STATUS_END_AUTH:
            __do_connect(s, buf, len);
            break;
        case S5_STATUS_END_CONNECT:
            if(s->s5->type == 1)
                __do_tcp_transfer(s, buf, len);
            if(s->s5->type == 2)
                __do_udp_transfer(s, buf, len);
            break;
        default:
            manager_close((gs_socket_t *) s);
            break;
    }
    LOG_DEBUG("socks5_parse end\n");
}
