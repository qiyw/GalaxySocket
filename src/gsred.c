#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <errno.h>

#include "iconf.h"
#include "aes.h"
#include "base64.h"
#include "uv.h"
#include "common.h"
#include "sockmnr.h"
#include "log.h"

typedef struct gs_tcp_s
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    char proc;
    struct sockaddr* srvaddr;
    struct gs_tcp_s *map;
} gs_tcp_t;

typedef struct gs_udp_s
{
    gs_socket_t socket;
    uv_os_sock_t *server;
    struct sockaddr* addr;
    char *aes_key;
} gs_udp_t;

typedef struct
{
    gs_socket_t socket;
    uv_loop_t *loop;
    char *aes_key;
    uv_os_sock_t *server;
    struct sockaddr* srvaddr;
} gs_udp_server_thread_t;

static int __do_bind(uv_os_fd_t *fd, int sa_family, char *host, int port);

static int __get_tcp_destaddr(uv_os_fd_t *fd, struct sockaddr_storage *destaddr);

static int __set_udp_redir_option(uv_os_fd_t *fd, int sa_family);

static int __get_udp_destaddr(struct msghdr *msg, struct sockaddr_storage *destaddr);

static void __on_tcp_conn(uv_stream_t *stream, int status);

static void __on_tcp_remote_connected(uv_connect_t *conn,int status);

static void __on_tcp_remote_read(uv_stream_t *remote, ssize_t nread, __const__ uv_buf_t *buf);

static void __on_tcp_remote_handle_connect(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_tcp_read(uv_stream_t *client, ssize_t nread, __const__ uv_buf_t *buf);

static void __on_tcp_remote_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __udp_read_thread(void *arg);

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags);

static void __on_udp_remote_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status);

static void __on_udp_timeout(gs_socket_t *remote);

static int __usage(char *prog)
{
    printf("Usage: %s INI_FILE\n", prog);
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv)
{
    gs_tcp_t * tcps[2];
    uv_os_sock_t fd[2];
    struct sockaddr_storage *srvaddr = NULL;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    gs_udp_server_thread_t *udps[2];
    uv_thread_t threads[2];
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
        gs_tcp_t *tcp = (gs_tcp_t *) malloc(sizeof(gs_tcp_t));
        memset(tcp, '\0', sizeof(gs_tcp_t));
        tcp->loop = loop;
        tcp->aes_key = aes_key;
        tcp->srvaddr = (struct sockaddr *) srvaddr;
        tcps[0] = tcp;
        tcps[1] = malloc(sizeof(gs_tcp_t));
        memcpy(tcps[1], tcps[0], sizeof(gs_tcp_t));
        uv_tcp_init(loop, (uv_tcp_t *) tcps[0]);
        uv_tcp_init(loop, (uv_tcp_t *) tcps[1]);

        gs_udp_server_thread_t *udp = (gs_udp_server_thread_t *) malloc(sizeof(gs_udp_server_thread_t));
        memset(udp, '\0', sizeof(gs_udp_server_thread_t));
        udp->loop = loop;
        udp->aes_key = aes_key;
        udp->srvaddr = (struct sockaddr *) srvaddr;
        udps[0] = udp;
        udps[1] = malloc(sizeof(gs_udp_server_thread_t));
        memcpy(udps[1], udps[0], sizeof(gs_udp_server_thread_t));

        if(__do_bind(fd, AF_INET6, conf->baddr6, conf->bport) != 0)
            continue;
        if(__do_bind(fd + 1, AF_INET, conf->baddr, conf->bport) != 0)
        {
            close(*fd);
            continue;
        }
        udps[0]->server = fd;
        udps[1]->server = fd + 1;
        if(do_bind(conf->baddr6, conf->baddr, conf->bport, (uv_tcp_t **) tcps, __on_tcp_conn, NULL, NULL) != 0)
            continue;
        uv_thread_create(threads, __udp_read_thread, *udps);
        uv_thread_create(threads + 1, __udp_read_thread, *(udps + 1));
    }
    manager_bind_loop(loop);
    uv_run(loop, UV_RUN_DEFAULT);
    LOG_DEBUG("main end\n");
    return 0;
}

static int __do_bind(uv_os_fd_t *fd, int sa_family, char *host, int port)
{
    struct sockaddr_storage addr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    if(sa_family == AF_INET)
    {
        if(getipv4hostbyname(host, (struct sockaddr_in *) &addr) != 0)
        {
            LOG_ERR("unknown server: %s\n", host);
            return 1;
        }
        addr4 = (struct sockaddr_in *) &addr;
        addr4->sin_port = port;
        reverse((char *) &addr4->sin_port, 2);
    }
    else
    {
        if(getipv6hostbyname(host, (struct sockaddr_in6 *) &addr) != 0)
        {
            LOG_ERR("unknown server: %s\n", host);
            return 1;
        }
        addr6 = (struct sockaddr_in6 *) &addr;
        addr6->sin6_port = port;
        reverse((char *) &addr6->sin6_port, 2);
    }
    int on = 1;
    *fd = socket(sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if(*fd < 0)
    {
        LOG_ERR("create udp socket failed\n");
        return 1;
    }
    if(sa_family == AF_INET6)
        setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    if(__set_udp_redir_option(fd, sa_family) != 0)
    {
        close(*fd);
        return 1;
    }
    if(bind(*fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_storage)) != 0)
    {
        LOG_ERR("bind udp socket failed\n");
        close(*fd);
        return 1;
    }
    return 0;
}

static int __get_tcp_destaddr(uv_os_fd_t *fd, struct sockaddr_storage *destaddr)
{
    socklen_t len = sizeof(struct sockaddr_storage);
    int en = 0;

    //get ipv6
    en = getsockopt(*fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &len);
    if(en == 0)
        return 0;
    //get ipv4
    return getsockopt(*fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &len);;
}

static int __set_udp_redir_option(uv_os_fd_t *fd, int sa_family)
{
    int en;
    int on = 1;
    setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if((en = setsockopt(*fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on))) != 0) {
        printf("err = %d\n", en);
        LOG_ERR("udp set option %s failed: %s\n", "IP_TRANSPARENT", strerror(errno));
        return 1;
    }
    if (sa_family == AF_INET) {
        if(setsockopt(*fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) != 0) {
            LOG_ERR("udp set option %s failed: %s\n", "IP_RECVORIGDSTADDR", strerror(errno));
            return 1;
        }
    } else {
        if (setsockopt(*fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on)) != 0) {
            LOG_ERR("udp set option %s failed: %s\n", "IPV6_RECVORIGDSTADDR", strerror(errno));
            return 1;
        }
    }
    return 0;
}

static int __get_udp_destaddr(struct msghdr *msg, struct sockaddr_storage *destaddr)
{
    struct cmsghdr *cmsg;
    for(cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if(cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR)
        {
            memcpy(destaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            destaddr->ss_family = AF_INET;
            return 0;
        }
        else if(cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR)
        {
            memcpy(destaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            destaddr->ss_family = AF_INET6;
            return 0;
        }
    }
    return 1;
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
    struct sockaddr_storage addr;
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
        if((en = uv_fileno((uv_handle_t *) client, &fd)) != 0)
        {
            LOG_ERR("get socket failed: %s\n", uv_strerror(en));
            manager_close((gs_socket_t *) client);
            manager_close((gs_socket_t *) remote);
            free(conn);
            return;
        }
        if(__get_tcp_destaddr(&fd, &addr) != 0)
        {
            LOG_ERR("get dest address failed\n");
            manager_close((gs_socket_t *) client);
            manager_close((gs_socket_t *) remote);
            free(conn);
            return;
        }
        if(addr.ss_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) &addr;
            LOG_INFO("tcp redir tp addr: %s:%d\n", inet_ntoa(addr4->sin_addr), ntohs(addr4->sin_port));
            len = 7;
            buf = (char *) malloc(sizeof(char) * len);
            buf[0] = 0x01;
            memcpy(&buf[1], &addr4->sin_addr, 4);
            memcpy(&buf[5], &addr4->sin_port, 2);
        }
        else
        {
            char s[INET6_ADDRSTRLEN];
            addr6 = (struct sockaddr_in6 *) &addr;
            inet_ntop(AF_INET6, &addr6->sin6_addr, s, sizeof s);
            LOG_INFO("tcp redir to addr: %s:%d\n", s, ntohs(addr6->sin6_port));
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

static void __udp_read_thread(void *arg)
{
    struct sockaddr_storage clntaddr;
    struct sockaddr_storage addr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    struct msghdr msg;
    char cntrlbuf[64];
    char buffer[BUFFER_SIZE];
    struct iovec iov[1];
    gs_udp_server_thread_t *udp = (gs_udp_server_thread_t *) arg;
    int readsize;
    char *buf;
    int len;
    while (1)
    {
        memset(&clntaddr, '\0', sizeof(struct sockaddr_storage));
        memset(cntrlbuf, '\0', 64);
        memset(buffer, '\0', BUFFER_SIZE);
        msg.msg_name = &clntaddr;
        msg.msg_namelen = sizeof(struct sockaddr_storage);
        msg.msg_control = cntrlbuf;
        msg.msg_controllen = 64;
        iov[0].iov_base = buffer;
        iov[0].iov_len = BUFFER_SIZE;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        readsize = recvmsg(*udp->server, &msg, 0);
        if(readsize <= 0)
        {
            LOG_ERR("recv udp message failed: %s\n", strerror(errno));
            continue;
        }
        if(__get_udp_destaddr(&msg, &addr) != 0)
        {
            LOG_ERR("get dest address failed\n");
            continue;
        }
        if(addr.ss_family == AF_INET)
        {
            addr4 = (struct sockaddr_in *) &addr;
            LOG_INFO("udp redir to addr: %s:%d\n", inet_ntoa(addr4->sin_addr), ntohs(addr4->sin_port));
            len = 7;
            buf = (char *) malloc(sizeof(char) * (len + readsize));
            buf[0] = 0x01;
            memcpy(&buf[1], &addr4->sin_addr, 4);
            memcpy(&buf[5], &addr4->sin_port, 2);
        }
        else
        {
            char s[INET6_ADDRSTRLEN];
            addr6 = (struct sockaddr_in6 *) &addr;
            inet_ntop(AF_INET6, &addr6->sin6_addr, s, sizeof s);
            LOG_INFO("udp redir to addr: %s:%d\n", s, ntohs(addr6->sin6_port));
            len = 19;
            buf = (char *) malloc(sizeof(char) * (len + readsize));
            buf[0] = 0x04;
            memcpy(&buf[1], &addr6->sin6_addr, 16);
            memcpy(&buf[17], &addr6->sin6_port, 2);
        }
        memcpy(&buf[len], buffer, readsize);
        gs_udp_t *remote = (gs_udp_t *) malloc(sizeof(gs_udp_t));
        memset(remote, '\0', sizeof(gs_udp_t));
        manager_register((gs_socket_t *) remote);
        remote->server = udp->server;
        remote->aes_key = udp->aes_key;
        remote->addr = (struct sockaddr *) malloc(sizeof(struct sockaddr_storage));
        memcpy(remote->addr, &clntaddr, sizeof(struct sockaddr_storage));
        uv_udp_init(udp->loop, (uv_udp_t *) remote);
        if(gs_enc_write((gs_socket_t *) remote, udp->srvaddr, buf, len + readsize, udp->aes_key, 1, 1, 0) != 0)
        {
            LOG_ERR("udp send failed\n");
            free(buf);
            free(remote->addr);
            manager_close((gs_socket_t *) remote);
            return;
        }
        uv_udp_recv_start((uv_udp_t *) remote, alloc_buffer, __on_udp_remote_read);
        ((gs_socket_t *) remote)->act_time = time(NULL);
        manager_timeout(udp->loop, (gs_socket_t *) remote, 60, __on_udp_timeout);
        free(buf);
    }
}

static void __on_udp_remote_read(uv_udp_t* handle, ssize_t nread, __const__ uv_buf_t *buf, __const__ struct sockaddr* addr, unsigned flags)
{
    LOG_DEBUG("__on_udp_remote_read start\n");
    gs_socket_t *remote = (gs_socket_t *) handle;
    if (nread > 0)
    {
        remote->act_time = time(NULL);
        gs_parse(remote, buf->base, nread, NULL, __on_udp_remote_handle_read, ((gs_udp_t *) remote)->aes_key, 1);
    }
    if (nread < 0)
    {
        LOG_INFO("udp read error\n");
        if (nread != UV_EOF)
            LOG_ERR("cause: %s\n", uv_err_name(nread));
        manager_close(remote);
    }
    free(buf->base);
    LOG_DEBUG("__on_udp_remote_read end\n");
}

static void __on_udp_remote_handle_read(gs_socket_t *remote, __const__ char *buf, __const__ size_t len, __const__ int status)
{
    LOG_DEBUG("__on_udp_remote_handle_read start\n");
    gs_udp_t *r = (gs_udp_t *) remote;
    if(status != 0)
    {
        manager_close(remote);
        return;
    }
    int ret = sendto(*r->server, buf, len, 0, r->addr, sizeof(struct sockaddr_storage));
    LOG_DEBUG("__on_udp_remote_handle_read end\n");
}

static void __on_udp_timeout(gs_socket_t *remote)
{
    free(((gs_udp_t *) remote)->addr);
}
