#ifndef _ICONF_H
#define _ICONF_H

#define CONF_DEFAULT_PORT 1520
#define CONF_DEFAULT_BIND_IPV4 "localhost"
#define CONF_DEFAULT_BIND_IPV6 "localhost"
#define CONF_DEFAULT_DNS "8.8.8.8"

#include "iniparser/iniparser.h"

typedef struct
{
    char *baddr;
    char *baddr6;
    int bport;
    char *server;
    int port;
    char *key;
    char *dns_server;
    int dns_port;
} conf_t;

conf_t **conf_read(char *filepath);

void conf_free(conf_t **confs);

#endif
