#ifndef _ICONF_H
#define _ICONF_H

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

#endif
