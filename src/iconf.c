#include <string.h>
#include <stdlib.h>

#include "iconf.h"
#include "log.h"

static char *__ckey(__const__ char *secname, __const__ char *prop)
{
    static char key[1024];
    char *tmp = key;
    while(*secname)
        *tmp++ = *secname++;
    *tmp++ = ':';
    while(*prop)
        *tmp++ = *prop++;
    *tmp = '\0';
    return key;
}

static conf_t *__read_from_section(__const__ dictionary *d, __const__ char *secname)
{
    char *server, *key, *baddr, *baddr6, *dns_server;
    int port, bport, dns_port;
    baddr = (char *) iniparser_getstring(d, __ckey(secname, "bind_addr"), CONF_DEFAULT_BIND_IPV4);
    baddr6 = (char *) iniparser_getstring(d, __ckey(secname, "bind_addr6"), CONF_DEFAULT_BIND_IPV6);
    bport = iniparser_getint(d, __ckey(secname, "bind_port"), CONF_DEFAULT_PORT);
    if(bport < 0 || bport > 65535)
    {
        LOG_ERR("%s: bind_port must be 0-65535\n", secname);
        return NULL;
    }
    server = (char *) iniparser_getstring(d, __ckey(secname, "server"), CONF_DEFAULT_BIND_IPV4);
    port = iniparser_getint(d, __ckey(secname, "port"), CONF_DEFAULT_PORT);
    if(port < 0 || port > 65535)
    {
        LOG_ERR("%s: port must be 0-65535\n", secname);
        return NULL;
    }
    key = (char *) iniparser_getstring(d, __ckey(secname, "key"), "");
    dns_server = (char *) iniparser_getstring(d, __ckey(secname, "dns_server"), CONF_DEFAULT_DNS);
    dns_port = iniparser_getint(d, __ckey(secname, "dns_port"), 53);
    conf_t *conf = (conf_t *) malloc(sizeof(conf_t));
    if(conf == NULL)
        return NULL;
    conf->baddr = baddr;
    conf->baddr6 = baddr6;
    conf->bport = bport;
    conf->server = server;
    conf->port = port;
    conf->key = key;
    conf->dns_server = dns_server;
    conf->dns_port = dns_port;
    return conf;
}

conf_t **conf_read(char *filepath)
{
    dictionary *ini;
    conf_t **r;
    int secs;
    ini = iniparser_load(filepath);
    if(ini == NULL)
    {
        LOG_ERR("can not open file %s\n", filepath);
        return NULL;
    }
    secs = iniparser_getnsec(ini);
    r = malloc(sizeof(conf_t *) * (secs + 1));
    r[secs] = NULL;
    for(int i = 0; i < secs; i++)
    {
        char* section_name = (char*) iniparser_getsecname(ini, i);
        conf_t *conf = __read_from_section(ini, section_name);
        if(conf == NULL)
        {
            free(r);
            return NULL;
        }
        r[i] = conf;
    }
    return r;
}

void conf_free(conf_t **confs)
{
    conf_t **tmp = confs;
    conf_t *conf;
    while((conf = *tmp++) != NULL)
        free(conf);
    free(confs);
}
