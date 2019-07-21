CC ?= cc
PREFIX ?= /usr/local

SRCDIR = src
OBJDIR = obj
BINDIR = bin
PREFIX_BIN = $(PREFIX)/$(BINDIR)
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(wildcard $(SRCDIR)/*.c))

GSDNS_SRCS = gsdns.c iconf.c common.c base64.c aes.c pipe.c thrdpool.c
GSDNS_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSDNS_SRCS))
GSDNS_BIN = $(BINDIR)/gsdns

GSGENKEN_SRCS = gsgenkey.c base64.c
GSGENKEN_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSGENKEN_SRCS))
GSGENKEN_BIN = $(BINDIR)/gsgenkey

GSRED_SRCS = gsred.c iconf.c common.c base64.c aes.c  pipe.c thrdpool.c
GSRED_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSRED_SRCS))
GSRED_BIN = $(BINDIR)/gsred

GSSOCKS5_SRCS = gssocks5.c iconf.c common.c base64.c aes.c  pipe.c thrdpool.c
GSSOCKS5_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSSOCKS5_SRCS))
GSSOCKS5_BIN = $(BINDIR)/gssocks5

GSSERVER_SRCS = gsserver.c iconf.c common.c base64.c aes.c  pipe.c thrdpool.c
GSSERVER_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSSERVER_SRCS))
GSSERVER_BIN = $(BINDIR)/gsserver

CFLAGS += -Os -Wall
LDFLAGS += -s -lssl -lcrypto -liniparser -lpthread -lz

ifdef DEBUG
CFLAGS += -DDEBUG -g
LDFLAGS += -g
endif

all: $(GSDNS_BIN) $(GSGENKEN_BIN) $(GSRED_BIN) $(GSSOCKS5_BIN) $(GSSERVER_BIN)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(GSDNS_BIN): $(OBJDIR) $(BINDIR) $(GSDNS_OBJS)
	$(CC) -o $(GSDNS_BIN) $(LDFLAGS) $(GSDNS_OBJS)

$(GSGENKEN_BIN): $(OBJDIR) $(BINDIR) $(GSGENKEN_OBJS)
	$(CC) -o $(GSGENKEN_BIN) $(LDFLAGS) $(GSGENKEN_OBJS)

$(GSRED_BIN): $(OBJDIR) $(BINDIR) $(GSRED_OBJS)
	$(CC) -o $(GSRED_BIN) $(LDFLAGS) $(GSRED_OBJS)

$(GSSOCKS5_BIN): $(OBJDIR) $(BINDIR) $(GSSOCKS5_OBJS)
	$(CC) -o $(GSSOCKS5_BIN) $(LDFLAGS) $(GSSOCKS5_OBJS)

$(GSSERVER_BIN): $(OBJDIR) $(BINDIR) $(GSSERVER_OBJS)
	$(CC) -o $(GSSERVER_BIN) $(LDFLAGS) $(GSSERVER_OBJS)

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(GSDNS_BIN) $(GSGENKEN_BIN) $(GSRED_BIN) $(GSSOCKS5_BIN) $(GSSERVER_BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(GSDNS_BIN) $(PREFIX)/$(GSGENKEN_BIN) $(PREFIX)/$(GSRED_BIN) $(PREFIX)/$(GSSOCKS5_BIN) $(PREFIX)/$(GSSERVER_BIN)

.PHONY: all clean install uninstall
