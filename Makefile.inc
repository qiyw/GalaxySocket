CC ?= cc
PREFIX ?= /usr/local

SRCDIR = src
OBJDIR = obj
BINDIR = bin
PREFIX_BIN = $(PREFIX)/$(BINDIR)

GSDNS_BIN = $(BINDIR)/gsdns
GSGENKEN_BIN = $(BINDIR)/gsgenkey
GSRED_BIN = $(BINDIR)/gsred
GSSOCKS5_BIN = $(BINDIR)/gssocks5
GSSERVER_BIN = $(BINDIR)/gsserver

CFLAGS += -Os -Wall
LDFLAGS += -s -lssl -lcrypto -liniparser -lpthread

ifdef DEBUG
CFLAGS += -DDEBUG -g
LDFLAGS += -g
endif
