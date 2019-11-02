include Makefile.inc

GSSERVER_SRCS = gsserver.c iconf.c common.c base64.c aes.c  pipe.c thrdpool.c crc32.c
GSSERVER_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSSERVER_SRCS))

all: $(GSSERVER_BIN)

$(GSSERVER_BIN): $(OBJDIR) $(BINDIR) $(GSSERVER_OBJS)
	$(CC) -o $@ $(GSSERVER_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
