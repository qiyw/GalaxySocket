include Makefile.inc

GSSOCKS5_SRCS = gssocks5.c iconf.c common.c base64.c aes.c  pipe.c thrdpool.c crc32.c
GSSOCKS5_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSSOCKS5_SRCS))

all: $(GSSOCKS5_BIN)

$(GSSOCKS5_BIN): $(OBJDIR) $(BINDIR) $(GSSOCKS5_OBJS)
	$(CC) -o $@ $(GSSOCKS5_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
