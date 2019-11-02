include Makefile.inc

GSRED_SRCS = gsred.c iconf.c common.c base64.c aes.c  pipe.c thrdpool.c crc32.c
GSRED_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSRED_SRCS))

all: $(GSRED_BIN)

$(GSRED_BIN): $(OBJDIR) $(BINDIR) $(GSRED_OBJS)
	$(CC) -o $@ $(GSRED_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
