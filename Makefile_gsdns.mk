include Makefile.inc

GSDNS_SRCS = gsdns.c iconf.c common.c base64.c aes.c pipe.c thrdpool.c
GSDNS_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSDNS_SRCS))

all: $(GSDNS_BIN)

$(GSDNS_BIN): $(OBJDIR) $(BINDIR) $(GSDNS_OBJS)
	$(CC) -o $@ $(GSDNS_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
