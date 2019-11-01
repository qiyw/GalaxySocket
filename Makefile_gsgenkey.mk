include Makefile.inc

GSGENKEN_SRCS = gsgenkey.c base64.c
GSGENKEN_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(GSGENKEN_SRCS))

all: $(GSGENKEN_BIN)

$(GSGENKEN_BIN): $(OBJDIR) $(BINDIR) $(GSGENKEN_OBJS)
	$(CC) -o $@ $(GSGENKEN_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
