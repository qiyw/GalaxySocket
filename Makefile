include Makefile.inc

all: $(GSDNS_BIN) $(GSGENKEN_BIN) $(GSRED_BIN) $(GSSOCKS5_BIN) $(GSSERVER_BIN)

$(GSDNS_BIN):
	@make -f Makefile_gsdns.mk

$(GSGENKEN_BIN):
	@make -f Makefile_gsgenkey.mk

$(GSRED_BIN):
	@make -f Makefile_gsred.mk

$(GSSOCKS5_BIN):
	@make -f Makefile_gssocks5.mk

$(GSSERVER_BIN):
	@make -f Makefile_gsserver.mk

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(GSDNS_BIN) $(GSGENKEN_BIN) $(GSRED_BIN) $(GSSOCKS5_BIN) $(GSSERVER_BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(GSDNS_BIN) $(PREFIX)/$(GSGENKEN_BIN) $(PREFIX)/$(GSRED_BIN) $(PREFIX)/$(GSSOCKS5_BIN) $(PREFIX)/$(GSSERVER_BIN)

.PHONY: all clean install uninstall
