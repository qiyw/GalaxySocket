include Makefile.inc

all:
	@make -f Makefile_gsdns.mk
	@make -f Makefile_gsgenkey.mk
	@make -f Makefile_gsred.mk
	@make -f Makefile_gssocks5.mk
	@make -f Makefile_gsserver.mk

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(GSDNS_BIN) $(GSGENKEN_BIN) $(GSRED_BIN) $(GSSOCKS5_BIN) $(GSSERVER_BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(GSDNS_BIN) $(PREFIX)/$(GSGENKEN_BIN) $(PREFIX)/$(GSRED_BIN) $(PREFIX)/$(GSSOCKS5_BIN) $(PREFIX)/$(GSSERVER_BIN)

.PHONY: all clean install uninstall
