MAKEFLAGS+= --no-print-directory
BIN_DIR = bin

.PHONY: clean all

all:
	@$(MAKE) -f common/makefile
	@$(MAKE) -f client/makefile
	@$(MAKE) -f auth-server/makefile
	@$(MAKE) -f tgs/makefile
	@$(MAKE) -f ss/makefile

clean:
	@rm -rf $(BIN_DIR)
	@$(MAKE) -f common/makefile clean
	@$(MAKE) -f client/makefile clean
	@$(MAKE) -f auth-server/makefile clean
	@$(MAKE) -f tgs/makefile clean
	@$(MAKE) -f ss/makefile clean