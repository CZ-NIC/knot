### Colours ###
COL_BLACK = \033[01;30m
COL_GREEN = \033[01;32m
COL_BLUE = \033[01;34m
COL_RED = \033[01;31m
COL_YELLOW = \033[01;33m
COL_VIOLET = \033[01;35m
COL_CYAN = \033[01;36m
COL_WHITE = \033[01;37m
COL_END = \033[0m

INC_DIRS = src/
SRC_DIRS = src/
OBJ_DIR = tmp/
BIN_DIR = bin/

VPATH += ${SRC_DIRS} ${OBJ_DIR}

SRC_FILES = $(shell find $(SRC_DIRS) -name "*.c" )

OBJS = $(addprefix $(OBJ_DIR)/, $(addsuffix .o, $(basename $(notdir $(SRC_FILES)))))

CC = gcc
CFLAGS += -Wall -std=c99 -D _XOPEN_SOURCE=600
LDFLAGS += -lpthread

all:cuckoo-hash

### Dependencies ###
DEPEND = $(CC) $(addprefix -I ,$(INC_DIRS)) -MM $(SRC_FILES)   2>/dev/null | sed "s%^\([^\ \t\n]*\.o\)%$(OBJ_DIR)/\1%"

Makefile.depend:
#    @echo ${DEPEND}
	@$(DEPEND) > Makefile.depend

# cuckoo hash
cuckoo-hash: Makefile.depend $(OBJS)
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(OBJS)$(COL_END)"
	@$(CC) $(LDFLAGS) $(OBJS) -o ${BIN_DIR}$@

.PHONY: Makefile.depend
.INTERMEDIATE: Makefile.depend

-include Makefile.depend

.SUFFIXES:

### Generic Rules ###

$(OBJ_DIR)/%.o : %.c
	@echo "$(COL_WHITE)Compiling $(COL_CYAN)$@: $(COL_BLUE)$< $(COL_END)"
	@$(CC) $(CFLAGS) -c -o $@ $<

### Cleaning ###
.PHONY: clean
clean:
	@echo "$(COL_WHITE)Cleaning object files...$(COL_RED)"
	@rm -vf ${OBJ_DIR}/*.o
	@echo "$(COL_WHITE)done$(COL_END)"
