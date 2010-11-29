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

INC_DIRS = src/ src/hash/ src/dns/ src/other/ src/server/ src/zone/ src/tests src/tests/libtap src/stat
SRC_DIRS = src/
TESTS_DIR = src/tests/
OBJ_DIR = obj/
BIN_DIR = bin/

VPATH += ${SRC_DIRS} ${INC_DIRS} ${OBJ_DIR}

SRC_FILES = $(shell find $(SRC_DIRS) ! -path "*/tests/*" -name "*.c" ! -name "main.c")
TESTS_FILES = $(TESTS_DIR)/main.c $(TESTS_DIR)/libtap/tap.c

OBJS = $(addprefix $(OBJ_DIR), $(addsuffix .o, $(basename $(notdir $(SRC_FILES)))))

CC = gcc
CFLAGS += -Wall -std=gnu99 -D _XOPEN_SOURCE=600 -D_GNU_SOURCE -g
LDFLAGS += -lpthread -lurcu -lldns -lrt

all: cutedns unittests

### Dependencies ###
DEPEND = $(CC) $(addprefix -I ,$(INC_DIRS)) -MM $(SRC_FILES)   2>/dev/null | sed "s%^\([^\ \t\n]*\.o\)%$(OBJ_DIR)/\1%"

Makefile.depend:
	@$(DEPEND) > Makefile.depend

# cutedns
cutedns: Makefile.depend $(OBJS) $(SRC_DIRS)main.c
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(OBJS) $(SRC_DIRS)main.c$(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) $(LDFLAGS) $(OBJS) $(SRC_DIRS)main.c -o ${BIN_DIR}$@

unittests: Makefile.depend cutedns $(OBJS) $(TESTS_FILES)
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(OBJS) $(TESTS_FILES)$(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) $(LDFLAGS) $(OBJS) $(TESTS_FILES) -o ${BIN_DIR}$@

test: unittests
	@bin/unittests samples/example.com.zone

.PHONY: Makefile.depend
.INTERMEDIATE: Makefile.depend

-include Makefile.depend

.SUFFIXES:

### Generic Rules ###

$(OBJ_DIR)%.o : %.c
	@echo "$(COL_WHITE)Compiling $(COL_CYAN)$@: $(COL_BLUE)$< $(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) -c -o $@ $<

### Cleaning and documentation ###
.PHONY: clean doc
clean:
	@echo "$(COL_WHITE)Cleaning object files...$(COL_RED)"
	@rm -vf ${OBJ_DIR}/*.o
	@echo "$(COL_WHITE)done$(COL_END)"

doc:
	@doxygen "Doxyfile"
