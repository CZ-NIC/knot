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

INC_DIRS = obj/ src/ src/hash/ src/dns/ src/other/ src/server/ src/zoneparser/ src/tests src/tests/libtap src/dnslib/ src/stat src/alloc/ src/ctl/ src/lib/ src/conf
SRC_DIRS = src/
TESTS_DIR = src/tests/
ZONEC_DIR = src/zoneparser/
CONF_DIR = src/conf
CTL_DIR = src/ctl
LIB_DIR = src/lib
OTHER_DIR = src/other
ALLOC_DIR = src/alloc
OBJ_DIR = obj/
BIN_DIR = bin/

YACC = yacc
LEX  = flex

VPATH += ${SRC_DIRS} ${INC_DIRS} ${OBJ_DIR}

PARSER_OBJ  = $(OBJ_DIR)zparser
LEXER_OBJ   = $(OBJ_DIR)zlexer
CFLEX_OBJ   = $(OBJ_DIR)cf-lex
CFPAR_OBJ   = $(OBJ_DIR)cf-parse
PARSER_FILES = $(PARSER_OBJ).c $(LEXER_OBJ).c
PARSER_OBJS = $(PARSER_OBJ).c $(LEXER_OBJ).o
# CONF_FILES = $(CFLEX_OBJ).c $(CFPAR_OBJ).c $(CONF_DIR)/conf.c $(CONF_DIR)/logconf.c
CONF_OBJS = $(CFLEX_OBJ).o $(CFPAR_OBJ).o $(OBJ_DIR)conf.o $(OBJ_DIR)logconf.o
CONF_EXTRA = $(OBJ_DIR)lists.o $(OBJ_DIR)latency.o
TESTS_FILES = $(TESTS_DIR)/main.c $(TESTS_DIR)/libtap/tap.c
ZONEC_FILES = $(ZONEC_DIR)/main.c
CTL_FILES = $(CTL_DIR)/main.c
CTL_OBJ = $(OBJ_DIR)log.o $(OBJ_DIR)process.o $(OBJ_DIR)dname.o $(OBJ_DIR)slab.o $(OBJ_DIR)print.o

ZPARSER_FILES = $(PARSER_OBJS) $(shell find $(SRC_DIRS)zoneparser -name "*.c")
ZPARSER_EXTRA = $(ALLOC_DIR)/slab.c $(OTHER_DIR)/print.c $(OTHER_DIR)/log.c $(LIB_DIR)/skip-list.c $(shell find $(SRC_DIRS)dnslib -name "*.c")
ZPARSER_OBJS = $(addprefix $(OBJ_DIR), $(addsuffix .o, $(basename $(notdir $(ZPARSER_EXTRA)))))
SRC_FILES = $(shell find $(SRC_DIRS) ! -path "*/tests/*" ! -path "*/zoneparser/*" ! -path "*/conf/*" -name "*.c" ! -name "main.c")
OBJS =  $(addprefix $(OBJ_DIR), $(addsuffix .o, $(basename $(notdir $(SRC_FILES)))))

CC = gcc
CFLAGS_DEBUG = -g -O0 -fno-stack-protector
CFLAGS_OPTIMAL = -O2 -funroll-loops -fomit-frame-pointer
CFLAGS += -Wall -std=gnu99 -D _XOPEN_SOURCE=600 -D_GNU_SOURCE
LDFLAGS += -lpthread -lurcu -lrt -lm
LEX_FLAGS += #-dvBT
YACC_FLAGS += #-t -v

all: cutedns unittests zoneparser cutectl
ifeq ($(DEBUG),1)
CFLAGS += $(CFLAGS_DEBUG)
else
CFLAGS += $(CFLAGS_OPTIMAL)
endif

ifeq ($(LATENCY),1)
CFLAGS += -DPROF_LATENCY
else
endif

# Config lexer/parser
$(CFLEX_OBJ).c: $(CONF_DIR)/cf-lex.l $(CFPAR_OBJ).h
	$(LEX) $(LEX_FLAGS) -o$(CFLEX_OBJ).c -Pcf_ $(CONF_DIR)/cf-lex.l

$(CFPAR_OBJ).c $(CFPAR_OBJ).h: $(CONF_DIR)/cf-parse.y
	$(YACC) $(YACC_FLAGS) -bcf-parse -dv -pcf_ -o $(CFPAR_OBJ).c $(CONF_DIR)/cf-parse.y

# Server lexer/parser
$(LEXER_OBJ).c: $(ZONEC_DIR)/zlexer.lex $(PARSER_OBJ).h
	$(LEX) $(LEX_FLAGS) -i -t $< >> $@

$(PARSER_OBJ).c $(PARSER_OBJ).h: $(ZONEC_DIR)/zparser.y
	$(YACC) $(YACC_FLAGS) -d -o $(PARSER_OBJ).c $(ZONEC_DIR)/zparser.y

### Resources ###
RC_DIR = src/tests/files
RC_FILES = $(RC_DIR)/parsed_data $(RC_DIR)/parsed_data_queries $(RC_DIR)/raw_data $(RC_DIR)/raw_data_queries $(RC_DIR)/sample_conf
RC_OBJS = $(addprefix $(OBJ_DIR), $(addsuffix .rc, $(basename $(notdir $(RC_FILES)))))

$(OBJ_DIR)%.rc: $(RC_DIR)/%
	@echo "$(COL_WHITE)Resource $(COL_CYAN)$@: $(COL_BLUE)$< $(COL_END)"
	@./resource.sh $< > $@

### Dependencies ###
DEPEND = $(CC) $(addprefix -I ,$(INC_DIRS)) -MM $(SRC_FILES)   2>/dev/null | sed "s%^\([^\ \t\n]*\.o\)%$(OBJ_DIR)/\1%"

Makefile.depend: $(RC_OBJS)
	@$(DEPEND) > Makefile.depend

# cutedns
cutedns: Makefile.depend $(OBJS) $(CONF_OBJS) $(SRC_DIRS)main.c
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(OBJS) $(CONF_OBJS) $(SRC_DIRS)main.c$(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) $(LDFLAGS) $(OBJS) $(CONF_OBJS) $(SRC_DIRS)main.c -o ${BIN_DIR}$@

zoneparser: Makefile.depend cutedns $(ZPARSER_FILES) $(ZPARSER_OBJS)
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(ZPARSER_FILES) $(ZPARSER_OBJS)$(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) $(LDFLAGS) $(ZPARSER_FILES) $(ZPARSER_OBJS) -o ${BIN_DIR}$@

cutectl: cutedns $(CTL_FILES) $(CTL_OBJ) $(CONF_OBJS) $(CONF_EXTRA)
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(CTL_FILES) $(CTL_OBJ) $(CONF_OBJS) $(CONF_EXTRA)$(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) $(LDFLAGS) $(CTL_FILES) $(CTL_OBJ) $(CONF_OBJS) $(CONF_EXTRA) -o ${BIN_DIR}$@

unittests: Makefile.depend cutedns $(OBJS) $(TESTS_FILES) $(CONF_OBJS)
	@echo "$(COL_WHITE)Linking... $(COL_YELLOW)${BIN_DIR}$@$(COL_END) <-- $(COL_CYAN)$(OBJS) $(TESTS_FILES) $(CONF_OBJS)$(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) $(LDFLAGS) $(OBJS) $(TESTS_FILES) $(CONF_OBJS) -o ${BIN_DIR}$@

test: unittests
	@bin/unittests samples/example.com.zone

.PHONY: Makefile.depend
.INTERMEDIATE: Makefile.depend

-include Makefile.depend

.SUFFIXES:

### Generic Rules ###

$(OBJ_DIR)%.o: %.c
	@echo "$(COL_WHITE)Compiling $(COL_CYAN)$@: $(COL_BLUE)$< $(COL_END)"
	@$(CC) $(CFLAGS) $(addprefix -I ,$(INC_DIRS)) -c -o $@ $<

### Cleaning and documentation ###
.PHONY: clean doc
clean:
	@echo "$(COL_WHITE)Cleaning resource files ...$(COL_RED)"
	@rm -vf $(OBJ_DIR)/*.rc
	@echo "$(COL_WHITE)Cleaning flex & bison files ...$(COL_RED)"
	@rm -vf $(OBJ_DIR)/*.h $(OBJ_DIR)/*.c
	@echo "$(COL_WHITE)Cleaning object files...$(COL_RED)"
	@rm -vf ${OBJ_DIR}/*.o
	@echo "$(COL_WHITE)done$(COL_END)"

doc:
	@doxygen "Doxyfile"
