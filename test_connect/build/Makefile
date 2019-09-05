
PROJECT=test_connect

ROOTDIR=../src
OUTPUT=../build

CC=gcc
LD=gcc

COFLAGS=
ASFLAGS=
LDFLAGS=
LDLIBS=

#libnl3
COFLAGS+=-I/usr/include/libnl3
LDLIBS+=-lnl-3 -lnl-genl-3


CFLAGS=$(COFLAGS)
CCFLAGS=$(COFLAGS)

vpath %.h $(ROOTDIR)
vpath %.c $(ROOTDIR)

VPATH=$(ROOTDIR)

INCLUDES = -I$(ROOTDIR)

C_SRC=$(wildcard $(ROOTDIR)/*.c)

C_OBJ_TEMP=$(patsubst %.c, %.o, $(notdir $(C_SRC)))
C_OBJ_FILTER=
C_OBJ=$(filter-out $(C_OBJ_FILTER), $(C_OBJ_TEMP))

#######################################################

all: $(PROJECT)

$(PROJECT): $(addprefix $(OUTPUT)/, $(C_OBJ))
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(addprefix $(OUTPUT)/, $(C_OBJ)): $(OUTPUT)/%.o : %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	@rm -rf $(OUTPUT)/*.o $(PROJECT)


