SRC := $(wildcard */*.c)
EXE := $(SRC:.c=)

CFLAGS := -O2 -s
LDLIBS := -ldeflate
LDFLAGS := -L../..
CPPFLAGS := -I../..

all:$(EXE)

clean:
	rm -f $(EXE)
