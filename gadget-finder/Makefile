#compiling and linking flags
CC      = gcc
CFLAGS  = -Wall -Werror -std=c11
ifdef MIKEYSBOX
LFLAGS	= -Wall -ludis86
else
LFLAGS	= -Wall --static -ludis86
endif

#target, objects and sources
SOURCES	= main.c input.c output.c global.c section.c
OBJECTS	= $(SOURCES:.c=.o)
TARGET	= gadget-finder

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LFLAGS)

OBJECTS: $(SOURCES)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(TARGET) $(OBJECTS)
