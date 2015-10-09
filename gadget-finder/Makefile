#compiling and linking flags
CC      = gcc
CFLAGS  = -Wall -Werror
LFLAGS	= -static -ludis86

#target, objects and sources
SOURCES	= main.c input.c output.c
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
