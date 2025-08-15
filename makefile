CC = gcc
CFLAGS = -Wall -O2
LIBS =

SRCS = src/main.c src/netinfo.c
OBJS = $(SRCS:.c=.o)
TARGET = etterclone_w1

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(TARGET)S
