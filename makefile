CC = gcc
CFLAGS = -Wall -O2
LIBS = -lpcap   # 👈 needed for libpcap functions

SRCS = src/main.c src/netinfo.c src/sniff.c   # 👈 added sniff.c
OBJS = $(SRCS:.c=.o)
TARGET = etterclone_w2   # 👈 new binary for W2

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(TARGET)

