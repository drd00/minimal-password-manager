CC = clang

INCLUDES = -I/usr/local/include
LIBS = -L/usr/local/lib -lsodium

CFLAGS = -std=gnu99 -g -Og -Wall $(INCLUDES)
LDFLAGS = $(LIBS)

SRCS = main.c
OBJS = $(SRCS:.c=.o)
TARGET = pmg

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

