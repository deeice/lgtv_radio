CC = gcc
CFLAGS = -Os -Wall -march=armv5te -mtune=xscale -std=gnu99 -pthread -I/usr/local/include
LDFLAGS = -pthread -lcurl

TARGET = lgtv_radio
SRCS = lgtv_radio.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	sstrip $(TARGET)

clean:
	rm -f $(TARGET)
