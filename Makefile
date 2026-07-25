CC = gcc
CFLAGS = -Os -Wall -std=gnu99 -pthread
LDFLAGS = -pthread -lcurl

TARGET = lgtv_radio
SRCS = lgtv_radio.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	sstrip $(TARGET)

clean:
	rm -f $(TARGET)
