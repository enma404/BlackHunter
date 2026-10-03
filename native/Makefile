CC ?= clang
CFLAGS ?= -Wall -Wextra -O2 -std=gnu11
LDFLAGS ?=
PTHREAD_FLAGS ?= -pthread

TARGETS = port_scanner banner_grabber payload_engine hash_cracker packet_crafter crypto_utils

.PHONY: all clean test

all: $(TARGETS)

port_scanner: port_scanner.c
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -o $@ $< $(LDFLAGS)

banner_grabber: banner_grabber.c
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -o $@ $< $(LDFLAGS)

payload_engine: payload_engine.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

hash_cracker: hash_cracker.c
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -o $@ $< $(LDFLAGS)

packet_crafter: packet_crafter.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

crypto_utils: crypto_utils.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

test: all
	@echo "Native module build test completed successfully."
