# Makefile for Secure Chat System

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
LDFLAGS = -lssl -lcrypto -pthread

# macOS specific
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # Homebrew OpenSSL path
    OPENSSL_PATH = $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
    CXXFLAGS += -I$(OPENSSL_PATH)/include
    LDFLAGS += -L$(OPENSSL_PATH)/lib
endif

TARGETS = server client

all: $(TARGETS)

server: server.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

client: client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
	rm -rf received_files

.PHONY: all clean
