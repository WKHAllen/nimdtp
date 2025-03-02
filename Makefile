ifeq ($(OS),Windows_NT)
	LINK_FLAGS = --passl:-LC:\OpenSSL-Win64\bin --passl:-llibcrypto-3-x64
else
	LINK_FLAGS = --passl:-L/usr/src/openssl-3.0.7 --passl:-l:libcrypto.so.3
endif

all: build

build:
	nimble build

test:
	nimble test $(LINK_FLAGS)

check:
	nimble check
