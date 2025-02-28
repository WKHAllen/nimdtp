ifeq ($(OS),Windows_NT)
	INCLUDE_FLAGS = --passc:-IC:\OpenSSL-Win64\include
	LINK_FLAGS = --passl:-LC:\OpenSSL-Win64\bin --passl:-llibcrypto-3-x64
else
	INCLUDE_FLAGS = 
	LINK_FLAGS = --passl:-L/usr/src/openssl-3.0.7 --passl:-llibcrypto.so.3
endif

all: build

build:
	nimble build

test:
	nimble test -d:ssl -d:sslVersion=3-x64 $(INCLUDE_FLAGS) $(LINK_FLAGS)

check:
	nimble check
