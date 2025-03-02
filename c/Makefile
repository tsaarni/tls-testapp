OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)

CFLAGS := -Wall -Wextra -Werror -g -O0 -std=c2x $(OPENSSL_CFLAGS)
LDFLAGS := $(OPENSSL_LIBS)

TARGET := tls
SRCS := tls.c
OBJS := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o $(TARGET) $(OBJS)

tls.o: logger.h

# https://github.com/tsaarni/certyaml
certs:
	certyaml

clean:
	rm -f $(TARGET) $(OBJS)

vscode_compile_commands: clean
	bear -- make tls

.PHONY: all certs clean vscode_compile_commands
