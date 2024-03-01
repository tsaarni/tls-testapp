
CFLAGS = -Wall -Wextra -Werror -g -O0

all: testapp

testapp: testapp.o
	$(CC) $(LDFLAGS) -o testapp testapp.o -lssl -lcrypto

testapp.o: logger.h

%.o: %.c
	$(CC) $(CFLAGS) -c $<

# https://github.com/tsaarni/certyaml
certs:
	certyaml

clean:
	rm -f testapp *.o


vscode_compile_commands: clean
	bear -- make testapp
