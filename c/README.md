## Compile on macos

Generate compile_commands.json for vscode

```
bear -- make CFLAGS=-I/opt/homebrew/include/ LDFLAGS=-L/opt/homebrew/lib
```

Compile

```
make CFLAGS=-I/opt/homebrew/include/ LDFLAGS=-L/opt/homebrew/lib
```
