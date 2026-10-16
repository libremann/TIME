# TIME

TIME is an interactive machine code executor for Linux.

It lets you enter raw machine code bytes in hexadecimal, execute them, and inspect register values while the process is stopped.

The interface is intentionally simple. No assembler, no scripting language, just machine code.

## Features

- Interactive machine code input.
- Execution using `ptrace`.
- Breakpoint handling with `int3`.
- Register inspection on Linux x86-64.
- Symbol address lookup using `dlsym()`.
- Address lookup for `stdin`, `stdout`, and `stderr`.

## Requirements

- Linux
- GCC or Clang
- x86-64 for register inspection

## Build

```sh
cc time.c -o time -ldl
```

## Usage

Run the program:

```sh
./time
```

Enter machine code bytes as hexadecimal values:

```text
90
```

Multiple bytes can be entered on the same line:

```text
48 31 c0
```

Each input line is followed by an `int3` breakpoint. When execution stops, the program waits for more input.

## Commands

```text
.reg <register>
.adr <stdin|stdout|stderr>
.fnc <symbol>
```

Examples:

```text
.reg rax
.reg rip
.adr stdout
.fnc puts
```

Register inspection currently supports x86-64 Linux register names.

## Notes

This is an experimental tool. It executes machine code directly and is not a sandbox.

The implementation is incomplete and has not been designed for untrusted input.

## License

MIT