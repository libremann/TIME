# TIME

**TIME (Tiny Interactive Machine Executor)** is an interactive x86-64 machine-code execution environment for Linux, written in C.

It lets you enter raw machine-code bytes in hexadecimal, execute them in a child process, and inspect CPU register values whenever execution stops.

TIME also provides a shared memory area for data buffers, allowing machine code to work with user-provided data and call existing functions.

The interface is intentionally minimal: no assembler, no scripting language, just machine code and a small set of commands.

## Features

- Interactive machine-code input in hexadecimal.
- Code execution in a child process using `fork()` and `ptrace()`.
- Shared executable memory for machine code.
- A shared data area for allocating buffers.
- Automatic `int3` breakpoint insertion after each submitted instruction sequence.
- CPU register inspection on Linux x86-64.
- Function address lookup using `dlsym()`.
- Address lookup for `stdin`, `stdout`, and `stderr`.
- Buffer creation with string, hexadecimal, or decimal input.

## Requirements

- Linux
- GCC or Clang
- x86-64 for register inspection

## Build

```sh
cc time.c -o time -ldl
```

## Usage

Run TIME:

```sh
./time
```

Enter machine-code bytes as hexadecimal values:

```text
90
```

Multiple bytes can be entered on the same line:

```text
48 31 c0
```

TIME appends an `int3` breakpoint after each submitted byte sequence. When the child process stops, you can inspect its state or enter more machine code to continue experimenting.

## Commands

### Register inspection

```text
.reg <register>
```

Examples:

```text
.reg rax
.reg rip
.reg rsp
.reg eflags
```

Register inspection supports general-purpose registers, instruction pointer, flags, segment registers, and FS/GS base registers on Linux x86-64.

### Address lookup

Look up standard I/O stream addresses:

```text
.adr <stdin|stdout|stderr>
```

Examples:

```text
.adr stdout
.adr stdin
```

### Function lookup

Look up the address of a function available through the program's dynamic symbol lookup scope:

```text
.fnc <function_name>
```

Example:

```text
.fnc puts
```

The returned address can be used in machine code to call the function.

### Buffer creation

Allocate a buffer in shared data memory:

```text
.buf <str|hex|dec> <buffer_size>
```

- `str` — enter string data.
- `hex` — enter byte values in hexadecimal.
- `dec` — enter byte values in decimal.

Examples:

```text
.buf str 32
.buf hex 4
.buf dec 4
```

TIME prints the address of the buffer so your machine code can access it. The shared data area has a total capacity of 1 MiB.

## How It Works

TIME maps a shared memory region for machine code and another for data before creating a child process.

The parent process accepts machine-code input and places it in the shared code area. The child executes the code, while `ptrace()` allows the parent to observe execution stops and inspect registers.

After each submitted instruction sequence, TIME inserts an `int3` breakpoint. When execution reaches it, the child stops and the parent can accept further input, creating an interactive execution cycle.

## Notes

TIME is an experimental tool, and its implementation is still incomplete.

It executes machine code directly with the privileges of the child process. **It is not a sandbox and must not be used to execute untrusted machine code.**

## License

MIT