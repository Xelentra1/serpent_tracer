# Serpent Tracer

**Custom pin tracer tool for Challenge 9 from Flare-On 11**

This tool is specifically designed to trace instructions for Challenge 9 from the Flare-On 11. It stops tracing on the `hlt` instruction and resumes tracing on `call rax` when it jumps into shellcode. Also, it patches registers to `0` upon encountering a `test reg, reg` instruction within the shellcode to pass all flag checks, enabling the full execution of the shellcode.

## Features

- **Stop and Resume Tracing**: Automatically pauses on `hlt` and resumes on `call rax` into the shellcode.
- **Patch checks for correct user input**: Sets register values to `0` when encountering `test reg, reg` within the shellcode, ensuring continuous shellcode execution with any user input that is 32 chars long.
- **Configurable Tracing**: Allows for clean traces that excludes self-modifying instructions from the trace.

## Requirements

- **Build Environment**: Visual Studio 2017

## Usage

To get a **full trace**:
```bash
pin.exe -smc_strict 1 -t serpent_tracer.dll -- serpentine.exe ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
```

To get a **clean trace** (without self-modifying instructions):
```bash
pin.exe -smc_strict 1 -t serpent_tracer.dll -clean 1 -- serpentine.exe ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
```
