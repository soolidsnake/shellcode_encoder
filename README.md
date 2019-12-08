# shellcode_encoder

Python Tool / library, shellcode_encoder is a SUB shellcode encoder that uses z3 to find the right valid instructions.

## Usage

### 0x00) As a python module:
Use the function "code_shellcode", the first argment should be the address of where the shellcode is stored in memory.

The second argument is a list of bad characters.

The third argument is the shellcode.

Example:
```python
code_shellcode(address_shellcode=0xDEADBEEF, bad_chars=[0x45,0x55,0x30], shellcode="\x41\x42\x43\x44", scripting=True)
```


### 0x01) As a tool:

[![asciicast](https://asciinema.org/a/ZlRmj6OlT4g6EAVG0nCioa5dy.svg)](https://asciinema.org/a/ZlRmj6OlT4g6EAVG0nCioa5dy)
