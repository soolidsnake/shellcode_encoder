# shellcode_encoder

Python Tool / library, shellcode_encoder is a SUB shellcode encoder that uses z3 to find the right valid instructions.

## Installation of the required library

```bash
pip install -r requirements.txt
```

## Usage

### 0x00) As a python module:
Use the function "code_shellcode".

#### Arguments:
offset_r_address: the offset from the start register to the address of the shellcode
register: the starting register(default: ESP)
bad_chars: a list of bad chars
shellcode: the shellcode to encode
scripting: Shouldd be set to True

Example:
```python
encoded_shellcode = encode_shellcode(offset_r_address=0xc7f, register='esp', bad_chars=[], shellcode="\x41\x42\x43\x44", scripting=True)
```


### 0x01) As a tool:

[![asciicast](https://asciinema.org/a/VeWxsxygmD0j1D0XNmfEIxyfv.svg)](https://asciinema.org/a/VeWxsxygmD0j1D0XNmfEIxyfv)