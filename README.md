# shellcode_encoder

Python Tool / library, shellcode_encoder is a SUB shellcode encoder that uses z3 to find the right valid instructions.

## Installation of the required library

```bash
pip install -r requirements.txt
```

## Usage

### 0x00) As a python module:
Use the function "code_shellcode", the first argment should be the content of ESP.

second argument is the address of where the shellcode is stored in memory

The third argument is a list of bad characters.

The forth argument is the shellcode.

Example:
```python
encoded_shellcode = encode_shellcode(esp_value=0x0018800C, address_shellcode=0x00188C8B, bad_chars=[], shellcode=msgbox, scripting=True)
```


### 0x01) As a tool:

[![asciicast](https://asciinema.org/a/ZlRmj6OlT4g6EAVG0nCioa5dy.svg)](https://asciinema.org/a/ZlRmj6OlT4g6EAVG0nCioa5dy)
