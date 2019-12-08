from shellcode_encoder import encode_shellcode

encode_shellcode(address_shellcode=0xDEADBEEF, bad_chars=[0x45,0x55,0x30], shellcode="\x41\x42\x43\x44", scripting=True)