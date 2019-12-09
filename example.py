from shellcode_encoder import encode_shellcode

encoded_shellcode = encode_shellcode(offset_r_address=0xc7f, register='esp', bad_chars=[], shellcode="\x41\x42\x43\x44", scripting=True)