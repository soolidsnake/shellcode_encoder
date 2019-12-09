from shellcode_encoder import encode_shellcode

encoded_shellcode = encode_shellcode(esp_value=0x0018800C, address_shellcode=0x00188C8B, bad_chars=[], shellcode=msgbox, scripting=True)