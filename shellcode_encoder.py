from binascii import hexlify
from pwn import *
from z3 import *

def parse_badchars():
	bad_chars = []
	filters = raw_input("Enter bad chars in hex format separated by ',' : \n").strip()
	if filters == '':
		return []
	filters = filters.replace(" ", "").split(',')
	for filter in filters:
		bad_chars.append(int(filter, 16))
	return bad_chars


def constraints(solver, x, bad_chars):
	for i in xrange(4):
		# Constraint alpha numerical bytes of the variables
		solver.add(Or(And((x>>8*i)&0xff >= 0x30, (x>>8*i)&0xff <= 0x39), And((x>>8*i)&0xff >= 0x41, (x>>8*i)&0xff <= 0x5a), And((x>>8*i)&0xff >= 0x61, (x>>8*i)&0xff <= 0x7a)))

	for bad_char in bad_chars:
		for i in xrange(4):
			# Constraint for the bad chars
			solver.add((x>>8*i)&0xff != bad_char)
	return solver


def encode_shellcode(address_shellcode='', bad_chars=[], shellcode='', scripting=False):
	if not scripting:
		bad_chars = parse_badchars()
		shellcode = raw_input('Enter shellcode to encode: ')
		address_shellcode = int(raw_input('Enter address of shellcode in hex format: ').strip(), 16)
	else:
		shellcode = hexlify(shellcode)

	log.success("bad chars: ")
	print [hex(i) for i in bad_chars]

	log.success("shellcode: \n%#s", shellcode)

	pack = make_packer(32, endian='little')
	unpack = make_unpacker(32, endian='big')

	shellcode = shellcode.replace('\\x', '').strip()

	values =  [unpack(pack(int(shellcode[i:i+8].ljust(8,'0'), 16))) for i in range(0,len(shellcode), 8)]

	# reverse the list so that we push the last bytes of the shellcode first
	values = values[::-1]

	enc_shellcode = ""

	# Create a solver, add constraints and then saving the context of the solver(push)
	solver = Solver()

	x = BitVec("x", 8*4)
	y = BitVec("y", 8*4)
	z = BitVec("z", 8*4)
	a = BitVec("a", 8*4)

	constraints(solver, x, bad_chars)
	constraints(solver, y, bad_chars)
	constraints(solver, z, bad_chars)
	constraints(solver, a, bad_chars)

	solver.push()

	solver.add(0 == x&y)
	solver.check()
	model = solver.model()
	# mov eax, 0
	enc_shellcode += "and eax," + hex(int(str(model[x]))) + ";"
	enc_shellcode += "and eax," + hex(int(str(model[y]))) + ";"


	# restore context of the solver
	solver.pop()
	solver.push()

	solver.add(address_shellcode == 0 - x - y - z)

	solver.check()
	model = solver.model()
	# mov eax, address_shellcode
	enc_shellcode += "sub eax," + hex(int(str(model[x]))) + ";"
	enc_shellcode += "sub eax," + hex(int(str(model[y]))) + ";"
	enc_shellcode += "sub eax," + hex(int(str(model[z]))) + ";"


	solver.pop()
	solver.push()

	to_add = 5*5 + (4*5 + 2) + len(values)*21 + len(values)*4

	solver.add(address_shellcode + to_add == address_shellcode - x - y - z - a)

	eax = address_shellcode + to_add

	solver.check()
	model = solver.model()
	# point eax to the end of the shellcode
	enc_shellcode += "sub eax," + hex(int(str(model[x]))) + ";"
	enc_shellcode += "sub eax," + hex(int(str(model[y]))) + ";"
	enc_shellcode += "sub eax," + hex(int(str(model[z]))) + ";"
	enc_shellcode += "sub eax," + hex(int(str(model[a]))) + ";"
	enc_shellcode += "push eax" + ";"
	enc_shellcode += "pop esp" + ";"


	for val in values:
		solver.pop()
		solver.push()
		
		solver.add(val == eax - x - y - z - a)

		while True:
			solver.check()
			model = solver.model()
			# mov eax, val
			enc_shellcode += "sub eax," + hex(int(str(model[x]))) + ";"
			enc_shellcode += "sub eax," + hex(int(str(model[y]))) + ";"
			enc_shellcode += "sub eax," + hex(int(str(model[z]))) + ";"
			enc_shellcode += "sub eax," + hex(int(str(model[a]))) + ";"
			enc_shellcode += "push eax" + ";"
			eax = val
			break


	for i in xrange(len(values)*4):
		enc_shellcode += "inc ecx" + ";"

	log.success('Assembly code generated')
	print enc_shellcode.replace(";", "\n")

	log.success('Compiled assembly code')
	print repr(asm(enc_shellcode))


if __name__ == '__main__':
	encode_shellcode()