def pad(data, block_size):
	if block_size > 0xFF:
		raise Exception("PKCS7 padding works only with block_size <= 0xFF")
	pad_size = block_size - (len(data) % block_size)
	return data + chr(pad_size) * pad_size

def unpad(data):
	pad_size = ord(data[-1])
	for i in range(-2, -pad_size - 1, -1):
		if(data[i] != data[-1]):
			return data
	return data[:len(data) - pad_size]

def validate_padding(data):
	pad_size = ord(data[-1])
	if pad_size == 0:
		raise Exception("data padding is incorrect (not pkcs7)")
	for i in range(-2, -pad_size - 1, -1):
		if(data[i] != data[-1]):
			raise Exception("data padding is incorrect (not pkcs7)")
	return data[:len(data) - pad_size]

def _solve_set2_ch9():
	padded =  pad("YELLOW SUBMARINE", 20)
	unpadded = unpad(padded)
	print unpadded.encode("hex")
	print padded.encode("hex")

def _solve_set2_ch15():
	print validate_padding("ICE ICE BABY\x04\x04\x04\x04")
	try:
		print validate_padding("ICE ICE BABY\x05\x05\x05\x05")
	except Exception:
		print "string \"ICE ICE BABY\x05\x05\x05\x05\" has no valid pkcs7 padding"
	try:
		print validate_padding("ICE ICE BABY\x01\x02\x03\x04")
	except Exception:
		print "string \"ICE ICE BABY\x01\x02\x03\x04\" has no valid pkcs7 padding"