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


def _solve_set2_ch9():
	padded =  pad("YELLOW SUBMARINE", 20)
	unpadded = unpad(padded)
	print unpadded
	print padded