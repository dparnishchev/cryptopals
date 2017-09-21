def pad(data, block_size):
	if block_size > 0xFF:
		raise Exception("PKCS7 padding works only with block_size <= 0xFF")
	pad_size = block_size - (len(data) % block_size)
	return data + chr(pad_size) * pad_size

def _solve_set2_ch9():
	return pad("YELLOW SUBMARINE", 20)