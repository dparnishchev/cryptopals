table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# produces <count> base64 symbols from integer value <temp>
def _encode(temp, count):
	result = ""
	for j in range(0, count):
		result = result + table[(temp >> (6 * (3 - j))) & 0x3F]
	return result

#decodes 4 base64 symbols to 3 ascii symbols
def _decode(temp, count):
	result = bytearray()
	temp3 = 0
	for j in range(0, 4):
		if(temp[j] == '='):
			break
		temp3 |= table.index(temp[j]) << (18 - j * 6)
	for j in range(0, count):
		result.append((temp3 >> (16 - j * 8)) & 0xFF)
	return result


#encodes specified <data> to base64 string
def encode(data):
	data = bytearray(data)
	byte_len = len(data)
	temp = 0
	result = ""
	for i in range(0, byte_len):
		temp |= data[i] << (8 * (2 - i % 3))
		if(i % 3 == 2):
			result = result + _encode(temp, 4)
			temp = 0
	if (byte_len % 3) == 1:
		b = 2
		a = 2
	elif (byte_len % 3) == 2:
		b = 3
		a = 1
	else:
		return result
	result = result + _encode(temp, b)
	result = result + "=" * a
	return result

#decodes base64 string to ascii string
def decode(data):
	result = bytearray()
	for i in range(0, len(data) / 4 - 1):
		result += _decode(data[i * 4:(i + 1) * 4], 3)
	if(data[-1] == '='):
		if(data[-2] == '='):
			result += _decode(data[-4:], 1)
		else:
			result += _decode(data[-4:], 2)
	else:
		result += _decode(data[-4:], 3)
	return str(result)

def _solve_set1_ch1():
	return encode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".decode("hex"))