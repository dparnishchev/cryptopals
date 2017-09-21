import ngram_score as ns

#performs XOR of <str1> and <str2>
def xor(str1, str2):
	str1 = bytearray(str1)
	str2 = bytearray(str2)
	for i in range(0, len(str1)):
		str1[i] ^= str2[i]
	return str(str1)

#Breaks single-byte XOR cipher. Returns (key, hex_plaintext) pair
def byte_xor_crack(ciphertext):
	fitness = ns.ngram_score('english_monograms.txt')
	max_score = -float('inf')
	for i in range(0x00, 0x100):
		gamma = chr(i) * len(ciphertext)
		text = xor(ciphertext, gamma)
		score = fitness.score(text)
		if score > max_score:
			max_score = score
			key = gamma[0]
			plaintext = text
	return (key, plaintext)

#detects single-byte XOR cipher by <hex_ciphertexts>
def byte_xor_detect(ciphertexts):
	fitness = ns.ngram_score('english_monograms.txt')
	max_score = -float('inf')
	for i in range(0, len(ciphertexts)):
		(key, plaintext) = byte_xor_crack(ciphertexts[i])
		score = fitness.score(plaintext)
		if(score > max_score):
			max_score = score
			n = i
			real_plaintext = plaintext
			real_key = key
	return (n, real_key, real_plaintext)

def _solve_set1_ch2():
	str1 = "1c0111001f010100061a024b53535009181c".decode("hex")
	str2 = "686974207468652062756c6c277320657965".decode("hex")
	return xor(str1, str2).encode("hex")

def _solve_set1_ch3():
	ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode("hex")
	return byte_xor_crack(ciphertext)

def _solve_set1_ch4():
	ciphertexts = open("input/4.txt", "r").read().split("\n")
	for i in range(0, len(ciphertexts)):
		ciphertexts[i] = ciphertexts[i].decode("hex")
	return byte_xor_detect(ciphertexts)
