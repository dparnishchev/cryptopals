import xor
import base64
import ngram_score as ns

def hamming_distance(str1, str2):
	d = 0
	if len(str1) != len(str2):
		raise Exception("Length of input strings must be equal")
	arr1 = bytearray(str1)
	arr2 = bytearray(str2)
	for i in range(0, len(arr1)):
		arr1[i] ^= arr2[i]
		d += bin(arr1[i]).count("1")
	return d

def encrypt(plaintext, key):
	ex_key = key * (len(plaintext) / len(key)) + key[0:(len(plaintext) % len(key))]
	return xor.xor(plaintext, ex_key)

def crack(ciphertext):
	distances = []
	correct_key = ""
	best_score = -float('inf')
	correct_plaintext = ""
	fitness = ns.ngram_score('english_monograms.txt')
	#1. Guess key length
	for i in range(2, 40):
		d1 = float(hamming_distance(ciphertext[0:i], ciphertext[i:2*i]) / i)
		d2 = float(hamming_distance(ciphertext[2*i:3*i], ciphertext[3*i:4*i]) / i)
		d3 = float(hamming_distance(ciphertext[4*i:5*i], ciphertext[5*i:6*i]) / i)
		d = float((d1 + d2 + d3) / 3)
		distances.append((i, d))
	distances = sorted(distances, key=lambda tup: tup[1])
	#2. Break ciphertext into blocks
	for i in range(0, 5):
		key_len = distances[i][0]
		text_blocks = ["" for _ in range(key_len)]
		for j in range(len(ciphertext)):
			text_blocks[j % key_len] = text_blocks[j % key_len] + ciphertext[j]
		key = ""
		#solve each block separately
		for j in range(len(text_blocks)):
			key = key + xor.byte_xor_crack(text_blocks[j])[0]
		plaintext = encrypt(ciphertext, key)
		score = fitness.score(plaintext)
		if score > best_score:
			best_score = score
			correct_plaintext = plaintext
			correct_key = key
	return (correct_key, correct_plaintext)


def _solve_set1_ch5():
	plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	return encrypt(plaintext, "ICE").encode("hex")

def _solve_set1_ch6():
	f = open("input/6.txt", "r")
	ciphertext = base64.decode(f.read().replace("\n", ""))
	f.close()
	return crack(ciphertext)