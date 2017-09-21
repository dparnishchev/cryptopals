import os
import base64
import xor
import pkcs7
from Crypto.Cipher import AES

def decrypt_ecb_128(ciphertext, key):
	return pkcs7.unpad(AES.new(key, AES.MODE_ECB, "").decrypt(ciphertext))

def encrypt_ecb_128(plaintext, key):
	return AES.new(key, AES.MODE_ECB, "").encrypt(pkcs7.pad(plaintext, 16))

def decrypt_cbc_128(ciphertext, iv, key):
	cipher = AES.new(key, AES.MODE_ECB, "")
	plaintext = ""
	for i in range(0, len(ciphertext) / 16):
		block = ciphertext[16 * i : 16 * (i + 1)]
		if i == 0:
			plaintext = plaintext + xor.xor(cipher.decrypt(block), iv)
		else:
			prev_block = ciphertext[16 * (i - 1): 16 * i]
			plaintext = plaintext + xor.xor(cipher.decrypt(block), prev_block)
	return pkcs7.unpad(plaintext)

def encrypt_cbc_128(plaintext, iv, key):
	cipher = AES.new(key, AES.MODE_ECB, "")
	ciphertext = ""
	plaintext = pkcs7.pad(plaintext, 16)
	for i in range(0, len(plaintext) / 16):
		block = plaintext[16 * i : 16 * (i + 1)]
		if i == 0:
			ciphertext = ciphertext + cipher.encrypt(xor.xor(block, iv))
		else:
			prev_block = ciphertext[16 * (i - 1): 16 * i]
			ciphertext = ciphertext + cipher.encrypt(xor.xor(block, prev_block))
	return ciphertext

#detects the score of a ciphertext. Higher score means 
#more chance that this text was encrypted by AES-128 in ECB mode
def score_ecb_128(ciphertext):
	score = 0
	while len(ciphertext) > 16:
		for j in range(1, len(ciphertext) / 16):
			if ciphertext[:16] == ciphertext[16 * j:16 * (j + 1)]:
				score += 1
		ciphertext = ciphertext[16:]
	return score

def encryption_oracle(plaintext):
	key = os.urandom(16)
	alg = ord(os.urandom(1)) % 2
	prefix = os.urandom(5 + (ord(os.urandom(1)) % 6))
	postfix = os.urandom(5 + (ord(os.urandom(1)) % 6))
	plaintext = prefix + plaintext + postfix
	if(alg == 0):
		return (encrypt_ecb_128(plaintext, key), 0)
	else:
		iv = os.urandom(16)
		return (encrypt_cbc_128(plaintext, iv, key), 1)

def _solve_set1_ch7():
	file = open("./input/7.txt", "r")
	data = file.read().replace("\n", "")
	file.close()
	print decrypt_ecb_128(base64.decode(data), "YELLOW SUBMARINE")

def _solve_set1_ch8():
	max_score = 0
	score = 0
	aes_ciphertext = ""
	file = open("./input/8.txt", "r")
	data = file.read().split("\n")
	file.close()
	for hex_ciphertext in data:
		score = score_ecb_128(hex_ciphertext.decode("hex"))
		if score > max_score:
			max_score = score
			aes_ciphertext = hex_ciphertext
	print aes_ciphertext, max_score

def _solve_set2_ch10():
	file = open("./input/10.txt", "r")
	data = file.read().replace("\n", "")
	file.close()
	return decrypt_cbc_128(base64.decode(data), "\x00" * 16, "YELLOW SUBMARINE")

def _solve_set2_ch11():
	plaintext = _solve_set2_ch10()
	for i in range(0, 10):
		(ciphertext, alg) = encryption_oracle(plaintext)
		if alg == 0:
			alg = "ECB"
		else:
			alg = "CBC"
		if score_ecb_128(ciphertext) > 0:
			print str(i) + " guessed alg is ECB (actual is {:s})".format(alg)
		else:
			print str(i) + " guessed alg is CBC (actual is {:s})".format(alg)
