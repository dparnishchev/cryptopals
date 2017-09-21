import os
import base64
import xor
from Crypto.Cipher import AES

def decrypt_ecb_128(ciphertext, key):
	return AES.new(key, AES.MODE_ECB, "").decrypt(ciphertext)

def encrypt_ecb_128(plaintext, key):
	return AES.new(key, AES.MODE_ECB, "").encrypt(plaintext)

def decrypt_cbc_128(ciphertext, iv, key):
	plaintext = ""
	for i in range(0, len(ciphertext) / 16):
		block = ciphertext[16 * i : 16 * (i + 1)]
		if i == 0:
			plaintext = plaintext + xor.xor(decrypt_ecb_128(block, key), iv)
		else:
			prev_block = ciphertext[16 * (i - 1): 16 * i]
			plaintext = plaintext + xor.xor(decrypt_ecb_128(block, key), prev_block)
	return plaintext

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

def random_key():
	return os.urandom(16)

def encryption_oracle(plaintext):
	key = random_key()


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
	print decrypt_cbc_128(base64.decode(data), "00" * 16, "YELLOW SUBMARINE")

