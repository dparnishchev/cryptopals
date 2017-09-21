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
def score_ecb(ciphertext, block_size = 16):
	score = 0
	while len(ciphertext) > block_size:
		for j in range(1, len(ciphertext) / block_size):
			if ciphertext[:block_size] == ciphertext[block_size * j:block_size * (j + 1)]:
				score += 1
		ciphertext = ciphertext[block_size:]
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

#returns pair: (block_size, pad_size)
#pad_size - the length of padding at the end of secret data
def identify_block_size(func_sample):
	feed = ""
	start_len = len(func_sample(feed))
	cur_len = start_len
	while cur_len == start_len:
		feed = feed + "A"
		cur_len = len(func_sample(feed))
	return (cur_len - start_len, len(feed))

def ecb_byte_at_a_time_attack(func_sample):
	#1. Identify block size
	(block_size, pad_size) = identify_block_size(func_sample)
	secret_size = len(func_sample("")) - pad_size
	secret = ""
	#2. Make sure that we are working with AES-ECB
	score = score_ecb(func_sample("A" * block_size * 4), block_size)
	if score == 0:
		raise Exception("Looks like func_sample is not AES-ECB-based")
	#3. For each secret text byte create dictionary and find corresponding
	#   plain text byte
	prefix = "A" * (block_size - 1)
	filling = prefix
	for k in range(0, secret_size):
		block_dict = {}
		for i in range(0, 0x100):
			key = filling + chr(i)
			block_dict[func_sample(key)[:block_size]] = chr(i)
		offset = len(secret) / block_size
		byte_key = func_sample(prefix)[offset * block_size: (offset + 1) * block_size]
		secret = secret + block_dict[byte_key]
		if prefix == "":
			prefix = "A" * (block_size - 1)
		else:
			prefix = prefix[:-1]
		filling = filling[1:] + secret[-1]
	return secret
	



def _ecb_break_byte_at_a_time_sample(plaintext):
	secret_str = (	"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
					"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
					"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
					"YnkK"	)
	key = _ecb_break_byte_at_a_time_sample.secret_key
	return encrypt_ecb_128(plaintext + base64.decode(secret_str), key)
_ecb_break_byte_at_a_time_sample.secret_key = os.urandom(16)

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
		score = score_ecb(hex_ciphertext.decode("hex"))
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
		if score_ecb(ciphertext) > 0:
			print str(i) + " guessed alg is ECB (actual is {:s})".format(alg)
		else:
			print str(i) + " guessed alg is CBC (actual is {:s})".format(alg)

def _solve_set2_ch12():
	return ecb_byte_at_a_time_attack(_ecb_break_byte_at_a_time_sample)