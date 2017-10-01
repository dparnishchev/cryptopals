import os
import aes
import pkcs7
import xor

secret_key = os.urandom(16)
iv = "\x00" * 16

def _parse_params(params_str):
	data = {}
	params = params_str.split("&")
	for param in params:
		(name, value) = param.split("=")
		data[name] = value
	return data

def _encrypt_params(params_str):
	return aes.encrypt_ecb_128(params_str, secret_key)

def profile_for(email):
	if "&" in email:
		raise Exception("email should not contain metacharacters")
	if "=" in email:
		raise Exception("email should not contain metacharacters")
	return _encrypt_params("email={:s}&uid=10&role=user".format(email))

def read_profile(enc_profile):
	return _parse_params(aes.decrypt_ecb_128(enc_profile, secret_key))

def cbc_bitflip_attack_sample_enc(userdata):
	#1 quote out = and ; from userdata
	userdata.replace("=", "%3D")
	userdata.replace(";", "%3B")
	#2. form plaintext string
	plaintext = "comment1=cooking%20MCs;userdata=" + userdata
	plaintext = plaintext + ";comment2=%20like%20a%20pound%20of%20bacon"
	#encrypt plaintext with aes in cbc
	return aes.encrypt_cbc_128(plaintext, iv, secret_key)

def cbc_bitflip_attack_sample_dec(ciphertext):
	plaintext = aes.decrypt_cbc_128(ciphertext, iv, secret_key)
	for param in plaintext.split(";"):
		pair = param.split("=")
		if len(pair) > 2:
			continue
		if pair == ["admin", "true"]:
			return (plaintext, True)
	return (plaintext, False)

def _solve_set2_ch13():
	#1. Identify block size
	(block_size, pad_size) = aes.identify_block_size(profile_for)
	#2. Generate admin digest
	#   We need to put "admin" str to the secon cipher block 
	cheat_str  = "*" * (block_size - len("email=")) + pkcs7.pad("admin", block_size)
	admin_digest = profile_for(cheat_str)[block_size:block_size * 2]
	#3. Set email to something of length = pad_size + len("user") = 9 + 4 = 13
	#   Then profile ending "user" will go to the beginning of separate AES block
	email = "ha@hacker.com"
	admin_profile = profile_for(email)[:-block_size] + admin_digest
	#4. Check our work
	print read_profile(admin_profile)

#cbc bitflip attack
#We have aes in cbc mode (128 bit). The first 2 blocks of plaintext are 
#"comment1=cooking%20MCs;userdata="
#Then goes our block "\x00" * 16s. We need to turn it to the string ";admin=true;"
#For aes in cbc we have the following:
#Ci = Ek(Ci-1 + pi) => pi = Dk(Ci) + Ci-1
#p0 = Dk(C0) + iv
#p1 = Dk(C1) + C0
#p2 = Dk(C2) + C1 => Dk(C2) = p2 + C1
#p2' = ";admin=true;XXXX" => Dk(C2) + C1' = p2' => p2 + C1 + C1' = p2' =>
# => C1' = p2' + C1 + p2
def _solve_set2_ch16():
	ciphertext = cbc_bitflip_attack_sample_enc("\x00" * 16)
	print cbc_bitflip_attack_sample_dec(ciphertext)
	C1 = ciphertext[16:32]
	p2_ = ";admin=true;;;;;"
	p2 = "\x00" * 16
	C1_ = xor.xor(xor.xor(C1, p2), p2_)
	ciphertext = ciphertext[:16] + C1_ + ciphertext[32:]
	print cbc_bitflip_attack_sample_dec(ciphertext)

_solve_set2_ch16()