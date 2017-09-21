import os
import aes
import pkcs7

secret_key = os.urandom(16)

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