from Crypto.Cipher import AES
#import os
import socket
from base64 import b64encode, b64decode
#import sys
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
import primroots

def dh():
	q,alpha=primroots.primeRoot()
	#a=[]
	#a.append(str(q))
	#a.append(str(alpha))
	#print(a)conn
	#client.send(str(a).encode())
	with open("private.pem") as f:
		sk = SigningKey.from_pem(f.read())
	client.send(str(q).encode())	
	client.send(str(alpha).encode())
	#q_sig = sk.sign(str(q).encode())
	#alpha_sig = sk.sign(str(alpha).encode())
	#client.send(q_sig)
	#client.send(alpha_sig)
	#print("q :",q)
	#print("alpha :",alpha)
	xa,ya=primroots.Xab(q,alpha)
	#print("Xa :",xa)
	#print("Ya :",ya)
	client.send(str(ya).encode())
	yb = int((client.recv(1024)).decode())
	#print("Yb :",yb)
	ka=primroots.key(yb,xa,q)
	#print("Ka :",ka)
	return(ka)

def aes_enc(key, data):
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(data)
	return ciphertext,nonce

def aes_dec(ciphertext, enc_key, nonce):
	cipher = AES.new(enc_key, AES.MODE_EAX, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext

while(1):
	#connection establishment
	print("Server is ready")
	port = 5000 
	#server_name = input("enter server name:")
	server = socket.socket()
	server.bind(('localhost',port))
	server.listen(10)
	client, address = server.accept()
	print("Connection established")
	
	d_key=dh()
	print("Deffie hellman key generated")
	if(len(str(d_key))==1):
		pad='000000000000000'
	elif(len(str(d_key))==2):
		pad='00000000000000'
	elif(len(str(d_key))==3):
		pad='0000000000000'
	elif(len(str(d_key))==4):
		pad='000000000000'
	d_keypad=(str(d_key)+pad).encode()  
	vk = VerifyingKey.from_pem(open("public.pem").read())


	nonce=client.recv(16)
	enc_key = client.recv(16)
	nonce1=client.recv(16)
	ciphertext=client.recv(1024)
#print(ciphertext, '\n',nonce,'\n', enc_key,'\n', nonce1,'\n')

	cipher_sig=client.recv(48)
#print(cipher_sig)
	enckey_sig=client.recv(48)
#print(cipher_sig, '\n', enckey_sig)
#print(enckey_sig)
	try:
		vk.verify(cipher_sig, ciphertext)
		vk.verify(enckey_sig,enc_key)
		print('ciphertext : ',ciphertext)
		print('encrypted key : ' ,enc_key)
		print("Signature verified")
		dec_key=aes_dec(enc_key ,d_keypad, nonce1)
		plain=aes_dec(ciphertext,dec_key,nonce)
		print("The decrypted domain name recieved from client : ",plain.decode())
	except BadSignatureError:
		print ("BAD SIGNATURE ciphertext or key tampered")

	import dns
	import dns.resolver
	result = dns.resolver.query(plain.decode(), 'A')
	for ipval in result:
		print('IP : ', ipval.to_text())
	
	cipherip,nonce3=aes_enc(dec_key, (ipval.to_text()).encode())	
	client.send(nonce3)
	client.send(cipherip)
'''
cipher_sig=client.recv(1024)
ciphertext=client.recv(1024)
try:
	vk.verify(cipher_sig, ciphertext)
	print(ciphertext)
	print("good signature")
except BadSignatureError:
	print ("BAD SIGNATURE ciphertext tampered")
	#exit()
#print(ciphertext)
nonce=client.recv(1024)
print(nonce)
enckey_sig=client.recv(1024)
print(enckey_sig)
enc_key = client.recv(1024)
print(enc_key)
try:
	vk.verify(enckey_sig, enc_key)
	print(enc_key)
	print("good signature")
except BadSignatureError:
	print ("BAD SIGNATURE enc_key tampered")
#print(enc_key)

nonce1=client.recv(1024)
print(nonce1)

dec_key=aes_dec(enc_key ,d_keypad, nonce1)
plain=aes_dec(ciphertext,dec_key,nonce)
print(plain.decode())

#enc_key = client.recv(1024)
#print(enc_key)
#ciphertext=client.recv(1024)
#print(ciphertext)
#nonce=client.recv(1024)
#print(nonce)

#cipher1 = AES.new(kb, AES.MODE_EAX, nonce=nonce1)
#key=cipher1.decrypt(enc_key)
#print(key)
cipher = AES.new(enc_key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
try:
	cipher.verify(tag)
	print("The message is authentic:", plaintext)
except ValueError:
	print("Key incorrect or message corrupted")'''