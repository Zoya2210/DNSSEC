from Crypto.Cipher import AES
import os
import socket
from base64 import b64encode, b64decode
import sys
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
import primroots


port = int(input("enter port no.:"))
#client_name = input("enter client name:")
conn = socket.socket()
conn.connect(('localhost',port))
print("Connection established")



#deffie hellman to generate the key that's going to encrypt the session key in aes
def dh():
	#a=(conn.recv(1024)).decode()
	#print(a)
	#print(a[0])
	q = int((conn.recv(1024)).decode())
	alpha = int((conn.recv(1024)).decode())
	xb,yb=primroots.Xab(q,alpha)
	#print("Xb :",xb)
	#print("Yb :",yb)
	ya=int((conn.recv(1024)).decode())
	#print("Ya :",ya)
	conn.send(str(yb).encode())
	kb=primroots.key(ya,xb,q)
	#print("Kb :",kb)
	return (kb)
	#kb=(str(kb)).encode()

#result=hashlib.md5(str(ka).encode())
#print(result.digest())
#ka=result.digest()
#len(result.digest())
#ka=(str(ka)).encode()

def aes_enc(key, data):
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(data)
	return ciphertext,nonce

def aes_dec(ciphertext, enc_key, nonce):
	cipher = AES.new(enc_key, AES.MODE_EAX, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext
	
#encrypt the generated sessionkey
#enc_key, tag1 = cipher1.encrypt_and_digest(key)

d_key=dh()
print("Deffie-Hellman key generated")

key = os.urandom(16)
print("Sixteen byte session key generated")
print(key)
print("Enter the domain name")
data=(input()).encode()


with open("private.pem") as f:
	sk = SigningKey.from_pem(f.read())

if(len(str(d_key))==1):
	pad='000000000000000'
elif(len(str(d_key))==2):
	pad='00000000000000'
elif(len(str(d_key))==3):
	pad='0000000000000'
elif(len(str(d_key))==4):
	pad='000000000000'
d_keypad=(str(d_key)+pad).encode()

#sig = sk.sign(message)
#conn.send(sig)
#key = b'Sixteen byte key' for aes

ciphertext,nonce=aes_enc(key, data)
enc_key,nonce1=aes_enc(d_keypad,key)
a=[]
a.append(len(ciphertext))
a.append(len(nonce))
a.append(len(enc_key))
a.append(len(nonce1))
#print(a)

conn.send(nonce)
conn.send(enc_key)
conn.send(nonce1)
conn.send(ciphertext)
#print(ciphertext,'\n',nonce,'\n',enc_key,'\n',nonce1,'\n')

cipher_sig = sk.sign(ciphertext)
enckey_sig = sk.sign(enc_key)

b=[]
b.append(len(cipher_sig))
b.append(len(enckey_sig))
#print(b)

conn.send(cipher_sig)
conn.send(enckey_sig)

print("Domain name is encrypted,signed and sent")
#print(cipher_sig,'\n', enckey_sig)
nonce3=conn.recv(16)
cipherip=conn.recv(1024)
#print(nonce3)
print("Encrypted IP address : ",cipherip)
if(cipherip==b''or nonce==b''):
	print('Error: Enter correct domain name')
	conn.close()
plain=aes_dec(cipherip,key,nonce3)
print("The resolved IP of the domain name is:",plain.decode())
conn.close()
'''
#n1_sig = sk.sign(nonce)
#conn.send(n1_sig)
#conn.send(nonce)
print(nonce)

enc_key,nonce1=aes_enc(d_keypad,key)

enckey_sig = sk.sign(enc_key)
conn.send(enckey_sig)
print(enckey_sig)
conn.send(enc_key)
print(enc_key)

conn.send(nonce1)
print(nonce1)'''