import tinyec.ec as ec
import tinyec.registry as reg
import secrets
from Crypto.Cipher import AES
import hashlib
import base64
import json

curve = ""
server_public_key = ""
server_private_key = ""
shared_key = ""

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def generateKeys():
    global curve
    global server_private_key
    global server_public_key
    print("generateKeys --> Init")
    curve = reg.get_curve('secp256r1')
    #Generating Server private 
    server_private_key = secrets.randbelow(curve.field.n)
    #print("Z(p): ", curve.field.n)
    print("generateKeys --> Server private key: ", server_private_key)
    #Generate Server publickey from the private key and Generator point
    server_public_key = server_private_key * curve.g
    print("generateKeys --> Server public key: ", server_public_key, "type: " , type(server_public_key))


def generate_shared_secret(client_publickey):
    global shared_key
    try:
        print("generate_shared_secret --> Init")
        coordinate_x = client_publickey['x_coordinate']
        coortinate_y = client_publickey['y_coordinate']
        client_curve_point = ec.Point(curve, int(coordinate_x), int(coortinate_y))
        print("generate_shared_secret --> Client public curve point: ", client_curve_point, "type: ", type(client_curve_point))
        shared_key = server_private_key*client_curve_point
        return True
    except Exception as ex:
        print("ERROR --> generate_shared_secret --> ", ex)
        return False
    
def __pad(plain_text):
    number_of_bytes_to_pad = AES.block_size - len(plain_text) % AES.block_size
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_plain_text = plain_text + padding_str
    return padded_plain_text

def __unpad(plain_text):
    last_character = plain_text[len(plain_text) - 1:]
    return plain_text[:-ord(last_character)]
    
def encrypt(text):
    print("encrypt() --> Intentando encriptar: ", text)
    padded_text = pad(text)
    print("encrypt() --> padded_text: ", padded_text ,"type: ",type(padded_text))
    padded_text_bytes = bytes(padded_text, "utf-8")
    print("encrypt() --> padded_text bytes: ", padded_text_bytes ,"type: ",type(padded_text_bytes))
    key_unhex = compress_point2(shared_key)
    print("encrypt() --> AES KEY UNHEX: ",  key_unhex)
    key_hex = bytes.fromhex(compress_point2(shared_key))
    print("encrypt() --> AES KEY HEX: ",  key_hex)
    cipher = AES.new(key_hex, AES.MODE_ECB)
    #encoded = base64.standard_b64encode(padded_text)
    #base64Test(encoded)
    #print("encoded: " , encoded, " lenght:", len(encoded))
    encrypted = cipher.encrypt(padded_text_bytes)
    print("encrypt() --> encrypted_text: ", encrypted)
    print("encrypt() --> encrypted_text2: ", base64.b64encode(encrypted))
    print("encrypt() --> encrypted_text3: ", base64.b64encode(encrypted).decode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt(text):
    key_unhex = compress_point2(shared_key)
    print("decryt() --> AES KEY UNHEX: ",  key_unhex)
    key_hex = bytes.fromhex(compress_point2(shared_key))
    print("decryt() --> AES KEY HEX: ",  key_hex)
    cipher = AES.new(key_hex, AES.MODE_ECB)
    print("decrypt() --> Intentando desencriptar raw:", text, ";bytes:", bytes(text, "utf-8") ,"; len: " ,len(text))
    decrypted_data_raw = cipher.decrypt(base64.decodebytes(bytes(text, "utf-8")))
    print("decrypt() --> Decrypted_text_raw:", decrypted_data_raw, type(decrypted_data_raw))
    decrypted_data_decoded = decrypted_data_raw.decode("utf-8")
    print("decrypt() --> Decrypted_text_decoded:", decrypted_data_decoded, type(decrypted_data_decoded))
    decrypted_data_unpadded = bytes(__unpad(decrypted_data_decoded),"utf-8")
    print("decrypt() --> Decrypted_text_unpadded:", decrypted_data_unpadded, "type:", type(decrypted_data_unpadded))
    return json.loads(decrypted_data_unpadded.decode("utf-8"))

def return_shared_key():
    return shared_key

def return_server_public_key():
    return_server_public_key

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def compress_point2(point):
    resp = hex(point.x) + hex(point.y % 2)
    return resp[2:len(resp)-3]

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    digest = sha.hexdigest()
    print("ecc_point_to_256_bit_key --> hexdigest: ", digest)
    return sha.digest()

def base64Test(text):
    for i in range(len(text)):
        print (compat_ord(text[i]))

def compat_ord(c):
    if type(c) is int:
        return c
    else:
        return ord(c)

"""
if __name__ == "__main__":
    generateKeys()
"""