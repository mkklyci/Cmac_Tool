import cryptography.hazmat.backends
import cryptography.hazmat.primitives.cmac
import hashlib
import binascii


key = b'\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB'


def sign_hex_file_with_cmac(hex_file, aes_key_hex):
    with open(hex_file, "rb") as f:
        hex_data = f.read()
#    hex_hash = hashlib.sha256(hex_data).digest()
    
    aes_key = binascii.unhexlify(aes_key_hex)
    
    cmac = cryptography.hazmat.primitives.cmac.CMAC(
        cryptography.hazmat.primitives.ciphers.algorithms.AES(aes_key),
        backend=cryptography.hazmat.backends.default_backend()
    )
    cmac.update(hex_data)
    signature = cmac.finalize()
    
    return signature.hex()


def bin_file_sign_cmac(file_path, key_hexstr):
    backend = cryptography.hazmat.backends.default_backend()
    key = binascii.unhexlify(key_hexstr)
    with open(file_path, "rb") as file:
        data = file.read()
        cmac = cryptography.hazmat.primitives.cmac.CMAC(
        cryptography.hazmat.primitives.ciphers.algorithms.AES(key),
        backend=cryptography.hazmat.backends.default_backend()
    )
        cmac.update(data)
        signature = cmac.finalize()
        return binascii.hexlify(signature)





def write_to_file(filename, hex_num):
    with open(filename, 'wb') as file:
        file.write((hex_num))






write_to_file("binary_number.bin", key)
signed_hex = sign_hex_file_with_cmac("binary_number.bin", "ABABABABABABABABABABABABABABABAB") #SECOND INPUT IS AESKEY
print("Signed Hex:", signed_hex)


file_path = "exampleinput.bin"
signature = bin_file_sign_cmac(file_path, "ABABABABABABABABABABABABABABABAB")   #SECOND INPUT IS AESKEY
print(f"File signature: {signature.decode()}")