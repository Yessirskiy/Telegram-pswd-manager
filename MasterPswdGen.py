'''
Important:
    Checking master password using verifyer and salt
    Combining salt and original password we get hash of this password
    Hash we got compares with verifyer(pre-made hash with same salt password)
    If hashes are equal password is verifyed.
    
    BUT, hash we use for encryption and decryption acutal profile's credentials
    is not the same hash we use to verify master password, so verifier cannot be used to decrypt secure data

'''

from getpass import getpass
import os
import config
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

def hashPassword(master_pswd: str, salt: bytes) -> bytes:
    '''
    Returns hashed master password

    Args:
        master_pswd (str): Raw master password
        salt (bytes): Salt for the password hashing

    Returns:
        hashed_pswd (bytes): Hashed master password
    '''
    pswd_encoded = master_pswd.encode()
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), salt=salt, iterations=390000, length=32)
    hashed_pswd = base64.urlsafe_b64encode(kdf.derive(pswd_encoded))
    return hashed_pswd

def main():
    password = getpass('Please type your master password: ')
    salt = base64.b64encode(os.urandom(16))
    verify = hashPassword(password, salt)
    data = {
        'salt' : salt.decode('utf-8'),
        'verify' : verify.decode('utf-8')
    }
    with open(config.VERIFIER_FILE, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)
        print(data)
    input(f'[+] File {config.VERIFIER_FILE} is generated')


if __name__ == "__main__":
    main()