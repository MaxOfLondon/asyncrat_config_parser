# pip install -U cryptography
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from logging import getLogger, basicConfig, DEBUG, WARNING

logger = getLogger('asyncratparser')

class AsyncRATParserAESDecryptor():
    class AsyncRATParserAESDecryptorException(Exception):
        pass

    def __init__(self, key_size_bytes:int, block_size:int, iterations:int, salt:bytes, passphrase:bytes) -> None:
        # Gather AES implementation metadata
            # key size
            # block size
            # iterations
            # AES salt
            # AES key - derive PBKDF2
        # Provide decryption function
        
        self.key_size = key_size_bytes
        self.block_size = block_size
        self.iterations = iterations
        self.salt = salt
        self.passphrase = passphrase
        self.key = self.get_key_from_passphrase(self.passphrase)

    
    def get_key_from_passphrase(self, passphrase: bytes) -> bytes:
        kdf = PBKDF2HMAC(SHA1(), self.key_size, self.salt, self.iterations)
        try:
            key = kdf.derive(passphrase)
        except Exception as e:
            raise self.AsyncRATParserAESDecryptorException(f'Error deriving key from passphrase {self.passphrase}') from e
        logger.debug(f' Derived AES key: {key.hex()}')
        return key

    def decrypt(self, iv: int, ctxt: bytes) -> bytes:
        logger.debug(f'Decrypting {ctxt}:{len(ctxt)} with key {self.key.hex()} and IV {iv}')
        ciphertext = ctxt
        aes_cipher = Cipher(AES(self.key), CBC(iv))
        decryptor = aes_cipher.decryptor()
        unpadder = PKCS7(self.block_size).unpadder()
        try:
            padded_text = decryptor.update(ciphertext) + decryptor.finalize()
            unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        except Exception as e:
            raise self.AsyncRATParserAESDecryptorException(f'Failed to decrypt {ciphertext} with key {self.key.hex()} and IV {iv}') from e
        logger.debug(f' Decrypted text: {unpadded_text.decode().strip()}')
        return unpadded_text
    
    def get_key(self) -> bytes:
        return self.key

        
        