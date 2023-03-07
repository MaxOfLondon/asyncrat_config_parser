from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.x509.extensions import SubjectKeyIdentifier, BasicConstraints
from logging import getLogger, basicConfig, DEBUG, WARNING

logger = getLogger('asyncratparser')

class ASyncRATCertParser():
    BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----\n'
    END_CERTIFICATE = '\n-----END CERTIFICATE-----'

    class AsyncRATCertParserException(Exception):
        pass

    def __init__(self, cert_body_b64: str) -> None:
        self.cert = self.BEGIN_CERTIFICATE + cert_body_b64 + self.END_CERTIFICATE

    def parse(self) -> dict:
        cert_dic = {}
        b = bytearray(self.cert,'utf-8')
        logger.debug(f'Parsing certificate of length {len(self.cert)}...')
        try:
            cert_obj = load_pem_x509_certificate(bytes(b))
            logger.debug(' PEM x509 certificate loaded')
            
            cert_dic['x509v3_extensions'] = []
            for i in range(0,len(cert_obj.extensions)):
                ext = cert_obj.extensions.__getitem__(i)
                if type(ext.value) is BasicConstraints:
                    cert_dic['x509v3_extensions'].append({
                        'basic_constraints': {
                            'ca': ext.value.ca,
                            'critical': ext.critical
                        }
                    })
                elif type(ext.value) is SubjectKeyIdentifier:
                    cert_dic['x509v3_extensions'].append({
                        'subject_key_identifier': self.get_hex_cert_form(self.bytes_to_int(ext.value.digest))
                        }
                    )
            logger.debug(' Parsed certificate extensions')
            cert_dic['signature_algorithm'] = str(cert_obj.signature_algorithm_oid._name)
            cert_dic['version'] = f'{str(cert_obj.version)[9:]} ({hex(cert_obj.version.value)})'
            cert_dic['issued_by'] = str(cert_obj.issuer.rfc4514_string())
            cert_dic['subject'] = str(cert_obj.subject.rfc4514_string())
            cert_dic['serial_number'] = self.get_hex_cert_form(cert_obj.serial_number)
            cert_dic['signature_hash_algorithm'] = cert_obj.signature_hash_algorithm.name
            cert_dic['signature'] = self.get_hex_cert_form(self.bytes_to_int(cert_obj.signature))
            cert_dic['validity'] = {
                'not_valid_before':str(cert_obj.not_valid_before),
                'not_valid_after': str(cert_obj.not_valid_after)
            }
            logger.debug(' Parsed signature_algorithm, version, issued_by, subject, serial_number, signature_hash_algorithm, signature, validyty')
            cert_dic['subject_public_key_info'] = {
                'public_key_algorithm': 'rsaEncryption',
                'rsa_public_key_length': cert_obj.public_key().key_size,
                'modulus': self.get_hex_cert_form(cert_obj.public_key().public_numbers().n),
                'exponent': f'{cert_obj.public_key().public_numbers().e} ({hex(cert_obj.public_key().public_numbers().e)})'
            }
            logger.debug(' Parsed subject_public_key_info')
            cert_dic['public_key'] = str(cert_obj.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
            cert_dic['public_bytes'] = cert_obj.public_bytes(serialization.Encoding.PEM).decode()
            logger.debug(' Parsed public key and bytes')
        except Exception as e:
            raise self.AsyncRATCertParserException(f'Failed to parse certificate {self.cert}') from e
        logger.debug('Certificate parsed successfuly')
        return cert_dic
    
    def bytes_to_int(self, bytes: bytes, order='little') -> int:
        try:
            result = int.from_bytes(bytes, byteorder=order)
        except Exception as e:
            raise self.AsyncRATCertParserException(f'Failed to convert bytes to int for {bytes}') from e
        return result
    
    def get_hex_cert_form(self, i: int) -> str:
        hs = f'{i:x}'
        lh = [hs[x]+hs[x+1] for x in range(0, len(hs) ,2)]
        return ':'.join(lh)