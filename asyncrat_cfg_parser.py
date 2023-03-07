from base64 import b64decode, b64encode
from json import dumps
from logging import getLogger
from re import search, findall, DOTALL
from typing import Tuple, List, Dict, Match

from asyncrat_aes_decryptor import AsyncRATParserAESDecryptor
from asyncrat_cert_parser import ASyncRATCertParser

logger = getLogger('asyncratparser')

class AsyncRATConfigParser:
    
    PATTERN_CONFIG_MATCH = b'(\x72.{4}\x80.{4}){5}' # find accumulation of options
    PATTERN_CONFIG_RVA = b'\x72(.{4})\x80(.{4})' # parse options 
    PATTERN_CLR_METADATA_START = b'\x42\x53\x4a\x42'
    PATTERN_AES_METADATA = b'\x73.{4}\x7a\x03\x7e(.{4})' # capture group is salt RVA pointer
    PATTERN_AES_KEY_AND_BLOCK_SIZE = b'\x07\x20(.{4})\x6f.{4}\x07\x20(.{4})'
    PATTERN_AES_SALT_INIT = b'\x80%b\x2a'
    PATTERN_AES_KEY = b'\x7e(.\x00\x00\x04)\x73' # TODO: improve pattern with key exact address
    OPCODE_LDSTR = b'\x72'
    OPCODE_LDTOKEN = b'\xd0'
    RVA_STRINGS_BASE = 0x04000000
    RVA_US_BASE = 0x70000000
    IL_OPCODE_RET = b'\x2a'
    STREAM_ID_STORAGE = b'#~'
    STREAN_ID_US = b'#US'
    STREAN_ID_STRINGS = b'#Strings'
    TABLE_FIELD_ID = 'Field'
    TABLE_FIELD_RVA_ID = 'FieldRVA'
    SECTION_TEXT_ID = b'.text'
    TRANSLATED_CERT_CONFIG_KEY = 'Certificate' # TODO: make it dynamic as names can change
    TRANSLATED_SERVERSIG_CONFIG_KEY = 'Serversignature' # TODO: make it dynamic as names can change

    MAP_TABLE = {
        'Module': {
            'row_size': 10
        },
        'TypeRef': {
            'row_size': 6
        },
        'TypeDef': {
            'row_size': 14
        },
        'FieldPtr': {
            'row_size': 2
        },
        'Field': {
            'row_size': 6
        },
        'MethodPtr': {
            'row_size': 2
        },
        'Method': {
            'row_size': 14
        },
        'ParamPtr': {
            'row_size': 2
        },
        'Param': {
            'row_size': 6
        },
        'InterfaceImpl': {
            'row_size': 4
        },
        'MemberRef': {
            'row_size': 6
        },
        'Constant': {
            'row_size': 6
        },
        'CustomAttribute': {
            'row_size': 6
        },
        'FieldMarshal': {
            'row_size': 4
        },
        'DeclSecurity': {
            'row_size': 6
        },
        'ClassLayout': {
            'row_size': 8
        },
        'FieldLayout': {
            'row_size': 6
        },
        'StandAloneSig': {
            'row_size': 2
        },
        'EventMap': {
            'row_size': 4
        },
        'EventPtr': {
            'row_size': 2
        },
        'Event': {
            'row_size': 6
        },
        'PropertyMap': {
            'row_size': 4
        },
        'PropertyPtr': {
            'row_size': 2
        },
        'Property': {
            'row_size': 6
        },
        'MethodSemantics': {
            'row_size': 6
        },
        'MethodImpl': {
            'row_size': 6
        },
        'ModuleRef': {
            'row_size': 2
        },
        'TypeSpec': {
            'row_size': 2
        },
        'ImplMap': {
            'row_size': 8
        },
        'FieldRVA': {
            'row_size': 6
        },
        'ENCLog': {},
        'ENCMap': {},
        'Assembly': {},
        'AssemblyProcessor': {},
        'AssemblyOS': {},
        'AssemblyRef': {},
        'AssemblyRefProcessor': {},
        'AssemblyRefOS': {},
        'File': {},
        'ExportedType': {},
        'ManifestResource': {},
        'NestedClass': {},
        'GenericParam': {},
        'MethodSpec': {},
        'GenericParamConstraint': {},
        'Reserved 2D': {},
        'Reserved 2E': {},
        'Reserved 2F': {},
        'Document': {},
        'MethodDebugInformation': {},
        'LocalScope': {},
        'LocalVariable': {},
        'LocalConstant': {},
        'ImportScope': {},
        'StateMachineMethod': {},
        'CustomDebugInformation': {},
        'Reserved 38': {},
        'Reserved 39': {},
        'Reserved 3A': {},
        'Reserved 3B': {},
        'Reserved 3C': {},
        'Reserved 3D': {},
        'Reserved 3E': {},
        'Reserved 3F': {}
    }

    class AsyncRATConfigParserException(Exception):
        pass

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.data = self.get_file_data()
        # Find start of the configuration section and retrieve the virtual
        # address of the config keys and their encrypted values
        self.config_addrs = self.get_config_addrs()
        # Map addresses from the configuration to their encrypted string values
        self.storage_stream_offset = self.get_stream_start(self.STREAM_ID_STORAGE)
        self.strings_stream_start = self.get_stream_start(self.STREAN_ID_STRINGS)
        self.us_stream_start = self.get_stream_start(self.STREAN_ID_US)
        self.table_map = self.get_table_map()
        self.fields_map = self.get_fields_map()
        # Get config in format trnslated_config[key] = encrypted value
        self.translated_config = self.get_translated_config()
        # parse AES parameters
        (
            self.aes_key_size_bytes,
            self.aes_block_size_bytes,
            self.aes_iterations,
            self.aes_salt,
            self.aes_passphrase,
        ) = self.parse_aes_params()
        # Decrypt values
        self.aes_decryptor = AsyncRATParserAESDecryptor(self.aes_key_size_bytes,
                                                        self.aes_block_size_bytes,
                                                        self.aes_iterations,
                                                        self.aes_salt,
                                                        self.aes_passphrase)
        self.config = self.decrypt_config()
        
    def get_file_data(self) -> bytes:
        logger.debug(f'Opening file {self.filepath}')
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            raise self.AsyncRATConfigParserException(f'Error reading file {self.filepath}') from e
        logger.debug(f'Successfuly read data from {self.filepath}')
        return data

    def get_config_addrs(self) -> List[Tuple[int, int]]:
        # 0x72 v1 v2 v3 v4 0x80 a1 a2 a3 a4
        logger.debug(f'Extracting config map ...')
        config = []
        hit = search(self.PATTERN_CONFIG_MATCH, self.data, DOTALL)
        if hit is None:
            raise self.AsyncRATConfigParserException('Error finding config map')
        config_start = hit.start()
        if config_start is not None:
            logger.debug(f'Found config map start at {hex(config_start)}')
        config_map = self.get_string_from_offset(config_start, self.IL_OPCODE_RET)
        parsed_rvas = findall(self.PATTERN_CONFIG_RVA, config_map, DOTALL)
        for us_rva, string_rva in parsed_rvas:
            config_value_rva = self.bytes_to_int(us_rva)
            config_name_rva = self.bytes_to_int(string_rva)
            config.append((config_name_rva, config_value_rva))
            logger.debug(f' Found config item (name, value) addresses: ({hex(config_name_rva)}, {hex(config_value_rva)})')
        logger.debug(f'Config map addresses extracted successfuly')
        
        return config

    def get_table_map(self) -> Dict[str, Dict[str, int]]:
        '''
        Determine whch tables are present in executable and skip tables that do not exist
        to skip irrelevant data to get to 'fields' table.
        '''
        logger.debug('Extracting table map ...')
        # Extract maskvalid value from PE
        # Get the start of storage stream and calculate offset to tables stream
        # For each table extract number of rows and size of each row
        mask_valid = self.get_mask_valid()
        table_map = self.MAP_TABLE.copy()
        table_start = self.storage_stream_offset + 24
        offset = table_start
        try:
            for table in table_map:
                if mask_valid & (2**list(table_map.keys()).index(table)):
                    row_count_packed = self.data[offset: offset+4]
                    row_count = self.bytes_to_int(row_count_packed)
                    table_map[table]['num_rows'] = row_count
                    logger.debug(f' Found {row_count} row{"s" if row_count > 1 else ""} for table {table}')
                    offset += 4
                else:
                    table_map[table]['num_rows'] = 0
        except Exception as e:
            raise self.AsyncRATConfigParserException('Failed to find row counts from tables') from e
        
        logger.debug('Table map extracted successfuly')
        
        return table_map

    def get_fields_map(self) -> List[Tuple[int, str]]:
        # Find the start of fields table
            # Find the end of the table stream metadata: storage_stream_offset + 24
                # + (4 * number of tables present)
                # until we reach fields table
        # Iterate over all rows in fields table, and use their offset to get the value in the #Strings stream
        logger.debug('Extracting fields map ...')
        fields_map = []
        fields_start = self.get_table_start(self.TABLE_FIELD_ID)
        offset = fields_start
        for x in range(self.table_map[self.TABLE_FIELD_ID]['num_rows']):
            try:
                field_offset = self.bytes_to_int(self.data[offset+2:offset+4])
                field_value = self.get_string_from_offset(self.strings_stream_start + field_offset)
                fields_map.append((field_offset, field_value))
                offset += self.table_map[self.TABLE_FIELD_ID]['row_size']
            except Exception as e:
                raise self.AsyncRATConfigParserException('Error parsing Field table') from e
            logger.debug(f' Found field: {hex(field_offset)} {field_value}')
        logger.debug('Fields map extracted successfully')
        return fields_map

    def get_translated_config(self) -> Dict[bytes, bytes]:
        # For each config address map and config key name
        # For each config key name:
            # Translate Field RVA to the value of the key in our fields map
        # For each config value:
            # Use a helper function to get the string from its position in the #US stream
            # Check length byte(s) to see if it is a long string (1 or 2 bytes length)
            # Read unicode string at that location using the length
        # Return the translated config where the addresses are mapped to string values
        # trnslated_config[key] = value
        # e.g.
        # translated_config['Ports'] = 'FteGGwSLveH/e9FFy9a4hfthYL9yV6WWWcYrI3NVKrOc8ZgvgE4YG2FWFAEvqATUBijm4StdauKxoiYVc2rJDQ=='

        logger.debug('Translating configuration addresses to value ...')
        translated_config = {}
        for (strings_rva, us_rva) in self.config_addrs:
            try:
                field_name = self.strings_rva_to_strings_val(strings_rva)
                field_value = self.us_rva_to_us_val(us_rva)
                logger.debug(f' Found config value: {field_name} = {field_value}')
                translated_config[field_name] = field_value
            except Exception as e:
                raise self.AsyncRATConfigParserException(f' Error translating RVA {hex(us_rva)} and {hex(strings_rva)}') from e
        logger.debug('Configuration successfuly translated')
        
        return translated_config

    def us_rva_to_us_val(self, us_rva) -> bytes:
        us_start = self.us_stream_start
        # length_byte_offset = 0x7000000f - 0x70000000 + file offset where #US starts
        # there are differences in length, they can be either 1 or 2 bytes. If 2 bytes then MSb is set. If set then subtract 0x8000
        
        length_byte_offset = us_rva - self.RVA_US_BASE + us_start
        if self.data[length_byte_offset] & 0x80:
            # two byte length
            val_offset = 2
            val_size = self.bytes_to_int(self.data[length_byte_offset:length_byte_offset + val_offset], 'big') - 0x8000
        else:
            # one byte length
            val_offset = 1
            val_size = self.bytes_to_int(self.data[length_byte_offset:length_byte_offset + val_offset])
        val_offset += length_byte_offset
        # Subtract 1 to account for null terminator at the end of the string
        us_val = self.data[val_offset:val_offset + val_size - 1]
        return us_val

    def strings_rva_to_strings_val(self, strings_rva) -> bytes:
        # Fields map offset = RVA - 0x4000000 - 1
        # Ports RVA: 0x4000001
        # Fields map offset = 0x4000001 - 0x4000000 - 1 = 0
        # Ports value = fields_map[Fields map offset][1]
        val_index = strings_rva - self.RVA_STRINGS_BASE - 1
        try:
            strings_val = self.fields_map[val_index][1]
        except Exception as e:
            raise self.AsyncRATConfigParserException(f'Could not retrieve string from RVA {strings_rva}') from e
        return strings_val

    def get_table_start(self, table_name: str) -> int:
        table_start_offset = self.storage_stream_offset + 24 + (4 * len([table for table in self.table_map if self.table_map[table]['num_rows'] > 0]))
        table_offset = table_start_offset
        for table in self.table_map:
            if table == table_name:
                break
            elif 'row_size' not in self.table_map[table]:
                    raise self.AsyncRATConfigParserException('Invalid table start offset found')
            table_offset += self.table_map[table]['row_size'] * self.table_map[table]['num_rows']
        return table_offset
    
    def get_mask_valid(self) -> int:
        logger.debug('Extracting m_maskvalid value ...')
        mask_valid_offset = self.storage_stream_offset + 8
        mask_valid = self.bytes_to_int(self.data[mask_valid_offset:mask_valid_offset+8])
        logger.debug(f'Extracted m_maskvalid value {hex(mask_valid)}')
        return mask_valid

    def get_stream_start(self, stream_id) -> int:
        metadata_header_offset = self.get_metadata_header_offset()
        hit = self.data.find(stream_id)
        if hit == -1:
            raise self.AsyncRATConfigParserException(f'Failed to find stream start for {stream_id}')
        stream_offset = self.bytes_to_int(self.data[hit-8:hit-4])
        return metadata_header_offset + stream_offset

    def get_metadata_header_offset(self) -> int:
        hit = self.data.find(self.PATTERN_CLR_METADATA_START)
        if hit == -1:
            raise self.AsyncRATConfigParserException('Failed to find CLR metadata header offset')
        return hit

    def bytes_to_int(self, bytes: bytes, order='little') -> int:
        try:
            result = int.from_bytes(bytes, byteorder=order)
        except Exception as e:
            raise self.AsyncRATConfigParserException(f'Failed to convert bytes to int for {bytes}') from e
        return result

    def decode_bytes(self, byte_str: bytes) -> str:
        result = None
        try:
            if b'\x00' in byte_str:
                # utf-16le
                result = byte_str.decode('utf-16le')
            else:
                # utf-8 or ascii
                result = byte_str.decode('utf-8')
        except Exception as e:
            raise self.AsyncRATConfigParserException(f'Failed to decode bytes to Unicode: {byte_str}') from e
        return result

    def get_string_from_offset(self, offset: int, delimiter=b'\0') -> bytes:
        try:
            result = self.data[offset:].partition(delimiter)[0]
        except Exception as e:
            raise self.AsyncRATConfigParserException(f'Failed to get string from offset 0x{format(offset, "04x")} with delimiter 0x{format(delimiter, "02x")}') from e
        return result

    def report(self, decode_cert=False) -> str:
        logger.debug(f'Generating report{" with certificate parsing" if(decode_cert)  else ""}')
        if self.TRANSLATED_SERVERSIG_CONFIG_KEY in self.config.keys():
            try:
                self.config[self.TRANSLATED_SERVERSIG_CONFIG_KEY] = hex(self.bytes_to_int(b64decode(self.config[self.TRANSLATED_SERVERSIG_CONFIG_KEY])))
            except Exception:
                pass
        if decode_cert and self.TRANSLATED_CERT_CONFIG_KEY in self.config.keys():
            self.config[self.TRANSLATED_CERT_CONFIG_KEY] = self.get_parsed_cert()
        result_dic = {'filepath': self.filepath,
                      'AES key': self.aes_decryptor.get_key().hex(),
                      'AES salt': self.aes_salt.hex(),
                      'config': self.config
                      }
        logger.debug('Report created successfuly')
        return dumps(result_dic)

    def get_parsed_cert(self, parse_cert=True) -> dict:
        cert_str = self.config[self.TRANSLATED_CERT_CONFIG_KEY]
        cert_dic = {}

        if parse_cert and self.TRANSLATED_CERT_CONFIG_KEY in self.config.keys():
            cert_parser = ASyncRATCertParser(cert_str)
            cert_dic = cert_parser.parse()
        return cert_dic

    def get_hex_cert_form(self, i: int) -> str:
        hs = f'{i:x}'
        h = [hs[x]+hs[x+1] for x in range(0, len(hs) ,2)]
        return ':'.join(h)
    
    def decrypt_config(self) -> Dict[str, str]:
        # For each config key:
        #   If it is base64 encoded:
        #       decode base64
        #       extract IV from after HMAC [32:48]
        #       extract ciphertext [48:]
        #       decrypt
        # Return config
        logger.debug('Decrypting config ...')
        config = {}
        for k, v in self.translated_config.items():
            key = self.decode_bytes(k)
            value = self.decode_bytes(v)
            if len(value) > 0 and self.is_base64(value):
                decoded = b64decode(value)
                if len(decoded) > 48:
                    iv = decoded[32:48]
                    ciphertext = decoded[48:]
                    decrypted_uni = self.aes_decryptor.decrypt(iv, ciphertext)
                    decrypted = decrypted_uni.decode()
                else:
                    decrypted = decoded.decode().strip()
            else:
                decrypted = value
            config[key] = decrypted
        logger.debug('Config decrypted')
        return config

    def is_base64(self, subject: str) -> bool:
        try:
            decoded = b64decode(subject)
            encoded = b64encode(decoded).decode()
            is_equal = encoded == subject
            return is_equal
        except Exception:
            return False
# AES helpers
    def get_aes_metadata_flag(self) -> Match:
        # looking for rfc2898DeriveBytes IL opcodes until salt AES256:Salt is initialized in the constructor

        # c# code:
        # public Aes256(string masterKey)
        # {
        #     if (string.IsNullOrEmpty(masterKey))
        #     {
        #         throw new ArgumentException("masterKey can not be null or empty.");
        #     }
        #     using Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(masterKey, Salt, 50000);
        #     _key = rfc2898DeriveBytes.GetBytes(32);
        #     _authKey = rfc2898DeriveBytes.GetBytes(64);
        # }

        logger.debug('Extracting AES metadata ...')
        md_flag_offset = search(self.PATTERN_AES_METADATA, self.data, DOTALL)
        if md_flag_offset is None:
            raise self.AsyncRATConfigParserException('Failed to locate AES metadata')
        logger.debug(f' AES metadata flag found at offset {hex(md_flag_offset.start())}')
        return md_flag_offset

    def get_aes_key_and_block_size(self) -> Tuple[int,int]:
        aes_key_and_block_size = search(self.PATTERN_AES_KEY_AND_BLOCK_SIZE, self.data, DOTALL)
        if aes_key_and_block_size is None:
            raise self.AsyncRATConfigParserException('Failed to locate AES key and/or block size')
        
        key_size_bytes = self.bytes_to_int(aes_key_and_block_size.groups()[0]) // 8
        block_size = self.bytes_to_int(aes_key_and_block_size.groups()[1])
        logger.debug(f' Found AES key size: {key_size_bytes} bytes')
        logger.debug(f' Found AES block size: {block_size} bits')
        return key_size_bytes, block_size
    
    def get_aes_iterations(self, offset: int) -> int:
        aes_iterations = self.bytes_to_int(self.data[offset: offset+4])
        logger.debug(f' Found number of AES iterations: {aes_iterations}')
        return aes_iterations

    def get_aes_salt(self, aes_salt_rva) -> bytes:
        # Find salt initialization pattern match
        # Determine if ldtoken or ldstr is used
        # If ldtoken: (0xd0,addr32)
        #   Get Field address for salt byte array identifier
        #   Get the offset of the byte array contents from fieldRVA table
        #   Read the bytes content and return as salt
        # Else if ldstr: (0x72,addr32)
        #   Find the string at the RVA given and encode it to bytes and return as salt from #US
        aes_salt_init = self.data.find(self.PATTERN_AES_SALT_INIT % aes_salt_rva)
        if aes_salt_init == -1:
            raise self.AsyncRATConfigParserException(f'Failed to find AES salt initialization for salt RVA {hex(aes_salt_rva)}')
        logger.debug(f' Found AES salt flag offset: {hex(aes_salt_init)}')
        salt_op_offset = aes_salt_init - 10
        salt_op = bytes([self.data[salt_op_offset]]) # convert to bytes for conparison
        salt_strings_rva = self.bytes_to_int(self.data[salt_op_offset+1:salt_op_offset + 5]) #skip salt_op
        if salt_op == self.OPCODE_LDTOKEN:
            salt_size = self.data[salt_op_offset - 7]
            salt = self.get_aes_salt_ldtoken_method(salt_strings_rva, salt_size)
            logger.debug(f' Obtained salt from token array using RVA {hex(salt_strings_rva)} and size {salt_size}')
        elif salt_op == self.OPCODE_LDSTR:
            salt = self.get_aes_salt_ldstr_method(salt_strings_rva)
            logger.debug(f' Obtained salt from #US string using RVA {hex(salt_strings_rva)}')
        else:
            raise self.AsyncRATConfigParserException(f'Unknow salt opcode {salt_op.hex()} found for salt RVA {hex(aes_salt_rva)}')
        
        logger.debug(f' Found AES salt: {salt.hex()}')
        return salt

    def get_aes_salt_ldstr_method(self, salt_strings_rva) -> bytes:
        salt_encoded = self.us_rva_to_us_val(salt_strings_rva)
        salt = self.decode_bytes(salt_encoded).encode()
        return salt

    def get_aes_salt_ldtoken_method(self, salt_strings_rva, salt_size) -> bytes:
        # salt identifier field id = salt strings rva - #Strings RVA base
        # 0x0400002d - 0x04000000 = 0x2d
        salt_field_id = salt_strings_rva - self.RVA_STRINGS_BASE
        # Go to FieldRVA table and find entry for salt_field_id
        # Take RVA for byte array contents from FieldRVA table
        # Retrieve salt value from that file offset
        salt_field_rva = self.field_id_to_field_rva(salt_field_id)
        salt_offset = self.field_rva_to_offset(salt_field_rva)
        salt_value = self.data[salt_offset:salt_offset + salt_size]
        return salt_value

    def field_id_to_field_rva(self, id) -> int:
        field_rva_table_start = self.get_table_start(self.TABLE_FIELD_RVA_ID)
        field_rva = None
        matched = False
        
        offset = field_rva_table_start
        for x in range(self.table_map[self.TABLE_FIELD_RVA_ID]['num_rows']):
            try:
                field_id = self.bytes_to_int(self.data[offset + 4: offset + 6])
                field_rva = self.bytes_to_int(self.data[offset: offset + 4])
                if field_id == id:
                    matched = True
                    break
                offset += self.table_map[self.TABLE_FIELD_RVA_ID]['row_size']
            except Exception as e:
                raise self.AsyncRATConfigParserException(f'Error parsing FieldRVA corresponding to ID {id}') from e
            
        if not matched:
            raise self.AsyncRATConfigParserException(f'Failed to find FieldRVA corresponding to ID {id}')
        return field_rva

    def field_rva_to_offset(self, field_rva: int) -> int:
        # Field RVA: 0x2050
        # .text secition RVA: 0x2000
        # .text section offset: 0x0200
        # Byte array offset = Field RVA - .text section RVA + .text section offset
        # 0x2050 - 0x2000 + 0x0200 = 0x0250
        text_section_metadata_offset = self.data.find(self.SECTION_TEXT_ID)
        if text_section_metadata_offset == -1:
            raise self.AsyncRATConfigParserException('Failed to find .text section')
        text_section_rva = self.bytes_to_int(self.data[text_section_metadata_offset + 12: text_section_metadata_offset + 16])
        text_section_offset = self.bytes_to_int(self.data[text_section_metadata_offset + 20: text_section_metadata_offset + 24])
        field_offset = field_rva - text_section_rva + text_section_offset
        return field_offset
        
    def get_aes_passphrase(self) -> bytes:
        # Use pattern to find key initialization
        # Use it to find the address of the key in the fields table
        # Translate the offset in the fields table to its value in translated config
        # Key RVA: 0x0400007
        # Key Fields map = 0x04000007 - 0x04000000 - 1 = 6
        # Key Fields name = fields_map[6]
        # Key value = translated_config[fields_map[6]]

        # Derive the key using PBKDF2
        logger.debug(' Extracting encoded AES key value ...')
        hit = search(self.PATTERN_AES_KEY, self.data, DOTALL)
        if hit is None:
            raise self.AsyncRATConfigParserException('Failed to find AES key pattern')
        
        key_field_rva = self.bytes_to_int(hit.groups()[0])
        key_field_name = self.strings_rva_to_strings_val(key_field_rva)
        key_val = self.translated_config[key_field_name]
        logger.debug(f' Found AES encoded key value {key_val}')
        try:
            passphrase = b64decode(key_val)
        except Exception as e:
            raise self.AsyncRATConfigParserException(f'Error decoding key value {key_val}')
        logger.debug(f' Found AES passphrase: {passphrase}')
        return passphrase

    def parse_aes_params(self) -> Tuple[int, int, int, bytes, bytes]:
        aes_metadata_flag_hit = self.get_aes_metadata_flag()
        #aes_md_flag_offset = aes_metadata_flag_hit.start()
        aes_key_size_bytes, aes_block_size = self.get_aes_key_and_block_size()
        aes_iterations = self.get_aes_iterations(aes_metadata_flag_hit.end() + 1)
        aes_salt_rva = aes_metadata_flag_hit.groups()[0]
        aes_salt = self.get_aes_salt(aes_salt_rva)
        aes_passphrase = self.get_aes_passphrase()
        return aes_key_size_bytes, aes_block_size, aes_iterations, aes_salt, aes_passphrase
