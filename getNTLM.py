from utilities import *
from regipy.registry import RegistryHive
import struct
from Crypto.Cipher import AES, DES

def plus_odd_parity(input_bytes):
    """
    NTLM에서 DES 키를 생성하기 위한 홀수 패리티 처리 함수
    :param input_bytes: 7바이트 길이의 입력값 (56비트)
    :return: 8바이트 길이의 DES 키 (64비트)
    """
    if len(input_bytes) != 7:
        raise ValueError("Input must be 7 bytes long")

    # 7바이트를 8바이트로 확장
    output = [0] * 8
    output[0] = input_bytes[0] >> 1
    output[1] = ((input_bytes[0] & 0x01) << 6) | (input_bytes[1] >> 2)
    output[2] = ((input_bytes[1] & 0x03) << 5) | (input_bytes[2] >> 3)
    output[3] = ((input_bytes[2] & 0x07) << 4) | (input_bytes[3] >> 4)
    output[4] = ((input_bytes[3] & 0x0F) << 3) | (input_bytes[4] >> 5)
    output[5] = ((input_bytes[4] & 0x1F) << 2) | (input_bytes[5] >> 6)
    output[6] = ((input_bytes[5] & 0x3F) << 1) | (input_bytes[6] >> 7)
    output[7] = input_bytes[6] & 0x7F

    # 홀수 패리티를 추가
    for i in range(8):
        # 현재 바이트의 1 비트 수를 계산
        if bin(output[i]).count('1') % 2 == 0:  # 짝수 패리티일 경우
            output[i] = (output[i] << 1) | 0x1  # 마지막 비트를 1로 설정
        else:
            output[i] = (output[i] << 1) & 0xFE  # 마지막 비트를 0으로 설정

    return bytes(output)

def decryptNTLM(_b_encriptedNTLM, _b_rid):

    """
    암호화된 NTLM 해시를 복호화
    :param enc_hash: 암호화된 해시 (16바이트)
    :param rid_bytes: RID를 바탕으로 생성된 7바이트 값
    :return: 복호화된 NTLM 해시
    """
    rid = bytes.fromhex(_b_rid)


    if len(_b_encriptedNTLM) != 16:
        raise ValueError("Encrypted hash must be 16 bytes long")
    if len(rid) != 4:
        raise ValueError("RID bytes must be 4 bytes long")

    little_endian_rid = struct.pack("<I", int(_b_rid,16))
    desSrc1 = [0] * 7
    desSrc2 = [0] * 7
    shift1 = [0,1,2,3,0,1,2]
    shift2 = [3,0,1,2,3,0,1]

    for i in range(0,7):
        desSrc1[i] = little_endian_rid[shift1[i]]
        desSrc2[i] = little_endian_rid[shift2[i]]

    deskey1 = plus_odd_parity(desSrc1)
    deskey2 = plus_odd_parity(desSrc2)

    try:
        cipher1 = DES.new(deskey1, DES.MODE_ECB)
        cipher2 = DES.new(deskey2, DES.MODE_ECB)
    except ValueError as e:
        return None


    plaintext1 = cipher1.decrypt(_b_encriptedNTLM[:8])
    plaintext2 = cipher2.decrypt(_b_encriptedNTLM[8:])

    return plaintext1.hex()+plaintext2.hex()

def decrypt_ntlm(_user_cred, _bootkey):

    for cred in _user_cred:
        if cred.data:
            if cred.aes:

                # AES CBC 모드 복호화 다음 NT Cecrypt 수행 필요
                decrpyted_ntlm = decrypt_AES(_bootkey, cred.iv, cred.data, cred.rid)
                print(f'Username is {cred.name}, ntlm is {decrpyted_ntlm}')
        else:
            print(f'Username is {cred.name}, ntlm is None')

    pass

def decrypt_AES(_key, _iv, _double_enc_hash, _rid):
    decDB = b""

    iv = bytes.fromhex(_iv)
    ciphertext = bytes.fromhex(_double_enc_hash)

    # AES-CBC 복호화
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    #plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    enc_hash = cipher.decrypt(ciphertext)
    plain_ntlm = decryptNTLM(enc_hash, _rid)
    #print(f'NTLM is {plaintext.hex()}')

    return plain_ntlm


def get_os_version_build(_software_registry_path='./software', _system_registry_path='./system'):

    try:
        hive = RegistryHive(_software_registry_path)
        current_version = hive.get_key(PATH_SOFTWARE_CURRENTVERSION)
    except Exception as e:
        print(e)
        exit    

    try:
        current_build = current_version.get_value('CurrentBuild')
        print(f'current build is {current_build}')
    except Exception as e:
        print(e)
        exit

    try:
        current_version = current_version.get_value('CurrentVersion')
        print(f'current version is {current_version}')
    except Exception as e:
        print(e)
        exit

    ## 
    try:
        hive = RegistryHive(_system_registry_path)
        product_option = hive.get_key(PATH_SYSTEM_PRODUCTOPTION2)
    except Exception as e:
        print(e)
        exit   

    try:
        product_type = product_option.get_value('ProductType')
        print(f'product type is {product_type}')
    except Exception as e:
        print(e)
        exit        

    return current_build, current_version, product_type

def get_rids(_sam_registry_path='./sam'):

    hive = RegistryHive(_sam_registry_path)
    users = hive.get_key(PATH_SAM_USERS)
    rids = [ skey.name for skey in users.iter_subkeys()]
    
    return rids
    


def get_ntlm(_system_registry_path='./system', _sam_registry_path='./sam', _software_registry_path='./software'):

    # product_type ServerNT, WinNT
    current_build, current_version, product_type = get_os_version_build(_software_registry_path, _system_registry_path)
    rids = get_rids(_sam_registry_path)

    # open registry hive
    try:
        hive = RegistryHive(_sam_registry_path)
        users = hive.get_key(PATH_SAM_USERS)
    except Exception as e:
        print(e)
        exit

    # get RID

    result = []
    for rid in rids:
        
        # get V
        try:
            value_v = users.get_subkey(rid).get_value('V')
        except Exception as e:
            print(e)
            exit

        if not value_v :
            continue

        # cutting
        hex_v = value_v.hex()
        v2 = [ int(hex_v[l:l+2],16) for l in range(0,len(hex_v),2)]


        # get username
        # offset_addr_username = v2[0x0c] + 0xcc #1C0
        offset_addr_username = struct.unpack('<I', value_v[0x0c:0x0c+0x4])[0] + 0xcc

        # size_addr_username = v2[0x10] # 0E
        size_addr_username = struct.unpack('<I', value_v[0x10:0x10+0x4])[0]

        username_raw = v2[offset_addr_username:offset_addr_username+size_addr_username]
        username = [ chr(username_raw[i]) for i in range(0, len(username_raw), 2)]
        username = ''.join(username)

        # get NTLM
        # offset_NTLM = v2[0xa8] + 0xcc # 0x54 + 0xcc = 0x120
        # 읽어온 값에 오프셋 0xcc 추가
        # offset_NTLM = struct.unpack('<I', v2[0xa8:0xa8+0x4])[0] + 0xcc
        offset_NTLM_structure = struct.unpack('<I', value_v[0xa8:0xa8+0x4])[0] + 0xcc
        #size_NTLM = v2[0xac] # 0x38
        #size_NTLM = struct.unpack('<I', v2[0xac:0xac+0x4])[0]
        size_NTLM = struct.unpack('<I', value_v[0xac:0xac+0x4])[0]

        ntlm_raw = v2[offset_NTLM_structure:offset_NTLM_structure+size_NTLM]

        if int(current_build) < 14393 and size_NTLM == 0x14:
            pass
        
        else:
            # win 11, 26100 build, 24
            # after IsWin10After1607
            if int(current_build) >= 14393:

                if size_NTLM == 0x14:
                    offset_HASH = offset_NTLM_structure + 4
                    ntlm = v2[offset_HASH:offset_HASH+16]
                    str_ntlm = ''.join(f'{x:02X}' for x in ntlm)  
                    #result.append(USER_DATA(rid=int(rid,16),name=username, aes=False, data=str_ntlm))         
                    result.append(USER_DATA(rid=rid,name=username, aes=False, data=str_ntlm))         

                elif size_NTLM == 0x38:
                    offsetIV = offset_NTLM_structure + 8
                    offset_HASH = offset_NTLM_structure + 24

                    iv = v2[offsetIV:offsetIV+16]
                    ntlm = v2[offset_HASH:offset_HASH+16]

                    str_iv = ''.join(f'{x:02X}' for x in iv)
                    str_ntlm = ''.join(f'{x:02X}' for x in ntlm)  

                    # winuser 1104

                    # result.append(USER_DATA(rid=int(rid,16),name=username, aes=True,iv=str_iv, data=str_ntlm))         
                    result.append(USER_DATA(rid=rid,name=username, aes=True,iv=str_iv, data=str_ntlm))         


                elif size_NTLM == 0x18:
                    
                    result.append(USER_DATA(rid=int(rid,16), name=username, aes=True))               

                elif size_NTLM == 0x04:
                    pass

            else:

                if size_NTLM == 0x04:
                    pass


    return result