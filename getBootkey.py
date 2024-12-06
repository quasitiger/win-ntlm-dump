from utilities import *
from regipy.registry import RegistryHive
import struct
from Crypto.Cipher import AES
#from Registry import Registry python-registry로는 classname을 읽을 수 없음

def decrypt_aes_syskey(_bootKey, _encSysKey, _sysKeyIV):
    chipher = AES.new(bytes.fromhex(_bootKey), AES.MODE_CBC, _sysKeyIV)
    plaintext = chipher.decrypt(_encSysKey[:16])
    return plaintext




def decrypt_database(key, iv, encDB):
    decDB = b""
    i = 0
    while i < len(encDB):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encDB[i:i+4096])
        decDB += decrypted_data
        i += 4096
    #b64_db = base64.b64encode(decDB).decode('utf-8')
    return decDB


def unmarshal_domain_account_f1(_value:bytes):

    if len(_value) < 104:
        print('not enough length F')
 
    #revision = int.from_bytes(_value[0:2], byteorder='little', signed=False)
    revision = struct.unpack('<H', _value[0:2])[0]
    creation_time = struct.unpack('<Q', _value[8:16])[0]
    domain_midified_account = struct.unpack('<Q', _value[16:24])[0]
    max_password_age = struct.unpack('<Q', _value[24:32])[0]
    min_password_age = struct.unpack('<Q', _value[32:40])[0]
    force_logoff = struct.unpack('<Q', _value[40:48])[0]
    lockout_duration = struct.unpack('<Q', _value[48:56])[0]
    lockout_observation_window = struct.unpack('<Q', _value[56:64])[0]
    modified_count_at_last_promotion = struct.unpack('<Q', _value[64:72])[0]
    next_rid = struct.unpack('<I', _value[72:76])[0]
    password_properties = struct.unpack('<I', _value[76:80])[0]
    min_password_length = struct.unpack('<H', _value[80:82])[0]
    password_history_length = struct.unpack('<H', _value[82:84])[0]
    lockout_threshold = struct.unpack('<H', _value[84:86])[0]
    server_state = struct.unpack('<I', _value[88:92])[0]
    server_role = struct.unpack('<I', _value[92:96])[0]
    uas_compatibility_required = struct.unpack('<I', _value[96:100])[0]

    if len(_value) > 104:
        data = struct.unpack(f'<{len(_value)-100}s', _value[100:])[0]



def unmarshal_domain_account_f2(_value:bytes) -> int:

    if len(_value) < 104:
        print('not enough length F')
        return -1
 
    #revision = int.from_bytes(_value[0:2], byteorder='little', signed=False)
    SAM_ACCOOUNT_F.revision = struct.unpack('<H', _value[0:2])[0]
    SAM_ACCOOUNT_F.creation_time = struct.unpack('<Q', _value[8:16])[0]
    SAM_ACCOOUNT_F.domain_midified_account = struct.unpack('<Q', _value[16:24])[0]
    SAM_ACCOOUNT_F.max_password_age = struct.unpack('<Q', _value[24:32])[0]
    SAM_ACCOOUNT_F.min_password_age = struct.unpack('<Q', _value[32:40])[0]
    SAM_ACCOOUNT_F.force_logoff = struct.unpack('<Q', _value[40:48])[0]
    SAM_ACCOOUNT_F.lockout_duration = struct.unpack('<Q', _value[48:56])[0]
    SAM_ACCOOUNT_F.lockout_observation_window = struct.unpack('<Q', _value[56:64])[0]
    SAM_ACCOOUNT_F.modified_count_at_last_promotion = struct.unpack('<Q', _value[64:72])[0]
    SAM_ACCOOUNT_F.next_rid = struct.unpack('<I', _value[72:76])[0]
    SAM_ACCOOUNT_F.password_properties = struct.unpack('<I', _value[76:80])[0]
    SAM_ACCOOUNT_F.min_password_length = struct.unpack('<H', _value[80:82])[0]
    SAM_ACCOOUNT_F.password_history_length = struct.unpack('<H', _value[82:84])[0]
    SAM_ACCOOUNT_F.lockout_threshold = struct.unpack('<H', _value[84:86])[0]
    SAM_ACCOOUNT_F.server_state = struct.unpack('<I', _value[88:92])[0]
    SAM_ACCOOUNT_F.server_role = struct.unpack('<I', _value[92:96])[0]
    SAM_ACCOOUNT_F.uas_compatibility_required = struct.unpack('<I', _value[96:100])[0]

    if len(_value) > 104:
        SAM_ACCOOUNT_F.data = struct.unpack(f'<{len(_value)-104}s', _value[104:])[0]

    return 0

def get_bootkey(_system_registry_path:str) -> int:
    
    # open registry hive
    try:
        hive = RegistryHive(_system_registry_path)
        lsa = hive.get_key(PATH_SYSTEM_LSA)
        #lsa = hive.get_key('controlset001').get_subkey('control').get_subkey('lsa')
    except Exception as e:
        print(e)
        exit

    # get JD
    try:
        JD = lsa.get_subkey('JD')
        classname_JD = JD.get_class_name()
        SYSTEM_BOOTKEY.classname_JD = classname_JD
        # print(f'classname JD is {classname_JD}')
    except Exception as e:
        print(e)
        exit

    # get Skew1
    try:
        Skew1 = lsa.get_subkey('Skew1')
        classname_Skew1 = Skew1.get_class_name()
        SYSTEM_BOOTKEY.classname_Skew1 = classname_Skew1
        # print(f'classname Skew1 is {classname_Skew1}')
    except Exception as e:
        print(e)
        exit
    # get GBG
    try:
        GBG = lsa.get_subkey('GBG')
        classname_GBG = GBG.get_class_name()
        SYSTEM_BOOTKEY.classname_GBG = classname_GBG
        # print(f'classname GBG is {classname_GBG}')
    except Exception as e:
        print(e)
        exit

    # get Data
    try:
        Data = lsa.get_subkey('Data')
        classname_Data = Data.get_class_name()
        SYSTEM_BOOTKEY.classname_Data = classname_Data
        # print(f'classname Data is {classname_Data}')
    except Exception as e:
        print(e)
        exit

    screambled_key = classname_JD + classname_Skew1 + classname_GBG + classname_Data

    i = 0
    bootkey = ''
    while i < len(screambled_key)/2:
        byte_key = screambled_key[BOOTKEY_PBOX[i]*2:BOOTKEY_PBOX[i]*2+2]
        bootkey = bootkey + byte_key
        i = i+1
    
    SYSTEM_BOOTKEY.bootkey = bootkey

    return 0


def get_syskey(_system_registry_path='./system', _sam_registry_path='./sam') -> int:

    if get_bootkey(_system_registry_path):
        return
    
    # open registry hive
    try:
        hive = RegistryHive(_sam_registry_path)
        #lsa = hive.get_key(SYSTEM_PATH_LSA)
        account = hive.get_key(PATH_SAM_ACCOUNT)
    except Exception as e:
        print(e)
        exit

    try:
        value_F = account.get_value('F')
    except Exception as e:
        print(e)
        exit
    
    if unmarshal_domain_account_f2(value_F):
        return -1
    
    if SAM_ACCOOUNT_F.revision == 3:
        
        SAM_KEY_DATA_AES.revision = struct.unpack('<I',SAM_ACCOOUNT_F.data[0:4])[0]
        SAM_KEY_DATA_AES.length = struct.unpack('<I',SAM_ACCOOUNT_F.data[4:8])[0]
        SAM_KEY_DATA_AES.checksum = struct.unpack('<I',SAM_ACCOOUNT_F.data[8:12])[0]
        SAM_KEY_DATA_AES.datalen = struct.unpack('<I',SAM_ACCOOUNT_F.data[12:16])[0]
        SAM_KEY_DATA_AES.salt = struct.unpack('<16s',SAM_ACCOOUNT_F.data[16:32])[0]
        SAM_KEY_DATA_AES.data = struct.unpack('<32s',SAM_ACCOOUNT_F.data[32:64])[0]

        SysKey = decrypt_aes_syskey(SYSTEM_BOOTKEY.bootkey, SAM_KEY_DATA_AES.data, SAM_KEY_DATA_AES.salt)

        return SysKey


    elif SAM_ACCOOUNT_F.revision ==2:
        pass
