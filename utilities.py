from dataclasses import dataclass

@dataclass
class SAM:
    rid: bool = False
    ntlm_hash: str = ''
    user_name: str = ''

@dataclass
class SYSTEM_BOOTKEY:
    classname_JD: str = ''
    classname_Skew1: str = ''
    classname_GBG: str = ''
    classname_Data: str = ''
    bootkey: str = ''

@dataclass
class SAM_ACCOOUNT_F:
    revision = 0
    creation_time = 0
    domain_midified_account = 0
    max_password_age = 0
    min_password_age = 0
    force_logoff = 0
    lockout_duration = 0
    lockout_observation_window = 0
    modified_count_at_last_promotion = 0
    next_rid = 0
    password_properties = 0
    min_password_length = 0
    password_history_length = 0
    lockout_threshold = 0
    server_state = 0
    server_role = 0
    uas_compatibility_required = 0
    data: bytes = b''

@dataclass
class SAM_KEY_DATA_AES:
    revision:int = 0
    length:int = 0
    checksum:int = 0
    datalen:int = 0
    salt:bytes = b''
    data:bytes = b''

@dataclass
class USER_DATA:
    rid:str = ''
    name:str = ''
    v:bytes = b''
    iv:str = ''
    data:str = ''
    aes:bool = False



BOOTKEY_PBOX = [
    0x8, 0x5, 0x4, 0x2,
    0xB, 0x9, 0xD, 0x3,
    0x0, 0x6, 0x1, 0xC,
    0xE, 0xA, 0xF, 0x7
]

PATH_SYSTEM_LSA = r'system\ControlSet001\Control\Lsa'
PATH_SAM_ACCOUNT = r'sam\sam\Domains\Account'
PATH_SAM_USERS = r'SAM\SAM\Domains\Account\Users'
PATH_SOFTWARE_CURRENTVERSION = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
PATH_SYSTEM_PRODUCTOPTION1 = r'SYSTEM\CurrentControlSet\Control\ProductOptions'
PATH_SYSTEM_PRODUCTOPTION2 = r'SYSTEM\ControlSet001\Control\ProductOptions'