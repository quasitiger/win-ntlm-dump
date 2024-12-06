import getBootkey
import getNTLM

if __name__ == '__main__':

    syskey = getBootkey.get_syskey(_system_registry_path='./system', _sam_registry_path='./sam' )
    print(f'bootkey is {syskey.hex()}')
    ntlm = getNTLM.get_ntlm()

    ntlm_decrypt_result = getNTLM.decrypt_ntlm(ntlm, syskey)

    print(ntlm_decrypt_result)