import random
from Crypto.Cipher import AES
from attack_cbc import decrypt, encrypt

EXAMPLE_TEXT = """Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

Curabitur pretium tincidunt lacus. Nulla gravida orci a odio. Nullam varius, turpis et commodo pharetra, est eros bibendum elit, nec luctus magna felis sollicitudin mauris. Integer in mauris eu nibh euismod gravida. Duis ac tellus et risus vulputate vehicula. Donec lobortis risus a elit. Etiam tempor. Ut ullamcorper, ligula eu tempor congue, eros est euismod turpis, id tincidunt sapien risus a quam. Maecenas fermentum consequat mi. Donec fermentum. Pellentesque malesuada nulla a mi. Duis sapien sem, aliquet nec, commodo eget, consequat quis, neque. Aliquam faucibus, elit ut dictum aliquet, felis nisl adipiscing sapien, sed malesuada diam lacus eget erat. Cras mollis scelerisque nunc. Nullam arcu. Aliquam consequat. Curabitur augue lorem, dapibus quis, laoreet et, pretium ac, nisi. Aenean magna nisl, mollis quis, molestie eu, feugiat in, orci. In hac habitasse platea dictumst.""".encode('utf-8')


class InvalidPadding(Exception):
    pass


def key_gen():
    return bytes([random.getrandbits(8) for _ in range(16)])


def pad_pkcs7(bytestring):
    length = 16 - (len(bytestring) % 16)
    return bytestring + bytearray([length] * length)


def unpad_pkcs7(bytestring):
    if not bytestring[-1:]*bytestring[-1] == bytestring[-bytestring[-1]:]:
        raise InvalidPadding()
    return bytestring[:-bytestring[-1]]


def raw_encrypt(plaintext, key, init_vec):
    cipher = AES.new(key, AES.MODE_CBC, init_vec)
    padded_text = pad_pkcs7(plaintext)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext


def oracle(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    padded_text = cipher.decrypt(ciphertext)
    try:
        unpad_pkcs7(padded_text)
    except InvalidPadding:
        return False
    else:
        return True


key = key_gen()
IV = key_gen()
ciphertext = raw_encrypt(EXAMPLE_TEXT, key, IV)


def test_simple_oracle_decrypt():
    assert unpad_pkcs7(decrypt(ciphertext, IV, oracle)) == EXAMPLE_TEXT
