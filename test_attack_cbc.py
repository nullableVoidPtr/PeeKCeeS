import random
from Crypto.Cipher import AES
import attack_cbc

EXAMPLE_TEXT = """Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

Curabitur pretium tincidunt lacus. Nulla gravida orci a odio. Nullam varius, turpis et commodo pharetra, est eros bibendum elit, nec luctus magna felis sollicitudin mauris. Integer in mauris eu nibh euismod gravida. Duis ac tellus et risus vulputate vehicula. Donec lobortis risus a elit. Etiam tempor. Ut ullamcorper, ligula eu tempor congue, eros est euismod turpis, id tincidunt sapien risus a quam. Maecenas fermentum consequat mi. Donec fermentum. Pellentesque malesuada nulla a mi. Duis sapien sem, aliquet nec, commodo eget, consequat quis, neque. Aliquam faucibus, elit ut dictum aliquet, felis nisl adipiscing sapien, sed malesuada diam lacus eget erat. Cras mollis scelerisque nunc. Nullam arcu. Aliquam consequat. Curabitur augue lorem, dapibus quis, laoreet et, pretium ac, nisi. Aenean magna nisl, mollis quis, molestie eu, feugiat in, orci. In hac habitasse platea dictumst.""".encode('utf-8')


def key_gen():
    return bytes([random.getrandbits(8) for _ in range(16)])


KEY = key_gen()
IV = key_gen()


class InvalidPadding(Exception):
    pass


def pad_pkcs7(bytestring):
    length = 16 - (len(bytestring) % 16)
    return bytestring + bytearray([length] * length)


def unpad_pkcs7(bytestring):
    if not bytestring[-1:]*bytestring[-1] == bytestring[-bytestring[-1]:]:
        raise InvalidPadding()
    return bytestring[:-bytestring[-1]]


def encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad_pkcs7(plaintext)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext


def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = cipher.decrypt(ciphertext)
    return unpad_pkcs7(padded_text)


def oracle(ciphertext):
    try:
        decrypt(ciphertext, KEY, IV)
    except InvalidPadding:
        return False
    else:
        return True


def test_simple_oracle_decrypt():
    ciphertext = encrypt(EXAMPLE_TEXT, KEY, IV)
    plaintext_attempt = unpad_pkcs7(attack_cbc.decrypt(ciphertext, None, oracle))
    assert plaintext_attempt == EXAMPLE_TEXT[16:]


def test_simple_oracle_decrypt_with_iv():
    ciphertext = encrypt(EXAMPLE_TEXT, KEY, IV)
    plaintext_attempt = unpad_pkcs7(attack_cbc.decrypt(ciphertext, IV, oracle))
    assert plaintext_attempt == EXAMPLE_TEXT


def test_simple_oracle_encrypt():
    ciphertext_attempt = attack_cbc.encrypt(pad_pkcs7(EXAMPLE_TEXT), oracle)
    assert decrypt(ciphertext_attempt, KEY, IV)[16:] == EXAMPLE_TEXT


def test_simple_oracle_encrypt_with_iv():
    ciphertext_attempt, iv_attempt = \
        attack_cbc.encrypt(pad_pkcs7(EXAMPLE_TEXT), oracle, True)
    assert decrypt(ciphertext_attempt, KEY, iv_attempt) == EXAMPLE_TEXT
