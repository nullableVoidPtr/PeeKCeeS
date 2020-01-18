# PeekCeeS

PeekCeeS (pronounced like peeksies, named after the PKCS7 scheme vulnerable to the padding oracle attack) is a Python
module designed for attacking cryptography, specifically designed for use with CTFs.

## Table of Contents

- [PeekCeeS](#peekcees)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
    - [cbc.py](#cbcpy)
      - [`intermediate_from_block`](#intermediatefromblock)
      - [`encrypt`](#encrypt)
      - [`decrypt`](#decrypt)
    - [merkledamgard.py](#merkledamgardpy)
      - [`mac_forge`](#macforge)
      - [`md5_pad`](#md5pad)
      - [`md5_update`](#md5update)

## Overview

### [cbc.py](peekcees/cbc.py)

#### `intermediate_from_block`

```py
def intermediate_from_block(
        block: bytearray,
        oracle: Callable[[bytearray], bool],
        block_size: int) -> bytearray
```

Derives intermediate bytes with the padding oracle.

Attacks the block using the oracle to get its intermediary, i.e. the decrypted block before it is XORed with the
preceding ciphertext block. This function should not be called externally, please refer to either encrypt or decrypt.

- `block`: A block of block_size length
- `oracle`: A user-defined callback function with the data to be decrypted as an argument, and returning the result of
    the padding oracle; False if a padding error occurred, True otherwise (i.e. on a successful decryption).
- `block_size`: The block size of the targeted encryption algorithm.

Returns the decrypted block before XORing in CBC mode.

#### `encrypt`

```py
def encrypt(
        plaintext: bytearray,
        oracle: Callable[[bytearray], bool],
        can_set_iv: bool = False,
        block_size: int = 16) -> Union[bytearray, Tuple[bytearray, bytearray]]
```

Encrypts plaintext using a padding oracle attack.

- `plaintext`: A bytearray containing the target plaintext to be encrypted.
- `oracle`: A user-defined callback function with the data to be decrypted as an argument, and returning the result of
    the padding oracle; False if a padding error occurred, True otherwise (i.e. on a successful decryption).
- `can_set_iv`: A boolean specifying if the user can set the IV of a decryption request.
- `block_size`: The block size of the targeted encryption algorithm.

If `can_set_iv` is True it returns a tuple, where its first element is the ciphertext, and the second element is the
calculated IV for the decryption to be effective. Otherwise, it returns the plaintext with a prepended "garbage" block
for the decryption to be effective.

#### `decrypt`

```py
def decrypt(
        ciphertext: bytearray,
        iv: Optional[bytearray],
        oracle: Callable[[bytearray], bool],
        block_size: int = 16)
```

Decrypts ciphertext using a padding oracle attack.

- `ciphertext`: A bytearray containing the target ciphertext to be encrypted.
- `iv`: Either a known IV, or None.
- `oracle`: A user-defined callback function with the data to be decrypted as an argument, and returning the result of
    the padding oracle; False if a padding error occurred, True otherwise (i.e. on a successful decryption).
- `block_size`: The block size of the targeted encryption algorithm.

If an IV is supplied, returns the decrypted plaintext in its entirety. Otherwise, returns the decrypted plaintext
without the first block.


### [merkledamgard.py](peekcees/merkledamgard.py)

#### `mac_forge`

```py
def mac_forge(
        hash: bytearray,
        secret_len: Union[int, range],
        data: bytearray,
        suffix: bytearray,
        padder: Callable[[bytearray, int], bytearray],
        updater: Callable[[bytearray, bytearray], bytearray]) ->\
            Union[Generator[Tuple[bytearray, bytearray], None, None],
                  Tuple[bytearray, bytearray]]
```

Forge a message authentication code.

This function applies the length extension attack to any vulnerable Merkle-Damgård construction. The padding of the
original message is calculated and is then treated as data in the forging of a new signature, as the intermediate state
of the hash can be derived from the digest and hence used in updating with the suffix. This function should only be
called directly if the user wishes to use a hash unimplemented in this module.

- `hash`: The original signature, i.e. the digest of secret||data.
- `secret_len`: Either the known length of the prepended secret, or a range if the user wishes to bruteforce the length.
- `data`: The original data of the signature.
- `suffix`: The data the user wishes to append.
- [`padder`](#md5pad): A padding function with the data to be padded according to the algorithm's specifications as an argument,
    returning the padded data.
- [`updater`](#md5update): An update function with the original hash to derive the state from, and the data to update the state with
    as arguments, returning the digest of the updated hash.

If `secret_len` is an int, returns a tuple containing the modified data to send, and the forged signature. If
`secret_len` is a range, yield a tuple containing the modified data to send, and the forged signature.

#### `md5_pad`

```py
def md5_pad(
        data: bytearray,
        secret_len: int) -> bytearray
```

#### `md5_update`

```py
def md5_update(
        hash: bytearray,
        data: bytearray) -> bytearray
```
