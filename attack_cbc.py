from typing import Callable, Optional


def xor(a: bytearray, b: bytearray) -> bytearray:
    return bytearray([x ^ y for x, y in zip(a, b)])


def intermediate_from_block(
        block: bytearray,
        oracle: Callable[[bytearray], bool],
        block_size: int) -> bytearray:
    i2 = bytearray(block_size)
    modified_c1 = bytearray(block_size)
    for i in range(block_size - 1, -1, -1):
        pad = block_size - i
        for r in range(0, 256):
            modified_c1[i] = r
            if oracle(modified_c1 + block):
                i2[i] = modified_c1[i] ^ pad
                for k in range(i, block_size):
                    modified_c1[k] ^= pad ^ (pad + 1)
                break
    return i2


def encrypt(
        plaintext: bytearray,
        iv: Optional[bytearray],
        oracle: Callable[[bytearray], bool],
        block_size: int = 16):
    pass


def decrypt(
        ciphertext: bytearray,
        iv: Optional[bytearray],
        oracle: Callable[[bytearray], bool],
        block_size: int = 16):
    assert(len(ciphertext) % block_size == 0)
    blocks = [ciphertext[i:i+block_size]
              for i in range(0, len(ciphertext), block_size)]

    if iv is None:
        c0, blocks = blocks[0], blocks[1:]
    else:
        c0 = iv

    plaintext = bytearray()
    for n, c2 in enumerate(blocks):
        print(f"Decrypting block {n} of {len(blocks)}")
        plaintext.extend(xor(intermediate_from_block(c2, oracle, block_size),
                             c0))
        c0 = c2
    return plaintext
