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
        oracle: Callable[[bytearray], bool],
        can_set_iv: bool = False,
        block_size: int = 16):
    assert(len(plaintext) % block_size == 0)
    blocks = [plaintext[i:i+block_size]
              for i in range(0, len(plaintext), block_size)]
    if can_set_iv:
        first_plaintext_block, blocks = blocks[0], blocks[1:]
    block = bytearray(block_size)
    ciphertext = bytearray(block)

    for n, c2 in enumerate(reversed(blocks)):
        print(f"Encrypting block {n+1} of {len(blocks)}", end='\r')
        block = xor(intermediate_from_block(block, oracle, block_size), c2)
        ciphertext = block + ciphertext
    print()
    if can_set_iv:
        decrypted_first_ciphertext_block = decrypt(ciphertext[:block_size],
                                                   bytearray(16),
                                                   oracle,
                                                   block_size)
        return (ciphertext,
                xor(decrypted_first_ciphertext_block, first_plaintext_block))
    return ciphertext


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
        print(f"Decrypting block {n+1} of {len(blocks)}", end='\r')
        plaintext.extend(xor(intermediate_from_block(c2, oracle, block_size),
                             c0))
        c0 = c2
    print()
    return plaintext
