from typing import Callable, Optional


class InvalidLength(Exception):
    pass


def xor(a: bytearray, b: bytearray) -> bytearray:
    return bytearray([x ^ y for x, y in zip(a, b)])


def intermediate_from_block(
        block: bytearray,
        oracle: Callable[[bytearray], bool],
        block_size: int) -> bytearray:
    """Derives intermediate bytes with the padding oracle.

    Analyses the block using the oracle to get its intermediary,
    i.e. the decrypted block before it is XORed with the preceding
    ciphertext block. This function should not be called externally,
    please refer to either encrypt or decrypt.

    Args:
        block: A block of block_size length
        oracle: A user-specified callback function of the following
            specification:
            Args:
                data: The data to be decrypted.
            Returns:
                The result of the padding oracle; False if a padding error
                occured, True otherwise (i.e. on a successful decryption).
        block_size: The block size of the targetted encryption algorithm.
    """
    assert(len(block) == block_size)
    i1 = bytearray(block_size)

    # Set the first block to null,
    # such that the next decrypted block is initially untouched in CBC XORing.
    modified_c0 = bytearray(block_size)
    for i in range(block_size - 1, -1, -1):
        pad = block_size - i  # Get padding target from the current position.
        for r in range(0, 256):  # Iterate until it hits a valid padding.
            modified_c0[i] = r
            if oracle(modified_c0 + block):  # Send c1.c2 to the oracle.

                # Derive intermediate byte from the c1 and pad.
                i1[i] = modified_c0[i] ^ pad

                # Prepare the first ciphertext block for the next padding byte
                # i.e 0xXX 0x01 -> 0x02 0x02.
                for k in range(i, block_size):
                    modified_c0[k] ^= pad ^ (pad + 1)
                break
    return i1


def encrypt(
        plaintext: bytearray,
        oracle: Callable[[bytearray], bool],
        can_set_iv: bool = False,
        block_size: int = 16):
    """Encrypts plaintext using a padding oracle attack.

    Args:
        plaintext: A bytearray containing the target plaintext to
            be encrypted.
        oracle: A user-specified callback function of the following
            specification:
            Args:
                data: The data to be decrypted.
            Returns:
                The result of the padding oracle; False if a padding error
                occured, True otherwise (i.e. on a successful decryption).
        can_set_iv: A boolean specifying if the user can set the IV of a
            decryption request.
        block_size: The block size of the targeted block cipher.

    Returns:
        If can_set_iv is True it returns a tuple, where its first element is
        the ciphertext, and the second element is the calculated IV for the
        decryption to be effective. Otherwise, it returns the plaintext with
        a prepended "garbage" block for the decryption to be effective.
    """
    if len(plaintext) % block_size != 0:
        raise InvalidLength(
                f"Length {len(plaintext)} is not a multiple of {block_size}")
    blocks = [plaintext[i:i+block_size]
              for i in range(0, len(plaintext), block_size)]

    # If in the situation the attacker can set the decryption IV, save the
    # first plaintext block for later calculation, and leave out the first
    # block in the final ciphertext.
    if can_set_iv:
        first_plaintext_block, blocks = blocks[0], blocks[1:]

    # Set the last block of the ciphertext to garbage (null); the plaintext
    # can be manipulated with the perceding blocks.
    block = bytearray(block_size)
    ciphertext = bytearray(block)

    # Work backwards since we want C_n-1 = Dec(C_n) ^ P_n.
    for n, c2 in enumerate(reversed(blocks)):
        print(f"Encrypting block {n+1} of {len(blocks)}", end='\r')
        block = xor(intermediate_from_block(block, oracle, block_size), c2)
        ciphertext = block + ciphertext

    print()

    # Decrypt the "garbage" block with a null IV to calculate a different
    # IV such that Dec(C) ^ IV = P.
    if can_set_iv:
        decrypted_first_ciphertext_block = decrypt(ciphertext[:block_size],
                                                   bytearray(16),
                                                   oracle,
                                                   block_size)
        return (ciphertext, xor(decrypted_first_ciphertext_block,
                                first_plaintext_block))
    return ciphertext


def decrypt(
        ciphertext: bytearray,
        iv: Optional[bytearray],
        oracle: Callable[[bytearray], bool],
        block_size: int = 16):
    """Decrypts ciphertext using a padding oracle attack.

    Args:
        ciphertext: A bytearray containing the target ciphertext to
            be encrypted.
        iv: Either a known IV, or None.
        oracle: A user-specified callback function of the following
            specification:
            Args:
                data: The data to be decrypted.
            Returns:
                The result of the padding oracle; False if a padding error
                occured, True otherwise (i.e. on a successful decryption).
        block_size: The block size of the targeted block cipher.

    Returns:
        If an IV is supplied, returns the decrypted plaintext in its entirety.
        Otherwise, returns the decrypted plaintext without the first block.
    """
    if len(ciphertext) % block_size != 0:
        raise InvalidLength(f"Ciphertext length {len(ciphertext)} is "
                            f"not a multiple of {block_size}")

    blocks = [ciphertext[i:i+block_size] for i in range(0,
                                                        len(ciphertext),
                                                        block_size)]

    # If IV is unknown, then ignore the first ciphertext block in the
    # attack, instead using it as our "initial" IV in the following blocks
    if iv is None:
        c0, blocks = blocks[0], blocks[1:]
    else:
        if len(iv) != block_size:
            raise InvalidLength(f"IV length {len(iv)} is not equal to"
                                f"{block_size}")
        c0 = iv

    plaintext = bytearray()
    for n, c1 in enumerate(blocks):
        print(f"Decrypting block {n+1} of {len(blocks)}", end='\r')
        plaintext.extend(xor(intermediate_from_block(c1, oracle, block_size),
                             c0))
        c0 = c1

    print()
    return plaintext
