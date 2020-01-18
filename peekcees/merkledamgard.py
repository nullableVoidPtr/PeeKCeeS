# SPDX-License-Identifier: MIT

"""Append arbitrary data validated with insecure message authentication
codes that use Merkle-Damgård hash functions using the length extension
attack.
"""

from typing import Callable, Generator, Tuple, Union
from struct import pack


def mac_forge(
        hash: bytearray,
        secret_len: Union[int, range],
        data: bytearray,
        suffix: bytearray,
        padder: Callable[[bytearray, int], bytearray],
        updater: Callable[[bytearray, bytearray], bytearray]) ->\
            Union[Generator[Tuple[bytearray, bytearray], None, None],
                  Tuple[bytearray, bytearray]]:
    """Forge a message authentication code.

    This function applies the length extension attack to any
    vulnerable Merkle-Damgård construction. The padding of the original
    message is calculated and is then treated as data in the forging
    of a new signature, as the intermediate state of the hash can be
    derived from the digest and hence used in updating with the suffix.
    This function should only be called directly if the user wishes to
    use a hash unimplemented in this module.

    Args:
        hash: The original signature, i.e. the digest of secret||data.
        secret_len: Either the known length of the prepended secret, or
            a range if the user wishes to bruteforce the length.
        data: The original data of the signature.
        suffix: The data the user wishes to append.
        padder: A padding function of the following specification:
            Args:
                data: The data to be padded according to the algorithm's
                specifications.

            Returns: The padded data.
        updater: An update function of the following specification:
            Args:
                hash: The original hash to derive the state from.
                data: The data to update the state with.

            Returns:
                The digest of the updated hash.

    Returns:
        If secret_len is an int, returns a tuple containing the modified data
        to send, and the forged signature.

    Yields:
        If secret_len is a range, yield a tuple containing the modified data to
        send, and the forged signature.
    """
    def crunch_forged_macs():
        for n in secret_len:
            yield (padder(data, secret_len) + suffix, updater(hash, suffix))
    if isinstance(secret_len, range):
        return crunch_forged_macs()
    return (padder(data, secret_len) + suffix, updater(hash, suffix))


def md5_pad(
        data: bytearray,
        secret_len: int) -> bytearray:

    length = len(data) + secret_len
    data += b'\x80'
    while length % 64 != 56:
        data += b'\x00'
    data += pack('<Q', length * 8)
    return data


def md5_update(
        hash: bytearray,
        data: bytearray) -> bytearray:

    pass
