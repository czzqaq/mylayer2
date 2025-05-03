from enum import Enum
import rlp
from eth_hash.auto import keccak  # pip install eth-hash

class NodeType(Enum):
    LEAF = 1
    EXTENSION = 2
    BRANCH = 3


class LeafNode():
    def __init__(self, key, value):
        self._key = key
        self._value = value
        self._type = NodeType.LEAF
        self.prefix = 1


class ExtensionNode():
    def __init__(self, key, value):
        self._key = key
        self._value = value
        self._type = NodeType.EXTENSION
        self.prefix = 1


class BranchNode():
    def __init__(self):
        self._key = None
        self._value = None
        self._type = NodeType.BRANCH
        self.prefix = 0
        self._children = [None] * 16
        self._hash = None

# keccak(rlp.encode(b''))
# BLANK_NODE_HASH = b"V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n\x5bH\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!"
# print(BLANK_NODE_HASH.hex())

# BLANK_HASH = b"\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p"
# print(BLANK_HASH.hex())




def bytes_to_nibbles(b: bytes):
    nibbles = []
    for byte in b:
        nibbles.append(byte >> 4)      # 高 4 位
        nibbles.append(byte & 0x0F)    # 低 4 位
    return nibbles


def nibbles_to_bytes(nibbles):
    b = bytearray()
    for i in range(0, len(nibbles), 2):
        b.append((nibbles[i] << 4) | nibbles[i + 1])
    return bytes(b)

def encode_node()

class Trie():
    def __init__(self, db=None):
        if db is None:
            db = {}
        self.db = db

        self.root = None
        self._type = NodeType.BRANCH
        self._key = None
        self._value = None
        self._prefix = 0
        self._children = [None] * 16
        self._hash = None

    
    def set(self, key, value):
        nibble_key = bytes_to_nibbles(key)
