#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @FileName     :   func.py
# @Function     :   使用转换函数
from random import choice
from typing import List


def xor(a, b) -> list:
    return list(map(lambda x, y: x ^ y, a, b))


def rotl(x, n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


def get_uint32_be(key_data):
    return ((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))


def put_uint32_be(n):
    return [((n >> 24) & 0xff), ((n >> 16) & 0xff), ((n >> 8) & 0xff), (n & 0xff)]


def padding(data, block=16):
    return data + [(16 - len(data) % block) for _ in range(16 - len(data) % block)]


def unpadding(data):
    return data[:-data[-1]]


def list_to_bytes(data: List[int]) -> bytes:
    return b''.join([bytes((i,)) for i in data])


def bytes_to_list(data: bytes) -> List[int]:
    return [i for i in data]


def random_hex(n: int) -> str:
    return ''.join([choice('0123456789abcdef') for _ in range(n)])


def int_to_hex(num: int) -> str:
    return hex(num)[2:] if len(hex(num)) % 2 == 0 else '0' + hex(num)[2:]


def hex_to_int(hex_str: str) -> int:
    return int(hex_str, 16)


def hex_to_bytes(*args: str) -> bytes:
    return bytes.fromhex(''.join(args))


def get_mask(para_len):
    return int('8' + '0' * (para_len - 1), 16)


def h256(*args) -> bytes:
    """拼接所有16进制字符串 并转为 二进制"""
    return bytes.fromhex(''.join(args))
