#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @FileName     :   func.py
# @Function     :   使用转换函数
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


def hex_to_int(hex_str: str) -> int:
    return int(hex_str, 16)


def hex_to_bytes(*args: str) -> bytes:
    return bytes.fromhex(''.join(args))
