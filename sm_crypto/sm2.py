#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @FileName     :   sm2.py
# @Function     :   SM2算法实现
"""
签名者用户A的密钥对包括其私钥dA和公钥PA=[dA]G= (xA,yA)
签名者用户A具有长度为entlenA比特的可辨别标识IDA，
ENTLA是由整数entlenA转换而成的两个字节
ZA=h256(ENTLA || IDA || a || b || xG || yG|| xA || yA)。
待签名的消息为M，
数字签名(r,s)
"""
import base64
import hashlib
import random

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import BitString, OctetString, Integer, SequenceOf
from .utils import hex_to_bytes

from . import sm3, asn1
from .curve import sm2p256v1, CurveFp, CurvePoint

# 默认用户A id
UID = b'1234567812345678'
ENTLA = '0080'


class HashType:
    SM3 = 'SM3'
    SHA256 = 'SHA256'
    SHA3_256 = 'SHA3_256'


class EncryptMode:
    C1C2C3 = 0
    C1C3C2 = 1


def random_k(n=64) -> int:
    h = ''.join([random.choice('0123456789abcdef') for _ in range(n)])
    return int(h, 16)


class SM2PrivateKey:
    """私钥"""

    def __init__(self, d: int, curve: CurveFp = sm2p256v1):
        """
        :param value: 私钥值-secret, hex string
        """
        # 私钥本质上就是一个256位的随机整数, 16进制字符串, 私钥可以由d表示
        self.d = d
        # 公钥对象
        self.curve = curve

    def __repr__(self):
        return '<SM2PrivateKey "%s">' % self.d

    def public_key(self) -> "SM2PublicKey":
        """
        公钥
        :return: 公钥对象
        """
        point = self.curve.scalar_base_mult(self.d)
        return SM2PublicKey(x=point.x, y=point.y, curve=self.curve)

    def sign(self, data: bytes, k: int = None, uid: bytes = UID, hash_type: str = HashType.SM3) -> bytes:
        if k is None:
            k = random_k(n=self.curve.key_size // 4)

        digest = self.public_key().get_digest(data, uid, hash_type)
        r, s = self.sign_digest(digest, k)
        return SM2Signature(r, s).dump()

    def sign_digest(self, digest: str, k: int) -> (int, int):
        # r, s = self.sign_digest(digest, k)  # 16进制
        # 消息, 私钥数字D, 随机数K, 曲线阶N 转int
        # curve = self._public_key.curve
        e = int(digest, 16)
        n = self.curve.n
        # kg运算
        point = self.curve.scalar_base_mult(k)
        r = ((e + point.x) % n)
        assert r != 0 and r + k != n
        # 计算 （私钥+1) ^ （N - 2）% N
        d_1 = pow(self.d + 1, n - 2, n)
        # ((私钥+1) * (随机数 + r) - r )  % N
        s = (d_1 * (k + r) - r) % n
        assert s != 0
        return r, s

    def decrypt(self, data: bytes, mode=EncryptMode.C1C3C2):
        """
        解密函数
        :param data: 密文
        :param mode: mode: 0-C1C2C3, 1-C1C3C2 (default is 1)
        :return: None
        """
        # curve = self._public_key.curve
        # curve = self.curve

        data = data.hex()

        para_len = self.curve.key_size // 4  # 64
        len_2 = 2 * para_len  # 128
        len_3 = len_2 + 64  # 192

        # C1 为随机产生的公钥
        c1 = data[0:len_2]
        if mode == EncryptMode.C1C3C2:  # C1C3C2
            # C2 为密文，与明文长度等长
            c2 = data[len_3:]
        else:  # C1C2C3
            c2 = data[len_2:-para_len]

        xy = SM2PublicKey.from_hex(c1).scalar_mult(self.d).hex()

        cl = len(c2)
        t = sm3.sm3_kdf(xy.encode(), cl // 2)
        if int(t, 16) == 0:
            return None
        else:
            fmt = '%%0%dx' % cl
            m = fmt % (int(c2, 16) ^ int(t, 16))
            return bytes.fromhex(m)

    @classmethod
    def from_pem(cls, pem: bytes):
        """
        从PEM加载私钥
        :param pem_bytes: 私钥PEM二进制
        :return: SM2PrivateKey对象
        """
        body = b'\n'.join(pem.rstrip(b'\n').split(b'\n')[1:-1])  # 去掉前后两行
        der = base64.b64decode(body)
        return cls.from_der(der)

    @classmethod
    def from_der(cls, der: bytes) -> "SM2PrivateKey":
        private_key, _ = decoder.decode(der, asn1Spec=asn1.SM2PrivateKey())
        d = int(''.join('%.2x' % x for x in private_key['privateKey'].asNumbers()), 16)
        return cls(d)

    def to_der(self) -> bytes:
        pkcs1_key = OctetString(hexValue='%x' % self.d)

        pkcs8_key = asn1.SM2PrivateKey()
        pkcs8_key["version"] = 0
        pkcs8_key["privateKeyAlgorithm"] = asn1.sm2_algorithm
        pkcs8_key["privateKey"] = pkcs1_key
        der = encoder.encode(pkcs8_key)
        return der

    def to_pem(self) -> bytes:
        der = self.to_der()
        body = base64.b64encode(der)
        lines = [b'-----BEGIN PRIVATE KEY-----']
        lines.extend([body[i:i + 64] for i in range(0, len(body), 64)])
        lines.append(b'-----END PRIVATE KEY-----\n')
        return b'\n'.join(lines)


class SM2PublicKey(CurvePoint):
    """
    公钥 公钥是在椭圆曲线上的一个点，由一对坐标（x，y）组成
    公钥字符串可由 x || y 即 x 拼接 y代表
    """

    def __init__(self, x: int, y: int, curve=sm2p256v1):
        super().__init__(x, y, curve)

    def __repr__(self):
        return '<SM2PublicKey x="%s" y="%s">' % (self.x, self.y)

    @classmethod
    def from_hex(cls, value: str, curve=sm2p256v1) -> "SM2PublicKey":
        para_len = curve.key_size // 4  # 64
        # assert len(value) % para_len == 0
        x, y = int(value[:para_len], 16), int(value[para_len:], 16)
        return cls(x=x, y=y, curve=curve)

    @staticmethod
    def _get_entla(uid: bytes) -> str:  # 对勾 ✅
        """
        计算ENTLA, 16进制字符串
        :param uid: uid: 用户A bytes类型的id, 默认为 b'1234567812345678'
        :return: 返回16进制字符串，默认结果为 '0080'
        """
        entla = 8 * len(uid)  # 128
        # 128 >> 8 128(二进制)右移8位, 相当于128 除以 2的8次方, 即 128 // 2 ** 8
        # (整数).to_bytes(1, byteorder='big').hex() 将int转为16进制字符串, 相当于 str(hex(整数))[2:]
        entla1 = (entla >> 8 & 255).to_bytes(1, byteorder='big').hex()
        entla2 = (entla & 255).to_bytes(1, byteorder='big').hex()
        return ''.join([entla1, entla2])  # 拼接entla1 || entla2，相当于 entla1 + entla2

    def _get_za(self, uid: bytes = UID) -> str:  # ✅
        """
        使用公钥和用户ID生成ZA-用户身份标识
        ZA=h256(ENTLA || IDA || a || b || G || x || y)  其中G为 Gx || Gy
        :param x: 公钥x坐标, 16进制字符串
        :param y: 公钥y坐标, 16进制字符串
        :param uid: 用户id, bytes字符串, 默认为 b'1234567812345678'
        :return:
        """
        entla = ENTLA if uid == UID else self._get_entla(uid)  # '0080'
        ida = uid.hex()  # '31323334353637383132333435363738'
        # calc H256
        z = bytes.fromhex('%s%s%x%x%x%x%x%x' % (entla, ida, self.curve.a, self.curve.b,
                                                self.curve.gx, self.curve.gy, self.x, self.y))
        za = sm3.sm3_hash(z)
        return za

    def get_digest(self, data: bytes, uid: bytes = UID, hash_type: str = HashType.SM3) -> str:
        """
        通过SM3哈希算法计算消息摘要
        :param hash_algorithm:
        :param data: 消息数据, bytes类型
        :param uid: 用户id, bytes字符串, 默认为 b'1234567812345678'
        :return:
        """
        if hash_type == HashType.SM3:
            # 杂凑
            za = self._get_za(uid)
            data_with_za = bytes.fromhex(''.join([za, data.hex()]))  # 待签名消息
            return sm3.sm3_hash(data_with_za)
            # return binascii.a2b_hex(digest_hex.encode())
        if hash_type == HashType.SHA256:
            return hashlib.sha256(data).hexdigest()
        if hash_type == HashType.SHA3_256:
            return hashlib.sha3_256(data).hexdigest()
        raise NotImplementedError('hash_type仅支持SM3、SHA256和SHA3_256')

    def verify(self, sig: bytes, data: bytes, uid: bytes = UID, hash_type: str = HashType.SM3):
        digest = self.get_digest(data, uid, hash_type)  # 消息摘要
        r, s = SM2Signature.load(sig).value()
        return self.verify_digest(digest, r, s)

    def verify_digest(self, digest: str, r: int, s: int) -> bool:
        # 消息转化为16进制字符串
        e = int(digest, 16)
        t = (r + s) % self.curve.n
        if t == 0:
            return False

        point1 = self.curve.scalar_base_mult(s)
        point2 = self.scalar_mult(t)
        point1 = point1.add(point2)

        return r == (e + point1.x) % self.curve.n

    def encrypt(self, data: bytes, k: int = None, mode=EncryptMode.C1C3C2):
        """
        公钥加密函数
        :param data: 待加密消息
        :param k: 16进制随机数
        :param mode:
        :return:
        """
        # 消息转化为16进制字符串
        data_hex = data.hex()

        # 生成随机数
        if k is None:
            k = random_k(n=self.curve.key_size // 4)

        # 基点坐标G
        g = self.curve.base_point()
        # 公钥坐标P
        c1 = g.scalar_mult(k).hex()
        xy = self.scalar_mult(k)
        x2, y2 = xy.x, xy.y

        # 消息长度
        data_length = len(data_hex)  # 128

        t = sm3.sm3_kdf(xy.hex().encode(), data_length // 2)
        if int(t, 16) == 0:
            return None
        fmt = '%%0%dx' % data_length
        # C2 为密文，与明文长度等长
        c2 = fmt % (int(data_hex, 16) ^ int(t, 16))
        # C3 为 SM3 算法对明文数计算得到消息摘要，长度固定为 256 位
        c3 = sm3.sm3_hash(bytes.fromhex('%x%s%x' % (x2, data_hex, y2)))

        if mode == EncryptMode.C1C3C2:
            return hex_to_bytes(c1, c3, c2)
        return hex_to_bytes(c1, c2, c3)

    @classmethod
    def from_pem(cls, pem: bytes) -> "SM2PublicKey":
        body = b'\n'.join(pem.rstrip(b'\n').split(b'\n')[1:-1])  # 去掉前后两行
        der = base64.b64decode(body)
        return cls.from_der(der)

    @classmethod
    def from_der(cls, der: bytes, curve=sm2p256v1) -> "SM2PublicKey":
        public_key, _ = decoder.decode(der, asn1Spec=asn1.SM2PublicKey())
        value = ''.join('%.2x' % x for x in public_key['publicKey'].asNumbers())
        # 去掉开头的04
        value = value[2:]
        return cls.from_hex(value, curve=curve)

    def to_der(self) -> bytes:
        pkcs8_key = asn1.SM2PublicKey()
        pkcs8_key["algorithm"] = asn1.sm2_algorithm
        value = '04%s' % self.hex()
        pkcs8_key["publicKey"] = BitString(hexValue=value)
        der = encoder.encode(pkcs8_key)
        return der

    def to_pem(self) -> bytes:
        der = self.to_der()
        body = base64.b64encode(der)
        lines = [b'-----BEGIN PUBLIC KEY-----']
        lines.extend([body[i:i + 64] for i in range(0, len(body), 64)])
        lines.append(b'-----END PUBLIC KEY-----\n')
        return b'\n'.join(lines)


class SM2Signature:
    """sm2签名对象"""

    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

    def __str__(self):
        return '%064x%064x' % (self.r, self.s)

    def __repr__(self):
        return '<SM2Signature r="%d" s="%d">' % (self.r, self.s)

    def value(self) -> (int, int):
        return (self.r, self.s)

    @classmethod
    def load(cls, data: bytes) -> "SM2Signature":
        """加载asn1序列化内容构造签名对象"""
        sig, _ = decoder.decode(data)
        r, s = [tag._value for tag in sig.components]
        return cls(r, s)

    def dump(self) -> bytes:
        """按asn1序列化成二进制"""
        seq = SequenceOf(componentType=Integer())
        seq.extend([self.r, self.s])
        return encoder.encode(seq)
