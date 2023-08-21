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
import binascii
import typing
from typing import Union

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import BitString, Integer, OctetString, SequenceOf

from . import ec, sm2_asn1, sm3
from .utils import h256, hex_to_bytes, hex_to_int, int_to_hex, random_hex

# 默认用户A id
DEFAULT_UID = b'1234567812345678'
PARA_LEN = 64


class SM2P256Curve(ec.CurveFp):
    name = 'sm2p256v1'
    key_size = 256  # 素数域256 位椭圆曲线

    gx = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'  # 基点 Gx, 16进制字符串
    gy = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'  # 基点 Gy, 16进制字符串

    # 如果椭圆曲线上一点P，存在最小的正整数n使得数乘nP=O∞ ,则将n称为P的阶若n不存在，则P是无限阶的
    n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'
    a = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'  # 曲线方程 y^2= x^3+ax+b 的系数a, 16进制字符串
    b = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'  # 曲线方程 y^2= x^3+ax+b 的系数a, 16进制字符串
    p = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF'  # 大于3的一个大素数

    def __repr__(self):
        return '<SM2P256Curve>'

    @property
    def para_len(self) -> int:
        return len(self.n)  # 64

    def scalar_mul(self, k: int, point: str) -> str:
        """
        kP点乘运算 向量乘
        :param k: 倍数k, 整数
        :param point: 曲线点, hex字符串
        :return: 另一个曲线点, hex字符串
        """
        point = '%s%s' % (point, '1')
        mask_str = '8'
        for i in range(self.para_len - 1):
            mask_str += '0'
        mask = int(mask_str, 16)
        temp = point
        flag = False
        for n in range(self.para_len * 4):
            if flag:
                temp = self.double(temp)
            if (k & mask) != 0:
                if flag:
                    temp = self.add(temp, point)
                else:
                    flag = True
                    temp = point
            k = k << 1
        return self._convert_jacb_to_nor(temp)

    def scalar_base_mul(self, k: int) -> str:
        """基点 向量乘"""
        point = ''.join([self.gx, self.gy])
        return self.scalar_mul(k, point)

    def double(self, point: str) -> Union[str, None]:  # TODO Remove this
        """
        倍点
        :param point:
        :return:
        """
        if len(point) < self.para_len * 2:
            return None

        x1, y1, z1 = self._get_point_x_y_z(point)

        p = int(self.p, 16)
        a = int(self.a, 16)

        a3 = a + 3 % p
        t6 = (z1 * z1) % p
        t2 = (y1 * y1) % p
        t3 = (x1 + t6) % p
        t4 = (x1 - t6) % p
        t1 = (t3 * t4) % p
        t3 = (y1 * z1) % p
        t4 = (t2 * 8) % p
        t5 = (x1 * t4) % p
        t1 = (t1 * 3) % p

        t6 = (t6 * t6) % p
        t6 = (a3 * t6) % p
        t1 = (t1 + t6) % p
        z3 = (t3 + t3) % p
        t3 = (t1 * t1) % p
        t2 = (t2 * t4) % p
        x3 = (t3 - t5) % p

        t4 = (t5 + ((t5 + p) >> 1) - t3) % p if (t5 % 2) == 1 else (t5 + (t5 >> 1) - t3) % p
        t1 = (t1 * t4) % p
        y3 = (t1 - t2) % p

        fmt = ('%%0%dx' % self.para_len) * 3
        return fmt % (x3, y3, z3)

    def _get_point_x_y_z(self, point: str) -> (int, int):
        x = int(point[0:self.para_len], 16)
        y = int(point[self.para_len:self.para_len * 2], 16)
        z = 1 if len(point) == self.para_len * 2 else int(point[self.para_len * 2:], 16)
        return x, y, z

    def add(self, point1: str, point2: str) -> Union[str, None]:  # TODO Remove this
        """
        点加函数，P2点为仿射坐标即z=1，P1为Jacobian加重射影坐标
        :param point1:
        :param point2:
        :return:
        """

        if len(point1) < 2 * self.para_len or len(point2) < 2 * self.para_len:
            return None

        x1, y1, z1 = self._get_point_x_y_z(point1)
        x2, y2, _ = self._get_point_x_y_z(point2)

        p = int(self.p, 16)

        t1 = (z1 * z1) % p
        t2 = (y2 * z1) % p
        t3 = (x2 * t1) % p

        t1 = (t1 * t2) % p  # Z1 * Z1 * T2
        t2 = (t3 - x1) % p  # x2 * T1 - X1
        t3 = (t3 + x1) % p  # x2 * T1 + X1
        t4 = (t2 * t2) % p  # (y2 * Z1) * (y2 * Z1)

        t1 = (t1 - y1) % p  # Z1 * Z1 * T2 - Y1
        z3 = (z1 * t2) % p  # Z1 * (x2 * T1 - X1)
        t2 = (t2 * t4) % p  # (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)
        t3 = (t3 * t4) % p  # Z1 * (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)
        t5 = (t1 * t1) % p  # (Z1 * Z1 * T2 - Y1) * (Z1 * Z1 * T2 - Y1)
        t4 = (x1 * t4) % p  # X1 * (y2 * Z1) * (y2 * Z1)
        x3 = (t5 - t3) % p  # (Z1 * Z1 * T2 - Y1) * (Z1 * Z1 * T2 - Y1) - Z1 * (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)
        t2 = (y1 * t2) % p  # Y1 * (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)
        t3 = (t4 - x3) % p  # X1 * (y2 * Z1) * (y2 * Z1) - Z1 * (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)
        t1 = (t1 * t3) % p  # (Z1 * Z1 * T2 - Y1) * Z1 * (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)

        # (Z1 * Z1 * T2 - Y1) * Z1 * (x2 * T1 - X1) * (y2 * Z1) *
        # (y2 * Z1) - Y1 * (x2 * T1 - X1) * (y2 * Z1) * (y2 * Z1)
        y3 = (t1 - t2) % p
        fmt = ('%%0%dx' % self.para_len) * 3
        return fmt % (x3, y3, z3)

    def _convert_jacb_to_nor(self, point: str) -> Union[str, None]:  # Jacobian加重射影坐标转换成仿射坐标
        x, y, z = self._get_point_x_y_z(point)
        p = int(self.p, 16)
        z_inv = pow(z, p - 2, p)
        z_inv_squar = (z_inv * z_inv) % p
        z_inv_qube = (z_inv_squar * z_inv) % p
        x_new = (x * z_inv_squar) % p
        y_new = (y * z_inv_qube) % p
        z_new = (z * z_inv) % p
        if z_new != 1:
            return None
        fmt = ('%%0%dx' % self.para_len) * 2
        return fmt % (x_new, y_new)


sm2p256v1 = SM2P256Curve()


class SM2WithSM3:
    def __init__(self, algorithm=sm3.sm3_hash):
        self._algorithm = algorithm

    @property
    def algorithm(self):
        return self._algorithm


sm2_with_sm3 = SM2WithSM3()


class SM2Signature:
    """sm2签名对象"""

    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

    def __str__(self):
        return '%064x%064x' % (self.r, self.s)

    def __repr__(self):
        return '<SM2Signature r="%d" s="%d">' % (self.r, self.s)

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


class SM2PublicKey:  # TODO ec.point
    """
    公钥 公钥是在椭圆曲线上的一个点，由一对坐标（x，y）组成
    公钥字符串可由 x || y 即 x 拼接 y代表
    """

    def __init__(self, x: str, y: str, curve: SM2P256Curve = sm2p256v1):
        self.curve: SM2P256Curve = curve
        assert curve.is_on_curve(x=hex_to_int(x), y=hex_to_int(y)), '公钥点x,y不在曲线上'
        self.x = x  # 公钥X坐标, 16进制字符串
        self.y = y  # 公钥Y坐标, 16进制字符串

    def __repr__(self):
        return '<SM2PublicKey x="%s" y="%s">' % (self.x, self.y)

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    @staticmethod
    def _calc_entla(uid: bytes) -> str:  # 对勾 ✅
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

    def _calc_za(self, uid: bytes = DEFAULT_UID) -> str:  # ✅
        """
        使用公钥和用户ID生成ZA-用户身份标识
        ZA=h256(ENTLA || IDA || a || b || G || x || y)  其中G为 Gx || Gy
        :param x: 公钥x坐标, 16进制字符串
        :param y: 公钥y坐标, 16进制字符串
        :param uid: 用户id, bytes字符串, 默认为 b'1234567812345678'
        :return:
        """
        entla = self._calc_entla(uid)  # '0080'
        ida = uid.hex()  # '31323334353637383132333435363738'
        a, b, gx, gy, x, y = self.curve.a, self.curve.b, self.curve.gx, self.curve.gy, self.x, self.y
        z = h256(entla, ida, a, b, gx, gy, x, y)
        za = sm3.sm3_hash(z)
        return za

    def _get_digest(self, data: bytes, uid: bytes = DEFAULT_UID, hash_algorithm=sm3.sm3_hash) -> str:
        """
        通过SM3哈希算法计算消息摘要
        :param hash_algorithm:
        :param data: 消息数据, bytes类型
        :param uid: 用户id, bytes字符串, 默认为 b'1234567812345678'
        :return:
        """
        # 杂凑
        za = self._calc_za(uid)
        data_with_za = bytes.fromhex(za + data.hex())  # 待签名消息
        digest = hash_algorithm(data_with_za)
        return digest

    def encrypt(self, data: bytes, k: str = None, mode=1):
        """
        公钥加密函数
        :param data: 待加密消息
        :param k: 16进制随机数
        :param mode:
        :return:
        """
        # 消息转化为16进制字符串
        data = data.hex()

        para_len = self.curve.para_len

        # 生成随机数
        if k is None:
            k = random_hex(para_len)
        random_key_int = hex_to_int(k)

        # 基点坐标G
        g = self.curve.gx + self.curve.gy
        # 公钥坐标P
        pub = self.x + self.y

        c1 = self.curve.scalar_mul(random_key_int, g)
        xy = self.curve.scalar_mul(random_key_int, pub)
        x2, y2 = xy[0:para_len], xy[para_len:2 * para_len]

        # 消息长度
        data_length = len(data)

        t = sm3.sm3_kdf(xy.encode('utf8'), data_length // 2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % data_length
            # C2 为密文，与明文长度等长
            c2 = form % (int(data, 16) ^ int(t, 16))
            # C3 为 SM3 算法对明文数计算得到消息摘要，长度固定为 256 位
            c3 = sm3.sm3_hash([i for i in hex_to_bytes(x2, data, y2)])
            if mode:
                return hex_to_bytes(c1, c3, c2)
            else:
                return hex_to_bytes(c1, c2, c3)

    def _verify(self, sig: SM2Signature, data_digest: bytes):
        """
        验证签名及消息摘要
        :param sig: 签名对象
        :param data_digest: 消息摘要
        :return:
        """
        # 验签函数，sign签名r||s，E消息hash，public_key公钥
        r, s = sig.r, sig.s

        # 消息转化为16进制字符串
        e = hex_to_int(data_digest.hex())
        n = hex_to_int(self.curve.n)

        t = (r + s) % n
        if t == 0:
            return 0

        point_g = ''.join([self.curve.gx, self.curve.gy])
        point_public_key = self.x + self.y
        point1 = self.curve.scalar_mul(s, point_g)
        point2 = self.curve.scalar_mul(t, point_public_key)
        if point1 == point2:
            point1 = '%s%s' % (point1, 1)
            point1 = self.curve.double(point1)
        else:
            point1 = '%s%s' % (point1, 1)
            point1 = self.curve.add(point1, point2)
            point1 = self.curve._convert_jacb_to_nor(point1)

        x = int(point1[0:self.curve.para_len], 16)
        return r == (e + x) % n

    def verify_with_sm3(self, sig: SM2Signature, data: bytes, uid: bytes = DEFAULT_UID) -> bool:
        """
        签名验证
        :param sig: 签名对象
        :param data: 原始消息
        :param uid: 用户UID
        :return: 验证成功返回True，否则返回False
        """
        digest = self._get_digest(data, uid)  # 消息摘要
        sign_data = binascii.a2b_hex(digest.encode('utf-8'))
        return self._verify(sig, sign_data)

    def verify(self, signature: bytes, data: bytes, uid: bytes = DEFAULT_UID,
               signature_algorithm=sm2_with_sm3):
        sig = SM2Signature.load(signature)
        digest = self._get_digest(data, uid, hash_algorithm=signature_algorithm.algorithm)  # 消息摘要
        return self._verify(sig, digest.encode('utf-8'))

    def public_bytes(self, encoding='PEM', format='PKCS#8') -> bytes:
        return self.to_pem()

    @classmethod
    def from_pem(cls, pem_bytes) -> "SM2PublicKey":
        pem_bytes = pem_bytes.rstrip(b'\n')
        body = b'\n'.join(pem_bytes.split(b'\n')[1:-1])  # 去掉前后两行
        body_bytes = base64.b64decode(body)
        # der, _ = decoder.decode(body_bytes)
        # value = int_to_hex(der.components[1]._value)
        # value = value[2:]  # 去掉开头的04
        # x, y = value[:64], value[64:]
        # return cls(x=x, y=y)
        return cls.load(body_bytes)

    @classmethod
    def load(cls, data: bytes) -> "SM2PublicKey":
        public_key, _ = decoder.decode(data, asn1Spec=sm2_asn1.SM2PublicKey())
        value = ''.join('%.2x' % x for x in public_key['publicKey'].asNumbers())
        # 去掉开头的04
        value = value[2:]
        x, y = value[:64], value[64:]
        return cls(x=x, y=y)

    def dump(self) -> bytes:
        pkcs8_key = sm2_asn1.SM2PublicKey()
        pkcs8_key["algorithm"] = sm2_asn1.sm2_algorithm
        value = '04%s%s' % (self.x, self.y)
        pkcs8_key["publicKey"] = BitString(hexValue=value)
        der = encoder.encode(pkcs8_key)
        return der

    def to_pem(self) -> bytes:
        der = self.dump()
        body = base64.b64encode(der)
        lines = [b'-----BEGIN PUBLIC KEY-----']
        lines.extend([body[i:i + PARA_LEN] for i in range(0, len(body), PARA_LEN)])
        lines.append(b'-----END PUBLIC KEY-----\n')
        return b'\n'.join(lines)


class SM2PrivateKey:
    """私钥"""

    def __init__(self, value: str):
        """
        :param value: 私钥值-secret, hex string
        """
        # 私钥本质上就是一个256位的随机整数, 16进制字符串, 私钥可以由d表示
        self.value = value  # int(value, 16) < n
        # 公钥对象
        self._public_key = self._get_public_key()

        self.para_len = len(self._public_key.curve.n)  # 64

    def __repr__(self):
        return '<SM2PrivateKey "%s">' % self.value

    def public_key(self) -> SM2PublicKey:
        """
        公钥
        :return: 公钥对象
        """
        return self._public_key

    def _get_public_key(self, curve=sm2p256v1):
        """
        根据曲线及私钥数字d通过kG计算出公钥
        :param curve:
        :return:
        """
        point_g = ec.Point(curve, hex_to_int(curve.gx), hex_to_int(curve.gy))
        private_key_value = hex_to_int(self.value)  # 私钥
        point_public_key = point_g * private_key_value  # 公钥
        return SM2PublicKey(int_to_hex(point_public_key.x), int_to_hex(point_public_key.y), curve=curve)

    def _sign(self, data_digest: bytes, random_key: str) -> (int, int):
        """
        签名函数
        :param data_digest: 待签名消息摘要（哈希后待消息）
        :param random_key: 随机数, hex string
        :return: 签名待r,s
        """
        # 消息, 私钥数字D, 随机数K, 曲线阶N 转int
        curve = self._public_key.curve

        e, d, random_key, n = map(hex_to_int, [data_digest.hex(), self.value, random_key, curve.n])

        # kg运算
        point1 = curve.scalar_base_mul(random_key)

        x = int(point1[0:self.para_len], 16)

        r = ((e + x) % n)

        if r == 0 or r + random_key == n:
            return None, None

        # 计算 （私钥+1) ^ （N - 2）% N
        d_1 = pow(d + 1, n - 2, n)

        # ((私钥+1) * (随机数 + r) - r )  % N
        s = (d_1 * (random_key + r) - r) % n

        if s == 0:
            return None, None

        return r, s

    def sign_with_sm3(self, data: bytes, random_key: str = None, uid: bytes = DEFAULT_UID) -> SM2Signature:
        """
        签名
        :param data: 待签名消息
        :param random_key: 随机数, hex string
        :param uid:
        :return:
        """
        digest_hex = self._public_key._get_digest(data, uid)  # 消息摘要
        data_digest = binascii.a2b_hex(digest_hex.encode('utf-8'))
        if random_key is None:
            random_key = random_hex(self.para_len)
        r, s = self._sign(data_digest, random_key)  # 16进制
        return SM2Signature(r, s)

    def sign(self, data: bytes, random_key: str = None, uid: bytes = DEFAULT_UID, hash_type='SM3') -> bytes:
        return self.sign_with_sm3(data, random_key, uid).dump()

    def decrypt(self, data: bytes, mode=1):
        """
        解密函数
        :param data: 密文
        :param mode: mode: 0-C1C2C3, 1-C1C3C2 (default is 1)
        :return: None
        """
        curve = self._public_key.curve
        para_len = curve.para_len

        data = data.hex()
        len_2 = 2 * para_len
        len_3 = len_2 + 64

        # C1 为随机产生的公钥
        C1 = data[0:len_2]
        if mode == 1:  # C1C3C2
            # C2 为密文，与明文长度等长
            C2 = data[len_3:]
        else:  # C1C2C3
            C2 = data[len_2:-para_len]

        xy = curve.scalar_mul(int(self.value, 16), C1)

        cl = len(C2)
        t = sm3.sm3_kdf(xy.encode('utf8'), cl // 2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % cl
            M = form % (int(C2, 16) ^ int(t, 16))
            return bytes.fromhex(M)

    @classmethod
    def from_pem(cls, pem_bytes: bytes):
        """
        从PEM加载私钥
        :param pem_bytes: 私钥PEM二进制
        :return: SM2PrivateKey对象
        """
        pem_bytes = pem_bytes.rstrip(b'\n')
        body = b'\n'.join(pem_bytes.split(b'\n')[1:-1])  # 去掉前后两行
        data = base64.b64decode(body)
        # der, _ = decoder.decode(body_bytes)
        # secret = der.components[2]._value.hex()
        # return cls(secret)
        return cls.load(data)

    @classmethod
    def load(cls, data: bytes) -> "SM2PrivateKey":
        private_key, _ = decoder.decode(data, asn1Spec=sm2_asn1.SM2PrivateKey())
        value = ''.join('%.2x' % x for x in private_key['privateKey'].asNumbers())
        return cls(value=value)

    def dump(self) -> bytes:
        pkcs1_key = OctetString(hexValue=self.value)

        pkcs8_key = sm2_asn1.SM2PrivateKey()
        pkcs8_key["version"] = 0
        pkcs8_key["privateKeyAlgorithm"] = sm2_asn1.sm2_algorithm
        pkcs8_key["privateKey"] = pkcs1_key
        der = encoder.encode(pkcs8_key)
        return der

    def to_pem(self) -> bytes:
        der = self.dump()
        body = base64.b64encode(der)
        lines = [b'-----BEGIN PRIVATE KEY-----']
        lines.extend([body[i:i + PARA_LEN] for i in range(0, len(body), PARA_LEN)])
        lines.append(b'-----END PRIVATE KEY-----\n')
        return b'\n'.join(lines)


def generate_private_key(curve=sm2p256v1, backend: typing.Any = None) -> SM2PrivateKey:
    pass


def derive_private_key(private_value: int, curve=sm2p256v1, backend: typing.Any = None) -> SM2PrivateKey:
    pass
