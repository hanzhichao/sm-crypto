#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time

import pytest

from sm_crypto import sm2
from sm_crypto.sm2 import SM2PrivateKey, SM2PublicKey, SM2Signature
from sm_crypto.utils import hex_to_int


@pytest.fixture
def public_key():
    """SM2公钥"""
    pub_x = 86486910365053747502063228060823248590345160013865894637560355242509364288962
    pub_y = 101181106946091265431204246512408544766318122779614061831337312322228957210561
    public_key = sm2.SM2PublicKey(pub_x, pub_y)
    return public_key


@pytest.fixture()
def private_key():
    d = 72365085398694144586688860843300263721740873715599498623547807927292312544749
    private_key = sm2.SM2PrivateKey(d)
    return private_key


class TestSM2PublicKey:
    public_key_pem = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERmeDTL7vugKqNgrSwUqH5D4kj0h2
6XJLXLYgoS1+yoNWuaXfSqEFAUmqbfttoZU/h+cPhzP7VoDG6jbzu4pvAw==
-----END PUBLIC KEY-----
'''

    def test_get_za(self, public_key):  # ✅
        # 计算用户标识
        za = public_key._get_za()
        # print(ZA)
        assert za == 'e2cf5cf5ea28a7d10af99ce926b5fd32d78cc4719cd69347e6e52dff31cd4f91'

    def test_sm3_digest(self, public_key):  # ✅
        msg = b'test'
        digest = public_key.get_digest(msg)
        assert digest == 'd2ecada8e3e418e3dcd3b6c33888516ae89ee6ddc3c28f82f27c10fcafe4f6b0'

    def test_verify(self, public_key):  # ✅
        r = 61084790583518678668921497484069524443200446623941418485868065414529830776921
        s = 27965431025136490852414910604523392500928667941406165140535514395677029249612
        sig = sm2.SM2Signature(r, s).dump()
        msg = b'test'
        result = public_key.verify(sig, msg)
        assert result is True

    def test_encrypt(self, public_key):  # ✅
        """测试公钥加密"""
        msg = b'test'
        k = int('c1cca047579c0c7a1b2afbade295abf19a1270b70ca0c9091facdcc65e3f7688', 16)
        result = public_key.encrypt(msg, k=k, mode=1)
        assert result.hex() == ('083562e4aaf52a6a886c8b9771f25060a89d8c1a5494b6258028cefed693af3b1e6ff607e0af30'
                                '4c0632cb6646ffd63113cf8b81b0605e98d00119832f0104f0183d6f0b7ef02a21244c4558ca38'
                                '1867ad8547f43f95936ea824d6b6638d893f20a248c7')

    def test_load_dump_public_key_pem(self):  # ✅
        public_key = SM2PublicKey.from_pem(self.public_key_pem)
        assert public_key.x == int('4667834cbeefba02aa360ad2c14a87e43e248f4876e9724b5cb620a12d7eca83', 16)
        assert public_key.y == int('56b9a5df4aa1050149aa6dfb6da1953f87e70f8733fb5680c6ea36f3bb8a6f03', 16)
        assert public_key.to_pem() == self.public_key_pem


class TestSM2PrivateKey:
    private_key_pem = b'''-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgBpQ7OBFIJJsYCYDc
bI93W5V0MCJrcTKqyBPioqLt5vagCgYIKoEcz1UBgi2hRANCAARjC0S7dmZPlmqi
HUBdWMNbTxIuXwZ5xso3C7CSqsxD6CMUj3Hnmv0vLdc+c8529937yBKVfK/xKMnF
kkUXDjud
-----END PRIVATE KEY-----
'''

    def test_sign(self, private_key, public_key):
        msg = b'test'
        k = 17862946205452999060962975573530209623112644258847452921350520798185987396203
        sig = private_key.sign(msg, k)
        r, s = SM2Signature.load(sig).value()
        assert r == 61084790583518678668921497484069524443200446623941418485868065414529830776921
        assert s == 27965431025136490852414910604523392500928667941406165140535514395677029249612

        assert public_key.verify(sig, msg) is True

    def test_sign_02(self):
        d = int('8d68cf85fdabdb8b3dae0169019dfce36497f1de874798c35232de84f015af6a', 16)
        private_key = sm2.SM2PrivateKey(d)

        msg = bytes.fromhex('0a06636861696e3110011a403137376332316239396237313132363863616465326566376437633234373136'
                            '626635306430643965633762346130393862616534336464363365643762333620c1d1f7a606320c43484149'
                            '4e5f434f4e4649473a104745545f434841494e5f434f4e464947')
        uid = bytes.fromhex('31323334353637383132333435363738')
        k = int('3040125843fb39fd6285735c8251169767459e8df89d08343420af004ba325b4', 16)
        sig = private_key.sign(msg, k, uid=uid)
        r, s = SM2Signature.load(sig).value()
        assert r == int('999624b0d2bcfedce7f489d2479ca6b883433ef0ebe7d91815f663ce5b906e22', 16)
        assert s == int('5867e008a96a7115f222b5c87f7fb8c30d228b75cdadfdcbc4fe99cb4b384ea2', 16)

    def test_sign_payload(self):
        d = 37358557871484366494697952200264103807161342851654873822879604245593248003105
        msg = bytes.fromhex('0a06636861696e3110011a4032313863316335653236393234396636616462396636333039333835643236666'
                            '16562313134393730383962343336303930623333653665646339306562343620ccf4bd8f06320b434841494'
                            'e5f51554552593a0e4745545f434841494e5f494e464f')
        k = int('277e11bb58bdec2f681fdb0d9fade5e37d0b2498980ba654321b9a7dffca526b', 16)

        private_key = sm2.SM2PrivateKey(d)
        sig = private_key.sign(msg, k)
        r, s = SM2Signature.load(sig).value()
        assert r == 28433366858890048214993446265910046009847155747547907491830611928704638157369
        assert s == 30529410057581304868817267597301739762941484125893063962167067250241894976898

    def test_load_dump_private_key_pem(self):  # ✅
        key = sm2.SM2PrivateKey.from_pem(self.private_key_pem)
        assert key.d == int('3077020101042006943b381148249b180980dc6c8f775b957430226b7132aac813e2a2a2ede6f6a00a06082a81'
                            '1ccf5501822da14403420004630b44bb76664f966aa21d405d58c35b4f122e5f0679c6ca370bb092aacc43e823'
                            '148f71e79afd2f2dd73e73ce76f7ddfbc812957caff128c9c59245170e3b9d', 16)
        assert key.to_pem() == self.private_key_pem

    def test_decrypt(self, private_key):  # ✅
        data = bytes.fromhex(
            '083562e4aaf52a6a886c8b9771f25060a89d8c1a5494b6258028cefed693af3b1e6ff607e0af304c0632cb6646ffd63113cf'
            '8b81b0605e98d00119832f0104f0183d6f0b7ef02a21244c4558ca381867ad8547f43f95936ea824d6b6638d893f20a248c7')
        msg = private_key.decrypt(data, mode=1)
        assert msg == b'test'

    def test_sign_performance(self):  # ✅
        """测试签名性能"""
        data = bytes.fromhex(
            '0a06636861696e3110011a40646365356331313330303466343034626136376665643462646366646365326533386'
            '5306161366263326533343962396261633430386535663264613234323720a9a08bb306320c434841494e5f434f4e'
            '4649473a104745545f434841494e5f434f4e464947')
        start_time = time.time()
        for i in range(1000):
            private_key = SM2PrivateKey(72365085398694144586688860843300263721740873715599498623547807927292312544749)
            sig = private_key.sign(data)
        print("耗时", time.time() - start_time)


class TestSignature:
    def test_asn1_dump(self):
        """测试asn1序列化签名"""
        sig = sm2.SM2Signature(r=28433366858890048214993446265910046009847155747547907491830611928704638157369,
                               s=30529410057581304868817267597301739762941484125893063962167067250241894976898)

        data = sig.dump()
        assert data.hex() == ('304402203edcb72060a1c7236058bbd3976000fcd0609ebfd844647cc80d18f8c1ea82390220437f08a39fd8'
                              '05d0fb34d94e6a4d2602a396052e6311c1e90d5c9c8709b18d82')

    def test_asn1_load(self):
        """测试asn1反列化签名"""
        data = bytes.fromhex('304402203edcb72060a1c7236058bbd3976000fcd0609ebfd844647cc80d18f8c1ea82390220437f08a39fd8'
                             '05d0fb34d94e6a4d2602a396052e6311c1e90d5c9c8709b18d82')
        sig = sm2.SM2Signature.load(data)
        assert sig.r == 28433366858890048214993446265910046009847155747547907491830611928704638157369
        assert sig.s == 30529410057581304868817267597301739762941484125893063962167067250241894976898
