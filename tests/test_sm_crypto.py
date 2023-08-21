#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from pyasn1.type.univ import SequenceOf

from sm_crypto import ec, sm2
from sm_crypto.sm2 import SM2PrivateKey, SM2PublicKey
from sm_crypto.utils import hex_to_int, int_to_hex

gm_key_bytes = b'''-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgBpQ7OBFIJJsYCYDc
bI93W5V0MCJrcTKqyBPioqLt5vagCgYIKoEcz1UBgi2hRANCAARjC0S7dmZPlmqi
HUBdWMNbTxIuXwZ5xso3C7CSqsxD6CMUj3Hnmv0vLdc+c8529937yBKVfK/xKMnF
kkUXDjud
-----END PRIVATE KEY-----'''


@pytest.fixture
def public_key():
    """SM2公钥"""
    pub_x = 86486910365053747502063228060823248590345160013865894637560355242509364288962
    pub_y = 101181106946091265431204246512408544766318122779614061831337312322228957210561
    public_key = sm2.SM2PublicKey(int_to_hex(pub_x), int_to_hex(pub_y))
    return public_key


@pytest.fixture()
def private_key():
    D = 72365085398694144586688860843300263721740873715599498623547807927292312544749
    private_key = sm2.SM2PrivateKey(int_to_hex(D))
    return private_key


@pytest.fixture()
def curve(public_key):
    return public_key.curve


@pytest.fixture()
def G(curve):
    return ec.Point(curve, hex_to_int(curve.gx), hex_to_int(curve.gy))


class TestPublicKey:
    def test_calc_ZA(self, public_key):
        # 计算用户标识
        ZA = public_key._calc_za()
        # print(ZA)
        assert ZA == 'e2cf5cf5ea28a7d10af99ce926b5fd32d78cc4719cd69347e6e52dff31cd4f91'

    def test_sm3_digest(self, public_key):
        msg = b'test'
        digest = public_key._get_digest(msg)
        assert digest == 'd2ecada8e3e418e3dcd3b6c33888516ae89ee6ddc3c28f82f27c10fcafe4f6b0'

    def test_verify_with_sm3(self, public_key):
        r = 61084790583518678668921497484069524443200446623941418485868065414529830776921
        s = 27965431025136490852414910604523392500928667941406165140535514395677029249612
        signature = sm2.SM2Signature(r, s)
        msg = b'test'
        result = public_key.verify_with_sm3(signature, msg)
        print(result)

    def test_encrypt(self, public_key):
        """测试公钥加密"""
        msg = b'test'
        k = 'c1cca047579c0c7a1b2afbade295abf19a1270b70ca0c9091facdcc65e3f7688'
        result = public_key.encrypt(msg, k=k, mode=1)
        assert result.hex() == '083562e4aaf52a6a886c8b9771f25060a89d8c1a5494b6258028cefed693af3b1e6ff607e0af30' \
                               '4c0632cb6646ffd63113cf8b81b0605e98d00119832f0104f0183d6f0b7ef02a21244c4558ca38' \
                               '1867ad8547f43f95936ea824d6b6638d893f20a248c7'


class TestPrivateKey:
    def test_sign_with_sm3(self, private_key, public_key):
        msg = b'test'
        k = int_to_hex(17862946205452999060962975573530209623112644258847452921350520798185987396203)
        sig = private_key.sign_with_sm3(msg, k)
        assert sig.r == 61084790583518678668921497484069524443200446623941418485868065414529830776921
        assert sig.s == 27965431025136490852414910604523392500928667941406165140535514395677029249612

        assert public_key.verify_with_sm3(sig, msg) is True

    def test_sign_with_sm3_02(self):
        private_key = sm2.SM2PrivateKey('8d68cf85fdabdb8b3dae0169019dfce36497f1de874798c35232de84f015af6a')

        msg = bytes.fromhex('0a06636861696e3110011a403137376332316239396237313132363863616465326566376437633234373136'
                            '626635306430643965633762346130393862616534336464363365643762333620c1d1f7a606320c43484149'
                            '4e5f434f4e4649473a104745545f434841494e5f434f4e464947')
        uid_bytes = bytes.fromhex('31323334353637383132333435363738')
        k = '3040125843fb39fd6285735c8251169767459e8df89d08343420af004ba325b4'
        sig = private_key.sign_with_sm3(msg, k, uid_bytes)
        assert int_to_hex(sig.r) == '999624b0d2bcfedce7f489d2479ca6b883433ef0ebe7d91815f663ce5b906e22'
        assert int_to_hex(sig.s) == '5867e008a96a7115f222b5c87f7fb8c30d228b75cdadfdcbc4fe99cb4b384ea2'

    def test_sign_payload(self):
        D = 37358557871484366494697952200264103807161342851654873822879604245593248003105
        msg = bytes.fromhex('0a06636861696e3110011a4032313863316335653236393234396636616462396636333039333835643236666'
                            '16562313134393730383962343336303930623333653665646339306562343620ccf4bd8f06320b434841494'
                            'e5f51554552593a0e4745545f434841494e5f494e464f')
        k = '277e11bb58bdec2f681fdb0d9fade5e37d0b2498980ba654321b9a7dffca526b'

        private_key = sm2.SM2PrivateKey(int_to_hex(D))
        sig = private_key.sign_with_sm3(msg, k)
        assert sig.r == 28433366858890048214993446265910046009847155747547907491830611928704638157369
        assert sig.s == 30529410057581304868817267597301739762941484125893063962167067250241894976898

    def test_load_pem_to_sm_private_key(self):
        sk = sm2.SM2PrivateKey.from_pem(gm_key_bytes)
        pk = sk.public_key()
        msg = b'test'
        k = int_to_hex(17862946205452999060962975573530209623112644258847452921350520798185987396203)
        sig = sk.sign_with_sm3(msg, k)
        assert pk.verify_with_sm3(sig, msg) is True

    @pytest.mark.skip('待修复')
    def test_sign_load_key_and_sign_payload(self):
        """测试加载私钥并生成sm2签名"""
        private_key = sm2.SM2PrivateKey.from_pem(gm_key_bytes)
        assert 2975779171698260078424564863478648882602251361876014642985074985594977642230 == hex_to_int(
            private_key.value)

        public_key = private_key.public_key
        assert 44798881700186481867478530749047307037907918333402141718404416851043955786728 == hex_to_int(
            public_key.x)
        assert 15867276662302353870668480236147363992828559411635465693043525110349488339869 == hex_to_int(
            public_key.y)

        k = '277e11bb58bdec2f681fdb0d9fade5e37d0b2498980ba654321b9a7dffca526b'
        msg = bytes.fromhex(
            '0a06636861696e3110011a40343963376337376536303635343962363935376536313163396466653031333937323863663138333'
            '8336538346536303863363137383932363138613130383520cf86bf8f06320b434841494e5f51554552593a0e4745545f43484149'
            '4e5f494e464f')
        sig = private_key.sign_with_sm3(msg, random_key=k)
        assert 64301789367307795946626421726693283401539325311527486667347093461494914687004 == sig.r
        assert 3896518202194914234585643109693938890529765912665548031832166116534576640790 == sig.s
        sign_bytes = sig.asn1_dump()
        assert sign_bytes.hex() == '30450221008e2985e636d9291edaa31361cbf92cb9e6064060d710a7c3c59ea7c1f1fd2' \
                                   '01c0220089d59e4d1872a0e150d4a03ac190b4d5296729d45d86d4db904584af1227316'

    def test_decrypt(self, private_key):
        data = bytes.fromhex(
            '083562e4aaf52a6a886c8b9771f25060a89d8c1a5494b6258028cefed693af3b1e6ff607e0af304c0632cb6646ffd63113cf'
            '8b81b0605e98d00119832f0104f0183d6f0b7ef02a21244c4558ca381867ad8547f43f95936ea824d6b6638d893f20a248c7')
        msg = private_key.decrypt(data, mode=1)
        assert msg == b'test'

    def test_get_public_key(self, private_key):
        assert private_key._get_public_key() == private_key.public_key()


class TestCurve:
    def test_is_on_curve(self, public_key):
        curve = public_key.curve
        gx, gy = hex_to_int(curve.gx), hex_to_int(curve.gy)
        assert curve.is_on_curve(gx, gy)
        pub_x, pub_y = hex_to_int(public_key.x), hex_to_int(public_key.y)
        assert curve.is_on_curve(pub_x, pub_y)

    def test_double(self, public_key):
        curve = public_key.curve
        gx, gy = hex_to_int(curve.gx), hex_to_int(curve.gy)
        assert curve.is_on_curve(gx, gy)


class TestPoint:
    def test_add(self, G):
        assert G * 2 == G + G
        assert G * 2 == G.double()

    def test_mul(self, G, curve):
        k = hex_to_int('17862946205452999060962975573530209623112644258847452921350520798185987396203')
        P2 = G * k
        assert curve.is_on_curve(P2.x, P2.y)

        P1 = '460333f094dcda438a35cb64ced03d04cc3694b598edb055056ce93c2149c0a8' \
             '255130b63b4b096c29c4db80148d27a1c3944a466d14b8f8f9aac68d35a2d1fb'
        assert int_to_hex(P2.x) + int_to_hex(P2.y) == P1

    def test_right_mul(self, G, curve):
        """测试左乘法"""
        k = hex_to_int('17862946205452999060962975573530209623112644258847452921350520798185987396203')

        P2 = k * G
        assert curve.is_on_curve(P2.x, P2.y)
        P1 = '460333f094dcda438a35cb64ced03d04cc3694b598edb055056ce93c2149c0a8' \
             '255130b63b4b096c29c4db80148d27a1c3944a466d14b8f8f9aac68d35a2d1fb'

        assert int_to_hex(P2.x) + int_to_hex(P2.y) == P1

    def test_neg(self, G):
        G1 = -G
        assert G1.curve == G.curve and G1.x == G1.x and G1.y + G.y == 0
        assert G1 + G == ec.INFINITY

    def test_sub(self, G):
        G1 = G * 2 - G
        assert G1 == G

    def test_get_public_key_from_private_key(self, private_key, G):
        k = hex_to_int(private_key.value)
        K = G * k
        pub_x = hex_to_int(private_key.public_key().x)
        pub_y = hex_to_int(private_key.public_key().y)

        assert K.x == pub_x and K.y == pub_y


class TestSM2P256Curve:
    @pytest.mark.skip("待修复")
    def test_double(self, curve):  # Fixme
        P1 = ''.join([curve.gx, curve.gy])
        print(len(P1))
        P2 = curve.double(P1)
        x2 = hex_to_int(P2[:64])
        y2 = hex_to_int(P2[64:128])
        assert curve.is_on_curve(x2, y2)


class TestSignature:
    def test_asn1_dump(self):
        """测试asn1序列化签名"""
        sig = sm2.SM2Signature(r=28433366858890048214993446265910046009847155747547907491830611928704638157369,
                               s=30529410057581304868817267597301739762941484125893063962167067250241894976898)

        data = sig.asn1_dump()
        assert data.hex() == ('304402203edcb72060a1c7236058bbd3976000fcd0609ebfd844647cc80d18f8c1ea82390220437f08a39fd8'
                              '05d0fb34d94e6a4d2602a396052e6311c1e90d5c9c8709b18d82')

    def test_asn1_load(self):
        """测试asn1反列化签名"""
        data = bytes.fromhex('304402203edcb72060a1c7236058bbd3976000fcd0609ebfd844647cc80d18f8c1ea82390220437f08a39fd8'
                             '05d0fb34d94e6a4d2602a396052e6311c1e90d5c9c8709b18d82')
        sig = sm2.SM2Signature.asn1_load(data)
        assert sig.r == 28433366858890048214993446265910046009847155747547907491830611928704638157369
        assert sig.s == 30529410057581304868817267597301739762941484125893063962167067250241894976898


def test_hex_int_bytes_change():
    """测试进制转换"""
    x = 838672667751004658910306792581697645209600399524876016465594220966924553081
    y = 40618358281630434260037166415012792491669407866299925195664255417602402261586
    assert x == hex_to_int(bytes.fromhex(int_to_hex(x)).hex())
    assert y == hex_to_int(bytes.fromhex(int_to_hex(y)).hex())


def test_load_public_key_pem():
    pem_bytes = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERmeDTL7vugKqNgrSwUqH5D4kj0h2
6XJLXLYgoS1+yoNWuaXfSqEFAUmqbfttoZU/h+cPhzP7VoDG6jbzu4pvAw==
-----END PUBLIC KEY-----
'''

    pk = SM2PublicKey.from_pem(pem_bytes)
    assert '4667834cbeefba02aa360ad2c14a87e43e248f4876e9724b5cb620a12d7eca83' == pk.x
    assert '56b9a5df4aa1050149aa6dfb6da1953f87e70f8733fb5680c6ea36f3bb8a6f03' == pk.y


def test_dump_public_key():
    x = '4667834cbeefba02aa360ad2c14a87e43e248f4876e9724b5cb620a12d7eca83'
    y = '56b9a5df4aa1050149aa6dfb6da1953f87e70f8733fb5680c6ea36f3bb8a6f03'
    pk = SM2PublicKey(x=x, y=y)

    pem_bytes = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERmeDTL7vugKqNgrSwUqH5D4kj0h2
6XJLXLYgoS1+yoNWuaXfSqEFAUmqbfttoZU/h+cPhzP7VoDG6jbzu4pvAw==
-----END PUBLIC KEY-----
'''
    assert repr(pem_bytes.decode()) == repr(pk.public_bytes().decode())



def test_load_private_key_pem():
    pem_bytes = b'''-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgjWjPhf2r24s9rgFp
AZ3842SX8d6HR5jDUjLehPAVr2qgCgYIKoEcz1UBgi2hRANCAARGZ4NMvu+6Aqo2
CtLBSofkPiSPSHbpcktctiChLX7Kg1a5pd9KoQUBSapt+22hlT+H5w+HM/tWgMbq
NvO7im8D
-----END PRIVATE KEY-----
'''
    sk = SM2PrivateKey.from_pem(pem_bytes)
    assert sk.value == ('307702010104208d68cf85fdabdb8b3dae0169019dfce36497f1'
                        'de874798c35232de84f015af6aa00a06082a811ccf5501822da1'
                        '44034200044667834cbeefba02aa360ad2c14a87e43e248f4876'
                        'e9724b5cb620a12d7eca8356b9a5df4aa1050149aa6dfb6da195'
                        '3f87e70f8733fb5680c6ea36f3bb8a6f03')


def test_dump_private_key_pem():
    value = ('307702010104208d68cf85fdabdb8b3dae0169019dfce36497f1de874798c35'
             '232de84f015af6aa00a06082a811ccf5501822da144034200044667834cbeef'
             'ba02aa360ad2c14a87e43e248f4876e9724b5cb620a12d7eca8356b9a5df4aa'
             '1050149aa6dfb6da1953f87e70f8733fb5680c6ea36f3bb8a6f03')
    sk = SM2PrivateKey(value=value)
    pem_bytes = b'''-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgjWjPhf2r24s9rgFp
AZ3842SX8d6HR5jDUjLehPAVr2qgCgYIKoEcz1UBgi2hRANCAARGZ4NMvu+6Aqo2
CtLBSofkPiSPSHbpcktctiChLX7Kg1a5pd9KoQUBSapt+22hlT+H5w+HM/tWgMbq
NvO7im8D
-----END PRIVATE KEY-----
'''
    assert sk.to_pem() == pem_bytes
