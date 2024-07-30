from pyasn1.type import namedtype, univ

SM2_OID = '1.2.840.10045.2.1'
EC_PUBLIC_KEY_OID = '1.2.156.10197.1.301'


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.NamedType('namedCurve', univ.ObjectIdentifier())
    )


class SM2PublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('publicKey', univ.BitString())
    )


# pkcs8
class SM2PrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('privateKeyAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('privateKey', univ.OctetString()),
    )


class SM2Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer()),
    )


sm2_algorithm = AlgorithmIdentifier()
sm2_algorithm["algorithm"] = SM2_OID
sm2_algorithm["namedCurve"] = EC_PUBLIC_KEY_OID
