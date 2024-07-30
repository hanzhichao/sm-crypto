import pytest

from sm_crypto.curve import CurvePoint, sm2p256v1


@pytest.fixture()
def curve():
    return sm2p256v1


@pytest.fixture()
def g(curve):
    return curve.base_point()


class TestCurvePoint:
    def test_add(self, g):
        print(g.add(g))  # Fixme g + g = None
        # assert g.scalar_mult(2) == g.add(g)
        assert g.scalar_mult(2) == g.double()

    def test_scalar_mult(self, g, curve):  # Fixme
        k = 17862946205452999060962975573530209623112644258847452921350520798185987396203
        point = g.scalar_mult(k)
        assert curve.is_on_curve(point.x, point.y)

        assert point.x == int('460333f094dcda438a35cb64ced03d04cc3694b598edb055056ce93c2149c0a8', 16)
        assert point.y == int('255130b63b4b096c29c4db80148d27a1c3944a466d14b8f8f9aac68d35a2d1fb', 16)

    def test_double(self, curve):
        point = curve.double()
        assert curve.is_on_curve(point.gx, point.gy)

    def test_is_on_curve(self, curve):
        assert curve.is_on_curve(curve.x, curve.y)
