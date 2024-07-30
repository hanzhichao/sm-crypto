class CurvePoint:
    def __init__(self, x: int, y: int, curve: "CurveFp"):
        self.x = x
        self.y = y
        self.curve = curve

    def __repr__(self):
        return '<PointFp(%d, %d)>' % (self.x, self.y)

    def __eq__(self, other: "CurvePoint"):
        return self.curve.name == other.curve.name and self.x == other.x and self.y == other.y

    def hex(self):
        return '%064x%064x' % (self.x, self.y)

    def values(self):
        return (self.x, self.y)

    def double(self) -> "CurvePoint":
        point = self.to_jacobian_point()
        return point.double().to_curve_point()

    def add(self, other: "CurvePoint") -> "CurvePoint":
        point1 = self.to_jacobian_point()
        point2 = other.to_jacobian_point()
        return point1.add(point2).to_curve_point()

    def scalar_mult(self, k: int) -> "CurvePoint":
        # kP运算
        point = self.to_jacobian_point()
        return point.scalar_mult(k).to_curve_point()

    def to_jacobian_point(self) -> "JacobianPoint":
        return JacobianPoint(self.x, self.y, 1, curve=self.curve)


class JacobianPoint:

    def __init__(self, x: int, y: int, z: int, curve: "CurveFp"):
        self.x = x
        self.y = y
        self.z = z
        self.curve = curve
        self.p = self.curve.p

    def double(self) -> "JacobianPoint":  # 倍点
        """
        Point: (x, y, z)

        return double_point
        """
        t6 = (self.z * self.z) % self.p
        t2 = (self.y * self.y) % self.p
        t3 = (self.x + t6) % self.p
        t4 = (self.x - t6) % self.p
        t1 = (t3 * t4) % self.p
        t3 = (self.y * self.z) % self.p
        t4 = (t2 * 8) % self.p
        t5 = (self.x * t4) % self.p
        t1 = (t1 * 3) % self.p

        z = (t3 + t3) % self.p
        t3 = (t1 * t1) % self.p
        t2 = (t2 * t4) % self.p
        x = (t3 - t5) % self.p

        if (t5 % 2) == 1:
            t4 = (t5 + ((t5 + self.p) >> 1) - t3) % self.p
        else:
            t4 = (t5 + (t5 >> 1) - t3) % self.p

        t1 = (t1 * t4) % self.p
        y = (t1 - t2) % self.p

        return JacobianPoint(x, y, z, curve=self.curve)

    def add(self, other: "JacobianPoint") -> "JacobianPoint":
        # 点加函数，P2点为Affine仿射坐标即z=1，P1为Jacobian加重射影坐标
        """
        P1: (x, y, z)
        P1: (x, y, z)

        return add_point
        """

        t1 = (self.z * self.z) % self.p
        t2 = (other.y * self.z) % self.p
        t3 = (other.x * t1) % self.p
        t1 = (t1 * t2) % self.p
        t2 = (t3 - self.x) % self.p
        t3 = (t3 + self.x) % self.p
        t4 = (t2 * t2) % self.p
        t1 = (t1 - self.y) % self.p

        z = (self.z * t2) % self.p
        t2 = (t2 * t4) % self.p
        t3 = (t3 * t4) % self.p
        t5 = (t1 * t1) % self.p
        t4 = (self.x * t4) % self.p

        x = (t5 - t3) % self.p
        t2 = (self.y * t2) % self.p
        t3 = (t4 - x) % self.p
        t1 = (t1 * t3) % self.p

        y = (t1 - t2) % self.p

        return JacobianPoint(x, y, z, curve=self.curve)

    def scalar_mult(self, k: int) -> "JacobianPoint":
        # kP运算
        key_size = self.curve.key_size
        mask = int('8' + '0' * (key_size // 4 - 1), 16)
        t = self
        flag = False
        for n in range(key_size):
            if flag:
                t = t.double()
            if (k & mask) != 0:
                if flag:
                    t = t.add(self)
                else:
                    flag = True
                    t = self
            k = k << 1
        return t

    def to_curve_point(self) -> CurvePoint:
        # Jacobian加重射影坐标转换成Affine仿射坐标
        """
        Point: (x, y, z)

        return double_point
        """
        # x, y, z = self.x, self.y, self.z
        z_inv = pow(self.z, self.p - 2, self.p)
        z_inv2 = (z_inv * z_inv) % self.p
        z_inv3 = (z_inv2 * z_inv) % self.p

        x = (self.x * z_inv2) % self.p
        y = (self.y * z_inv3) % self.p
        z = (self.z * z_inv) % self.p
        if z == 1:
            return CurvePoint(x, y, curve=self.curve)
        else:
            return None  # TODO


class CurveFp:
    name: str
    key_size: int
    a: int
    b: int
    p: int
    n: int
    gx: int
    gy: int

    def base_point(self) -> CurvePoint:
        return CurvePoint(self.gx, self.gy, curve=self)

    def scalar_mult(self, x: int, y: int, k: int) -> CurvePoint:
        p = CurvePoint(x, y, curve=self)
        return p.scalar_mult(k)

    def scalar_base_mult(self, k: int) -> CurvePoint:
        return self.base_point().scalar_mult(k)

    def params(self) -> dict:
        """
        曲线参数
        :return: 字典类型的曲线参数
        """
        return dict(a=self.a, b=self.b, p=self.p, gx=self.gx, gy=self.gy, n=self.n)

    def is_on_curve(self, x: int, y: int) -> bool:
        """
        点(x, y)是否在曲线上 y^2 - (x^3 + ax + b) 应为p的倍数
        :param x: x坐标
        :param y: y坐标
        :return: 在曲线上返回True, 否则返回False
        """

        # (y^2 - x^3 - a - b ) % p == 0
        return (y ** 2 - x ** 3 - self.a * x - self.b) % self.p == 0


class SM2P256Curve(CurveFp):
    name = 'sm2p256v1'
    key_size = 256
    a = 115792089210356248756420345214020892766250353991924191454421193933289684991996
    b = 18505919022281880113072981827955639221458448578012075254857346196103069175443
    p = 115792089210356248756420345214020892766250353991924191454421193933289684991999
    n = 115792089210356248756420345214020892766061623724957744567843809356293439045923
    gx = 22963146547237050559479531362550074578802567295341616970375194840604139615431
    gy = 85132369209828568825618990617112496413088388631904505083283536607588877201568


sm2p256v1 = SM2P256Curve()
