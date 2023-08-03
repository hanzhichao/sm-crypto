#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @FileName     :   ec.py
# @Function     :   椭圆曲线算法
# 参考Crypto实现 https://github.com/ashutosh1206/Crypton/blob/master/Elliptic-Curves/ellipticcurve.py
from typing import Optional

from .utils import hex_to_int


def inverse_mod(a, m):
    if a < 0 or m <= a:
        a = a % m
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + m


class CurveFp:
    """Fp有限域曲线 方程 y^2= x^3+ax+b"""
    name: str  # 曲线名称
    key_size: int  # 曲线位数

    # 必要参数
    a: str  # 曲线方程 y^2= x^3+ax+b 的系数a, 16进制字符串
    b: str  # 曲线方程 y^2= x^3+ax+b 的系数a, 16进制字符串
    p: str  # 大于3的一个大素数

    gx: str  # 基点x坐标, 16进制字符串
    gy: str  # 基点y坐标, 16进制字符串
    n: str  # 曲线的阶, 如果椭圆曲线上一点P，存在最小的正整数n使得数乘nP=O∞ ,则将n称为P的阶若n不存在，则P是无限阶的

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
        # _verify if y^2 - (x^3 + ax + b) is a multiple of p,
        a, b, p = hex_to_int(self.a), hex_to_int(self.b), hex_to_int(self.p)

        # (y^2 - x^3 - a - b ) % p == 0
        return (y ** 2 - x ** 3 - a * x - b) % p == 0


class Point:
    """有限领Fp曲线Curve上的点"""

    def __init__(self, curve: Optional[CurveFp],
                 x: Optional[int], y: Optional[int],
                 order=None):
        self.curve = curve
        self.x = x
        self.y = y
        self.order = order

        if self.curve:
            assert self.curve.is_on_curve(x, y), '点(x, y)不在曲线上'

        if order:
            assert self * order == INFINITY

    def __add__(self, other):
        assert isinstance(other, Point), '仅支持点+点'
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.curve == other.curve, '两个点不在同一条曲线上'

        p = hex_to_int(self.curve.p)  # 16进制字符串转int

        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return INFINITY
            else:
                return self.double()

        l = ((other.y - self.y) * inverse_mod(other.x - self.x, p)) % p

        x3 = (l * l - self.x - other.x) % p
        y3 = (l * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)

    def __mul__(self, other: int):
        assert isinstance(other, int), '仅支持乘以整数'

        def leftmost_bit(x):
            assert x > 0, 'x不大于0'
            result = 1
            while result <= x:
                result = 2 * result
            return result // 2

        e = other
        if self.order:
            e = e % self.order
        if e == 0:
            return INFINITY
        if self == INFINITY:
            return INFINITY
        assert e > 0, 'e不大于0'

        e3 = 3 * e

        # 相对于x轴的反向点
        negative_self = Point(self.curve, self.x, -self.y, self.order)

        i = leftmost_bit(e3) // 2
        result = self
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            i = i // 2
        return result

    def __rmul__(self, other: int):
        """反乘法，当左边对象不支持时调用，如 2 * point """
        assert isinstance(other, int), '仅支持乘以整数'
        return self * other

    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "(%d,%d)" % (self.x, self.y)

    def __sub__(self, other):
        """减法"""
        assert isinstance(other, Point), '仅支持 点-点 '
        return self + (-other)

    def __neg__(self):
        """负数值，x轴对称点"""
        if self == INFINITY:
            return INFINITY
        return Point(self.curve, self.x, -self.y)

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def double(self):
        if self == INFINITY:
            return INFINITY

        p = hex_to_int(self.curve.p)
        a = hex_to_int(self.curve.a)

        _l = ((3 * self.x * self.x + a) * inverse_mod(2 * self.y, p)) % p
        x3 = (_l * _l - 2 * self.x) % p
        y3 = (_l * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)


INFINITY = Point(None, None, None)
