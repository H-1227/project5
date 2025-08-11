import os
import hashlib
from gmssl import sm3, func

from project.project5.project5.baseSM2 import point_mul

p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class Point:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __str__(self):
        if self.infinity:
            return "Point(infinity)"
        return f"Point({hex(self.x)}, {hex(self.y)})"

    def __eq__(self, other):
        if self.infinity and other.infinity:
            return True
        if self.infinity or other.infinity:
            return False
        return self.x == other.x and self.y == other.y


# 优化1: 使用射影坐标减少模逆运算
def point_add_projective(p1, p2):
    # 实现射影坐标下的点加法
    if p1.infinity:
        return p2
    if p2.infinity:
        return p1

    # 转换为射影坐标 (X, Y, Z) 其中 x = X/Z², y = Y/Z³
    X1, Y1, Z1 = p1.x, p1.y, 1
    X2, Y2, Z2 = p2.x, p2.y, 1

    # 计算中间变量
    U1 = (X1 * pow(Z2, 2, p)) % p
    U2 = (X2 * pow(Z1, 2, p)) % p
    V1 = (Y1 * pow(Z2, 3, p)) % p
    V2 = (Y2 * pow(Z1, 3, p)) % p

    if U1 == U2:
        if V1 != V2:
            return Point(0, 0, True)  # 相反点，和为无穷远点
        # 点加倍
        S = (2 * V1 * Z1 * Z2) % p
        M = (3 * U1 * U1 + a * pow(Z1 * Z2, 4, p)) % p
        T = (M * M - 2 * S * U1) % p

        X3 = (S * T) % p
        Y3 = (M * (S * U1 - T) - 2 * S * S * V1) % p
        Z3 = (S * Z1 * Z2) % p
    else:
        # 点加法
        W = (U2 - U1) % p
        R = (V2 - V1) % p
        T = (R * R) % p
        M = (U1 * W * W) % p
        S = (V1 * W * W * W) % p
        U3 = (T - 2 * M) % p

        X3 = (W * U3) % p
        Y3 = (R * (M - U3) - S) % p
        Z3 = (W * W * W) % p

    # 转换回仿射坐标
    Z3_inv = pow(Z3, p - 2, p)
    x3 = (X3 * pow(Z3_inv, 2, p)) % p
    y3 = (Y3 * pow(Z3_inv, 3, p)) % p

    return Point(x3, y3)


# 优化2: 窗口法点乘
def point_mul_window(k, p, window_size=4):
    # 预计算窗口表
    window_table = [Point(0, 0, True)] * (1 << window_size)
    window_table[1] = p

    # 预计算 2P, 3P, ..., (2^window_size - 1)P
    for i in range(2, 1 << window_size):
        window_table[i] = point_add_projective(window_table[i - 1], p)

    # 处理负系数
    for i in range(1, 1 << (window_size - 1)):
        neg_i = (1 << window_size) - i
        window_table[neg_i] = Point(window_table[i].x, (-window_table[i].y) % p)

    # 将k转换为二进制，并按窗口分组
    k_bits = bin(k)[2:].zfill(((len(bin(k)) - 2 + window_size - 1) // window_size) * window_size)
    num_windows = len(k_bits) // window_size

    result = Point(0, 0, True)
    for i in range(num_windows):
        # 从高位到低位处理
        window = k_bits[i * window_size: (i + 1) * window_size]
        digit = int(window, 2)

        if digit != 0:
            result = point_add_projective(result, window_table[digit])

        # 每处理一个窗口，结果乘以2^window_size
        if i != num_windows - 1:
            for _ in range(window_size):
                result = point_add_projective(result, result)

    return result

def performance_test():
    import time

    # 生成密钥对
    d = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1
    G = Point(Gx, Gy)

    # 测试原始点乘性能
    start = time.time()
    for _ in range(100):
        point_mul(d, G)  # 假设point_mul是原始实现
    original_time = time.time() - start

    # 测试优化点乘性能
    start = time.time()
    for _ in range(100):
        point_mul_window(d, G)
    optimized_time = time.time() - start

    print(f"原始点乘100次耗时: {original_time:.4f}秒")
    print(f"优化点乘100次耗时: {optimized_time:.4f}秒")
    print(f"性能提升: {original_time / optimized_time:.2f}倍")

if __name__ == "__main__":
    performance_test()
