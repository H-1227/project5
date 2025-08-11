import os
from gmssl import sm3, func

# SM2曲线参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


# 椭圆曲线点类
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


# 椭圆曲线运算
def point_add(p1, p2):
    if p1.infinity:
        return p2
    if p2.infinity:
        return p1
    if p1.x == p2.x and p1.y != p2.y:
        return Point(0, 0, True)

    if p1 != p2:
        lam = (p2.y - p1.y) * pow(p2.x - p1.x, p - 2, p) % p
    else:
        lam = (3 * p1.x * p1.x + a) * pow(2 * p1.y, p - 2, p) % p

    x3 = (lam * lam - p1.x - p2.x) % p
    y3 = (lam * (p1.x - x3) - p1.y) % p
    return Point(x3, y3)


def point_mul(k, p):
    result = Point(0, 0, True)
    current = p
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result


# 密钥生成
def generate_key_pair():
    d = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1
    Q = point_mul(d, Point(Gx, Gy))
    return d, Q


# SM3哈希函数
def sm3_hash(data):
    return sm3.sm3_hash(func.bytes_to_list(data))


# 签名算法
def sm2_sign(d, M, Z):
    # Z为用户标识的杂凑值
    global s
    M_prime = Z + M
    e = int(sm3_hash(bytes.fromhex(M_prime)), 16)

    while True:
        k = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1
        kG = point_mul(k, Point(Gx, Gy))
        r = (e + kG.x) % n
        if r == 0 or r + k == n:
            continue
        s = (pow(1 + d, n - 2, n) * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)


# 验证算法
def sm2_verify(Q, M, Z, signature):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    M_prime = Z + M
    e = int(sm3_hash(bytes.fromhex(M_prime)), 16)

    t = (r + s) % n
    if t == 0:
        return False

    sG = point_mul(s, Point(Gx, Gy))
    tQ = point_mul(t, Q)
    P = point_add(sG, tQ)

    if P.infinity:
        return False

    return (e + P.x) % n == r


# 加密算法
def sm2_encrypt(Q, M):
    # 生成随机数k
    k = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1

    # 计算kG和kQ
    kG = point_mul(k, Point(Gx, Gy))
    kQ = point_mul(k, Q)

    # 计算x2 || y2
    x2y2 = format(kQ.x, '064x') + format(kQ.y, '064x')

    # 计算t = SM3(x2 || y2)
    t = sm3_hash(bytes.fromhex(x2y2))
    if t == '0' * 64:
        return None

    # 计算C1 = kG
    C1 = format(kG.x, '064x') + format(kG.y, '064x')

    # 计算C2 = M ^ t
    M_bytes = bytes.fromhex(M)
    t_bytes = bytes.fromhex(t)
    C2 = bytes([a ^ b for a, b in zip(M_bytes, t_bytes)]).hex()

    # 计算C3 = SM3(x2 || M || y2)
    x2 = format(kQ.x, '064x')
    y2 = format(kQ.y, '064x')
    C3 = sm3_hash(bytes.fromhex(x2 + M + y2))

    return C1 + C2 + C3


# 解密算法
def sm2_decrypt(d, C):
    # 解析密文
    global a, b
    C1_len = 128  # 64字节x + 64字节y
    C3_len = 64  # SM3哈希结果长度
    C1 = C[:C1_len]
    C2 = C[C1_len:-C3_len]
    C3 = C[-C3_len:]

    # 从C1中解析x1和y1
    x1 = int(C1[:64], 16)
    y1 = int(C1[64:], 16)
    P1 = Point(x1, y1)

    # 验证P1是否在椭圆曲线上
    if (y1 * y1 - (x1 * x1 * x1 + a * x1 + b)) % p != 0:
        return None

    # 计算dP1
    dP1 = point_mul(d, P1)
    x2 = dP1.x
    y2 = dP1.y

    # 计算t = SM3(x2 || y2)
    x2y2 = format(x2, '064x') + format(y2, '064x')
    t = sm3_hash(bytes.fromhex(x2y2))
    if t == '0' * 64:
        return None

    # 计算M = C2 ^ t
    C2_bytes = bytes.fromhex(C2)
    t_bytes = bytes.fromhex(t)
    M = bytes([a ^ b for a, b in zip(C2_bytes, t_bytes)]).hex()

    # 验证C3是否正确
    x2_hex = format(x2, '064x')
    y2_hex = format(y2, '064x')
    if sm3_hash(bytes.fromhex(x2_hex + M + y2_hex)) != C3:
        return None

    return M


def test_sm2():
    # 生成密钥对
    d, Q = generate_key_pair()
    print(f"私钥 d: {hex(d)}")
    print(f"公钥 Q: ({hex(Q.x)}, {hex(Q.y)})")

    # 生成用户标识Z (简化处理)
    Z = "00"

    # 测试签名与验证
    message = "616263"  # "abc"的十六进制表示
    signature = sm2_sign(d, message, Z)
    print(f"签名结果: r={hex(signature[0])}, s={hex(signature[1])}")

    verify_result = sm2_verify(Q, message, Z, signature)
    print(f"验证结果: {verify_result}")

    # 测试加密解密
    plaintext = "48656C6C6F20534D3221"  # "Hello SM2!"的十六进制表示
    ciphertext = sm2_encrypt(Q, plaintext)
    print(f"加密结果: {ciphertext}")

    decrypted = sm2_decrypt(d, ciphertext)
    print(f"解密结果: {decrypted}")
    print(f"解密是否正确: {decrypted == plaintext}")


if __name__ == "__main__":
    test_sm2()
