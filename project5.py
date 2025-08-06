import random

from gmssl import sm3, func

# 椭圆曲线参数 (SM2推荐曲线)
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


# 点加运算
def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 != y2:
        return None  # 无穷远点

    if x1 != x2:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    else:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


# 点乘运算（快速幂）
def point_mul(k, P):
    result = None
    current = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result


# 密钥生成
def generate_key_pair():
    # 私钥 sk ∈ [1, n-2]
    sk = random.randint(1, n - 2)
    # 公钥 pk = sk * G
    pk = point_mul(sk, (Gx, Gy))
    return sk, pk


# SM3杂凑函数
def sm3_hash(data):
    return sm3.sm3_hash(func.bytes_to_list(data))


# 签名算法
def sign(sk, msg, Z):
    # Z为用户标识的杂凑值
    # 计算e = Hv(Z || M)
    global s
    e = sm3_hash(Z + msg)
    e = int(e, 16)

    while True:
        # 生成随机数k ∈ [1, n-1]
        k = random.randint(1, n - 1)
        # 计算kG = (x1, y1)
        kG = point_mul(k, (Gx, Gy))
        x1, y1 = kG

        # 计算r = (e + x1) mod n
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue

        # 计算s = ((1 + sk)^-1 * (k - r * sk)) mod n
        inv = pow(1 + sk, n - 2, n)
        s = (inv * (k - r * sk)) % n
        if s != 0:
            break

    return (r, s)


# 验证算法
def verify(pk, msg, Z, signature):
    r, s = signature

    # 验证r和s的范围
    if not (1 <= r < n and 1 <= s < n):
        return False

    # 计算e = Hv(Z || M)
    e = sm3_hash(Z + msg)
    e = int(e, 16)

    # 计算t = (r + s) mod n
    t = (r + s) % n
    if t == 0:
        return False

    # 计算u1 = (e * t) mod n, u2 = (r * t) mod n
    u1 = (e * t) % n
    u2 = (r * t) % n

    # 计算u1G + u2pk = (x1, y1)
    P = point_add(point_mul(u1, (Gx, Gy)), point_mul(u2, pk))
    if P is None:
        return False

    x1, y1 = P
    # 计算R = (e + x1) mod n
    R = (e + x1) % n

    return R == r


# 加密算法
def encrypt(pk, msg):
    # 生成随机数k ∈ [1, n-1]
    k = random.randint(1, n - 1)
    # 计算kG = (x1, y1)
    kG = point_mul(k, (Gx, Gy))
    x1, y1 = kG

    # 计算kpk = (x2, y2)
    kpk = point_mul(k, pk)
    x2, y2 = kpk

    # 计算t = KDF(x2 || y2, len(msg))
    t = kdf(hex(x2)[2:] + hex(y2)[2:], len(msg))
    if int(t, 16) == 0:
        return encrypt(pk, msg)

    # 计算C1 = kG, C2 = M ⊕ t, C3 = Hv(x2 || M || y2)
    C1 = (x1, y1)
    C2 = bytes(a ^ b for a, b in zip(msg, bytes.fromhex(t)))
    C3 = sm3_hash(hex(x2)[2:].encode() + msg + hex(y2)[2:].encode())

    return (C1, C2, C3)


# 解密算法
def decrypt(sk, ciphertext):
    C1, C2, C3 = ciphertext
    x1, y1 = C1

    # 验证C1是否在椭圆曲线上
    if not is_on_curve((x1, y1)):
        return None

    # 计算skC1 = (x2, y2)
    skC1 = point_mul(sk, (x1, y1))
    x2, y2 = skC1

    # 计算t = KDF(x2 || y2, len(C2))
    t = kdf(hex(x2)[2:] + hex(y2)[2:], len(C2))

    # 计算M' = C2 ⊕ t
    M_prime = bytes(a ^ b for a, b in zip(C2, bytes.fromhex(t)))

    # 计算u = Hv(x2 || M' || y2)
    u = sm3_hash(hex(x2)[2:].encode() + M_prime + hex(y2)[2:].encode())

    if u == C3:
        return M_prime
    else:
        return None


# 密钥派生函数
def kdf(z, klen):
    # z为16进制字符串，klen为密钥长度（字节）
    hlen = 32  # SM3哈希值长度为32字节
    n = (klen + hlen - 1) // hlen  # 计算需要的迭代次数

    t = ''
    for i in range(1, n + 1):
        # 计算c_i = SM3(Z || ct_i)，ct_i为32位大端整数
        ct = hex(i)[2:].zfill(8)  # 转换为8位16进制字符串
        t += sm3_hash(bytes.fromhex(z + ct))

    return t[:2 * klen]  # 返回前klen字节


# 验证点是否在椭圆曲线上
def is_on_curve(P):
    x, y = P
    # 验证 y^2 ≡ x^3 + a x + b (mod p)
    return (y * y - x * x * x - a * x - b) % p == 0


# 测试函数
def test_sm2():
    # 生成密钥对
    sk, pk = generate_key_pair()
    print(f"私钥: {hex(sk)}")
    print(f"公钥: ({hex(pk[0])}, {hex(pk[1])})")

    # 用户标识
    ID = b"ALICE123@YAHOO.COM"
    # 计算Z = Hv(ENTL || ID || a || b || Gx || Gy || px || py)
    ENTL = hex(len(ID) * 8)[2:].zfill(4)  # 16位
    Z = sm3_hash(
        bytes.fromhex(ENTL) + ID +
        bytes.fromhex(hex(a)[2:].zfill(64)) +
        bytes.fromhex(hex(b)[2:].zfill(64)) +
        bytes.fromhex(hex(Gx)[2:].zfill(64)) +
        bytes.fromhex(hex(Gy)[2:].zfill(64)) +
        bytes.fromhex(hex(pk[0])[2:].zfill(64)) +
        bytes.fromhex(hex(pk[1])[2:].zfill(64))
    )
    Z = bytes.fromhex(Z)

    # 测试签名验证
    msg = b"Hello SM2!"
    signature = sign(sk, msg, Z)
    print(f"签名: (r={hex(signature[0])}, s={hex(signature[1])})")

    valid = verify(pk, msg, Z, signature)
    print(f"签名验证结果: {'成功' if valid else '失败'}")

    # 测试加密解密
    ciphertext = encrypt(pk, msg)
    print(
        f"加密结果: C1=({hex(ciphertext[0][0])}, {hex(ciphertext[0][1])}), C2={ciphertext[1].hex()}, C3={ciphertext[2]}")

    plaintext = decrypt(sk, ciphertext)
    print(f"解密结果: {plaintext.decode()}")
    print(f"解密验证: {'成功' if plaintext == msg else '失败'}")


if __name__ == "__main__":
    test_sm2()
