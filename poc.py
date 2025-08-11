import os
import hashlib
from gmssl import sm3, func

# 使用固定随机数k的签名函数
def sm2_sign_fixed_k(d, M, Z, fixed_k):
    M_prime = Z + M
    e = int(sm3_hash(bytes.fromhex(M_prime)), 16)

    k = fixed_k
    kG = point_mul(k, Point(Gx, Gy))
    r = (e + kG.x) % n

    s = (pow(1 + d, n - 2, n) * (k - r * d)) % n
    return (r, s)


# 从两个使用相同k的签名中恢复私钥d
def recover_private_key(M1, Z1, sig1, M2, Z2, sig2):
    r1, s1 = sig1
    r2, s2 = sig2

    # 确保两个签名使用了相同的r (表明可能使用了相同的k)
    if r1 != r2:
        print("r1 != r2，可能没有使用相同的随机数k")
        return None

    r = r1
    e1 = int(sm3_hash(bytes.fromhex(Z1 + M1)), 16)
    e2 = int(sm3_hash(bytes.fromhex(Z2 + M2)), 16)

    # 计算d = (s1 - s2) / (s2*r - s1*r + e1 - e2) mod n
    numerator = (s1 - s2) % n
    denominator = (s2 * r - s1 * r + e1 - e2) % n

    if denominator == 0:
        print("无法计算，分母为0")
        return None

    d = (numerator * pow(denominator, n - 2, n)) % n
    return d

# POC验证
def fixed_k_poc():
    # 生成合法密钥对
    d = int.from_bytes(os.urandom(32), byteorder='big') % (n - 1) + 1
    Q = point_mul(d, Point(Gx, Gy))
    Z = "00"  # 用户标识

    # 固定随机数k (漏洞点)
    fixed_k = 0x123456789ABCDEF

    # 对两个不同消息签名
    M1 = "48656C6C6F20576F726C64"
    M2 = "5468697320697320616E6F74686572206D657373616765"

    sig1 = sm2_sign_fixed_k(d, M1, Z, fixed_k)
    sig2 = sm2_sign_fixed_k(d, M2, Z, fixed_k)

    print(f"消息1签名: r={hex(sig1[0])}, s={hex(sig1[1])}")
    print(f"消息2签名: r={hex(sig2[0])}, s={hex(sig2[1])}")

    # 攻击者恢复私钥
    recovered_d = recover_private_key(M1, Z, sig1, M2, Z, sig2)
    print(f"原始私钥: {hex(d)}")
    print(f"恢复的私钥: {hex(recovered_d) if recovered_d else '无法恢复'}")

    # 验证恢复的私钥是否正确
    if recovered_d:
        # 使用恢复的私钥对新消息签名
        M3 = "466F72676564207369676E6174757265"
        forged_sig = sm2_sign_fixed_k(recovered_d, M3, Z, fixed_k)

        # 验证伪造的签名
        verify_result = sm2_verify(Q, M3, Z, forged_sig)
        print(f"伪造签名验证结果: {verify_result}")


# 辅助函数 (需要从前面的实现中导入或定义)
def point_mul(k, p):
    result = Point(0, 0, True)
    current = p
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result


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


def sm3_hash(data):
    return sm3.sm3_hash(func.bytes_to_list(data))


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


if __name__ == "__main__":
    fixed_k_poc()
