import random
from sm2 import *


# 漏洞1: 使用固定随机数k进行签名
def vulnerability_fixed_k():
    print("=== 测试固定随机数k漏洞 ===")

    # 生成密钥对
    sk, pk = generate_key_pair()
    ID = b"VULNERABLE_USER"

    # 计算用户标识杂凑值Z
    ENTL = hex(len(ID) * 8)[2:].zfill(4)
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

    # 使用固定的k进行两次签名
    fixed_k = random.randint(1, n - 1)  # 固定的随机数

    # 第一次签名
    msg1 = b"message1"
    e1 = sm3_hash(Z + msg1)
    e1 = int(e1, 16)
    kG1 = point_mul(fixed_k, (Gx, Gy))
    x1_1, y1_1 = kG1
    r1 = (e1 + x1_1) % n
    inv1 = pow(1 + sk, n - 2, n)
    s1 = (inv1 * (fixed_k - r1 * sk)) % n
    sig1 = (r1, s1)

    # 第二次签名
    msg2 = b"message2"
    e2 = sm3_hash(Z + msg2)
    e2 = int(e2, 16)
    kG2 = point_mul(fixed_k, (Gx, Gy))  # 同样的k，得到同样的点
    x1_2, y1_2 = kG2
    r2 = (e2 + x1_2) % n
    inv2 = pow(1 + sk, n - 2, n)
    s2 = (inv2 * (fixed_k - r2 * sk)) % n
    sig2 = (r2, s2)

    # 验证签名有效
    assert verify(pk, msg1, Z, sig1), "签名1验证失败"
    assert verify(pk, msg2, Z, sig2), "签名2验证失败"
    print("两次签名均有效")

    # 从两个签名推导私钥sk
    # 由s1 = (1+sk)^-1 * (k - r1*sk)
    # 由s2 = (1+sk)^-1 * (k - r2*sk)
    # 两式相除得 s1/s2 = (k - r1*sk)/(k - r2*sk)
    # 整理得 sk = (s2*k - s1*k) / (s2*r1 - s1*r2 + s1 - s2)

    # 计算k = (s1*(1+sk) + r1*sk) 但我们不知道sk，换种方式
    # 另一种方法：由r1 = (e1 + x1) mod n，x1是kG的x坐标
    # 由于使用了相同的k，x1_1 = x1_2 = x1

    # 推导过程：
    # s1*(1+sk) ≡ k - r1*sk mod n
    # s1 + s1*sk ≡ k - r1*sk mod n
    # s1 + sk*(s1 + r1) ≡ k mod n ...(1)

    # 同理对s2:
    # s2 + sk*(s2 + r2) ≡ k mod n ...(2)

    # (1)-(2)得:
    # s1 - s2 + sk*(s1 + r1 - s2 - r2) ≡ 0 mod n
    # 解得:
    # sk ≡ (s2 - s1) / (s1 + r1 - s2 - r2) mod n

    numerator = (s2 - s1) % n
    denominator = (s1 + r1 - s2 - r2) % n
    if denominator == 0:
        print("无法推导私钥（分母为0）")
        return

    inv_denominator = pow(denominator, n - 2, n)
    derived_sk = (numerator * inv_denominator) % n

    print(f"原始私钥: {hex(sk)}")
    print(f"推导私钥: {hex(derived_sk)}")
    print(f"私钥推导{'成功' if derived_sk == sk else '失败'}")

    return derived_sk == sk


# 漏洞2: 签名结果泄露随机数k
def vulnerability_expose_k():
    print("\n=== 测试泄露随机数k漏洞 ===")

    # 生成密钥对
    sk, pk = generate_key_pair()
    ID = b"EXPOSE_K_USER"

    # 计算用户标识杂凑值Z
    ENTL = hex(len(ID) * 8)[2:].zfill(4)
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

    # 生成签名并泄露k
    msg = b"secret message"
    k = random.randint(1, n - 1)

    # 计算签名
    e = sm3_hash(Z + msg)
    e = int(e, 16)
    kG = point_mul(k, (Gx, Gy))
    x1, y1 = kG
    r = (e + x1) % n
    inv = pow(1 + sk, n - 2, n)
    s = (inv * (k - r * sk)) % n
    sig = (r, s)

    # 验证签名有效
    assert verify(pk, msg, Z, sig), "签名验证失败"
    print("签名有效")

    # 从泄露的k推导私钥
    # 由s = (1+sk)^-1 * (k - r*sk)
    # 得: s*(1+sk) = k - r*sk
    # s + s*sk = k - r*sk
    # s*sk + r*sk = k - s
    # sk*(s + r) = k - s
    # sk = (k - s) / (s + r) mod n

    numerator = (k - s) % n
    denominator = (s + r) % n
    if denominator == 0:
        print("无法推导私钥（分母为0）")
        return

    inv_denominator = pow(denominator, n - 2, n)
    derived_sk = (numerator * inv_denominator) % n

    print(f"原始私钥: {hex(sk)}")
    print(f"推导私钥: {hex(derived_sk)}")
    print(f"私钥推导{'成功' if derived_sk == sk else '失败'}")

    return derived_sk == sk


# 漏洞3: 错误的签名验证实现
def vulnerability_bad_verification():
    print("\n=== 测试错误的签名验证实现漏洞 ===")

    # 生成密钥对
    sk, pk = generate_key_pair()
    ID = b"BAD_VERIFY_USER"

    # 计算用户标识杂凑值Z
    ENTL = hex(len(ID) * 8)[2:].zfill(4)
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

    # 正确签名
    msg = b"original message"
    sig = sign(sk, msg, Z)
    r, s = sig
    assert verify(pk, msg, Z, sig), "正确签名验证失败"
    print("正确签名验证通过")

    # 错误的验证实现：不检查t=0的情况
    def bad_verify(pk, msg, Z, signature):
        r, s = signature
        if not (1 <= r < n and 1 <= s < n):
            return False

        e = sm3_hash(Z + msg)
        e = int(e, 16)

        t = (r + s) % n
        # 错误：没有检查t是否为0

        u1 = (e * t) % n
        u2 = (r * t) % n

        P = point_add(point_mul(u1, (Gx, Gy)), point_mul(u2, pk))
        if P is None:
            return False

        x1, y1 = P
        R = (e + x1) % n

        return R == r

    # 构造一个t=0的伪造签名
    fake_s = (n - r) % n  # 使r + s ≡ 0 mod n
    fake_sig = (r, fake_s)

    # 使用错误的验证函数会通过验证
    bad_result = bad_verify(pk, msg, Z, fake_sig)
    # 使用正确的验证函数会拒绝
    good_result = verify(pk, msg, Z, fake_sig)

    print(f"错误验证函数结果: {'通过' if bad_result else '拒绝'}")
    print(f"正确验证函数结果: {'通过' if good_result else '拒绝'}")
    print(f"漏洞利用{'成功' if bad_result and not good_result else '失败'}")

    return bad_result and not good_result


def main():
    # 运行所有漏洞测试
    vuln1 = vulnerability_fixed_k()
    vuln2 = vulnerability_expose_k()
    vuln3 = vulnerability_bad_verification()

    print("\n=== 测试总结 ===")
    print(f"固定随机数漏洞: {'存在' if vuln1 else '不存在'}")
    print(f"泄露随机数漏洞: {'存在' if vuln2 else '不存在'}")
    print(f"错误验证实现漏洞: {'存在' if vuln3 else '不存在'}")


if __name__ == "__main__":
    main()
