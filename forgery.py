import os
import hashlib
import ecdsa
from ecdsa.util import sigencode_string, sigdecode_string

# 比特币使用的曲线是secp256k1
curve = ecdsa.SECP256k1
hashfunc = hashlib.sha256


# 假设场景：如果中本聪曾重复使用过随机数k签名两个不同消息
def simulate_nakamoto_signatures():
    # 生成一个模拟的中本聪私钥
    private_key = ecdsa.SigningKey.generate(curve=curve, hashfunc=hashfunc)
    public_key = private_key.get_verifying_key()

    # 模拟重复使用随机数k
    k = int.from_bytes(os.urandom(32), byteorder='big') % curve.order

    # 对两个不同消息签名
    message1 = b"Bitcoin is a peer-to-peer electronic cash system"
    message2 = b"Transaction 12345: Send 10 BTC to Alice"

    # 使用相同的k签名两个消息
    sig1 = private_key.sign(message1, k=k, sigencode=sigencode_string)
    sig2 = private_key.sign(message2, k=k, sigencode=sigencode_string)

    return public_key, message1, sig1, message2, sig2, private_key


# 从两个使用相同k的签名中恢复私钥
def recover_private_key(public_key, message1, sig1, message2, sig2):
    # 解析签名
    r1, s1 = sigdecode_string(sig1, curve.order)
    r2, s2 = sigdecode_string(sig2, curve.order)

    # 确保r相同
    if r1 != r2:
        print("r值不同，无法恢复私钥")
        return None
    r = r1

    # 计算消息哈希
    e1 = int.from_bytes(hashfunc(message1).digest(), byteorder='big') % curve.order
    e2 = int.from_bytes(hashfunc(message2).digest(), byteorder='big') % curve.order

    # 计算私钥d = (s1 - s2) / (s2*r - s1*r + e1 - e2) mod n
    numerator = (s1 - s2) % curve.order
    denominator = (s2 * r - s1 * r + e1 - e2) % curve.order

    if denominator == 0:
        print("无法计算，分母为0")
        return None

    d = (numerator * pow(denominator, curve.order - 2, curve.order)) % curve.order
    return ecdsa.SigningKey.from_secret_exponent(d, curve=curve, hashfunc=hashfunc)


# 使用恢复的私钥伪造新签名
def forge_signature(recovered_private_key, message):
    return recovered_private_key.sign(message)

def demo_nakamoto_forgery():
    # 模拟中本聪签名场景
    public_key, msg1, sig1, msg2, sig2, real_private = simulate_nakamoto_signatures()
    print("模拟中本聪签名场景完成")

    # 攻击者恢复私钥
    recovered_private = recover_private_key(public_key, msg1, sig1, msg2, sig2)
    if not recovered_private:
        print("无法恢复私钥")
        return

    print("成功恢复私钥")

    # 验证恢复的私钥是否正确
    test_msg = b"Test message for verification"
    test_sig = recovered_private.sign(test_msg)
    try:
        public_key.verify(test_sig, test_msg)
        print("恢复的私钥验证成功")
    except:
        print("恢复的私钥验证失败")
        return

    # 伪造一个"中本聪"签名
    forged_msg = b"I, Satoshi Nakamoto, approve this transaction."
    forged_sig = forge_signature(recovered_private, forged_msg)

    # 验证伪造的签名
    try:
        public_key.verify(forged_sig, forged_msg)
        print("伪造签名验证成功！")
        print("伪造的消息:", forged_msg.decode())
        print("伪造的签名:", forged_sig.hex())
    except:
        print("伪造签名验证失败")

if __name__ == "__main__":
    demo_nakamoto_forgery()
