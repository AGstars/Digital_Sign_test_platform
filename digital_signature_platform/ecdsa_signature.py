import random
import math
from typing import Tuple

class EllipticCurve:
    def __init__(self, p: int, a: int, b: int, G: Tuple[int, int], n: int, h: int):
        """初始化椭圆曲线
        p: 有限域的阶
        a, b: 椭圆曲线方程 y² = x³ + ax + b 的系数
        G: 基点 (x, y)
        n: 基点G的阶
        h: 余因子
        """
        self.p = p
        self.a = a
        self.b = b
        self.G = G
        self.n = n
        self.h = h
    
    def is_on_curve(self, point: Tuple[int, int]) -> bool:
        """检查点是否在曲线上"""
        if point is None:  # 无穷远点
            return True
        
        x, y = point
        return (y*y - (x*x*x + self.a*x + self.b)) % self.p == 0
    
    def add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线上的点加法 P + Q"""
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 != y2:
            return None  # 无穷远点
        
        if P == Q:
            # 倍点运算
            s = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p)
        else:
            # 普通加法
            s = (y2 - y1) * self._mod_inverse(x2 - x1, self.p)
        
        s %= self.p
        x3 = (s*s - x1 - x2) % self.p
        y3 = (s*(x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def multiply(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线上的标量乘法 kP"""
        if k % self.n == 0 or P is None:
            return None
        
        result = None
        current = P
        
        while k:
            if k & 1:
                result = self.add(result, current)
            current = self.add(current, current)
            k >>= 1
        
        return result
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """计算模逆元，即满足 (a * x) % m == 1 的x"""
        g, x, y = self._extended_gcd(a % m, m)
        if g != 1:
            raise Exception("模逆元不存在")
        else:
            return x % m
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """扩展欧几里得算法，计算gcd和贝祖系数"""
        if a == 0:
            return (b, 0, 1)
        else:
            g, x, y = self._extended_gcd(b % a, a)
            return (g, y - (b // a) * x, x)

class ECDSASigner:
    def __init__(self, curve: EllipticCurve = None):
        """初始化ECDSA签名器
        curve: 椭圆曲线，默认为secp256k1
        """
        if curve is None:
            # 使用secp256k1曲线（比特币使用的曲线）
            self.curve = EllipticCurve(
                p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
                a=0,
                b=7,
                G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
                n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
                h=1
            )
        else:
            self.curve = curve
        
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> None:
        """生成ECDSA密钥对"""
        # 选择私钥：1 ≤ d ≤ n-1
        self.private_key = random.randint(1, self.curve.n - 1)
        
        # 计算公钥：Q = dG
        self.public_key = self.curve.multiply(self.private_key, self.curve.G)
        return self.private_key, self.public_key
    
    def sign(self, message_hash: int, k: int = None) -> Tuple[int, int]:
        """使用私钥对消息进行签名
        message_hash: 消息的哈希值（整数）
        k: 可选的随机数，如果未提供则生成一个
        """
        if self.private_key is None or self.public_key is None:
            raise ValueError("密钥未生成，请先调用generate_keys方法")
        
        n = self.curve.n
        
        # 如果未提供k，则生成一个随机数
        if k is None:
            k = random.randint(1, n - 1)
        
        # 计算点 (x1, y1) = kG
        x1, y1 = self.curve.multiply(k, self.curve.G)
        
        # 计算 r = x1 mod n
        r = x1 % n
        
        # 如果r为0，需要重新选择k
        if r == 0:
            return self.sign(message_hash, random.randint(1, n - 1))
        
        # 计算 s = k^(-1) * (hash + r*d) mod n
        k_inv = self.curve._mod_inverse(k, n)
        s = (k_inv * (message_hash + r * self.private_key)) % n
        
        # 如果s为0，需要重新选择k
        if s == 0:
            return self.sign(message_hash, random.randint(1, n - 1))
        
        # 为了兼容性，通常要求s <= n/2
        if s > n // 2:
            s = n - s
        
        return (r, s)
    
    def verify(self, message_hash: int, signature: Tuple[int, int]) -> bool:
        """使用公钥验证签名
        message_hash: 消息的哈希值（整数）
        signature: 签名(r, s)
        """
        if self.public_key is None:
            raise ValueError("公钥未生成，请先调用generate_keys方法")
        
        r, s = signature
        n = self.curve.n
        G = self.curve.G
        Q = self.public_key
        
        # 检查r和s是否在有效范围内
        if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
            return False
        
        # 计算 w = s^(-1) mod n
        w = self.curve._mod_inverse(s, n)
        
        # 计算 u1 = hash * w mod n
        u1 = (message_hash * w) % n
        
        # 计算 u2 = r * w mod n
        u2 = (r * w) % n
        
        # 计算点 (x1, y1) = u1*G + u2*Q
        point1 = self.curve.multiply(u1, G)
        point2 = self.curve.multiply(u2, Q)
        x1, y1 = self.curve.add(point1, point2)
        
        # 验证 r ≡ x1 mod n
        return r == (x1 % n)

# 使用示例
if __name__ == "__main__":
    # 创建ECDSA签名器实例（使用默认的secp256k1曲线）
    signer = ECDSASigner()
    
    # 生成密钥对
    signer.generate_keys()
    
    # 打印公钥和私钥
    print(f"私钥: {signer.private_key}")
    print(f"公钥: (0x{signer.public_key[0]:x}, 0x{signer.public_key[1]:x})")
    
    # 要签名的消息（通常是消息的哈希值，这里简化为一个整数）
    message_hash = 123456789  # 代表消息的哈希值
    
    # 生成签名
    r, s = signer.sign(message_hash)
    print(f"签名: (r=0x{r:x}, s=0x{s:x})")
    
    # 验证签名
    valid = signer.verify(message_hash, (r, s))
    print(f"签名验证结果: {valid}")
    
    # 尝试验证错误的消息
    invalid_message_hash = 987654321
    invalid = signer.verify(invalid_message_hash, (r, s))
    print(f"错误消息验证结果: {invalid}")