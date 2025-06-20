import random
import math
from typing import Tuple

class DSASigner:
    def __init__(self):
        self.private_key = None  # x
        self.public_key = None   # y = g^x mod p
        self.p = None
        self.q = None
        self.g = None
    
    def generate_keys(self, L: int = 1024, N: int = 160) -> None:
        """生成DSA密钥对
        L: 模数p的位数，通常为1024, 2048或3072
        N: 子群阶q的位数，通常为160或256
        """
        # 生成p和q
        self.p, self.q = self._generate_p_q(L, N)
        
        # 生成g
        self.g = self._generate_g()
        
        # 生成私钥x
        self.private_key = random.randint(1, self.q - 1)
        
        # 生成公钥y
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.private_key, self.public_key
    
    def sign(self, message: int, k: int = None) -> Tuple[int, int]:
        """使用私钥对消息进行签名
        message: 要签名的消息的哈希值
        k: 可选的随机数，如果未提供则生成一个
        """
        if self.private_key is None or self.public_key is None:
            raise ValueError("密钥未生成，请先调用generate_keys方法")
        
        # 如果未提供k，则生成一个随机数
        if k is None:
            k = random.randint(1, self.q - 1)
        
        # 计算r = (g^k mod p) mod q
        r = pow(self.g, k, self.p) % self.q
        if r == 0:
            # 如果r为0，需要重新选择k
            return self.sign(message, random.randint(1, self.q - 1))
        
        # 计算s = (k^(-1) * (H(m) + x*r)) mod q
        k_inv = self._modular_inverse(k, self.q)
        s = (k_inv * (message + self.private_key * r)) % self.q
        if s == 0:
            # 如果s为0，需要重新选择k
            return self.sign(message, random.randint(1, self.q - 1))
        
        return (r, s)
    
    def verify(self, message: int, signature: Tuple[int, int]) -> bool:
        """使用公钥验证签名
        message: 消息的哈希值
        signature: 签名(r, s)
        """
        r, s = signature
        
        # 检查r和s是否在有效范围内
        if not (1 <= r <= self.q - 1 and 1 <= s <= self.q - 1):
            return False
        
        # 计算w = s^(-1) mod q
        w = self._modular_inverse(s, self.q)
        
        # 计算u1 = (H(m) * w) mod q
        u1 = (message * w) % self.q
        
        # 计算u2 = (r * w) mod q
        u2 = (r * w) % self.q
        
        # 计算v = ((g^u1 * y^u2) mod p) mod q
        v1 = pow(self.g, u1, self.p)
        v2 = pow(self.public_key, u2, self.p)
        v = (v1 * v2) % self.p
        v = v % self.q
        
        return v == r
    
    def _generate_p_q(self, L: int, N: int) -> Tuple[int, int]:
        """生成DSA参数p和q"""
        # 生成q，一个N位的素数
        q = self._generate_large_prime(N)
        
        # 生成p，一个L位的素数，并且满足p-1能被q整除
        p = 0
        while True:
            # 生成一个L位的随机数
            seed = random.getrandbits(L - 1)
            # 确保p的位数正确
            p_candidate = (seed // q) * q + 1
            # 确保p是奇数
            if p_candidate % 2 == 0:
                p_candidate += 1
            
            # 检查p是否为素数
            if self._is_prime(p_candidate):
                p = p_candidate
                break
        
        return (p, q)
    
    def _generate_g(self) -> int:
        """生成DSA参数g"""
        h = random.randint(2, self.p - 2)
        e = (self.p - 1) // self.q
        g = pow(h, e, self.p)
        
        # 确保g的阶为q
        if g == 1:
            return self._generate_g()
        
        return g
    
    def _generate_large_prime(self, bit_length: int) -> int:
        """生成指定位数的大质数"""
        while True:
            # 生成随机数
            p = random.getrandbits(bit_length)
            # 确保数字是奇数且大小合适
            p |= (1 << bit_length - 1) | 1
            
            # 检查是否为质数
            if self._is_prime(p):
                return p
    
    def _is_prime(self, n: int, k: int = 40) -> bool:
        """使用Miller-Rabin素性测试检查数字是否为质数"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        # 将n-1表示为2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # 进行k次测试
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _modular_inverse(self, a: int, m: int) -> int:
        """计算模逆元，即满足 (a * x) % m == 1 的x"""
        g, x, y = self._extended_gcd(a, m)
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

# 使用示例
if __name__ == "__main__":
    # 创建DSA签名器实例
    signer = DSASigner()
    
    # 生成密钥对
    signer.generate_keys(L=1024, N=160)
    
    # 要签名的消息（通常是消息的哈希值，这里简化为一个整数）
    message_hash = 123456789  # 代表消息的哈希值
    
    # 生成签名
    r, s = signer.sign(message_hash)
    print(f"签名: (r={r}, s={s})")
    
    # 验证签名
    valid = signer.verify(message_hash, (r, s))
    print(f"签名验证结果: {valid}")
    
    # 尝试验证错误的消息
    invalid_message_hash = 987654321
    invalid = signer.verify(invalid_message_hash, (r, s))
    print(f"错误消息验证结果: {invalid}")