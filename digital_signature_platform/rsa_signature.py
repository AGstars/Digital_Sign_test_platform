import random
import math
from typing import Tuple

class RSASigner:
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self, bit_length: int = 1024) -> None:
        """生成RSA密钥对"""
        # 生成两个大质数p和q
        p = self._generate_large_prime(bit_length // 2)
        q = self._generate_large_prime(bit_length // 2)
        
        # 计算模数n和欧拉函数φ(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # 选择公钥指数e，通常选择65537
        e = 65537
        if phi_n <= e:
            raise ValueError("密钥长度过短，无法使用标准公钥指数")
        
        # 计算私钥指数d，满足 (d * e) % phi_n == 1
        d = self._modular_inverse(e, phi_n)
        
        # 保存密钥对
        self.private_key = (d, n)
        self.public_key = (e, n)
        return self.private_key, self.public_key
    
    def sign(self, message: int) -> int:
        """使用私钥对消息进行签名"""
        if self.private_key is None:
            raise ValueError("私钥未生成，请先调用generate_keys方法")
        
        d, n = self.private_key
        # 签名过程：s = message^d mod n
        return pow(message, d, n)
    
    def verify(self, message: int, signature: int) -> bool:
        """使用公钥验证签名"""
        if self.public_key is None:
            raise ValueError("公钥未生成，请先调用generate_keys方法")
        
        e, n = self.public_key
        # 验证过程：message == signature^e mod n
        return message == pow(signature, e, n)
    
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
    
    def _gcd(self, a: int, b: int) -> int:
        """计算两个数的最大公约数"""
        while b:
            a, b = b, a % b
        return a
    
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
    # 创建RSA签名器实例
    signer = RSASigner()
    
    # 生成密钥对
    signer.generate_keys(2048)
    
    # 要签名的消息（转换为整数）
    message = 123456789
    
    # 生成签名
    signature = signer.sign(message)
    print(f"签名: {signature}")
    
    # 验证签名
    valid = signer.verify(message, signature)
    print(f"签名验证结果: {valid}")
    
    # 尝试验证错误的消息
    invalid_message = 987654321
    invalid = signer.verify(invalid_message, signature)
    print(f"错误消息验证结果: {invalid}")