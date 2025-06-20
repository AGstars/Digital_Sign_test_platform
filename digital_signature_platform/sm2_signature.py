import random
import math
from typing import Tuple, List

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

class SM3:
    """SM3哈希算法实现"""
    
    def __init__(self):
        self.block_size = 64  # 64字节 = 512位
        self.digest_size = 32  # 32字节 = 256位
        self.T_j = [
            0x79cc4519 if 0 <= j <= 15 else 0x7a879d8a for j in range(64)
        ]
    
    def hash(self, message: bytes) -> bytes:
        """计算消息的SM3哈希值"""
        # 填充消息
        padded = self._pad_message(message)
        
        # 初始化哈希值
        h = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
             0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
        
        # 处理每个数据块
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            h = self._process_block(block, h)
        
        # 将哈希值转换为字节
        digest = b''
        for x in h:
            digest += x.to_bytes(4, 'big')
        
        return digest
    
    def _pad_message(self, message: bytes) -> bytes:
        """填充消息到512位的倍数"""
        original_length = len(message) * 8  # 消息长度（位）
        
        # 添加1个1比特
        padded = message + b'\x80'
        
        # 添加0比特，直到长度 ≡ 448 (mod 512)
        while (len(padded) * 8) % 512 != 448:
            padded += b'\x00'
        
        # 添加原始消息长度（64位）
        padded += original_length.to_bytes(8, 'big')
        
        return padded
    
    def _process_block(self, block: bytes, h: List[int]) -> List[int]:
        """处理一个数据块"""
        # 将块划分为16个32位字
        w = [int.from_bytes(block[i*4:(i+1)*4], 'big') for i in range(16)]
        
        # 扩展到68个字
        w.extend([0] * 52)  # 确保w有足够的空间
        for j in range(16, 68):
            w[j] = self._p1(w[j-16] ^ w[j-9] ^ self._rotate_left(w[j-3], 15)) ^ \
                   self._rotate_left(w[j-13], 7) ^ w[j-6]
        
        # 再扩展到64个字
        w_prime = [w[j] ^ w[j+4] for j in range(64)]
        
        # 初始化中间变量
        a, b, c, d, e, f, g, h_temp = h
        
        # 压缩函数
        for j in range(64):
            ss1 = self._rotate_left(
                (self._rotate_left(a, 12) + e + self._rotate_left(self.T_j[j], j % 32)) & 0xFFFFFFFF,
                7
            )
            ss2 = ss1 ^ self._rotate_left(a, 12)
            tt1 = (self._ffj(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (self._ggj(e, f, g, j) + h_temp + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = self._rotate_left(b, 9)
            b = a
            a = tt1
            h_temp = g
            g = self._rotate_left(f, 19)
            f = e
            e = self._p0(tt2)
        
        # 更新哈希值
        h[0] ^= a
        h[1] ^= b
        h[2] ^= c
        h[3] ^= d
        h[4] ^= e
        h[5] ^= f
        h[6] ^= g
        h[7] ^= h_temp
        
        return h
    
    def _ffj(self, x: int, y: int, z: int, j: int) -> int:
        """压缩函数中的FF_j函数"""
        if 0 <= j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)
    
    def _ggj(self, x: int, y: int, z: int, j: int) -> int:
        """压缩函数中的GG_j函数"""
        if 0 <= j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | ((~x) & z)
    
    def _p0(self, x: int) -> int:
        """置换函数P0"""
        return x ^ self._rotate_left(x, 9) ^ self._rotate_left(x, 17)
    
    def _p1(self, x: int) -> int:
        """置换函数P1"""
        return x ^ self._rotate_left(x, 15) ^ self._rotate_left(x, 23)
    
    def _rotate_left(self, x: int, n: int) -> int:
        """循环左移n位"""
        n = n % 32
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

class SM2:
    def __init__(self, curve: EllipticCurve = None):
        """初始化SM2签名器
        curve: 椭圆曲线，默认为SM2推荐曲线
        """
        if curve is None:
            # 使用SM2推荐曲线
            self.curve = EllipticCurve(
                p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
                a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
                b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940,
                G=(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
                   0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0),
                n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
                h=1
            )
        else:
            self.curve = curve
        
        self.private_key = None
        self.public_key = None
        self.sm3 = SM3()
    
    def generate_keys(self) -> None:
        """生成SM2密钥对"""
        # 选择私钥：1 ≤ d ≤ n-2
        self.private_key = random.randint(1, self.curve.n - 2)
        
        # 计算公钥：Q = dG
        self.public_key = self.curve.multiply(self.private_key, self.curve.G)
    
    def sign(self, message: bytes, user_id: bytes = b'1234567812345678') -> Tuple[int, int]:
        """使用私钥对消息进行签名
        message: 要签名的消息（字节）
        user_id: 用户ID（字节），默认为'1234567812345678'
        """
        if self.private_key is None or self.public_key is None:
            raise ValueError("密钥未生成，请先调用generate_keys方法")
        
        # 计算Z_A
        Z_A = self._calculate_Z(user_id, self.public_key)
        
        # 计算e = H(Z_A || M)
        e_bytes = self.sm3.hash(Z_A + message)
        e = int.from_bytes(e_bytes, 'big')
        
        n = self.curve.n
        d = self.private_key
        
        while True:
            # 选择随机数k ∈ [1, n-1]
            k = random.randint(1, n - 1)
            
            # 计算点 (x1, y1) = kG
            x1, y1 = self.curve.multiply(k, self.curve.G)
            
            # 计算 r = (e + x1) mod n
            r = (e + x1) % n
            if r == 0 or r + k == n:
                continue
            
            # 计算 s = ((1 + d)^(-1) * (k - r*d)) mod n
            d_inv = self.curve._mod_inverse(d + 1, n)
            s = (d_inv * (k - r * d)) % n
            if s == 0:
                continue
            
            return (r, s)
    
    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Tuple[int, int], 
               user_id: bytes = b'1234567812345678') -> bool:
        """使用公钥验证签名
        message: 消息（字节）
        signature: 签名(r, s)
        public_key: 公钥(x, y)
        user_id: 用户ID（字节），默认为'1234567812345678'
        """
        r, s = signature
        n = self.curve.n
        G = self.curve.G
        
        # 检查r和s是否在有效范围内
        if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
            return False
        
        # 计算Z_A
        Z_A = self._calculate_Z(user_id, public_key)
        
        # 计算e = H(Z_A || M)
        e_bytes = self.sm3.hash(Z_A + message)
        e = int.from_bytes(e_bytes, 'big')
        
        # 计算t = (r + s) mod n
        t = (r + s) % n
        if t == 0:
            return False
        
        # 计算点 (x1, y1) = sG + tQ
        point1 = self.curve.multiply(s, G)
        point2 = self.curve.multiply(t, public_key)
        x1, y1 = self.curve.add(point1, point2)
        
        # 验证 r' = (e + x1) mod n == r
        r_prime = (e + x1) % n
        return r_prime == r
    
    def _calculate_Z(self, user_id: bytes, public_key: Tuple[int, int]) -> bytes:
        """计算用户标识Z
        user_id: 用户ID（字节）
        public_key: 公钥(x, y)
        """
        # 计算ENTL_A，用户ID的比特长度
        entl_a = (len(user_id) * 8).to_bytes(2, 'big')
        
        # 拼接所有元素
        data = (entl_a + user_id + 
                self.curve.a.to_bytes(32, 'big') +
                self.curve.b.to_bytes(32, 'big') +
                self.curve.G[0].to_bytes(32, 'big') +
                self.curve.G[1].to_bytes(32, 'big') +
                public_key[0].to_bytes(32, 'big') +
                public_key[1].to_bytes(32, 'big'))
        
        # 计算哈希值
        return self.sm3.hash(data)

# 使用示例
if __name__ == "__main__":
    # 创建SM2签名器实例
    sm2 = SM2()
    
    # 生成密钥对
    sm2.generate_keys()
    
    # 打印公钥和私钥
    print(f"私钥: 0x{sm2.private_key:x}")
    print(f"公钥: (0x{sm2.public_key[0]:x}, 0x{sm2.public_key[1]:x})")
    
    # 要签名的消息
    message = b"Hello, SM2!"
    
    # 生成签名
    r, s = sm2.sign(message)
    print(f"签名: (r=0x{r:x}, s=0x{s:x})")
    
    # 验证签名
    valid = sm2.verify(message, (r, s), sm2.public_key)
    print(f"签名验证结果: {valid}")
    
    # 尝试验证错误的消息
    invalid_message = b"Hello, World!"
    invalid = sm2.verify(invalid_message, (r, s), sm2.public_key)
    print(f"错误消息验证结果: {invalid}")