from flask import Flask, render_template, request, jsonify
import time
import secrets
import numpy as np
import psutil
import os
from typing import Tuple, List
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__, template_folder='html', static_folder='html')

# 签名算法基类及实现（保留原有算法逻辑）
class SignatureAlgorithm:
    def generate_keys(self) -> Tuple[object, object]:
        raise NotImplementedError

    def sign(self, private_key: object, message: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, public_key: object, message: bytes, signature: bytes) -> bool:
        raise NotImplementedError

    def get_name(self) -> str:
        raise NotImplementedError

class RSAAlgorithm(SignatureAlgorithm):
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keys(self) -> Tuple[object, object]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(self, private_key: object, message: bytes) -> bytes:
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        return signature

    def verify(self, public_key: object, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def get_name(self) -> str:
        return f"RSA-{self.key_size}"

class DSAAlgorithm(SignatureAlgorithm):
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keys(self) -> Tuple[object, object]:
        private_key = dsa.generate_private_key(
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(self, private_key: object, message: bytes) -> bytes:
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )
        return signature

    def verify(self, public_key: object, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def get_name(self) -> str:
        return f"DSA-{self.key_size}"

class ECDSAAlgorithm(SignatureAlgorithm):
    def __init__(self, curve: ec.EllipticCurve = ec.SECP256R1()):
        self.curve = curve

    def generate_keys(self) -> Tuple[object, object]:
        private_key = ec.generate_private_key(
            self.curve,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(self, private_key: object, message: bytes) -> bytes:
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify(self, public_key: object, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def get_name(self) -> str:
        curve_name = type(self.curve).__name__
        return f"ECDSA-{curve_name}"

class SignatureTester:
    def __init__(self, algorithms: List[SignatureAlgorithm]):
        self.algorithms = algorithms

    def test_performance(self, message: bytes, num_tests: int = 10) -> dict:
        results = {}
        process = psutil.Process(os.getpid())

        for algorithm in self.algorithms:
            name = algorithm.get_name()
            algorithm_results = {
                'key_generation_time': [],
                'signing_time': [],
                'verification_time': [],
                'signature_length': [],
                'key_generation_memory': [],
                'signing_memory': [],
                'verification_memory': [],
                'cpu_usage': []
            }

            for _ in range(num_tests):
                # 测试密钥生成时间和内存
                start_time = time.time()
                mem_before = process.memory_info().rss
                cpu_before = psutil.cpu_percent(interval=None)
                private_key, public_key = algorithm.generate_keys()
                key_gen_time = time.time() - start_time
                mem_after = process.memory_info().rss
                cpu_after = psutil.cpu_percent(interval=None)
                algorithm_results['key_generation_time'].append(key_gen_time)
                algorithm_results['key_generation_memory'].append((mem_after - mem_before) / 1024 / 1024)
                algorithm_results['cpu_usage'].append((cpu_before + cpu_after) / 2)

                # 测试签名生成时间和内存
                start_time = time.time()
                mem_before = process.memory_info().rss
                signature = algorithm.sign(private_key, message)
                sign_time = time.time() - start_time
                mem_after = process.memory_info().rss
                algorithm_results['signing_time'].append(sign_time)
                algorithm_results['signing_memory'].append((mem_after - mem_before) / 1024 / 1024)

                # 测试签名验证时间和内存
                start_time = time.time()
                mem_before = process.memory_info().rss
                is_valid = algorithm.verify(public_key, message, signature)
                verify_time = time.time() - start_time
                mem_after = process.memory_info().rss
                algorithm_results['verification_time'].append(verify_time)
                algorithm_results['verification_memory'].append((mem_after - mem_before) / 1024 / 1024)

                # 记录签名长度
                algorithm_results['signature_length'].append(len(signature))

                # 确保验证结果正确
                assert is_valid, f"{name}验证失败"

            # 计算平均值
            results[name] = {
                'key_generation_time': np.mean(algorithm_results['key_generation_time']),
                'signing_time': np.mean(algorithm_results['signing_time']),
                'verification_time': np.mean(algorithm_results['verification_time']),
                'signature_length': np.mean(algorithm_results['signature_length']),
                'security_level': self._get_security_level(name),
                'key_generation_memory': np.mean(algorithm_results['key_generation_memory']),
                'signing_memory': np.mean(algorithm_results['signing_memory']),
                'verification_memory': np.mean(algorithm_results['verification_memory']),
                'cpu_usage': np.mean(algorithm_results['cpu_usage'])
            }

        return results

    def _get_security_level(self, algorithm_name: str) -> int:
        if algorithm_name.startswith('RSA-') or algorithm_name.startswith('DSA-'):
            return int(algorithm_name.split('-')[1]) // 2
        elif algorithm_name.startswith('ECDSA-'):
            if 'SECP256R1' in algorithm_name:
                return 128
            elif 'SECP384R1' in algorithm_name:
                return 192
            elif 'SECP521R1' in algorithm_name:
                return 256

# 初始化算法
algorithms = [
    RSAAlgorithm(key_size=2048),
    RSAAlgorithm(key_size=3072),
    RSAAlgorithm(key_size=4096),
    DSAAlgorithm(key_size=2048),
    DSAAlgorithm(key_size=3072),
    ECDSAAlgorithm(curve=ec.SECP256R1()),
    ECDSAAlgorithm(curve=ec.SECP384R1()),
]

tester = SignatureTester(algorithms)

# Web路由
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/test', methods=['POST'])
def run_test():
    data = request.json
    message_size = int(data.get('message_size', 1024))
    num_tests = int(data.get('num_tests', 10))
    message = secrets.token_bytes(message_size)
    results = tester.test_performance(message, num_tests)
    return jsonify(results)

@app.route('/api/sign', methods=['POST'])
def sign_message():
    data = request.json
    algorithm_name = data.get('algorithm')
    message = data.get('message', '').encode('utf-8')

    # 查找选中的算法
    selected_alg = None
    for alg in algorithms:
        if alg.get_name() == algorithm_name:
            selected_alg = alg
            break

    if not selected_alg:
        return jsonify({'error': '算法不存在'}), 400

    # 生成密钥和签名
    private_key, public_key = selected_alg.generate_keys()
    signature = selected_alg.sign(private_key, message)
    is_valid = selected_alg.verify(public_key, message, signature)

    # 序列化密钥以便显示
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return jsonify({
        'algorithm': selected_alg.get_name(),
        'signature': signature.hex(),
        'signature_length': len(signature),
        'is_valid': is_valid,
        'private_key': private_pem.decode('utf-8'),
        'public_key': public_pem.decode('utf-8')
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)