import time
import secrets
import numpy as np
import matplotlib.pyplot as plt
from typing import Tuple, List
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

class SignatureAlgorithm:
    """签名算法基类"""
    def generate_keys(self) -> Tuple[object, object]:
        """生成密钥对"""
        raise NotImplementedError

    def sign(self, private_key: object, message: bytes) -> bytes:
        """生成签名"""
        raise NotImplementedError

    def verify(self, public_key: object, message: bytes, signature: bytes) -> bool:
        """验证签名"""
        raise NotImplementedError

    def get_name(self) -> str:
        """获取算法名称"""
        raise NotImplementedError

class RSAAlgorithm(SignatureAlgorithm):
    """RSA签名算法实现"""
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
    """DSA签名算法实现"""
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
    """ECDSA签名算法实现"""
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
    """签名测试器"""
    def __init__(self, algorithms: List[SignatureAlgorithm]):
        self.algorithms = algorithms

    def test_performance(self, message: bytes, num_tests: int = 10) -> dict:
        """测试算法性能"""
        results = {}

        for algorithm in self.algorithms:
            name = algorithm.get_name()
            algorithm_results = {
                'key_generation_time': [],
                'signing_time': [],
                'verification_time': [],
                'signature_length': []
            }

            for _ in range(num_tests):
                # 测试密钥生成时间
                start_time = time.time()
                private_key, public_key = algorithm.generate_keys()
                key_gen_time = time.time() - start_time
                algorithm_results['key_generation_time'].append(key_gen_time)

                # 测试签名生成时间
                start_time = time.time()
                signature = algorithm.sign(private_key, message)
                sign_time = time.time() - start_time
                algorithm_results['signing_time'].append(sign_time)

                # 测试签名验证时间
                start_time = time.time()
                is_valid = algorithm.verify(public_key, message, signature)
                verify_time = time.time() - start_time
                algorithm_results['verification_time'].append(verify_time)

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
                'security_level': self._get_security_level(name)
            }

        return results

    def _get_security_level(self, algorithm_name: str) -> int:
        """获取算法安全级别"""
        if algorithm_name.startswith('RSA-') or algorithm_name.startswith('DSA-'):
            return int(algorithm_name.split('-')[1]) // 2
        elif algorithm_name.startswith('ECDSA-'):
            if 'SECP256R1' in algorithm_name:
                return 128
            elif 'SECP384R1' in algorithm_name:
                return 192
            elif 'SECP521R1' in algorithm_name:
                return 256
                
    def print_results(self, results: dict) -> None:
        """打印测试结果"""
        print("\n性能测试结果:")
        print("{:<15} {:<20} {:<20} {:<20} {:<20} {:<15}".format(
            "算法", "密钥生成时间(秒)", "签名生成时间(秒)", "签名验证时间(秒)", "签名长度(字节)", "安全级别(位)"
        ))
        print("-" * 110)

        for algorithm, metrics in results.items():
            print("{:<15} {:<20.6f} {:<20.6f} {:<20.6f} {:<20.0f} {:<15}".format(
                algorithm,
                metrics['key_generation_time'],
                metrics['signing_time'],
                metrics['verification_time'],
                metrics['signature_length'],
                metrics['security_level']
            ))

    def plot_results(self, results: dict) -> None:
        """绘制性能对比图"""
        algorithms = list(results.keys())
        key_gen_times = [results[alg]['key_generation_time'] for alg in algorithms]
        signing_times = [results[alg]['signing_time'] for alg in algorithms]
        verification_times = [results[alg]['verification_time'] for alg in algorithms]
        signature_lengths = [results[alg]['signature_length'] for alg in algorithms]

        x = np.arange(len(algorithms))
        width = 0.2

        fig, axs = plt.subplots(2, 2, figsize=(12, 10))

        # 密钥生成时间
        axs[0, 0].bar(x, key_gen_times, width)
        axs[0, 0].set_ylabel('时间 (秒)')
        axs[0, 0].set_title('密钥生成时间')
        axs[0, 0].set_xticks(x)
        axs[0, 0].set_xticklabels(algorithms, rotation=45)

        # 签名生成时间
        axs[0, 1].bar(x, signing_times, width)
        axs[0, 1].set_ylabel('时间 (秒)')
        axs[0, 1].set_title('签名生成时间')
        axs[0, 1].set_xticks(x)
        axs[0, 1].set_xticklabels(algorithms, rotation=45)

        # 签名验证时间
        axs[1, 0].bar(x, verification_times, width)
        axs[1, 0].set_ylabel('时间 (秒)')
        axs[1, 0].set_title('签名验证时间')
        axs[1, 0].set_xticks(x)
        axs[1, 0].set_xticklabels(algorithms, rotation=45)

        # 签名长度
        axs[1, 1].bar(x, signature_lengths, width)
        axs[1, 1].set_ylabel('字节')
        axs[1, 1].set_title('签名长度')
        axs[1, 1].set_xticks(x)
        axs[1, 1].set_xticklabels(algorithms, rotation=45)

        plt.tight_layout()
        plt.show()


class SignatureUI:
    """签名算法用户界面"""
    def __init__(self, tester: SignatureTester):
        self.tester = tester

    def run(self) -> None:
        """运行用户界面"""
        while True:
            print("\n数字签名算法实验平台")
            print("1. 生成并验证签名")
            print("2. 运行性能测试")
            print("3. 退出")
            choice = input("请选择操作 (1-3): ")

            if choice == '1':
                self._run_signature_demo()
            elif choice == '2':
                self._run_performance_test()
            elif choice == '3':
                print("感谢使用!")
                break
            else:
                print("无效选择，请重试")

    def _run_signature_demo(self) -> None:
        """运行签名演示"""
        print("\n签名生成与验证演示")
        print("可用算法:")
        for i, alg in enumerate(self.tester.algorithms, 1):
            print(f"{i}. {alg.get_name()}")

        try:
            alg_choice = int(input("请选择算法 (1-{}): ".format(len(self.tester.algorithms))))
            if 1 <= alg_choice <= len(self.tester.algorithms):
                algorithm = self.tester.algorithms[alg_choice - 1]
                message = input("请输入要签名的消息: ").encode('utf-8')

                # 生成密钥
                private_key, public_key = algorithm.generate_keys()
                print(f"已生成{algorithm.get_name()}密钥对")

                # 生成签名
                signature = algorithm.sign(private_key, message)
                print(f"签名生成成功，长度: {len(signature)} 字节")

                # 验证签名
                is_valid = algorithm.verify(public_key, message, signature)
                print(f"签名验证结果: {'有效' if is_valid else '无效'}")
            else:
                print("无效选择")
        except ValueError:
            print("请输入数字")

    def _run_performance_test(self) -> None:
        """运行性能测试"""
        print("\n性能测试")
        message_size = int(input("请输入测试消息大小 (字节): "))
        num_tests = int(input("请输入每个算法的测试次数: "))

        # 生成随机消息
        message = secrets.token_bytes(message_size)

        # 运行测试
        print("\n正在运行测试，请稍候...")
        results = self.tester.test_performance(message, num_tests)

        # 显示结果
        self.tester.print_results(results)

        # 询问是否绘制图表
        plot_choice = input("是否显示性能对比图? (y/n): ").lower()
        if plot_choice == 'y':
            self.tester.plot_results(results)


if __name__ == "__main__":
    # 初始化算法
    algorithms = [
        RSAAlgorithm(key_size=2048),
        DSAAlgorithm(key_size=2048),
        ECDSAAlgorithm(curve=ec.SECP256R1()),
        ECDSAAlgorithm(curve=ec.SECP384R1()),
    ]

    # 初始化测试器
    tester = SignatureTester(algorithms)

    # 初始化用户界面
    ui = SignatureUI(tester)

    # 运行界面
    ui.run()