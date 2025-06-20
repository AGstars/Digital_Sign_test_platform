import time
import dsa_signature
import ecdsa_signature
import rsa_signature
import sm2_signature

def generate_keys(signer):
    start_time = time.time()
    signer.generate_keys()
    end_time = time.time()
    return end_time - start_time

def sign_message(signer, message):
    start_time = time.time()
    if isinstance(signer, sm2_signature.SM2):
        signature = signer.sign(message.encode())
    else:
        signature = signer.sign(hash(message))
    end_time = time.time()
    sign_time = end_time - start_time
    sign_length = len(str(signature).encode())
    return signature, sign_time, sign_length

def verify_signature(signer, message, signature):
    start_time = time.time()
    if isinstance(signer, sm2_signature.SM2):
        valid = signer.verify(message.encode(), signature, signer.public_key)
    else:
        valid = signer.verify(hash(message), signature)
    end_time = time.time()
    return end_time - start_time, valid

def performance_test():
    messages = ["Test message 1", "Test message 2", "Test message 3"]

    algorithms = [
        ("DSA", dsa_signature.DSASigner()),
        ("ECDSA", ecdsa_signature.ECDSASigner()),
        ("RSA", rsa_signature.RSASigner()),
        ("SM2", sm2_signature.SM2())
    ]

    results = {}
    for algo_name, signer in algorithms:
        key_gen_time = generate_keys(signer)
        sign_times = []
        verify_times = []
        sign_lengths = []

        for message in messages:
            signature, sign_time, sign_length = sign_message(signer, message)
            verify_time, valid = verify_signature(signer, message, signature)
            sign_times.append(sign_time)
            verify_times.append(verify_time)
            sign_lengths.append(sign_length)

        avg_sign_time = sum(sign_times) / len(sign_times)
        avg_verify_time = sum(verify_times) / len(verify_times)
        avg_sign_length = sum(sign_lengths) / len(sign_lengths)

        results[algo_name] = {
            "Key Generation Time": key_gen_time,
            "Average Sign Time": avg_sign_time,
            "Average Verify Time": avg_verify_time,
            "Average Sign Length": avg_sign_length
        }

    return results

def display_results(results):
    print("Performance Test Results:")
    for algo, stats in results.items():
        print(f"\n{algo}:")
        for stat, value in stats.items():
            print(f"{stat}: {value}")

if __name__ == "__main__":
    results = performance_test()
    display_results(results)