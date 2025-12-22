import pyotp
import hashlib
import base64
from bitarray import bitarray
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime
from pybloom_live import BloomFilter


# 生成 RSA 密钥对
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# 加密身份信息
def encrypt_id(public_key, id):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_id = cipher_rsa.encrypt(id.encode())
    return encrypted_id


# 解密身份信息
def decrypt_id(private_key, encrypted_id):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted_id = cipher_rsa.decrypt(encrypted_id)
    return decrypted_id.decode()


# 解析时间戳
def parse_time(t):
    """将时间字符串转换为 Unix 时间戳，如果已经是整数则直接返回"""
    if isinstance(t, str):
        try:
            dt = datetime.fromisoformat(t)
        except ValueError:
            dt = datetime.strptime(t, "%Y-%m-%d %H:%M:%S")
        return int(dt.timestamp())
    return t


# 生成 GTOTP 口令
def generate_gtotp(seed, t):
    t = parse_time(t)

    # 将普通字符串种子转换为有效的 Base32 编码
    seed_hash = hashlib.sha256(seed.encode('utf-8')).digest()[:20]
    seed_base32 = base64.b32encode(seed_hash).decode('utf-8')

    totp = pyotp.TOTP(seed_base32)
    return totp.at(t)


# 生成验证点
def generate_verification_point(pw, encrypted_id, t):
    t = parse_time(t)
    data = f"{pw}{encrypted_id}{t}".encode()
    return hashlib.sha256(data).hexdigest()


# 构建 Merkle 树
class MerkleTree:
    def __init__(self, leaves):
        self.leaves = leaves
        self.tree = [leaves]
        while len(self.tree[-1]) > 1:
            level = []
            for i in range(0, len(self.tree[-1]), 2):
                left = self.tree[-1][i]
                right = self.tree[-1][i + 1] if i + 1 < len(self.tree[-1]) else left
                combined = (left + right).encode()
                hash_value = hashlib.sha256(combined).hexdigest()
                level.append(hash_value)
            self.tree.append(level)

    def get_root(self):
        return self.tree[-1][0]

    def get_proof(self, index):
        proof = []
        sibling_positions = []
        for i in range(len(self.tree) - 1):
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            sibling_position = 'right' if index % 2 == 0 else 'left'
            if sibling_index < len(self.tree[i]):
                proof.append(self.tree[i][sibling_index])
                sibling_positions.append(sibling_position)
            index = index // 2
        return proof, sibling_positions


# 布隆过滤器
class BloomFilter:
    def __init__(self, size, hash_count):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)

    def _hash_functions(self, value):
        hashes = []
        for i in range(self.hash_count):
            hash_value = int(hashlib.sha256(f"{value}{i}".encode()).hexdigest(), 16) % self.size
            hashes.append(hash_value)
        return hashes

    def insert(self, value):
        hashes = self._hash_functions(value)
        for hash_value in hashes:
            self.bit_array[hash_value] = 1

    def query(self, value):
        hashes = self._hash_functions(value)
        for hash_value in hashes:
            if not self.bit_array[hash_value]:
                return False
        return True


# 系统初始化 - 为每个成员生成不同的 sk_i
def system_initialization(num_members):
    private_key, public_key = generate_rsa_keys()
    members_info = []
    member_sks = []  # 存储每个成员的私钥

    for i in range(num_members):
        id = f"E{i}"
        encrypted_id = encrypt_id(public_key, id)
        members_info.append(encrypted_id)

        # 为每个成员生成唯一的 sk_i
        sk_i = hashlib.sha256(f"member_{i}_secret".encode()).hexdigest()
        member_sks.append(sk_i)

    return private_key, public_key, members_info, member_sks


# Attester 生成远程证明请求
def attester_generate_report():
    nonce = "123456"
    timestamp = "2024-01-01 12:00:00"
    measurement = "measurement_data"
    report = f"{nonce}{timestamp}{measurement}"
    return report, timestamp


# TCB 成员验证报告
def tcb_member_verify_report(report, sk_i, encrypted_id, t):
    seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
    print(f"成员使用的 sk_i: {sk_i[:10]}...")  # 打印前10个字符用于调试
    print(f"生成的种子: {seed[:32]}...")

    pw = generate_gtotp(seed, t)
    print(f"生成的 GTOTP 口令: {pw}")

    vp = generate_verification_point(pw, encrypted_id, t)
    return vp


# RA 处理
def ra_process(members_vps):
    merkle_roots = []
    merkle_proofs = []
    for vps in members_vps:
        mt = MerkleTree(vps)
        root = mt.get_root()
        merkle_roots.append(root)
        proofs = [mt.get_proof(i) for i in range(len(vps))]
        merkle_proofs.append(proofs)
        print(f"计算的 Merkle 根: {root[:32]}...")

    bf = BloomFilter(1000, 3)
    for root in merkle_roots:
        bf.insert(root)

    return merkle_proofs, bf


# TCB 成员进行签名
def tcb_member_sign(pw, encrypted_id, merkle_proof):
    signature = (pw, encrypted_id, merkle_proof)
    return signature


# Relying Party 验证群签名
def relying_party_verify(signature, t, bf):
    pw, encrypted_id, (merkle_proof, sibling_positions) = signature
    vp = generate_verification_point(pw, encrypted_id, t)
    print(f"验证点: {vp[:32]}...")

    # 使用 Merkle 证明重建根哈希
    current_hash = vp
    for i, sibling in enumerate(merkle_proof):
        position = sibling_positions[i]
        if position == 'right':
            combined = (current_hash + sibling).encode()
        else:
            combined = (sibling + current_hash).encode()
        current_hash = hashlib.sha256(combined).hexdigest()

    root = current_hash
    print(f"重建的 Merkle 根: {root[:32]}...")

    return bf.query(root)


# 主函数
def main():
    num_members = 3
    private_key, public_key, members_info, member_sks = system_initialization(num_members)
    report, timestamp = attester_generate_report()
    t = parse_time(timestamp)

    members_vps = []
    for i, encrypted_id in enumerate(members_info):
        sk_i = member_sks[i]  # 获取对应成员的私钥
        print(f"\n处理成员 {i} 的验证:")
        vp = tcb_member_verify_report(report, sk_i, encrypted_id, t)
        members_vps.append([vp])

    merkle_proofs, bf = ra_process(members_vps)

    signatures = []
    for i in range(num_members):
        sk_i = member_sks[i]  # 使用正确的成员私钥
        seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
        pw = generate_gtotp(seed, t)
        signature = tcb_member_sign(pw, members_info[i], merkle_proofs[i][0])
        signatures.append(signature)

    for i, signature in enumerate(signatures):
        print(f"\n验证成员 {i} 的签名:")
        result = relying_party_verify(signature, t, bf)
        print(f"Signature verification result: {result}")

        # 可选：RA 开启签名，身份追踪
        if result:
            encrypted_id = signature[1]
            id = decrypt_id(private_key, encrypted_id)
            print(f"Signature made by: {id}")


if __name__ == "__main__":
    main()