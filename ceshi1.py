import pyotp
import hashlib
import base64
from bitarray import bitarray
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime, timedelta

# 时间窗口大小（秒）
WINDOW_SIZE = 600  # 10分钟，即±5分钟


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
    """生成GTOTP口令，确保种子是有效的Base32编码"""
    # 将普通字符串种子转换为有效的Base32编码
    seed_bytes = seed.encode('utf-8')
    seed_hash = hashlib.sha256(seed_bytes).digest()[:20]  # 取前20字节（160位）
    seed_base32 = base64.b32encode(seed_hash).decode('utf-8')

    # 如果t是字符串，转换为Unix时间戳
    if isinstance(t, str):
        try:
            dt = datetime.fromisoformat(t)
        except ValueError:
            dt = datetime.strptime(t, "%Y-%m-%d %H:%M:%S")
        t = int(dt.timestamp())

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


# 系统初始化
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
def attester_generate_report(timestamp=None):
    nonce = "123456"
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    measurement = "measurement_data"
    report = f"{nonce}{timestamp}{measurement}"
    return report, timestamp


# TCB 成员验证报告
def tcb_member_verify_report(report, sk_i, encrypted_id, t):
    seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
    print(f"成员使用的 sk_i: {sk_i[:10]}...")
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

        # 为每个叶子节点生成证明
        proofs = [mt.get_proof(i) for i in range(len(vps))]
        merkle_proofs.append(proofs)

        print(f"计算的 Merkle 根: {root[:32]}...")

    bf = BloomFilter(1000, 3)
    for root in merkle_roots:
        bf.insert(root)

    return merkle_proofs, bf


# TCB 成员进行签名
def tcb_member_sign(pw, encrypted_id, merkle_proof, t):
    """签名时包含时间戳"""
    signature = (pw, encrypted_id, merkle_proof, t)  # 添加时间戳到签名中
    return signature


# Relying Party 验证群签名
def relying_party_verify(signature, current_time, bf):
    """
    验证群签名，检查凭证时间戳是否在当前时间窗口内

    参数:
    - signature: 待验证的签名 (pw, encrypted_id, merkle_proof, t)
    - current_time: 当前验证时间
    - bf: 布隆过滤器
    """
    pw, encrypted_id, merkle_proof, t = signature
    current_timestamp = parse_time(current_time)
    t_timestamp = parse_time(t)

    # 计算当前时间窗口
    window_start = current_timestamp - WINDOW_SIZE // 2
    window_end = current_timestamp + WINDOW_SIZE // 2

    # 检查凭证时间戳是否在当前时间窗口内
    if not (window_start <= t_timestamp <= window_end):
        print(
            f"凭证时间戳 {t} 不在当前时间窗口 {datetime.fromtimestamp(window_start)} - {datetime.fromtimestamp(window_end)} 内")
        return False

    print(f"凭证时间戳 {t} 在当前时间窗口内")

    # 使用凭证中的时间戳计算验证点
    vp = generate_verification_point(pw, encrypted_id, t)
    print(f"验证点: {vp[:32]}...")

    # 使用 Merkle 证明重建根哈希
    current_hash = vp
    proof_nodes, positions = merkle_proof  # 正确解包Merkle证明

    for sibling, position in zip(proof_nodes, positions):
        if position == 'right':
            combined = (current_hash + sibling).encode()
        else:
            combined = (sibling + current_hash).encode()
        current_hash = hashlib.sha256(combined).hexdigest()

    root = current_hash
    print(f"重建的 Merkle 根: {root[:32]}...")

    return bf.query(root)


# 测试时间窗口功能
def Test_time_window():
    """测试时间窗口验证功能"""
    num_members = 1
    private_key, public_key, members_info, member_sks = system_initialization(num_members)

    # 生成凭证的时间
    issue_time = datetime(2024, 1, 1, 12, 0, 0)
    issue_time_str = issue_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"凭证生成时间: {issue_time_str}")

    # 生成报告
    report, _ = attester_generate_report(issue_time_str)

    # 成员验证报告
    sk_i = member_sks[0]
    encrypted_id = members_info[0]
    print(f"\n处理成员验证:")
    vp = tcb_member_verify_report(report, sk_i, encrypted_id, issue_time_str)

    # 处理验证点
    merkle_proofs, bf = ra_process([[vp]])

    # 生成签名（包含时间戳）
    seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
    pw = generate_gtotp(seed, issue_time_str)

    # 注意：这里使用 merkle_proofs[0][0] 而不是 merkle_proofs[0]
    signature = tcb_member_sign(pw, encrypted_id, merkle_proofs[0][0], issue_time_str)

    # 测试在不同时间验证
    test_times = [
        issue_time - timedelta(seconds=WINDOW_SIZE // 2 + 10),  # 窗口开始前10秒（应该失败）
        issue_time - timedelta(seconds=WINDOW_SIZE // 2),  # 窗口开始（应该通过）
        issue_time,  # 凭证时间（应该通过）
        issue_time + timedelta(seconds=WINDOW_SIZE // 2),  # 窗口结束（应该通过）
        issue_time + timedelta(seconds=WINDOW_SIZE // 2 + 10),  # 窗口结束后10秒（应该失败）
    ]

    for test_time in test_times:
        test_time_str = test_time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n===== 在时间 {test_time_str} 验证 =====")

        result = relying_party_verify(signature, test_time_str, bf)
        print(f"验证结果: {result}")

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

    # 签名时间
    issue_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    signatures = []
    for i in range(num_members):
        sk_i = member_sks[i]  # 使用正确的成员私钥
        seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
        pw = generate_gtotp(seed, t)
        signature = tcb_member_sign(pw, members_info[i], merkle_proofs[i][0],issue_time)
        signatures.append(signature)

    # 验证签名时间
    test_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for i, signature in enumerate(signatures):
        print(f"\n验证成员 {i} 的签名:")
        result = relying_party_verify(signature, test_time_str, bf)
        print(f"Signature verification result: {result}")

        # 可选：RA 开启签名，身份追踪
        if result:
            encrypted_id = signature[1]
            id = decrypt_id(private_key, encrypted_id)
            print(f"Signature made by: {id}")

if __name__ == "__main__":
    # Test_time_window()
    main()