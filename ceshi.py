import pyotp
import hashlib
import base64
from bitarray import bitarray
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime, timedelta


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


# 生成 GTOTP 口令 - 增加时间窗口参数
def generate_gtotp(seed, t, time_step=30):
    """生成指定时间的 GTOTP 口令，time_step 为时间窗口大小（秒）"""
    t = parse_time(t)

    # 将普通字符串种子转换为有效的 Base32 编码
    seed_hash = hashlib.sha256(seed.encode('utf-8')).digest()[:20]
    seed_base32 = base64.b32encode(seed_hash).decode('utf-8')

    totp = pyotp.TOTP(seed_base32, interval=time_step)
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
    member_sks = []

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


# TCB 成员验证报告 - 增加时间窗口参数
def tcb_member_verify_report(report, sk_i, encrypted_id, t, time_step=30):
    seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
    print(f"成员使用的 sk_i: {sk_i[:10]}...")
    print(f"生成的种子: {seed[:32]}...")

    pw = generate_gtotp(seed, t, time_step)
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


# Relying Party 验证群签名 - 增加时间窗口参数
def relying_party_verify(signature, t, bf, time_step=30):
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


# 测试时间窗口功能
def test_time_window():
    """测试不同时间窗口的验证情况"""
    num_members = 1  # 只测试一个成员
    private_key, public_key, members_info, member_sks = system_initialization(num_members)

    # 测试参数
    time_step = 30  # 时间窗口大小（秒）
    base_time = datetime(2024, 1, 1, 12, 0, 0)  # 基准时间

    # 测试不同时间点
    test_times = [
        base_time,  # 基准时间
        base_time + timedelta(seconds=time_step // 2),  # 窗口中间
        base_time + timedelta(seconds=time_step - 1),  # 窗口末尾
        base_time + timedelta(seconds=time_step),  # 下一个窗口开始
        base_time + timedelta(seconds=time_step + 1),  # 下一个窗口
    ]

    for i, test_time in enumerate(test_times):
        test_time_str = test_time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n===== 测试时间点 {i + 1}: {test_time_str} =====")

        # 生成报告
        report, timestamp = attester_generate_report(test_time_str)
        t = parse_time(timestamp)

        # 成员验证报告
        sk_i = member_sks[0]
        encrypted_id = members_info[0]
        print(f"\n处理成员验证:")
        vp = tcb_member_verify_report(report, sk_i, encrypted_id, t, time_step)

        # 处理验证点
        merkle_proofs, bf = ra_process([[vp]])

        # 生成签名
        seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
        pw = generate_gtotp(seed, t, time_step)
        signature = tcb_member_sign(pw, encrypted_id, merkle_proofs[0][0])

        # 验证签名
        print(f"\n验证签名:")
        result = relying_party_verify(signature, t, bf, time_step)
        print(f"时间窗口 {time_step} 秒，时间点 {test_time_str} 的验证结果: {result}")


# 测试过期口令的情况
def test_expired_token():
    """测试过期口令的验证情况"""
    num_members = 1  # 只测试一个成员
    private_key, public_key, members_info, member_sks = system_initialization(num_members)

    # 设置时间窗口为 30 秒
    time_step = 30

    # 当前时间
    current_time = datetime.now()
    print(f"当前时间: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # 生成一个过期的时间戳（2个时间窗口前）
    expired_time = current_time - timedelta(seconds=time_step * 2)
    expired_time_str = expired_time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"过期时间: {expired_time_str}")

    # 使用过期时间生成报告
    report, timestamp = attester_generate_report(expired_time_str)
    t = parse_time(timestamp)

    # 成员验证报告（使用过期时间）
    sk_i = member_sks[0]
    encrypted_id = members_info[0]

    print("\n使用过期时间生成验证点:")
    expired_vp = tcb_member_verify_report(report, sk_i, encrypted_id, t, time_step)

    # 处理验证点
    merkle_proofs, bf = ra_process([[expired_vp]])

    # 生成签名
    seed = hashlib.sha256((sk_i + report).encode()).hexdigest()
    pw = generate_gtotp(seed, t, time_step)
    signature = tcb_member_sign(pw, encrypted_id, merkle_proofs[0][0])

    # 使用当前时间进行验证（应该失败）
    print("\n使用当前时间进行验证:")
    current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
    current_t = parse_time(current_time_str)

    result = relying_party_verify(signature, current_t, bf, time_step)
    print(f"过期口令验证结果: {result}")

    # 使用相同的过期时间进行验证（应该成功）
    print("\n使用相同的过期时间进行验证:")
    result = relying_party_verify(signature, t, bf, time_step)
    print(f"相同过期时间验证结果: {result}")


# 主函数
def main():
    print("===== 测试时间窗口功能 =====")
    test_time_window()

    print("\n\n===== 测试过期口令功能 =====")
    test_expired_token()


if __name__ == "__main__":
    main()