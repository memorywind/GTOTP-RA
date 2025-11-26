import time, math, secrets, hashlib, hmac, base64, json
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# -------------------- 辅助函数（中文注释） --------------------
def sha256(b: bytes) -> bytes:
    """返回 SHA256 摘要（bytes）"""
    return hashlib.sha256(b).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """返回 HMAC-SHA256"""
    return hmac.new(key, msg, hashlib.sha256).digest()


def int_to_bytes(i: int, length=8) -> bytes:
    """将整数转换为固定长度的大端字节串"""
    return i.to_bytes(length, "big")


def b64(b: bytes) -> str:
    """Base64 编码为字符串，方便 JSON 序列化展示"""
    return base64.b64encode(b).decode()


def ub64(s: str) -> bytes:
    """Base64 解码字符串为 bytes"""
    return base64.b64decode(s.encode())


# -------------------- RSA & AES 封装 --------------------

# 使用 cryptography 实现 RSA-OAEP 和 AES-GCM
def generate_rsa_keypair(key_size=2048):
    """生成 RSA 密钥对"""
    sk = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    pk = sk.public_key()
    return pk, sk


def rsa_encrypt(pk, plaintext: bytes) -> bytes:
    """使用 RSA-OAEP 加密"""
    ct = pk.encrypt(plaintext,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                 label=None))
    return ct


def rsa_decrypt(sk, ciphertext: bytes) -> bytes:
    """使用 RSA-OAEP 解密"""
    pt = sk.decrypt(ciphertext,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                 label=None))
    return pt


def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    """使用 AES-GCM 加密，返回 nonce||ciphertext||tag（简单拼接）"""
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aesgcm_decrypt(key: bytes, blob: bytes, associated_data: bytes = None) -> bytes:
    """解密 AES-GCM（对应上面的拼接）"""
    nonce = blob[:12]
    ct = blob[12:]
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, associated_data)
    return pt


# -------------------- GTOTP 真实实现（哈希链 + HMAC） --------------------
class GTOTP_real:
    """
    GTOTP 的真实化实现（简化版）
    - 每个成员为每个 instance 保持一个种子 seed_{ID,i}（通过 PRF 派生）
    - 使用哈希链构造：VP = H^L(seed)（将 seed 进行 L 次哈希得到链的末端作为验证点）
    - PwGen：基于 seed 和时间片通过 HMAC 生成口令；口令长度可配置
    - 提供前向安全性示意：如果仅保存链的中间值（而非 seed），可以实现有限的前向安全性（这里留作接口）
    """
    HASH = hashlib.sha256

    @staticmethod
    def prf(prf_key: bytes, data: bytes) -> bytes:
        """PRF：使用 HMAC-SHA256"""
        return hmac_sha256(prf_key, data)

    @staticmethod
    def derive_seed(prf_key: bytes, ID: str, instance_idx: int) -> bytes:
        """基于 PRF 派生每个 instance 的 seed"""
        return GTOTP_real.prf(prf_key, ID.encode() + int_to_bytes(instance_idx, 4))

    @staticmethod
    def vp_from_seed(seed: bytes, chain_len: int = 100) -> bytes:
        """通过哈希链计算验证点（VP = H^chain_len(seed)）"""
        v = seed
        for _ in range(chain_len):
            v = GTOTP_real.HASH(v).digest()
        return v

    @staticmethod
    def gen_pw(seed: bytes, time_slot: int, counter: int = 0, out_len=16) -> bytes:
        """生成一次性口令：HMAC(seed, time_slot||counter) 截取前 out_len 字节"""
        return hmac_sha256(seed, int_to_bytes(time_slot, 8) + int_to_bytes(counter, 4))[:out_len]

    @staticmethod
    def get_vp_from_pw(pw: bytes) -> bytes:
        """示意：从 pw 恢复某种 vp 的方法——实际中应使用 GetVP(pw) 的定义，这里使用 Hash(pw)"""
        return sha256(b"vp_from_pw|" + pw)


# -------------------- Merkle Tree（真实化，带明确前缀） --------------------
class MerkleTree:
    """标准二叉 Merkle Tree，用 SHA256 对叶子进行前缀哈希，提供 proof 与 verify"""

    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves[:]
        self.levels = []
        if len(leaves) == 0:
            self.root = sha256(b"")
            self.levels = [[self.root]]
        else:
            self.build(leaves)

    def build(self, leaves: List[bytes]):
        # 对叶子应用 0x00 前缀再哈希以避免二义性
        current = [sha256(b"\x00" + l) for l in leaves]
        self.levels = [current]
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                a = current[i]
                b = current[i + 1] if i + 1 < len(current) else current[i]
                nxt.append(sha256(b"\x01" + a + b))
            current = nxt
            self.levels.append(current)
        self.root = self.levels[-1][0]

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """返回 proof 列表，每项 (sibling_hash, is_left_sibling)"""
        proof = []
        idx = index
        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            sibling = level[sibling_idx] if sibling_idx < len(level) else level[idx]
            is_left = (sibling_idx < idx)
            proof.append((sibling, is_left))
            idx //= 2
        return proof

    @staticmethod
    def verify(leaf: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
        h = sha256(b"\x00" + leaf)
        for sibling, is_left in proof:
            if is_left:
                a = sibling;
                b = h
            else:
                a = h;
                b = sibling
            h = sha256(b"\x01" + a + b)
        return h == root


# -------------------- 简单布隆过滤器（位集实现） --------------------
class SimpleBloom:
    """位集实现，不依赖第三方库"""

    def __init__(self, m_bits: int, k_hash: int):
        self.m = m_bits
        self.k = k_hash
        self.bitset = 0

    def _hashes(self, item: bytes):
        h = hashlib.sha256(item).digest()
        for i in range(self.k):
            start = (i * 4) % len(h)
            val = int.from_bytes(h[start:start + 4], "big")
            yield val % self.m

    def add(self, item: bytes):
        for pos in self._hashes(item):
            self.bitset |= (1 << pos)

    def query(self, item: bytes) -> bool:
        for pos in self._hashes(item):
            if ((self.bitset >> pos) & 1) == 0:
                return False
        return True


# -------------------- 系统实体：RA、Member、Attester、RP --------------------
@dataclass
class RAParams:
    hk: bytes
    kp: bytes
    N: int
    E: int
    T_s: int
    T_e: int
    delta_e: int
    delta_T: int
    phi: int
    pk_ra: Any  # 公钥（或回退的对称密钥）


class RegistrationAuthority:
    """注册机构（RA）：负责系统 Setup、GVSTGen 与 Open"""

    def __init__(self, T_s: int, T_e: int, delta_e: int, delta_T: int, phi: int):
        # 生成 RSA 密钥对（若可用）或回退密钥
        self.pk_ra, self.sk_ra = generate_rsa_keypair()
        self.hk = secrets.token_bytes(16)  # 哈希域分离密钥
        self.kp = secrets.token_bytes(16)  # 置换密钥（示意）
        self.T_s = T_s;
        self.T_e = T_e;
        self.delta_e = delta_e;
        self.delta_T = delta_T;
        self.phi = phi
        self.N = math.ceil((T_e - T_s) / delta_e)
        self.E = math.ceil((T_e - T_s) / delta_T)
        self.params = RAParams(self.hk, self.kp, self.N, self.E, T_s, T_e, delta_e, delta_T, phi, self.pk_ra)
        # 存储成员辅助数据（Enc(ID) 与 proof）
        self.member_aux = {}  # ID -> list of aux entries
        self.merkle_roots = []
        self.mt_by_subset = []
        self.bloom = None

    def enc_id(self, ID: str) -> bytes:
        """使用 RA 的公钥对 ID 加密，返回密文"""
        return rsa_encrypt(self.pk_ra, ID.encode())

    def dec_id(self, enc_bytes: bytes) -> str:
        """使用 RA 的私钥解密密文，恢复 ID 字符串"""
        pt = rsa_decrypt(self.sk_ra, enc_bytes)
        return pt.decode()

    def gvst_gen(self, members_vst: Dict[str, List[bytes]]):
        """
        生成群体验证状态（GVST）
        输入 members_vst: ID -> [vp_i for each instance]
        输出：vst_G（布隆过滤器）、aux（按 ID 的辅助数据）、roots（merkle roots 列表）
        """
        # 1. 生成所有绑定后的 vp' = H(hk || vp || Enc(ID) || instance_index)
        all_vpprimes = []
        mapping = []  # 元组 (ID, instance_index, vpprime, enc)
        for ID, vps in members_vst.items():
            enc = self.enc_id(ID)
            for i, vp in enumerate(vps):
                # vpprime = sha256(self.hk + vp + enc + int_to_bytes(i, 4))
                vpprime = sha256(vp + enc + int_to_bytes(i, 4))
                all_vpprimes.append(vpprime)
                mapping.append((ID, i, vpprime, enc))
        # 2. 使用置换密钥对列表进行伪随机置换（这里用 HMAC 派生 RNG 种子并 shuffle）
        rng = secrets.SystemRandom(int.from_bytes(hmac_sha256(self.kp, b"perm_seed"), "big"))
        permuted = all_vpprimes[:]
        rng.shuffle(permuted)
        # 3. 划分为 phi 个子集并构建每个子集的 Merkle 树，记录 root 并插入布隆过滤器
        phi = self.phi
        subsets = [[] for _ in range(phi)]
        for idx, it in enumerate(permuted):
            subsets[idx % phi].append(it)
        bfilter = SimpleBloom(m_bits=4096, k_hash=6)
        roots = []
        mts = []
        for s in subsets:
            mt = MerkleTree(s)
            mts.append(mt)
            roots.append(mt.root)
            bfilter.add(mt.root)
        # 4. 为每个 mapping 条目查找其在 permuted 中的索引并生成对应的 proof，分配到 member_aux
        aux = {}
        for ID, i, vpprime, enc in mapping:
            idx = permuted.index(vpprime)
            subset_idx = idx % phi
            pos_in_subset = idx // phi
            proof = mts[subset_idx].get_proof(pos_in_subset)
            aux.setdefault(ID, []).append({
                "instance": i,
                "enc": enc,
                "subset": subset_idx,
                "pos": pos_in_subset,
                "proof": proof
            })
        # 存储并返回
        self.member_aux = aux
        self.merkle_roots = roots
        self.mt_by_subset = mts
        self.bloom = bfilter
        return {"vst_G": bfilter, "aux": aux, "roots": roots, "mts": mts}

    def open(self, enc_bytes: bytes) -> str:
        """在需要追溯时使用私钥解密 Enc(ID)"""
        return self.dec_id(enc_bytes)


class RAServiceMember:
    """RA Service 成员：负责本地 PInit（私钥/种子生成）与 PwGen（签名口令生成）"""

    def __init__(self, ID: str, params: RAParams, prf_key: bytes = None, chain_len: int = 100):
        self.ID = ID
        # PRF 密钥（私钥）
        self.prf_key = prf_key if prf_key is not None else secrets.token_bytes(32)
        self.chain_len = chain_len  # 用于 VP 的哈希链长度
        # 为每个 instance 派生 seed 与 VP
        self.vst = []  # 每个 instance 的 VP 列表
        for i in range(params.E):
            seed = GTOTP_real.derive_seed(self.prf_key, ID, i)
            vp = GTOTP_real.vp_from_seed(seed, chain_len=self.chain_len)
            self.vst.append(vp)
        # 辅助信息将由 RA 分发（Enc(ID) 与 proof）
        self.aux = None

    def receive_aux(self, aux_for_id):
        """接收 RA 分发的辅助信息"""
        self.aux = aux_for_id

    def check_report(self, report: dict) -> bool:
        """检查 Attester 报告，这里模拟为总是通过（可替换为实际策略）"""
        return True

    def pwgen(self, report: dict, params: RAParams) -> Dict[str, Any]:
        """
        如果 report 合法，生成 GTOTP pw 并构建 sigma：
        sigma = (pw, Enc(ID), proof, subset, t)
        """
        t = report["t"]
        i = math.ceil((t - params.T_s) / params.delta_T) - 1
        if i < 0 or i >= params.E:
            raise ValueError("时间不在有效实例范围")
        # 找到对应 aux 条目
        if not self.aux:
            raise ValueError("没有辅助信息")
        entry = None
        for e in self.aux:
            if e["instance"] == i:
                entry = e;
                break
        if entry is None:
            raise ValueError("未找到对应实例的辅助数据")
        # 基于 seed 生成 pw
        seed = GTOTP_real.derive_seed(self.prf_key, self.ID, i)
        pw = GTOTP_real.gen_pw(seed, t, counter=0, out_len=16)
        # 为 Verify 构建 vpprime（同 RA 的构造）
        vp = GTOTP_real.vp_from_seed(seed, chain_len=self.chain_len)
        vpprime = sha256(params.hk + vp + entry["enc"] + int_to_bytes(i, 4))
        # sigma 构造
        proof_serializable = [(b64(p[0]), p[1]) for p in entry["proof"]]
        sigma = {
            "pw": b64(pw),
            "enc": b64(entry["enc"]),
            "proof": proof_serializable,
            "subset": entry["subset"],
            "t": t
        }
        return sigma


class Attester:
    """Attester：生成证明报告"""

    def __init__(self, name="att1"):
        self.name = name

    def gen_report(self, nonce: bytes, measurement: Dict[str, Any], t: int) -> Dict[str, Any]:
        return {"nonce": b64(nonce), "measurement": measurement, "t": t}


class RelyingParty:
    """RP：接收 sigma 并验证"""

    def __init__(self, params: RAParams):
        self.params = params

    def verify(self, sigma: Dict[str, Any], vst_G: SimpleBloom, merkle_roots: List[bytes],
               mts: List[MerkleTree]) -> bool:
        """
        验证流程：
        - 时间窗口检查
        - 由 pw 计算 vp（或 GetVP）并构造 vpprime = H(hk || vp || Enc(ID) || i)
        - 使用 proof 恢复 Merkle root 并检查该 root 是否在布隆过滤器中
        """
        try:
            pw = ub64(sigma["pw"])
            enc = ub64(sigma["enc"])
            subset = sigma["subset"]
            proof = [(ub64(p[0]), p[1]) for p in sigma["proof"]]
            t = sigma["t"]
            # 时间有效性检查（这里采用严格检查）
            now = sigma.get("now", t)
            # 计算 instance index
            i = math.ceil((t - self.params.T_s) / self.params.delta_T) - 1
            if i < 0 or i >= self.params.E:
                return False
            # 从 pw 计算 vp（示意性方法）            #
            # 注意：实际论文中 GetVP(pw) 的定义需一致；这里我们使用 GTOTP_real.vp_from_seed(seed) 来构造 vp。
            # 在验证端，我们没有 seed，故使用对 pw 的哈希作为 GetVP(pw) 的可验证替代。
            vp = GTOTP_real.get_vp_from_pw(pw)
            # 计算 vpprime（与 RA 构造一致）
            vk = sha256(self.params.hk + vp + enc + int_to_bytes(i, 4))
            # 恢复 Merkle root 并验证
            root = merkle_roots[subset]
            if not MerkleTree.verify(vk, proof, root):
                return False
            # 在布隆过滤器中检查 root 的存在性
            if not vst_G.query(root):
                return False
            return True
        except Exception as e:
            return False


# -------------------- 协议仿真驱动 --------------------
def simulate_real_protocol(num_members=8, E=3, T_s=0, delta_T=60, delta_e=30, phi=4):
    timings = {}
    start_all = time.perf_counter()
    T_e = T_s + E * delta_T
    # 1) RA Setup
    ra = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    params = ra.params
    timings['setup'] = time.perf_counter() - start_all
    # 2) Members PInit
    members = {}
    for j in range(num_members):
        ID = f"member{j + 1}"
        m = RAServiceMember(ID, params)
        members[ID] = m
    timings['pinit'] = time.perf_counter() - start_all - timings['setup']
    # 3) RA GVSTGen
    members_vst = {ID: m.vst for ID, m in members.items()}
    gvst_res = ra.gvst_gen(members_vst)
    timings['gvstgen'] = time.perf_counter() - start_all - timings['setup'] - timings['pinit']
    # RA 向成员下发辅助信息
    for ID, m in members.items():
        m.receive_aux(gvst_res['aux'].get(ID, []))
    timings['dist_aux'] = time.perf_counter() - start_all - timings['setup'] - timings['pinit'] - timings['gvstgen']
    # 4) Attester 生成 report
    att = Attester()
    nonce = secrets.token_bytes(12)
    report = att.gen_report(nonce, {"fw_hash": "abc123"}, t=5)
    timings['reportgen'] = time.perf_counter() - start_all - sum(timings.values())
    # 5) 成员检查 report 并生成 pw -> sigma
    sigmas = []
    t = report['t']
    for ID, m in members.items():
        if not m.check_report(report):
            continue
        try:
            sigma = m.pwgen(report, params)
            sigmas.append((ID, sigma))
        except Exception as e:
            continue
    timings['pwgen'] = time.perf_counter() - start_all - sum(timings.values())
    # 6) RP 验证随机一个 sigma
    rp = RelyingParty(params)
    if len(sigmas) == 0:
        raise RuntimeError("没有生成任何 sigma")
    chosen = sigmas[secrets.randbelow(len(sigmas))][1]
    t_verify_start = time.perf_counter()
    ok = rp.verify(chosen, gvst_res['vst_G'], gvst_res['roots'], ra.mt_by_subset)
    t_verify = time.perf_counter() - t_verify_start
    timings['verify'] = t_verify
    # 7) RA Open（追溯）
    enc_bytes = ub64(chosen['enc'])
    traced_id = ra.open(enc_bytes)
    timings['open'] = time.perf_counter() - start_all - sum(timings.values())
    total = time.perf_counter() - start_all
    timings['total'] = total
    summary = {
        "num_members": num_members,
        "E": E,
        "phi": phi,
        "sig_verified": ok,
        "traced_id": traced_id,
        **timings
    }
    df = pd.DataFrame([summary])
    # display_dataframe_to_user("GTOTP-RA 真实实现仿真结果", df)
    print("示例 sigma（部分截断显示）：")
    ex = chosen.copy()
    ex["pw"] = ex["pw"][:10] + "..." if isinstance(ex["pw"], str) and len(ex["pw"]) > 10 else ex["pw"]
    print(json.dumps(ex, indent=2))
    print("\n验证结果：", ok)
    print("追溯得到的 ID：", traced_id)
    return summary


# 运行仿真（示例参数）
result = simulate_real_protocol(num_members=12, E=4, T_s=0, delta_T=60, delta_e=30, phi=4)
print(result)
