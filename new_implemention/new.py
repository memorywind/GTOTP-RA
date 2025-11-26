import time, math, secrets, hashlib, hmac, base64, json
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from pybloom_live import BloomFilter


# -------------------- 辅助函数 --------------------
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


# ----------------- 哈希链工具 -----------------
def hash_power(x: bytes, r: int) -> bytes:
    """对 x 连续 r 次应用 SHA256 -> H^r(x)"""
    h = x
    for _ in range(r):
        h = sha256(h)
    return h


# ----------------- GTOTP 链式实现（论文语义） -----------------
class GTOTP_chain:
    @staticmethod
    def gen_head(length_bytes=32):
        return secrets.token_bytes(length_bytes)

    @staticmethod
    def compute_tail(head, chain_len):
        return hash_power(head, chain_len)  # vp = H^L(head)

    @staticmethod
    def gen_pw_from_head(head, chain_len, z):
        # pw = H^{z}(head)
        return hash_power(head, z)

    @staticmethod
    def get_vp_from_pw(pw, chain_len, z):
        # vp = H^{chain_len - z}(pw)
        steps = max(chain_len - z, 0)
        return hash_power(pw, steps)


# ----------------- Merkle Tree（含前缀哈希） -----------------
class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves[:]
        self.levels = []
        if len(leaves) == 0:
            self.root = sha256(b"");
            self.levels = [[self.root]]
        else:
            self.build(leaves)

    def build(self, leaves: List[bytes]):
        # 叶子做 0x00 前缀再哈希以避免二义性
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
        proof = [];
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


# ----------------- 布隆过滤器 -----------------
class SimpleBloom:
    """
    改进版布隆过滤器（基于 pybloom_live）
    与原 SimpleBloom 接口兼容：
        - add(item: bytes)
        - query(item: bytes) -> bool
    """

    def __init__(self, m_bits: int = 4096, k_hash: int = 6, error_rate: float = 1e-5):
        # m_bits/k_hash 仅用于占位，与 pybloom_live 直接参数化 false positive rate
        self.error_rate = error_rate
        # 设定容量略大于 m_bits，避免 underflow
        self.capacity = max(1000, m_bits)
        # 初始化 pybloom_live 的 BloomFilter
        self.bloom = BloomFilter(capacity=self.capacity, error_rate=error_rate)

    def add(self, item: bytes):
        """
        将 item（bytes）加入布隆过滤器
        """
        # 统一将 bytes 转成 hex 字符串以便存储
        self.bloom.add(item.hex())

    def query(self, item: bytes) -> bool:
        """
        查询 item 是否存在于布隆过滤器中
        """
        return item.hex() in self.bloom

    def __len__(self):
        return len(self.bloom)

    def export(self):
        """
        可选：导出为字典（便于序列化保存）
        """
        return {
            "capacity": self.capacity,
            "error_rate": self.error_rate,
            "count": len(self.bloom)
        }


# ----------------- 系统实体与协议实现 -----------------
@dataclass
class RAParams:
    hk: bytes;
    kp: bytes;
    N: int;
    E: int;
    T_s: int;
    T_e: int;
    delta_e: int;
    delta_T: int;
    phi: int;
    pk_ra: Any


# ----------------- 注册机构 -----------------
class RegistrationAuthority:
    """注册机构 RA：负责 Setup、GVSTGen、Open（追溯）"""

    def __init__(self, T_s: int, T_e: int, delta_e: int, delta_T: int, phi: int):
        self.pk_ra, self.sk_ra = generate_rsa_keypair()
        self.hk = secrets.token_bytes(16);
        self.kp = secrets.token_bytes(16)
        self.T_s = T_s;
        self.T_e = T_e;
        self.delta_e = delta_e;
        self.delta_T = delta_T;
        self.phi = phi
        self.N = math.ceil((T_e - T_s) / delta_e);
        self.E = math.ceil((T_e - T_s) / delta_T)
        self.params = RAParams(self.hk, self.kp, self.N, self.E, T_s, T_e, delta_e, delta_T, phi, self.pk_ra)
        self.member_aux = {};
        self.merkle_roots = [];
        self.mt_by_subset = [];
        self.bloom = None

    def enc_id(self, ID: str) -> bytes:
        """使用 RA 公钥加密 ID（RSA-OAEP），随机化以防关联"""
        return rsa_encrypt(self.pk_ra, ID.encode())

    def dec_id(self, enc_bytes: bytes) -> str:
        """使用 RA 私钥解密 Enc(ID) -> ID"""
        return rsa_decrypt(self.sk_ra, enc_bytes).decode()

    def gvst_gen(self, members_vst: Dict[str, List[bytes]]):
        """
        构建群验证状态：
        - 为每个 (ID, instance) 计算 vpprime = H(vp_tail || Enc(ID) || i)
        - 对 entries 整体置换（保持元信息一起移动），再按 idx % phi 切分子集
        - 为每个子集建 Merkle tree，roots 插入 Bloom
        - 为每个 member 返回 aux（包括 Enc(ID), proof, subset, pos）
        """
        entries = []
        for ID, vps in members_vst.items():
            enc = self.enc_id(ID)
            for i, vp_tail in enumerate(vps):
                vpprime = sha256(vp_tail + enc + int_to_bytes(i, 4))
                entries.append((vpprime, ID, i, enc))
        # 用 kp 派生的确定性随机源做置换
        rng = secrets.SystemRandom(int.from_bytes(hmac_sha256(self.kp, b"perm_seed"), "big"))
        rng.shuffle(entries)
        # 切分为 phi 子集并构建 merkle
        phi = self.phi
        subsets = [[] for _ in range(phi)]
        entry_locs = {}
        for idx, ent in enumerate(entries):
            subset_idx = idx % phi
            subsets[subset_idx].append(ent[0])  # 存 vpprime
            entry_locs[(ent[1], ent[2])] = (subset_idx, len(subsets[subset_idx]) - 1, ent[3])
        mts = [];
        roots = []
        for s in subsets:
            mt = MerkleTree(s);
            mts.append(mt);
            roots.append(mt.root)
        bfilter = SimpleBloom(m_bits=4096, k_hash=6)
        for r in roots: bfilter.add(r)
        aux = {}
        for (vpprime, ID, i, enc) in entries:
            subset_idx, pos_in_subset, enc_bytes = entry_locs[(ID, i)]
            proof = mts[subset_idx].get_proof(pos_in_subset)
            aux.setdefault(ID, []).append({
                "instance": i, "enc": enc_bytes, "subset": subset_idx, "pos": pos_in_subset, "proof": proof
            })
        self.member_aux = aux;
        self.merkle_roots = roots;
        self.mt_by_subset = mts;
        self.bloom = bfilter
        return {"vst_G": bfilter, "aux": aux, "roots": roots, "mts": mts}

    def open(self, enc_bytes: bytes) -> str:
        """追溯：解密 Enc(ID)"""
        return self.dec_id(enc_bytes)


# ----------------- RA成员 -----------------
class RAServiceMember:
    """RA Service 成员：PInit -> 生成 head 和 tail(vp)，PwGen -> 生成 sigma"""

    def __init__(self, ID: str, params: RAParams, chain_len_per_instance: int = 12):
        self.ID = ID;
        self.prf_key = secrets.token_bytes(32);
        self.chain_len = chain_len_per_instance
        self.heads = [];
        self.vst = []
        for i in range(params.E):
            head = GTOTP_chain.gen_head(32)
            tail = GTOTP_chain.compute_tail(head, self.chain_len)
            self.heads.append(head);
            self.vst.append(tail)
        self.aux = None

    def receive_aux(self, aux_for_id):
        """接收 RA 分发的辅助数据（Enc(ID), proof 等）"""
        self.aux = aux_for_id

    def check_report(self, report: dict) -> bool:
        """检查 Attester 报告（此处默认通过；可替换策略）"""
        return True

    def pwgen(self, params: RAParams) -> Dict[str, Any]:
        """生成 sigma（pw, Enc(ID), proof, subset, t, z）"""
        # 设定t为70进行测试
        t = 70;
        i = math.ceil((t - params.T_s) / params.delta_T) - 1
        if i < 0 or i >= params.E: raise ValueError("时间不在实例范围")
        # 计算 z：从0开始
        # delta_s = max(1, params.delta_e // self.chain_len)
        Ti_start = params.T_s + i * params.delta_T
        # z = (t - Ti_start) // delta_s
        z = int((t - Ti_start) // params.delta_e)
        if z < 0: z = 0
        if z >= self.chain_len: z = self.chain_len - 1
        if not self.aux: raise ValueError("缺少辅助信息")
        entry = None
        for e in self.aux:
            if e["instance"] == i:
                entry = e;
                break
        if entry is None: raise ValueError("未找到辅助数据")
        head = self.heads[i]
        pw = GTOTP_chain.gen_pw_from_head(head, self.chain_len, z)
        vp_tail = self.vst[i]
        vpprime = sha256(vp_tail + entry["enc"] + int_to_bytes(i, 4))
        proof_serializable = [(b64(p[0]), p[1]) for p in entry["proof"]]
        sigma = {"pw": b64(pw), "enc": b64(entry["enc"]), "proof": proof_serializable, "subset": entry["subset"],
                 "t": t, "z": int(z)}
        return sigma


# ----------------- Attester -----------------
class Attester:
    def __init__(self, name="att1"): self.name = name

    def gen_report(self, nonce: bytes, measurement: Dict[str, Any], t: int) -> Dict[str, Any]:
        return {"nonce": b64(nonce), "measurement": measurement, "t": t}


# ----------------- RP -----------------
class RelyingParty:
    """RP：验证 sigma"""

    def __init__(self, params: RAParams):
        self.params = params

    def verify(self, sigma: Dict[str, Any], vst_G: SimpleBloom, merkle_roots: List[bytes],
               mts: List[MerkleTree]) -> bool:
        # try:
        pw = ub64(sigma["pw"]);
        enc = ub64(sigma["enc"]);
        subset = sigma["subset"]
        proof = [(ub64(p[0]), p[1]) for p in sigma["proof"]];
        t = sigma["t"];
        z = sigma.get("z", 0)
        i = math.ceil((t - self.params.T_s) / self.params.delta_T) - 1
        if i < 0 or i >= self.params.E: return False
        chain_len = int(self.params.delta_T / self.params.delta_e)
        vp = GTOTP_chain.get_vp_from_pw(pw, chain_len, z)
        vk = sha256(vp + enc + int_to_bytes(i, 4))
        root = merkle_roots[subset]
        if not MerkleTree.verify(vk, proof, root): return False
        if not vst_G.query(root): return False
        return True
    # except Exception:
    # return False


def run_demo(num_members=4, T_s=0, T_e=100, delta_T=50, delta_e=10, phi=2):
    timings = {}
    start_all = time.perf_counter()
    # RA Setup
    ra = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    params = ra.params
    timings['setup'] = time.perf_counter() - start_all
    chain_len = int(params.delta_T / params.delta_e)

    # PInit
    members = {}
    for j in range(num_members):
        ID = f"member{j + 1}"
        m = RAServiceMember(ID, params, chain_len_per_instance=chain_len)
        members[ID] = m
    timings['pinit'] = time.perf_counter() - start_all - timings['setup']
    # GVSTGen
    members_vst = {ID: m.vst for ID, m in members.items()}
    gvst_res = ra.gvst_gen(members_vst)
    timings['gvstgen'] = time.perf_counter() - start_all - timings['setup'] - timings['pinit']
    # 分发 aux
    for ID, m in members.items():
        m.receive_aux(gvst_res['aux'].get(ID, []))
    timings['dist_aux'] = time.perf_counter() - start_all - timings['setup'] - timings['pinit'] - timings['gvstgen']
    # Attester 生成 report（选择 t 在第一个实例内）
    att = Attester()
    report = att.gen_report(secrets.token_bytes(12), {"fw_hash": "abc"}, t=5)
    timings['reportgen'] = time.perf_counter() - start_all - sum(timings.values())
    # 成员生成 sigma
    sigmas = []
    for ID, m in members.items():
        try:
            if m.check_report(report):
                sigma = m.pwgen(params)
                sigmas.append((ID, sigma))
        except Exception:
            pass
    print(f"Generated {len(sigmas)} sigmas.")
    timings['pwgen'] = time.perf_counter() - start_all - sum(timings.values())
    rp = RelyingParty(params)
    if len(sigmas) == 0:
        raise RuntimeError("没有生成任何 sigma")
    chosen = sigmas[secrets.randbelow(len(sigmas))][1]
    t_verify_start = time.perf_counter()
    ok = rp.verify(chosen, gvst_res['vst_G'], gvst_res['roots'], ra.mt_by_subset)
    t_verify = time.perf_counter() - t_verify_start
    timings['verify'] = t_verify
    traced = ra.open(ub64(chosen['enc']))
    timings['open'] = time.perf_counter() - start_all - sum(timings.values())
    total = time.perf_counter() - start_all
    timings['total'] = total
    print(f"Verification result: {ok}, traced ID: {traced}")
    summary = {"num_members": num_members, "E": (T_e - T_s) // delta_T, "phi": phi, "verified": ok, "traced": traced,
               **timings}
    print(summary)


if __name__ == "__main__":
    run_demo()
