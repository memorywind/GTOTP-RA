#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GTOTP-RA 原型实现（论文一致性版）
- 链式 GTOTP（hash-chain）: head, tail=H^L(head), pw=H^{L-z}(head)
- GVSTGen: vp' = H(hk || vp_tail || Enc(ID) || i), entries 整体置换后分片成 phi 个子集
- 每个子集建 Merkle tree，Roots 插入 Bloom filter
- Enc(ID) 使用 RSA-OAEP（若环境安装 cryptography），否则回退到不安全的对称模拟（仅演示）
- 注释均为中文，便于论文对接
"""
import time, math, secrets, hashlib, hmac, base64, json
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any

# 可选展示（需要在 notebook 环境），否则注释掉 display_dataframe_to_user 的调用
# try:
#     from caas_jupyter_tools import display_dataframe_to_user
#     HAS_DISPLAY = True
# except Exception:
#     HAS_DISPLAY = False

# 尝试导入 cryptography（若可用则启用真实 RSA-OAEP）
HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except Exception as e:
    HAS_CRYPTO = False
    crypto_import_error = str(e)

# ----------------- 工具函数（中文注释） -----------------
def sha256(b: bytes) -> bytes:
    """计算 SHA256 摘要"""
    return hashlib.sha256(b).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """计算 HMAC-SHA256"""
    return hmac.new(key, msg, hashlib.sha256).digest()

def int_to_bytes(i: int, length=8) -> bytes:
    """整数转定长字节（大端序）"""
    return i.to_bytes(length, "big")

def b64(b: bytes) -> str:
    """Base64 编码为字符串，便于 JSON/打印"""
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    """Base64 解码"""
    return base64.b64decode(s.encode())

# ----------------- RSA 封装（cryptography 推荐） -----------------
if HAS_CRYPTO:
    def generate_rsa_keypair(key_size=2048):
        """生成 RSA 密钥对（公钥, 私钥）"""
        sk = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        pk = sk.public_key()
        return pk, sk

    def rsa_encrypt(pk, plaintext: bytes) -> bytes:
        """使用 RSA-OAEP 加密（随机化）"""
        return pk.encrypt(plaintext,
                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))

    def rsa_decrypt(sk, ciphertext: bytes) -> bytes:
        """RSA-OAEP 解密"""
        return sk.decrypt(ciphertext,
                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))
else:
    # 回退实现（不安全，仅演示）
    def generate_rsa_keypair(key_size=2048):
        sk = secrets.token_bytes(32); pk = sk; return pk, sk
    def rsa_encrypt(pk, plaintext: bytes) -> bytes:
        ks = hmac_sha256(pk, b"rsa_enc" + int_to_bytes(len(plaintext),4))
        out = bytearray(len(plaintext))
        for i in range(len(plaintext)):
            out[i] = plaintext[i] ^ ks[i % len(ks)]
        return bytes(out)
    def rsa_decrypt(sk, ciphertext: bytes) -> bytes:
        return rsa_encrypt(sk, ciphertext)

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
    def gen_head(length_bytes=32) -> bytes:
        """生成随机链头 head"""
        return secrets.token_bytes(length_bytes)
    @staticmethod
    def compute_tail(head: bytes, chain_len: int) -> bytes:
        """计算链尾 vp = H^{L}(head)"""
        return hash_power(head, chain_len)
    @staticmethod
    def gen_pw_from_head(head: bytes, chain_len:int, z:int) -> bytes:
        """生成 pw = H^{L - z}(head)，z 为在该实例内的序号（0-based）"""
        steps = max(chain_len - z, 0)
        return hash_power(head, steps)
    @staticmethod
    def get_vp_from_pw(pw: bytes, z:int) -> bytes:
        """验证端由 pw 和 z 计算 vp = H^{z}(pw)"""
        return hash_power(pw, z)

# ----------------- Merkle Tree（含前缀哈希） -----------------
class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves[:]
        self.levels = []
        if len(leaves) == 0:
            self.root = sha256(b""); self.levels = [[self.root]]
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
                b = current[i+1] if i+1 < len(current) else current[i]
                nxt.append(sha256(b"\x01" + a + b))
            current = nxt
            self.levels.append(current)
        self.root = self.levels[-1][0]
    def get_proof(self, index: int) -> List[Tuple[bytes,bool]]:
        proof = []; idx = index
        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            sibling = level[sibling_idx] if sibling_idx < len(level) else level[idx]
            is_left = (sibling_idx < idx)
            proof.append((sibling, is_left))
            idx //= 2
        return proof
    @staticmethod
    def verify(leaf: bytes, proof: List[Tuple[bytes,bool]], root: bytes) -> bool:
        h = sha256(b"\x00" + leaf)
        for sibling, is_left in proof:
            if is_left:
                a = sibling; b = h
            else:
                a = h; b = sibling
            h = sha256(b"\x01" + a + b)
        return h == root

# ----------------- 简单 Bloom 过滤器（位集） -----------------
class SimpleBloom:
    def __init__(self, m_bits: int, k_hash: int):
        self.m = m_bits; self.k = k_hash; self.bitset = 0
    def _hashes(self, item: bytes):
        h = hashlib.sha256(item).digest()
        for i in range(self.k):
            start = (i*4) % len(h)
            val = int.from_bytes(h[start:start+4], "big")
            yield val % self.m
    def add(self, item: bytes):
        for pos in self._hashes(item): self.bitset |= (1 << pos)
    def query(self, item: bytes) -> bool:
        for pos in self._hashes(item):
            if ((self.bitset >> pos) & 1) == 0: return False
        return True

# ----------------- 系统实体与协议实现 -----------------
@dataclass
class RAParams:
    hk: bytes; kp: bytes; N: int; E: int; T_s: int; T_e: int; delta_e: int; delta_T: int; phi: int; pk_ra: Any

class RegistrationAuthority:
    """注册机构 RA：负责 Setup、GVSTGen、Open（追溯）"""
    def __init__(self, T_s:int, T_e:int, delta_e:int, delta_T:int, phi:int):
        self.pk_ra, self.sk_ra = generate_rsa_keypair()
        self.hk = secrets.token_bytes(16); self.kp = secrets.token_bytes(16)
        self.T_s = T_s; self.T_e = T_e; self.delta_e = delta_e; self.delta_T = delta_T; self.phi = phi
        self.N = math.ceil((T_e - T_s)/delta_e); self.E = math.ceil((T_e - T_s)/delta_T)
        self.params = RAParams(self.hk, self.kp, self.N, self.E, T_s, T_e, delta_e, delta_T, phi, self.pk_ra)
        self.member_aux = {}; self.merkle_roots = []; self.mt_by_subset = []; self.bloom = None

    def enc_id(self, ID: str) -> bytes:
        """使用 RA 公钥加密 ID（RSA-OAEP），随机化以防关联"""
        return rsa_encrypt(self.pk_ra, ID.encode())

    def dec_id(self, enc_bytes: bytes) -> str:
        """使用 RA 私钥解密 Enc(ID) -> ID"""
        return rsa_decrypt(self.sk_ra, enc_bytes).decode()

    def gvst_gen(self, members_vst: Dict[str, List[bytes]]):
        """
        构建群验证状态：
        - 为每个 (ID, instance) 计算 vpprime = H(hk || vp_tail || Enc(ID) || i)
        - 对 entries 整体置换（保持元信息一起移动），再按 idx % phi 切分子集
        - 为每个子集建 Merkle tree，roots 插入 Bloom
        - 为每个 member 返回 aux（包括 Enc(ID), proof, subset, pos）
        """
        entries = []
        for ID, vps in members_vst.items():
            enc = self.enc_id(ID)
            for i, vp_tail in enumerate(vps):
                vpprime = sha256(self.hk + vp_tail + enc + int_to_bytes(i,4))
                entries.append((vpprime, ID, i, enc))
        # 用 kp 派生的确定性随机源做置换
        rng = secrets.SystemRandom(int.from_bytes(hmac_sha256(self.kp, b"perm_seed"), "big"))
        rng.shuffle(entries)
        # 切分为 phi 子集并构建 merkle
        phi = self.phi; subsets = [[] for _ in range(phi)]
        entry_locs = {}
        for idx, ent in enumerate(entries):
            subset_idx = idx % phi
            subsets[subset_idx].append(ent[0])  # 存 vpprime
            entry_locs[(ent[1], ent[2])] = (subset_idx, len(subsets[subset_idx]) - 1, ent[3])
        mts = []; roots = []
        for s in subsets:
            mt = MerkleTree(s); mts.append(mt); roots.append(mt.root)
        bfilter = SimpleBloom(m_bits=4096, k_hash=6)
        for r in roots: bfilter.add(r)
        aux = {}
        for (vpprime, ID, i, enc) in entries:
            subset_idx, pos_in_subset, enc_bytes = entry_locs[(ID, i)]
            proof = mts[subset_idx].get_proof(pos_in_subset)
            aux.setdefault(ID, []).append({
                "instance": i, "enc": enc_bytes, "subset": subset_idx, "pos": pos_in_subset, "proof": proof
            })
        self.member_aux = aux; self.merkle_roots = roots; self.mt_by_subset = mts; self.bloom = bfilter
        return {"vst_G": bfilter, "aux": aux, "roots": roots, "mts": mts}

    def open(self, enc_bytes: bytes) -> str:
        """追溯：解密 Enc(ID)"""
        return self.dec_id(enc_bytes)

class RAServiceMember:
    """RA Service 成员：PInit -> 生成 head 和 tail(vp)，PwGen -> 生成 sigma"""
    def __init__(self, ID: str, params: RAParams, chain_len_per_instance: int = 12):
        self.ID = ID; self.prf_key = secrets.token_bytes(32); self.chain_len = chain_len_per_instance
        self.heads = []; self.vst = []
        for i in range(params.E):
            head = GTOTP_chain.gen_head(32)
            tail = GTOTP_chain.compute_tail(head, self.chain_len)
            self.heads.append(head); self.vst.append(tail)
        self.aux = None

    def receive_aux(self, aux_for_id):
        """接收 RA 分发的辅助数据（Enc(ID), proof 等）"""
        self.aux = aux_for_id

    def check_report(self, report: dict) -> bool:
        """检查 Attester 报告（此处默认通过；可替换策略）"""
        return True

    def pwgen(self, report: dict, params: RAParams) -> Dict[str,Any]:
        """生成 sigma（pw, Enc(ID), proof, subset, t, z）"""
        t = report["t"]; i = math.ceil((t - params.T_s)/params.delta_T) - 1
        if i < 0 or i >= params.E: raise ValueError("时间不在实例范围")
        # 计算 z：示例采用 delta_s = delta_e // chain_len
        delta_s = max(1, params.delta_e // self.chain_len)
        Ti_start = params.T_s + i * params.delta_T
        z = (t - Ti_start) // delta_s
        if z < 0: z = 0
        if z >= self.chain_len: z = self.chain_len - 1
        if not self.aux: raise ValueError("缺少辅助信息")
        entry = None
        for e in self.aux:
            if e["instance"] == i:
                entry = e; break
        if entry is None: raise ValueError("未找到辅助数据")
        head = self.heads[i]
        pw = GTOTP_chain.gen_pw_from_head(head, self.chain_len, z)
        vp_tail = self.vst[i]
        vpprime = sha256(params.hk + vp_tail + entry["enc"] + int_to_bytes(i,4))
        proof_serializable = [(b64(p[0]), p[1]) for p in entry["proof"]]
        sigma = {"pw": b64(pw), "enc": b64(entry["enc"]), "proof": proof_serializable, "subset": entry["subset"], "t": t, "z": int(z)}
        return sigma

class Attester:
    def __init__(self,name="att1"): self.name = name
    def gen_report(self, nonce: bytes, measurement: Dict[str,Any], t:int) -> Dict[str,Any]:
        return {"nonce": b64(nonce), "measurement": measurement, "t": t}

class RelyingParty:
    """RP：验证 sigma"""
    def __init__(self, params: RAParams): self.params = params
    def verify(self, sigma: Dict[str,Any], vst_G: SimpleBloom, merkle_roots: List[bytes], mts: List[MerkleTree]) -> bool:
        try:
            pw = ub64(sigma["pw"]); enc = ub64(sigma["enc"]); subset = sigma["subset"]
            proof = [(ub64(p[0]), p[1]) for p in sigma["proof"]]; t = sigma["t"]; z = sigma.get("z", 0)
            i = math.ceil((t - self.params.T_s)/self.params.delta_T) - 1
            if i < 0 or i >= self.params.E: return False
            vp = GTOTP_chain.get_vp_from_pw(pw, z)
            vk = sha256(self.params.hk + vp + enc + int_to_bytes(i,4))
            root = merkle_roots[subset]
            if not MerkleTree.verify(vk, proof, root): return False
            if not vst_G.query(root): return False
            return True
        except Exception:
            return False

# ----------------- 演示驱动：一次端到端仿真 -----------------
def run_demo(num_members=10, E=4, T_s=0, delta_T=60, delta_e=60, phi=4, chain_len=12):
    start_all = time.perf_counter()
    T_e = T_s + E * delta_T
    ra = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    params = ra.params
    # PInit
    members = {}
    for j in range(num_members):
        ID = f"member{j+1}"
        m = RAServiceMember(ID, params, chain_len_per_instance=chain_len)
        members[ID] = m
    # GVSTGen
    members_vst = {ID: m.vst for ID,m in members.items()}
    gvst_res = ra.gvst_gen(members_vst)
    # 分发 aux
    for ID,m in members.items():
        m.receive_aux(gvst_res['aux'].get(ID, []))
    # Attester 生成 report（选择 t 在第一个实例内）
    att = Attester()
    report = att.gen_report(secrets.token_bytes(12), {"fw_hash":"abc"}, t=5)
    # 成员生成 sigma
    sigmas = []
    for ID,m in members.items():
        try:
            sigma = m.pwgen(report, params)
            sigmas.append((ID, sigma))
        except Exception:
            pass
    rp = RelyingParty(params)
    if len(sigmas) == 0:
        raise RuntimeError("没有生成任何 sigma")
    chosen = sigmas[secrets.randbelow(len(sigmas))][1]
    ok = rp.verify(chosen, gvst_res['vst_G'], gvst_res['roots'], ra.mt_by_subset)
    traced = ra.open(ub64(chosen['enc']))
    summary = {"num_members":num_members, "E":E, "phi":phi, "verified": ok, "traced": traced,
               "has_crypto": HAS_CRYPTO}
    # # 输出显示
    # if HAS_DISPLAY:
    #     import pandas as pd
    #     df = pd.DataFrame([summary]); display_dataframe_to_user("GTOTP-RA 论文一致性实现 仿真结果", df)
    # else:
    #     print("仿真结果:", summary)
    # 打印示例 sigma（截断）
    ex = chosen.copy()
    if isinstance(ex.get("pw"), str) and len(ex["pw"])>10: ex["pw"] = ex["pw"][:10] + "..."
    print("示例 sigma（截断）："); print(json.dumps(ex, indent=2))
    if not HAS_CRYPTO:
        print("\n注意：当前环境缺少 'cryptography'，Enc(ID) 使用回退模拟实现。")
        print("请在真实部署环境安装 cryptography（pip install cryptography），以启用 RSA-OAEP（更安全）。")
    return summary

if __name__ == "__main__":
    # 运行示例
    run_demo()
