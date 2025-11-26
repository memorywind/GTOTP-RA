import time, math, secrets, hashlib, hmac, base64, json, datetime
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pybloom_live import BloomFilter
import argparse
import time
import secrets
import math


# -------------------- 工具函数 --------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def int_to_bytes(i: int, length=8) -> bytes:
    return i.to_bytes(length, "big")

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

def fmt(ts: float) -> str:
    """格式化时间戳为可读字符串"""
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# -------------------- RSA --------------------
def generate_rsa_keypair(key_size=2048):
    sk = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    pk = sk.public_key()
    return pk, sk

def rsa_encrypt(pk, plaintext: bytes) -> bytes:
    return pk.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_decrypt(sk, ciphertext: bytes) -> bytes:
    return sk.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )


# -------------------- 哈希链 --------------------
def hash_power(x: bytes, r: int) -> bytes:
    h = x
    for _ in range(r):
        h = sha256(h)
    return h


class GTOTP_chain:
    @staticmethod
    def gen_head(length_bytes=32): return secrets.token_bytes(length_bytes)
    @staticmethod
    def compute_tail(head, chain_len): return hash_power(head, chain_len)
    @staticmethod
    def gen_pw_from_head(head, chain_len, z): return hash_power(head, z)
    @staticmethod
    def get_vp_from_pw(pw, chain_len, z):
        steps = max(chain_len - z, 0)
        return hash_power(pw, steps)


# -------------------- Merkle Tree --------------------
class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves[:]
        if len(leaves) == 0:
            self.root = sha256(b"")
            self.levels = [[self.root]]
        else:
            self.build(leaves)

    def build(self, leaves: List[bytes]):
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
        proof = []
        idx = index
        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            sibling = level[sibling_idx] if sibling_idx < len(level) else level[idx]
            is_left = sibling_idx < idx
            proof.append((sibling, is_left))
            idx //= 2
        return proof

    @staticmethod
    def verify(leaf: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
        h = sha256(b"\x00" + leaf)
        for sibling, is_left in proof:
            if is_left:
                a, b = sibling, h
            else:
                a, b = h, sibling
            h = sha256(b"\x01" + a + b)
        return h == root


# -------------------- 布隆过滤器 --------------------
class SimpleBloom:
    # def __init__(self, m_bits: int = 8192, k_hash: int = 6, error_rate: float = 2**-40):
    #     self.error_rate = error_rate
    #     self.capacity = max(1000, m_bits)
    #     self.bloom = BloomFilter(capacity=self.capacity, error_rate=error_rate)

    def __init__(self, phi: int = 1024, error_rate: float = 2**-40):
        # 设置 BloomFilter 容量为 φ 的 2 倍
        capacity = max(phi * 2, 1024)

        self.bloom = BloomFilter(capacity=capacity, error_rate=error_rate)

    def add(self, item: bytes):
        self.bloom.add(item.hex())

    def query(self, item: bytes) -> bool:
        return item.hex() in self.bloom


# -------------------- 系统实体 --------------------
@dataclass
class RAParams:
    hk: bytes; kp: bytes; N: int; E: int; T_s: float; T_e: float
    delta_e: float; delta_T: float; phi: int; pk_ra: Any


class RegistrationAuthority:
    def __init__(self, T_s: float, T_e: float, delta_e: float, delta_T: float, phi: int):
        self.pk_ra, self.sk_ra = generate_rsa_keypair()
        self.hk = secrets.token_bytes(16)
        self.kp = secrets.token_bytes(16)
        self.T_s, self.T_e, self.delta_e, self.delta_T, self.phi = T_s, T_e, delta_e, delta_T, phi
        self.N = math.ceil((T_e - T_s) / delta_e)
        self.E = math.ceil((T_e - T_s) / delta_T)
        self.params = RAParams(self.hk, self.kp, self.N, self.E, T_s, T_e, delta_e, delta_T, phi, self.pk_ra)
        self.member_aux = {}; self.merkle_roots = []; self.mt_by_subset = []; self.bloom = None

    def enc_id(self, ID: str) -> bytes: return rsa_encrypt(self.pk_ra, ID.encode())
    def dec_id(self, enc_bytes: bytes) -> str: return rsa_decrypt(self.sk_ra, enc_bytes).decode()

    def gvst_gen(self, members_vst: Dict[str, List[bytes]]):
        entries = []
        for ID, vps in members_vst.items():
            enc = self.enc_id(ID)
            for i, vp_tail in enumerate(vps):
                vpprime = sha256(vp_tail + enc + int_to_bytes(i, 4))
                entries.append((vpprime, ID, i, enc))
        rng = secrets.SystemRandom(int.from_bytes(hmac_sha256(self.kp, b"perm_seed"), "big"))
        rng.shuffle(entries)
        phi = self.phi; subsets = [[] for _ in range(phi)]; entry_locs = {}
        for idx, ent in enumerate(entries):
            subset_idx = idx % phi
            subsets[subset_idx].append(ent[0])
            entry_locs[(ent[1], ent[2])] = (subset_idx, len(subsets[subset_idx]) - 1, ent[3])
        mts, roots = [], []
        for s in subsets:
            mt = MerkleTree(s); mts.append(mt); roots.append(mt.root)
        bfilter = SimpleBloom(self.phi)
        for r in roots: bfilter.add(r)
        aux = {}
        for (vpprime, ID, i, enc) in entries:
            subset_idx, pos_in_subset, enc_bytes = entry_locs[(ID, i)]
            proof = mts[subset_idx].get_proof(pos_in_subset)
            aux.setdefault(ID, []).append({
                "instance": i, "enc": enc_bytes, "subset": subset_idx, "pos": pos_in_subset, "proof": proof
            })
        self.member_aux, self.merkle_roots, self.mt_by_subset, self.bloom = aux, roots, mts, bfilter
        return {"vst_G": bfilter, "aux": aux, "roots": roots, "mts": mts}

    def open(self, enc_bytes: bytes) -> str:
        return self.dec_id(enc_bytes)


class RAServiceMember:
    def __init__(self, ID: str, params: RAParams, chain_len_per_instance: int):
        self.ID = ID; self.chain_len = chain_len_per_instance
        self.heads, self.vst = [], []
        for _ in range(params.E):
            head = GTOTP_chain.gen_head(32)
            tail = GTOTP_chain.compute_tail(head, self.chain_len)
            self.heads.append(head); self.vst.append(tail)
        self.aux = None

    def receive_aux(self, aux_for_id): self.aux = aux_for_id
    def check_report(self, report): return True

    def pwgen(self, params: RAParams) -> Dict[str, Any]:
        t = time.time()
        i = math.ceil((t - params.T_s) / params.delta_T) - 1
        if i < 0 or i >= params.E: raise ValueError("时间不在实例范围")
        Ti_start = params.T_s + i * params.delta_T
        z = int((t - Ti_start) / params.delta_e)
        z = max(0, min(z, self.chain_len - 1))
        if not self.aux: raise ValueError("缺少辅助信息")
        entry = next((e for e in self.aux if e["instance"] == i), None)
        if entry is None: raise ValueError("未找到辅助数据")
        head = self.heads[i]; pw = GTOTP_chain.gen_pw_from_head(head, self.chain_len, z)
        proof_serializable = [(b64(p[0]), p[1]) for p in entry["proof"]]
        print(f"[{self.ID}] 当前签名时间 {fmt(t)}, 实例 i={i}, z={z}")
        return {"pw": b64(pw), "enc": b64(entry["enc"]), "proof": proof_serializable,
                "subset": entry["subset"], "t": t, "z": z}


class RelyingParty:
    def __init__(self, params: RAParams):
        self.params = params

    def verify(self, sigma: Dict[str, Any], vst_G: SimpleBloom, roots: List[bytes], mts: List[MerkleTree]) -> bool:
        # ---- 基础解码 ----
        pw = ub64(sigma["pw"])
        enc = ub64(sigma["enc"])
        subset = sigma["subset"]
        proof = [(ub64(p[0]), p[1]) for p in sigma["proof"]]
        t_sigma = float(sigma["t"])
        z = int(sigma["z"])

        # ---- 计算 sigma 所属实例 ----
        i = int(math.ceil((t_sigma - self.params.T_s) / self.params.delta_T) - 1)
        delta_T = self.params.delta_T
        if i < 0 or i >= self.params.E:
            print("[RP] sigma 声明的实例超出范围")
            return False

        # ---- 当前真实时间与窗口定位 ----
        t_now = time.time()
        # -------- 当前窗口计算（基于当前时间） --------
        delta_e = self.params.delta_e
        T_s = self.params.T_s
        current_idx = int(math.floor((t_now - T_s) / delta_e))
        Ti_start = T_s + current_idx * delta_e
        Ti_end = Ti_start + delta_e

        # 容忍区间（如网络传播等）
        grace = max(0.1, 0.2 * delta_e)

        def fmt_ms(ts):
            return f"{time.strftime('%H:%M:%S', time.localtime(ts))}.{int((ts % 1) * 1000):03d}"

        print("\n[RP][时间验证 - 当前窗口判断]")
        print(f"  当前时间: {fmt_ms(t_now)}")
        print(f"  口令生成时间: {fmt_ms(t_sigma)}")
        print(f"  口令可用窗口: {fmt_ms(T_s + i * delta_T + z * delta_e)} ~ {fmt_ms(T_s + i * delta_T + (z+1) * delta_e)}")
        print(f"  当前窗口: {fmt_ms(Ti_start)} ~ {fmt_ms(Ti_end)} (±{grace:.2f}s)")

        # 判断 σ 的时间是否属于当前窗口
        if t_sigma < Ti_start - grace:
            print("  当前口令已过期")
            return False
        elif t_sigma > Ti_end + grace:
            print("  当前口令尚未到使用时间")
            return False
        else:
            print("  当前口令在当前时间窗口内有效")

        # ---- 原验证逻辑 ----
        chain_len = int(self.params.delta_T / self.params.delta_e)
        vp = GTOTP_chain.get_vp_from_pw(pw, chain_len, z)
        vk = sha256(vp + enc + int_to_bytes(i, 4))
        root = roots[subset]

        ok_merkle = MerkleTree.verify(vk, proof, root)
        ok_bloom = vst_G.query(root)

        print("\n[RP][结构验证]")
        print(f"  Merkle 验证结果: {ok_merkle}")
        print(f"  Bloom 过滤检查: {ok_bloom}")

        if not ok_merkle:
            print("Merkle 证明验证失败")
            return False
        if not ok_bloom:
            print("Bloom 检查失败")
            return False

        print("  所有验证通过\n")
        return True



# -------------------- 主流程 --------------------
# def run_demo(num_members=100, delta_T=300, delta_e=5, phi=8192):
#     T_s = time.time()
#     T_e = T_s + 100 * delta_T  # 2 个 instance 周期
#     ra = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
#     params = ra.params
#     chain_len = int(params.delta_T / params.delta_e)
#     members = {f"member{j+1}": RAServiceMember(f"member{j+1}", params, chain_len) for j in range(num_members)}
#     gvst_res = ra.gvst_gen({ID: m.vst for ID, m in members.items()})
#     for ID, m in members.items(): m.receive_aux(gvst_res["aux"][ID])
#     chosen_member = secrets.choice(list(members.values()))
#     sigma = chosen_member.pwgen(params)
#     # time.sleep(1.9)
#     rp = RelyingParty(params)
#     ok = rp.verify(sigma, gvst_res["vst_G"], gvst_res["roots"], ra.mt_by_subset)
#     traced = ra.open(ub64(sigma["enc"]))
#     print(f"\n验证结果：{ok}，追溯身份：{traced}")
#     print(f"验证时间：{fmt(time.time())}, 实例 {math.ceil((sigma['t'] - params.T_s)/params.delta_T)-1}, z={sigma['z']}")
#
#
# if __name__ == "__main__":
#     run_demo()


def run_demo(num_members=100, delta_T=300, delta_e=5, phi=8192):
    T_s = time.time()
    T_e = T_s + 100 * delta_T     # 100 个 instance 周期

    print(f"\n[参数]")
    print(f"  成员数 num_members = {num_members}")
    print(f"  ΔT = {delta_T}")
    print(f"  Δe = {delta_e}")
    print(f"  φ = {phi}")
    print(f"  当前时间 T_s = {fmt(T_s)}")

    # ---- RA Setup ----
    ra = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    params = ra.params
    chain_len = int(params.delta_T / params.delta_e)

    # ---- PInit ----
    members = {
        f"member{j+1}": RAServiceMember(f"member{j+1}", params, chain_len)
        for j in range(num_members)
    }

    # ---- GVSTGen ----
    gvst_res = ra.gvst_gen({ID: m.vst for ID, m in members.items()})

    # ---- 分发 aux ----
    for ID, m in members.items():
        m.receive_aux(gvst_res["aux"][ID])

    # ---- 随机选一个成员生成 sigma ----
    chosen_member = secrets.choice(list(members.values()))
    sigma = chosen_member.pwgen(params)

    # ---- RP 验证 ----
    rp = RelyingParty(params)
    ok = rp.verify(sigma, gvst_res["vst_G"], gvst_res["roots"], ra.mt_by_subset)
    traced = ra.open(ub64(sigma["enc"]))

    print("\n================== 验证结果 ==================")
    print(f"验证结果：{ok}")
    print(f"追溯身份：{traced}")
    print(f"验证时间：{fmt(time.time())}")
    print(f"实例 i = {math.ceil((sigma['t'] - params.T_s)/params.delta_T) - 1}")
    print(f"z = {sigma['z']}")
    print("==============================================\n")



# ===================== 主入口：命令行接口 =====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GTOTP-RA 运行演示")

    parser.add_argument("--num", type=int, default=100,
                        help="成员数量（默认 100）")
    parser.add_argument("--deltaT", type=float, default=300,
                        help="实例周期 ΔT（秒，默认 300）")
    parser.add_argument("--deltae", type=float, default=5,
                        help="口令周期 Δe（秒，默认 5）")
    parser.add_argument("--phi", type=int, default=8192,
                        help="子集数量 φ（默认 8192）")

    args = parser.parse_args()

    run_demo(
        num_members=args.num,
        delta_T=args.deltaT,
        delta_e=args.deltae,
        phi=args.phi
    )