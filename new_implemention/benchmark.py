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
import statistics
from verifyreport import *


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

    def __init__(self, phi: int = 1024, error_rate: float = 2 ** -40):
        # 设置 BloomFilter 容量为 φ 的 2 倍
        capacity = max(phi * 2, 1024)

        self.bloom = BloomFilter(capacity=capacity, error_rate=error_rate)

    def add(self, item: bytes):
        self.bloom.add(item.hex())

    def query(self, item: bytes) -> bool:
        return item.hex() in self.bloom

    def num_bits(self) -> int:
        return self.bloom.num_bits


# -------------------- 系统实体 --------------------
@dataclass
class RAParams:
    hk: bytes;
    kp: bytes;
    N: int;
    E: int;
    T_s: float;
    T_e: float
    delta_e: float;
    delta_T: float;
    phi: int;
    pk_ra: Any


class RegistrationAuthority:
    def __init__(self, T_s: float, T_e: float, delta_e: float, delta_T: float, phi: int):
        self.pk_ra, self.sk_ra = generate_rsa_keypair()
        self.hk = secrets.token_bytes(16)
        self.kp = secrets.token_bytes(16)
        self.T_s, self.T_e, self.delta_e, self.delta_T, self.phi = T_s, T_e, delta_e, delta_T, phi
        self.N = math.ceil((T_e - T_s) / delta_e)
        self.E = math.ceil((T_e - T_s) / delta_T)
        self.params = RAParams(self.hk, self.kp, self.N, self.E, T_s, T_e, delta_e, delta_T, phi, self.pk_ra)
        self.member_aux = {};
        self.merkle_roots = [];
        self.mt_by_subset = [];
        self.bloom = None

    def enc_id(self, ID: str) -> bytes:
        return rsa_encrypt(self.pk_ra, ID.encode())

    def dec_id(self, enc_bytes: bytes) -> str:
        return rsa_decrypt(self.sk_ra, enc_bytes).decode()

    def gvst_gen(self, members_vst: Dict[str, List[bytes]]):
        entries = []
        for ID, vps in members_vst.items():
            enc = self.enc_id(ID)
            for i, vp_tail in enumerate(vps):
                vpprime = sha256(vp_tail + enc + int_to_bytes(i, 4))
                entries.append((vpprime, ID, i, enc))
        rng = secrets.SystemRandom(int.from_bytes(hmac_sha256(self.kp, b"perm_seed"), "big"))
        rng.shuffle(entries)
        phi = self.phi;
        subsets = [[] for _ in range(phi)];
        entry_locs = {}
        for idx, ent in enumerate(entries):
            subset_idx = idx % phi
            subsets[subset_idx].append(ent[0])
            entry_locs[(ent[1], ent[2])] = (subset_idx, len(subsets[subset_idx]) - 1, ent[3])
        mts, roots = [], []
        for s in subsets:
            mt = MerkleTree(s);
            mts.append(mt);
            roots.append(mt.root)
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
        self.ID = ID;
        self.chain_len = chain_len_per_instance
        self.heads, self.vst = [], []
        for _ in range(params.E):
            head = GTOTP_chain.gen_head(32)
            tail = GTOTP_chain.compute_tail(head, self.chain_len)
            self.heads.append(head);
            self.vst.append(tail)
        self.aux = None

    def receive_aux(self, aux_for_id):
        self.aux = aux_for_id

    def check_report(self, report):
        return True

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
        head = self.heads[i];
        pw = GTOTP_chain.gen_pw_from_head(head, self.chain_len, z)
        proof_serializable = [(b64(p[0]), p[1]) for p in entry["proof"]]
        print(f"[{self.ID}] 当前签名时间 {fmt(t)}, 实例 i={i}, z={z}")
        return {"pw": b64(pw), "enc": b64(entry["enc"]), "proof": proof_serializable,
                "subset": entry["subset"], "t": t, "z": z}

    def _pwgen_with_timing(self, params: RAParams) -> Dict[str, Any]:
        """带时间测量的密码生成"""
        timing_results = {}

        # 1. 时间窗口和实例计算
        t0 = time.time()
        t = time.time()
        i = math.ceil((t - params.T_s) / params.delta_T) - 1
        if i < 0 or i >= params.E:
            raise ValueError("时间不在实例范围")
        Ti_start = params.T_s + i * params.delta_T
        z = int((t - Ti_start) / params.delta_e)
        z = max(0, min(z, self.chain_len - 1))
        timing_results["time_window"] = (time.time() - t0) * 1000  # 转换为毫秒

        # 2. 查找辅助数据
        t1 = time.time()
        if not self.aux:
            raise ValueError("缺少辅助信息")
        entry = next((e for e in self.aux if e["instance"] == i), None)
        if entry is None:
            raise ValueError("未找到辅助数据")
        timing_results["aux_lookup"] = (time.time() - t1) * 1000

        # 3. 哈希链计算
        t2 = time.time()
        head = self.heads[i]
        pw = GTOTP_chain.gen_pw_from_head(head, self.chain_len, z)
        timing_results["hash_chain"] = (time.time() - t2) * 1000

        # 4. 报告验证（检查当前状态）
        t3 = time.time()
        # 这里可以添加额外的报告验证逻辑


        try:
            # 创建报告验证器
            verifier = ReportVerifier(verbose=False)

            # 尝试加载报告文件
            report_data = verifier.load_report_from_file("report.json")

            if report_data:
                # 执行完整的报告验证，只获取总时间
                verification_result = verifier.verify_report_complete(report_data)
                report_verification_time = verification_result["total_time_ms"]
                report_verification_success = verification_result["overall_success"]
            else:
                # 如果找不到报告文件，创建模拟结果
                report_verification_time = 0.5  # 模拟验证时间
                report_verification_success = True
        except Exception as e:
            # 如果验证过程中出现异常，记录错误
            print(f"[{self.ID}] 报告验证异常: {e}")
            report_verification_success = False
            report_verification_time = 0

        timing_results["report_verify"] = report_verification_time
        timing_results["report_success"] = report_verification_success

        # 如果报告验证失败，可以选择抛出异常
        if not timing_results["report_success"]:
            print(f"[{self.ID}] 报告验证失败，但继续执行以测量时间")

        timing_results["report_verify"] = (time.time() - t3) * 1000

        # 5. 证明组装
        t4 = time.time()
        proof_serializable = [(b64(p[0]), p[1]) for p in entry["proof"]]
        timing_results["proof_assemble"] = (time.time() - t4) * 1000

        # 总时间
        timing_results["total"] = sum([
            timing_results["time_window"],
            timing_results["aux_lookup"],
            timing_results["hash_chain"],
            timing_results["report_verify"],
            timing_results["proof_assemble"]
        ])

        # 计算百分比
        for key in ["time_window", "aux_lookup", "hash_chain", "report_verify", "proof_assemble"]:
            if timing_results["total"] > 0:
                timing_results[f"{key}_percent"] = (timing_results[key] / timing_results["total"]) * 100
            else:
                timing_results[f"{key}_percent"] = 0

        print(f"[{self.ID}] 当前签名时间 {fmt(t)}, 实例 i={i}, z={z}")

        result = {
            "pw": b64(pw),
            "enc": b64(entry["enc"]),
            "proof": proof_serializable,
            "subset": entry["subset"],
            "t": t,
            "z": z,
            "timing": timing_results  # 添加时间测量结果
        }

        return result


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
        print(
            f"  口令可用窗口: {fmt_ms(T_s + i * delta_T + z * delta_e)} ~ {fmt_ms(T_s + i * delta_T + (z + 1) * delta_e)}")
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


def run_demo(num_members=100, delta_T=300, delta_e=5, phi=8192, N=2):
    T_s = time.time()
    T_e = T_s + N * delta_T  # 100 个 instance 周期

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
        f"member{j + 1}": RAServiceMember(f"member{j + 1}", params, chain_len)
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
    print(f"实例 i = {math.ceil((sigma['t'] - params.T_s) / params.delta_T) - 1}")
    print(f"z = {sigma['z']}")
    print("==============================================\n")


# -------------------------------------------------------------
# 实验功能：GTOTP Benchmark 测试模块
# -------------------------------------------------------------

def benchmark_password_generation(members, params, repeat=100):
    """测试 GTOTP 一次性密码生成性能"""
    costs = []

    for _ in range(repeat):
        m = secrets.choice(members)
        t0 = time.time()
        m.pwgen(params)
        t1 = time.time()
        costs.append((t1 - t0) * 1000)  # convert to ms

    return {
        "avg_ms": statistics.mean(costs),
        "std_ms": statistics.stdev(costs) if len(costs) > 1 else 0,
        "min_ms": min(costs),
        "max_ms": max(costs),
        "samples": repeat
    }


def benchmark_pwgen_components(members, params, repeat=100):
    """测试密码生成阶段的各个组成部分时间"""
    print("======== 密码生成阶段时间分解测试 ========")

    # 存储各阶段的时间
    time_components = {
        "time_window": [],  # 时间窗口和实例计算
        "aux_lookup": [],  # 辅助数据查找
        "hash_chain": [],  # 哈希链计算
        "report_verify": [],  # 报告验证
        "proof_assemble": [],  # 证明组装
        "total": []  # 总时间
    }

    for _ in range(repeat):
        m = secrets.choice(members)
        try:
            # 使用带时间测量的密码生成
            result = m._pwgen_with_timing(params)
            timing = result["timing"]

            # 记录各阶段时间
            for component in ["time_window", "aux_lookup", "hash_chain", "report_verify", "proof_assemble", "total"]:
                time_components[component].append(timing[component])

        except Exception as e:
            print(f"密码生成失败: {e}")
            continue

    # 计算各阶段的统计信息
    results = {}
    total_avg = statistics.mean(time_components["total"]) if time_components["total"] else 0

    for component, times in time_components.items():
        if times:
            avg = statistics.mean(times)
            results[component] = {
                "avg_ms": avg,
                "std_ms": statistics.stdev(times) if len(times) > 1 else 0,
                "min_ms": min(times),
                "max_ms": max(times),
                "percentage": (avg / total_avg * 100) if total_avg > 0 else 0,
                "samples": len(times)
            }

    return results


# def benchmark_verification(member, RA, params, repeat=100):
#     """测试 Bloom + Merkle 验证性能"""
#     costs = []
#
#     for _ in range(repeat):
#         data = member.pwgen(params)
#         pw = ub64(data["pw"])
#         enc = ub64(data["enc"])
#         subset = data["subset"]
#         proof = [(ub64(b), f) for b, f in data["proof"]]
#
#         root = RA.merkle_roots[subset]
#
#         t0 = time.time()
#         # 1. Bloom filter test
#         RA.bloom.query(root)
#
#         # 2. Merkle proof verify
#         MerkleTree.verify(pw, proof, root)
#         t1 = time.time()
#
#         costs.append((t1 - t0) * 1000)
#
#     return {
#         "avg_ms": statistics.mean(costs),
#         "std_ms": statistics.stdev(costs) if len(costs) > 1 else 0,
#         "min_ms": min(costs),
#         "max_ms": max(costs),
#         "samples": repeat
#     }


def benchmark_proof_generation_time(num_members=100, delta_T=300, delta_e=5, phi=8192, n=2, repeat=100):
    """测试证明生成阶段的总时间及各部分时间"""
    print("======== 证明生成阶段时间测试 ========")

    T_s = time.time()
    T_e = T_s + n * delta_T
    RA = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    chain_len = int(delta_T / delta_e)

    # 创建成员
    members = [RAServiceMember(f"ID{i}", RA.params, chain_len) for i in range(num_members)]

    # 生成GVST和分发aux
    vst = RA.gvst_gen({m.ID: m.vst for m in members})
    for m in members:
        m.receive_aux(RA.member_aux[m.ID])

    # 测量密码生成阶段的时间分解
    pwgen_results = benchmark_pwgen_components(members, RA.params, repeat)

    # 测量哈希链计算、报告验证和证明组装的总时间
    hash_chain_times = []
    report_verify_times = []
    proof_assemble_times = []
    total_pwgen_times = []

    for _ in range(repeat):
        m = secrets.choice(members)
        try:
            # 使用带时间测量的密码生成
            result = m._pwgen_with_timing(RA.params)
            timing = result["timing"]

            # 记录各阶段时间
            hash_chain_times.append(timing["hash_chain"])
            report_verify_times.append(timing["report_verify"])
            proof_assemble_times.append(timing["proof_assemble"])
            total_pwgen_times.append(timing["total"])

        except Exception as e:
            print(f"密码生成失败: {e}")
            continue

    # 计算统计信息
    results = {
        "hash_chain": {
            "avg_ms": statistics.mean(hash_chain_times) if hash_chain_times else 0,
            "std_ms": statistics.stdev(hash_chain_times) if len(hash_chain_times) > 1 else 0,
            "samples": len(hash_chain_times)
        },
        "report_verify": {
            "avg_ms": statistics.mean(report_verify_times) if report_verify_times else 0,
            "std_ms": statistics.stdev(report_verify_times) if len(report_verify_times) > 1 else 0,
            "samples": len(report_verify_times)
        },
        "proof_assemble": {
            "avg_ms": statistics.mean(proof_assemble_times) if proof_assemble_times else 0,
            "std_ms": statistics.stdev(proof_assemble_times) if len(proof_assemble_times) > 1 else 0,
            "samples": len(proof_assemble_times)
        },
        "total": {
            "avg_ms": statistics.mean(total_pwgen_times) if total_pwgen_times else 0,
            "std_ms": statistics.stdev(total_pwgen_times) if len(total_pwgen_times) > 1 else 0,
            "samples": len(total_pwgen_times)
        }
    }

    # 计算百分比
    total_avg = results["total"]["avg_ms"]
    if total_avg > 0:
        results["hash_chain"]["percentage"] = (results["hash_chain"]["avg_ms"] / total_avg) * 100
        results["report_verify"]["percentage"] = (results["report_verify"]["avg_ms"] / total_avg) * 100
        results["proof_assemble"]["percentage"] = (results["proof_assemble"]["avg_ms"] / total_avg) * 100

    return results



def benchmark_verification(member, RA, params, repeat=100):
    """测试 Bloom + Merkle 验证性能，包括各步骤时间分解"""
    # 存储各阶段的时间
    time_components = {
        "decode": [],  # 数据解码
        "time_check": [],  # 时间窗口验证
        "hash_chain": [],  # 哈希链重计算
        "bloom_query": [],  # Bloom Filter查询
        "merkle_verify": [],  # Merkle证明验证
        "total": []  # 总验证时间
    }

    # 为了进行时间验证，我们需要一个RelyingParty实例
    rp = RelyingParty(params)

    for _ in range(repeat):
        # 生成一个签名用于验证
        sigma = member.pwgen(params)

        # 1. 数据解码阶段
        decode_start = time.time()
        pw = ub64(sigma["pw"])
        enc = ub64(sigma["enc"])
        subset = sigma["subset"]
        proof = [(ub64(p[0]), p[1]) for p in sigma["proof"]]
        t_sigma = float(sigma["t"])
        z = int(sigma["z"])
        decode_end = time.time()

        # 2. 时间窗口验证
        time_check_start = time.time()
        # 计算实例索引
        i = int(math.ceil((t_sigma - params.T_s) / params.delta_T) - 1)
        # 验证时间是否在有效窗口内
        t_now = time.time()
        current_idx = int(math.floor((t_now - params.T_s) / params.delta_e))
        Ti_start = params.T_s + current_idx * params.delta_e
        Ti_end = Ti_start + params.delta_e
        grace = max(0.1, 0.2 * params.delta_e)

        # 判断时间窗口
        time_valid = (t_sigma >= Ti_start - grace) and (t_sigma <= Ti_end + grace)
        time_check_end = time.time()

        if not time_valid:
            # 如果时间窗口无效，跳过此次测量
            continue

        # 3. 哈希链重计算（验证点计算）
        hash_chain_start = time.time()
        chain_len = int(params.delta_T / params.delta_e)
        vp = GTOTP_chain.get_vp_from_pw(pw, chain_len, z)
        vk = sha256(vp + enc + int_to_bytes(i, 4))
        hash_chain_end = time.time()

        # 4. Bloom Filter查询
        bloom_start = time.time()
        root = RA.merkle_roots[subset]
        bloom_result = RA.bloom.query(root)
        bloom_end = time.time()

        if not bloom_result:
            # 如果Bloom Filter查询失败，跳过此次测量
            continue

        # 5. Merkle证明验证
        merkle_start = time.time()
        merkle_result = MerkleTree.verify(vk, proof, root)
        merkle_end = time.time()

        if not merkle_result:
            # 如果Merkle证明验证失败，跳过此次测量
            continue

        # 计算各阶段耗时（毫秒）
        decode_time = (decode_end - decode_start) * 1000
        time_check_time = (time_check_end - time_check_start) * 1000
        hash_chain_time = (hash_chain_end - hash_chain_start) * 1000
        bloom_time = (bloom_end - bloom_start) * 1000
        merkle_time = (merkle_end - merkle_start) * 1000
        total_time = (merkle_end - decode_start) * 1000

        # 记录各阶段时间
        time_components["decode"].append(decode_time)
        time_components["time_check"].append(time_check_time)
        time_components["hash_chain"].append(hash_chain_time)
        time_components["bloom_query"].append(bloom_time)
        time_components["merkle_verify"].append(merkle_time)
        time_components["total"].append(total_time)

    # 如果没有有效测量，返回错误
    if not time_components["total"]:
        return {
            "error": "没有有效的验证测量（可能由于时间窗口无效或验证失败）",
            "samples": 0
        }

    # 计算各阶段的统计信息
    results = {}
    total_avg = statistics.mean(time_components["total"])

    for component, times in time_components.items():
        if times:
            avg = statistics.mean(times)
            results[component] = {
                "avg_ms": avg,
                "std_ms": statistics.stdev(times) if len(times) > 1 else 0,
                "min_ms": min(times),
                "max_ms": max(times),
                "percentage": (avg / total_avg * 100) if total_avg > 0 else 0,
                "samples": len(times)
            }

    return results


def benchmark_phi_effect(U=8, delta_T=20, delta_e=1, phi_values=[1024, 2048, 4096, 8192], n=2):
    """测试不同 φ 对验证性能的影响"""
    results = {}

    for phi in phi_values:
        print(f"\n==== 测试 φ = {phi} ====")
        T_s = time.time()
        T_e = T_s + n * delta_T

        RA = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
        chain_len = int(delta_T / delta_e)

        members = [RAServiceMember(f"ID{i}", RA.params, chain_len)
                   for i in range(U)]

        vst = RA.gvst_gen({m.ID: m.vst for m in members})
        for m in members:
            m.receive_aux(RA.member_aux[m.ID])

        member = members[0]
        test_res = benchmark_verification(member, RA, RA.params, repeat=200)
        results[phi] = test_res

    return results


def benchmark_gvst_gen(U_values=[4, 8, 16, 32, 64], delta_T=20, delta_e=1, phi=8192, n=2):
    """测试不同成员数 U 的 GVSTGen 时间"""
    results = {}

    for U in U_values:
        T_s = time.time()
        T_e = T_s + n * delta_T

        RA = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
        chain_len = int(delta_T / delta_e)

        members = [RAServiceMember(f"ID{i}", RA.params, chain_len)
                   for i in range(U)]

        t0 = time.time()
        vst = RA.gvst_gen({m.ID: m.vst for m in members})
        t1 = time.time()

        results[U] = {
            "gvst_ms": (t1 - t0) * 1000,
            "phi": phi,
            "U": U
        }

    return results


def benchmark_initialization_time(num_members=100, delta_T=300, delta_e=5, phi=8192, n=2, repeat=10):
    """测试系统初始化阶段的总时间"""
    print("======== 初始化时间测试 ========")

    total_times = []

    for r in range(repeat):
        T_s = time.time()
        T_e = T_s + n * delta_T

        # 1. RA Setup 时间
        t0 = time.time()
        RA = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
        t1 = time.time()

        chain_len = int(delta_T / delta_e)

        # 2. 成员PInit时间
        t2 = time.time()
        members = [RAServiceMember(f"ID{i}", RA.params, chain_len)
                   for i in range(num_members)]
        t3 = time.time()

        # 3. GVSTGen时间
        t4 = time.time()
        vst = RA.gvst_gen({m.ID: m.vst for m in members})
        t5 = time.time()

        # 分发aux（可选）
        for m in members:
            m.receive_aux(RA.member_aux[m.ID])

        # 计算各阶段时间
        ra_setup_time = (t1 - t0) * 1000  # ms
        pinit_time = (t3 - t2) * 1000  # ms
        gvstgen_time = (t5 - t4) * 1000  # ms
        total_time = (t5 - t0) * 1000  # ms

        total_times.append({
            "ra_setup_ms": ra_setup_time,
            "pinit_ms": pinit_time,
            "gvstgen_ms": gvstgen_time,
            "total_ms": total_time
        })

        print(f"第 {r + 1} 次测量: RA Setup={ra_setup_time:.2f}ms, PInit={pinit_time:.2f}ms, "
              f"GVSTGen={gvstgen_time:.2f}ms, 总时间={total_time:.2f}ms")

    # 统计分析

    ra_setup_avg = statistics.mean([t["ra_setup_ms"] for t in total_times])
    pinit_avg = statistics.mean([t["pinit_ms"] for t in total_times])
    gvstgen_avg = statistics.mean([t["gvstgen_ms"] for t in total_times])
    total_avg = statistics.mean([t["total_ms"] for t in total_times])

    return {
        "num_members": num_members,
        "phi": phi,
        "repeat": repeat,
        "ra_setup_avg_ms": ra_setup_avg,
        "pinit_avg_ms": pinit_avg,
        "gvstgen_avg_ms": gvstgen_avg,
        "total_avg_ms": total_avg,
        "components_percentage": {
            "ra_setup": (ra_setup_avg / total_avg) * 100,
            "pinit": (pinit_avg / total_avg) * 100,
            "gvstgen": (gvstgen_avg / total_avg) * 100
        }
    }


# ===================== 新增的存储数据量测试功能 =====================

def benchmark_storage_size(num_members=100, delta_T=300, delta_e=5, phi=8192, n=2):
    """测试系统存储数据量大小"""
    print("======== 存储数据量测试 ========")

    T_s = time.time()
    T_e = T_s + n * delta_T

    # 创建RA和成员
    RA = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    chain_len = int(delta_T / delta_e)
    members = [RAServiceMember(f"ID{i}", RA.params, chain_len) for i in range(num_members)]

    # 生成GVST
    vst = RA.gvst_gen({m.ID: m.vst for m in members})
    for m in members:
        m.receive_aux(RA.member_aux[m.ID])

    # 计算各种数据量大小
    storage_info = {}

    # 1. 单个签名数据量分析
    sample_sigma = members[0].pwgen(RA.params)
    sigma_json = json.dumps(sample_sigma)
    storage_info["sigma_serialization_size_bytes"] = len(sigma_json.encode('utf-8'))
    storage_info["sigma_serialization_size_kb"] = storage_info["sigma_serialization_size_bytes"] / 1024

    # 分析签名各组成部分
    # storage_info["pw_size_bytes"] = len(sample_sigma["pw"])  # base64编码的口令
    # storage_info["enc_size_bytes"] = len(sample_sigma["enc"])  # base64编码的加密身份
    storage_info["pw_size_bytes"] = len(ub64(sample_sigma["pw"]))  # 原始口令大小
    storage_info["enc_size_bytes"] = len(ub64(sample_sigma["enc"]))  # 原始加密身份大小

    # 更精确地计算证明大小
    proof_size = 0
    for proof_item in sample_sigma["proof"]:
        # 每个证明项包含一个base64编码的哈希值和一个布尔值
        hash_b64 = proof_item[0]  # base64编码的哈希值
        is_left = proof_item[1]  # 布尔值

        # base64解码获取原始哈希值大小
        hash_bytes = ub64(hash_b64)
        proof_size += len(hash_bytes)  # 原始哈希值大小
        proof_size += 1  # 布尔值大小（估算）

    storage_info["proof_size_bytes"] = proof_size

    # 其他字段的原始大小估算
    storage_info["subset_raw_size_bytes"] = 4  # 整数，4字节
    storage_info["t_raw_size_bytes"] = 8  # 浮点数，8字节
    storage_info["z_raw_size_bytes"] = 4  # 整数，4字节

    # 计算签名的原始总大小（不包含JSON序列化开销）
    storage_info["sigma_raw_size_bytes"] = (
            storage_info["pw_size_bytes"] +
            storage_info["enc_size_bytes"] +
            storage_info["proof_size_bytes"] +
            storage_info["subset_raw_size_bytes"] +
            storage_info["t_raw_size_bytes"] +
            storage_info["z_raw_size_bytes"]
    )
    storage_info["sigma_raw_size_kb"] = storage_info["sigma_raw_size_bytes"] / 1024

    storage_info["proof_size_bytes"] = proof_size

    # 计算各部分占比
    total_sigma_size = (
            storage_info["pw_size_bytes"] +
            storage_info["enc_size_bytes"] +
            storage_info["proof_size_bytes"]
    )

    storage_info["sigma_component_percentages"] = {
        "pw_percent": (storage_info["pw_size_bytes"] / total_sigma_size) * 100,
        "enc_percent": (storage_info["enc_size_bytes"] / total_sigma_size) * 100,
        "proof_percent": (storage_info["proof_size_bytes"] / total_sigma_size) * 100
    }

    # 2. 布隆过滤器大小
    bloom_size = RA.bloom.num_bits() / 8  # 位转换为字节
    storage_info["bloom_filter_size_bytes"] = bloom_size
    storage_info["bloom_filter_size_kb"] = bloom_size / 1024

    # 3. Merkle树总大小
    total_merkle_nodes = 0
    total_merkle_size_bytes = 0
    for mt in RA.mt_by_subset:
        # 估算Merkle树节点数量
        leaves_count = len(mt.leaves)
        # Merkle树节点数大约是叶子节点的2倍
        nodes_count = leaves_count * 2 - 1 if leaves_count > 0 else 0
        total_merkle_nodes += nodes_count
        # 每个节点是32字节的哈希值
        total_merkle_size_bytes += nodes_count * 32

    storage_info["total_merkle_nodes"] = total_merkle_nodes
    storage_info["total_merkle_size_bytes"] = total_merkle_size_bytes
    storage_info["total_merkle_size_kb"] = total_merkle_size_bytes / 1024
    storage_info["total_merkle_size_mb"] = total_merkle_size_bytes / (1024 * 1024)

    # 4. 成员辅助信息大小分析
    total_aux_size_bytes = 0
    aux_component_sizes = {
        "instance_total": 0,
        "enc_total": 0,
        "subset_total": 0,
        "pos_total": 0,
        "proof_total": 0
    }

    for member_id, aux_list in RA.member_aux.items():
        # 计算单个成员的辅助信息大小
        for aux_item in aux_list:
            # 实例索引
            aux_component_sizes["instance_total"] += 4  # 整数，4字节

            # 加密身份
            enc_bytes = aux_item["enc"]
            aux_component_sizes["enc_total"] += len(enc_bytes)

            # 子集索引
            aux_component_sizes["subset_total"] += 4  # 整数，4字节

            # 位置索引
            aux_component_sizes["pos_total"] += 4  # 整数，4字节

            # 证明
            proof = aux_item["proof"]
            for proof_item in proof:
                hash_bytes = proof_item[0]  # 哈希值
                is_left = proof_item[1]  # 布尔值
                aux_component_sizes["proof_total"] += len(hash_bytes) + 1  # 哈希值+布尔值

    # 总辅助信息大小
    total_aux_size_bytes = sum(aux_component_sizes.values())
    storage_info["total_aux_size_bytes"] = total_aux_size_bytes
    storage_info["total_aux_size_kb"] = total_aux_size_bytes / 1024
    storage_info["total_aux_size_mb"] = total_aux_size_bytes / (1024 * 1024)
    storage_info["avg_aux_per_member_bytes"] = total_aux_size_bytes / num_members

    # 辅助信息各组成部分大小
    storage_info["aux_component_sizes"] = aux_component_sizes
    storage_info["aux_component_percentages"] = {
        component: (size / total_aux_size_bytes) * 100
        for component, size in aux_component_sizes.items()
    }

    # 5. 总存储估算
    total_storage_bytes = (
            bloom_size +
            total_merkle_size_bytes +
            total_aux_size_bytes
    )
    storage_info["total_storage_bytes"] = total_storage_bytes
    storage_info["total_storage_kb"] = total_storage_bytes / 1024
    storage_info["total_storage_mb"] = total_storage_bytes / (1024 * 1024)

    # 6. 系统各组件占比
    storage_info["storage_component_percentages"] = {
        "bloom_percent": (bloom_size / total_storage_bytes) * 100,
        "merkle_percent": (total_merkle_size_bytes / total_storage_bytes) * 100,
        "aux_percent": (total_aux_size_bytes / total_storage_bytes) * 100
    }

    return storage_info


def benchmark_storage_scaling(U_values=[100, 500, 1000, 2000],
                              phi_values=[1024, 2048, 4096, 8192],
                              delta_T=300, delta_e=5, n=2):
    """测试不同参数对存储数据量的影响"""
    results = {}

    print("======== 存储数据量扩展性测试 ========")

    # 测试不同成员数量
    print("\n[1] 测试不同成员数量对存储的影响")
    U_results = {}
    for U in U_values:
        print(f"--- 测试 U={U} ---")
        storage_info = benchmark_storage_size(
            num_members=U,
            delta_T=delta_T,
            delta_e=delta_e,
            phi=8192,  # 固定phi
            n=n
        )
        U_results[U] = storage_info
        print(f"  总存储: {storage_info['total_storage_mb']:.2f} MB")
        print(f"  单个签名大小: {storage_info['sigma_raw_size_bytes']} 字节")
        print(f"  签名组件占比 - 口令: {storage_info['sigma_component_percentages']['pw_percent']:.2f}%, "
              f"加密身份: {storage_info['sigma_component_percentages']['enc_percent']:.2f}%, "
              f"证明: {storage_info['sigma_component_percentages']['proof_percent']:.2f}%")
        print(f"  平均每个成员辅助信息: {storage_info['avg_aux_per_member_bytes']:.2f} 字节")

    results["U_scaling"] = U_results

    # 测试不同phi值
    print("\n[2] 测试不同φ值对存储的影响")
    phi_results = {}
    for phi in phi_values:
        print(f"--- 测试 φ={phi} ---")
        storage_info = benchmark_storage_size(
            num_members=100,  # 固定成员数量
            delta_T=delta_T,
            delta_e=delta_e,
            phi=phi,
            n=n
        )
        phi_results[phi] = storage_info
        print(f"  总存储: {storage_info['total_storage_mb']:.2f} MB")
        print(f"  Bloom过滤器: {storage_info['bloom_filter_size_kb']:.2f} KB")
        print(f"  Merkle树: {storage_info['total_merkle_size_kb']:.2f} KB")
        print(f"  辅助信息: {storage_info['total_aux_size_mb']:.2f} MB")
        print(f"  存储组件占比 - Bloom: {storage_info['storage_component_percentages']['bloom_percent']:.2f}%, "
              f"Merkle: {storage_info['storage_component_percentages']['merkle_percent']:.2f}%, "
              f"辅助信息: {storage_info['storage_component_percentages']['aux_percent']:.2f}%")

    results["phi_scaling"] = phi_results

    return results


def run_all_benchmarks(num_members=8, delta_T=20, delta_e=1, phi=8192, n=2):
    """运行所有性能测试，使用传入的参数"""
    print("======== 启动 GTOTP Benchmark ========")

    # 使用传入的参数
    T_s = time.time()
    T_e = T_s + n * delta_T

    RA = RegistrationAuthority(T_s, T_e, delta_e, delta_T, phi)
    chain_len = int(delta_T / delta_e)

    members = [
        RAServiceMember(f"ID{i}", RA.params, chain_len)
        for i in range(num_members)
    ]

    vst = RA.gvst_gen({m.ID: m.vst for m in members})
    for m in members:
        m.receive_aux(RA.member_aux[m.ID])

    # 1. Password Generation
    print("\n[1] Password Generation Benchmark")
    r1 = benchmark_password_generation(members, RA.params)
    print(r1)

    # 2. Verification Benchmark
    print("\n[2] Verification Benchmark")
    r2 = benchmark_verification(members[0], RA, RA.params)
    print(r2)

    # 3. φ scaling
    print("\n[3] φ 实验")
    r3 = benchmark_phi_effect(U=num_members, delta_T=delta_T, delta_e=delta_e, n=n)

    # 4. U scaling
    print("\n[4] U 实验")
    r4 = benchmark_gvst_gen(delta_T=delta_T, delta_e=delta_e, phi=phi, n=n)

    # 5. Storage Size Benchmark
    print("\n[5] Storage Size Benchmark")
    r5 = benchmark_storage_size(num_members, delta_T, delta_e, phi, n)
    print("\n存储数据量测试结果:")
    for key, value in r3.items():
        if key == "sigma_component_percentages":
            print(f"  签名组件占比:")
            for comp, percent in value.items():
                print(f"    {comp}: {percent:.2f}%")
        elif key == "aux_component_sizes":
            print(f"  辅助信息组件大小:")
            for comp, size in value.items():
                print(f"    {comp}: {size} 字节")
        elif key == "aux_component_percentages":
            print(f"  辅助信息组件占比:")
            for comp, percent in value.items():
                print(f"    {comp}: {percent:.2f}%")
        elif key == "storage_component_percentages":
            print(f"  存储组件占比:")
            for comp, percent in value.items():
                print(f"    {comp}: {percent:.2f}%")
        else:
            print(f"  {key}: {value}")

    # 6. Storage scaling
    print("\n[6] 存储扩展性实验")
    r6 = benchmark_storage_scaling(
        U_values=[100, 500, 1000],  # 可以调整这些值
        phi_values=[1024, 2048, 4096, 8192],
        delta_T=delta_T,
        delta_e=delta_e,
        n=n
    )

    return {"pw_gen": r1, "verify": r2, "phi": r3, "U": r4, "strage": r5}


# ===================== 主入口：命令行接口 =====================
if __name__ == "__main__":
    # 运行示例：python benchmark.py --benchmark --benchmark-type all --num 50 --deltaT 600 --deltae 10 --phi 4096 --insnum 5
    # python benchmark.py --benchmark --benchmark-type storage --num 4 --deltaT 300 --deltae 5 --phi 2 --insnum 2
    parser = argparse.ArgumentParser(description="GTOTP-RA 运行演示")

    parser.add_argument("--num", type=int, default=100,
                        help="成员数量（默认 100）")
    parser.add_argument("--deltaT", type=float, default=300,
                        help="实例周期 ΔT（秒，默认 300）")
    parser.add_argument("--deltae", type=float, default=5,
                        help="口令周期 Δe（秒，默认 5）")
    parser.add_argument("--phi", type=int, default=8192,
                        help="子集数量 φ（默认 8192）")
    parser.add_argument("--insnum", type=int, default=2,
                        help="成员维护实例数量（默认 2）")

    # 新增 benchmark 模式参数
    parser.add_argument("--benchmark", action="store_true",
                        help="运行性能测试模式")
    parser.add_argument("--benchmark-type", type=str,
                        choices=["all", "pwgen", "verify", "phi", "U", "init", "storage", "storage-scaling","proof-gen"],
                        default="all",
                        help="性能测试类型：all-全部, pwgen-密码生成, verify-验证, phi-子集数量影响, U-成员数量影响,storage-存储数据量, storage-scaling-存储扩展性, init-初始化时间, proof-generation-证明生成时间分解")

    args = parser.parse_args()

    if args.benchmark:
        print("======== 启动 GTOTP Benchmark ========")
        print(
            f"使用参数: num_members={args.num}, delta_T={args.deltaT}, delta_e={args.deltae}, phi={args.phi}, insnum={args.insnum}")

        if args.benchmark_type == "all":
            results = run_all_benchmarks(
                num_members=args.num,
                delta_T=args.deltaT,
                delta_e=args.deltae,
                phi=args.phi,
                n=args.insnum
            )
            print("\n=== 完整性能测试结果 ===")
            for test_name, result in results.items():
                print(f"\n{test_name}: {result}")

        elif args.benchmark_type == "pwgen":
            # 密码生成性能测试
            T_s = time.time()
            T_e = T_s + args.insnum * args.deltaT
            RA = RegistrationAuthority(T_s, T_e, args.deltae, args.deltaT, args.phi)
            chain_len = int(args.deltaT / args.deltae)
            members = [RAServiceMember(f"ID{i}", RA.params, chain_len) for i in range(args.num)]
            vst = RA.gvst_gen({m.ID: m.vst for m in members})
            for m in members:
                m.receive_aux(RA.member_aux[m.ID])

            result = benchmark_password_generation(members, RA.params)
            print(f"\n密码生成性能测试: {result}")

        elif args.benchmark_type == "verify":
            # 验证性能测试
            T_s = time.time()
            T_e = T_s + args.insnum * args.deltaT
            RA = RegistrationAuthority(T_s, T_e, args.deltae, args.deltaT, args.phi)
            chain_len = int(args.deltaT / args.deltae)
            members = [RAServiceMember(f"ID{i}", RA.params, chain_len) for i in range(args.num)]
            vst = RA.gvst_gen({m.ID: m.vst for m in members})
            for m in members:
                m.receive_aux(RA.member_aux[m.ID])

            result = benchmark_verification(members[0], RA, RA.params)
            print(f"\n验证性能测试: {result}")

        elif args.benchmark_type == "phi":
            # φ 影响测试
            results = benchmark_phi_effect(
                U=args.num,
                delta_T=args.deltaT,
                delta_e=args.deltae,
                n=args.insnum,
            )
            print(f"\nφ 影响测试结果:")
            for phi, result in results.items():
                print(f"  φ={phi}: {result}")

        elif args.benchmark_type == "U":
            # U 影响测试
            results = benchmark_gvst_gen(
                delta_T=args.deltaT,
                delta_e=args.deltae,
                phi=args.phi,
                n=args.insnum
            )
            print(f"\n成员数量影响测试结果:")
            for U, result in results.items():
                print(f"  U={U}: {result}")

        elif args.benchmark_type == "init":
            # 初始化时间测试
            result = benchmark_initialization_time(
                num_members=args.num,
                delta_T=args.deltaT,
                delta_e=args.deltae,
                phi=args.phi,
                n=args.insnum,
                repeat=100  # 默认测量10次
            )
            print(f"\n初始化时间测试结果: {result}")

        elif args.benchmark_type == "proof-gen":
            # 证明生成时间分解测试
            result = benchmark_proof_generation_time(
                num_members=args.num,
                delta_T=args.deltaT,
                delta_e=args.deltae,
                phi=args.phi,
                n=args.insnum,
                repeat=100
            )
            print(f"\n证明生成阶段时间分解测试结果:")
            print(
                f"  哈希链计算: {result['hash_chain']['avg_ms']} ms ({result['hash_chain'].get('percentage', 0):.2f}%)")
            print(
                f"  报告验证: {result['report_verify']['avg_ms']} ms ({result['report_verify'].get('percentage', 0):.2f}%)")
            print(
                f"  证明组装: {result['proof_assemble']['avg_ms']} ms ({result['proof_assemble'].get('percentage', 0):.2f}%)")
            print(f"  总时间: {result['total']['avg_ms']} ms")

        elif args.benchmark_type == "storage":
            # 存储数据量测试
            result = benchmark_storage_size(
                num_members=args.num,
                delta_T=args.deltaT,
                delta_e=args.deltae,
                phi=args.phi,
                n=args.insnum
            )
            print(f"\n存储数据量测试结果:")
            for key, value in result.items():
                if key == "sigma_component_percentages":
                    print(f"  签名组件占比:")
                    for comp, percent in value.items():
                        print(f"    {comp}: {percent:.2f}%")
                elif key == "aux_component_sizes":
                    print(f"  辅助信息组件大小:")
                    for comp, size in value.items():
                        print(f"    {comp}: {size} 字节")
                elif key == "aux_component_percentages":
                    print(f"  辅助信息组件占比:")
                    for comp, percent in value.items():
                        print(f"    {comp}: {percent:.2f}%")
                elif key == "storage_component_percentages":
                    print(f"  存储组件占比:")
                    for comp, percent in value.items():
                        print(f"    {comp}: {percent:.2f}%")
                else:
                    print(f"  {key}: {value}")
        elif args.benchmark_type == "storage-scaling":
            # 存储扩展性测试
            results = benchmark_storage_scaling(
                U_values=[100],  # 可以调整这些值
                phi_values=[8192],
                delta_T=args.deltaT,
                delta_e=args.deltae,
                n=args.insnum
            )
            print(f"\n存储扩展性测试结果:")
            for test_type, test_results in results.items():
                print(f"\n{test_type}:")
                for param, storage_info in test_results.items():
                    print(f"  参数={param}: 总存储={storage_info['total_storage_mb']:.2f} MB, " +
                          f"单个签名大小={storage_info['sigma_size_bytes']} 字节")
    else:
        run_demo(
            num_members=args.num,
            delta_T=args.deltaT,
            delta_e=args.deltae,
            phi=args.phi,
            N=args.insnum
        )
