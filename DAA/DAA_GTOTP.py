# DAA-GTOTP.py
import time
import math
import secrets
import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from pybloom_live import BloomFilter

# 常量定义
HASH_LEN = 32
PRF_KEY_LEN = 16
RSA_KEY_SIZE = 2048
BLOOM_ERROR_RATE = 2 ** -40

@dataclass
class DAAParams:
    lambda_sec: int
    delta_e: float      # 验证周期
    delta_T: float      # 实例生命周期
    delta_s: float      # 口令生成间隔
    phi: int            # 子集数量
    T_s: float
    T_e: float
    N: int              # 每个实例的链长
    E: int              # 实例总数
    gpk: bytes
    hk: bytes

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def hash_power(x: bytes, r: int) -> bytes:
    h = x
    for _ in range(r):
        h = sha256(h)
    return h

class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves[:]
        self.levels = []
        if not leaves:
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
            a, b = (sibling, h) if is_left else (h, sibling)
            h = sha256(b"\x01" + a + b)
        return h == root

class Issuer:
    def __init__(self, params: DAAParams):
        self.params = params
        self.sk, self.pk = self._generate_rsa_keypair()
        self.st_I: Dict[str, Dict] = {}
        self.merkle_roots: List[bytes] = []
        self.mt_by_subset: List[MerkleTree] = []
        self.bloom: Optional[BloomFilter] = None

    def _generate_rsa_keypair(self):
        sk = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE, backend=default_backend())
        pk = sk.public_key()
        return sk, pk

    def setup(self) -> Tuple[bytes, bytes, Dict]:
        gpk = self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ik = self.sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        st_I = {}
        return gpk, ik, st_I

    def join(self, ID: str, vst_points: List[bytes]) -> List[Dict]:
        """单成员加入（兼容旧接口，用于小规模测试）"""
        return self.join_all({ID: vst_points})[ID]

    def join_all(self, members_vst: Dict[str, List[bytes]]) -> Dict[str, List[Dict]]:
        """
        全局 Join 方法：一次性处理所有成员，生成 GVST（符合论文 GVSTGen）
        输入: {ID: [vp_0, vp_1, ..., vp_{E-1}]}
        输出: {ID: aux_list}
        """
        entries = []
        for ID, vst_points in members_vst.items():
            if len(vst_points) != self.params.E:
                raise ValueError(f"VST points for {ID} must have length E")
            for i, vp in enumerate(vst_points):
                r = secrets.token_bytes(HASH_LEN)
                tag = sha256(ID.encode() + int.to_bytes(i, 4, 'big') + r)
                sig = self._rsa_sign(tag + int.to_bytes(i, 4, 'big'))
                vp_prime = sha256(vp + tag + int.to_bytes(i, 4, 'big'))
                entries.append((vp_prime, ID, i, r, tag, sig))
                self.st_I[tag.hex()] = {'ID': ID, 'i': i, 'r': r}

        # 随机置换
        secrets.SystemRandom().shuffle(entries)

        # 分 phi 个子集
        subsets = [[] for _ in range(self.params.phi)]
        entry_locs = {}
        for idx, ent in enumerate(entries):
            subset_idx = idx % self.params.phi
            subsets[subset_idx].append(ent[0])
            entry_locs[(ent[1], ent[2])] = (subset_idx, len(subsets[subset_idx]) - 1, ent[3], ent[4], ent[5])

        # 构建 Merkle 树
        mts, roots = [], []
        for s in subsets:
            mt = MerkleTree(s)
            mts.append(mt)
            roots.append(mt.root)

        # 真正的 Bloom 过滤器
        self.bloom = BloomFilter(capacity=self.params.phi, error_rate=BLOOM_ERROR_RATE)
        for r in roots:
            self.bloom.add(r.hex())

        # 生成每个成员的 aux
        aux_dict: Dict[str, List[Dict]] = {}
        for ent in entries:
            ID, i = ent[1], ent[2]
            subset_idx, pos, r, tag, sig = entry_locs[(ID, i)]
            proof = mts[subset_idx].get_proof(pos)
            aux_dict.setdefault(ID, []).append({
                'i': i,
                'r': r,
                'tag': tag,
                'sig': sig,
                'proof': proof,
                'subset': subset_idx
            })

        self.merkle_roots = roots
        self.mt_by_subset = mts
        return aux_dict

    def _rsa_sign(self, msg: bytes) -> bytes:
        return self.sk.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def open(self, tag: bytes, i: int) -> Optional[str]:
        key = tag.hex()
        if key in self.st_I and self.st_I[key]['i'] == i:
            return self.st_I[key]['ID']
        return None

class Prover:
    def __init__(self, ID: str, params: DAAParams, sk: bytes):
        self.ID = ID
        self.params = params
        self.sk = sk
        self.aux: List[Dict] = []

    def receive_cred(self, aux: List[Dict]):
        self.aux = sorted(aux, key=lambda x: x['i'])

    def sign(self, m: bytes) -> Dict:
        T = time.time()
        i = math.ceil((T - self.params.T_s) / self.params.delta_T) - 1
        if i < 0 or i >= self.params.E:
            raise ValueError("Time out of instance range")

        Ti_start = self.params.T_s + i * self.params.delta_T
        z = int((T - Ti_start) / self.params.delta_s)
        z = max(0, min(z, self.params.N - 1))

        entry = self.aux[i]
        seed = hmac_sha256(self.sk, self.ID.encode() + int.to_bytes(i, 4, 'big'))
        pw = hash_power(seed, z)

        return {
            'pw': pw,
            'tag': entry['tag'],
            'sig': entry['sig'],
            'proof': entry['proof'],
            'i': i,
            'T': T,
            'm': m,
            'subset': entry['subset'],
            'z': z
        }

class Verifier:
    def __init__(self, params: DAAParams, gpk: bytes, bloom: BloomFilter, merkle_roots: List[bytes]):
        self.params = params
        self.gpk = serialization.load_pem_public_key(gpk)
        self.bloom = bloom
        self.merkle_roots = merkle_roots

    def verify(self, sigma: Dict) -> bool:
        pw = sigma['pw']
        tag = sigma['tag']
        sig = sigma['sig']
        proof = sigma['proof']
        i = sigma['i']
        T = sigma['T']
        z = sigma['z']

        # 时间窗口检查
        grace = self.params.delta_s
        Ti_start = self.params.T_s + i * self.params.delta_T
        window_start = Ti_start + z * self.params.delta_s
        window_end = window_start + self.params.delta_s
        if not (window_start - grace <= T <= window_end + grace):
            return False

        # 签名验证
        try:
            self.gpk.verify(
                sig,
                tag + int.to_bytes(i, 4, 'big'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except:
            return False

        # vp 重构
        vp = hash_power(pw, self.params.N - z)
        vp_prime = sha256(vp + tag + int.to_bytes(i, 4, 'big'))

        # Merkle 证明验证
        root = self.merkle_roots[sigma['subset']]
        if not MerkleTree.verify(vp_prime, proof, root):
            return False

        # Bloom 查询
        if root.hex() not in self.bloom:
            return False

        return True


if __name__ == "__main__":
    # 示例使用 (可选，用于测试)
    T_s = time.time()
    T_e = T_s + 3600
    params = DAAParams(
        lambda_sec=128,
        delta_e=300.0,
        delta_T=300.0,
        delta_s=5.0,
        phi=32,
        T_s=T_s,
        T_e=T_e,
        N=int(300 / 5),
        E=1,
        gpk=b'',
        hk=secrets.token_bytes(16)
    )
    issuer = Issuer(params)
    gpk, ik, st_I = issuer.setup()
    params.gpk = gpk

    ID = "user1"
    sk_prover = secrets.token_bytes(PRF_KEY_LEN)
    prover = Prover(ID, params, sk_prover)

    vst_points = []
    for i in range(params.E):
        seed = hmac_sha256(sk_prover, ID.encode() + int.to_bytes(i, 4, 'big'))
        vp = hash_power(seed, params.N)
        vst_points.append(vp)

    aux = issuer.join(ID, vst_points)
    prover.receive_cred(aux)

    m = b"message"
    sigma = prover.sign(m)

    verifier = Verifier(params, gpk, issuer.bloom, issuer.merkle_roots)
    is_valid = verifier.verify(sigma)
    print(f"Verify: {is_valid}")

    traced_ID = issuer.open(sigma['tag'], sigma['i'])
    print(f"Traced ID: {traced_ID}")