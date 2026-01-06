# storage_benchmark.py
import secrets
import sys
import argparse
import time

from DAA_GTOTP import DAAParams, Issuer, Prover, hmac_sha256, hash_power

def recursive_size(obj) -> int:
    seen = set()
    def size_of(o):
        if id(o) in seen:
            return 0
        seen.add(id(o))
        if isinstance(o, (bytes, bytearray)):
            return len(o)
        elif isinstance(o, str):
            return len(o.encode('utf-8'))
        elif isinstance(o, (list, tuple)):
            return sum(size_of(item) for item in o)
        elif isinstance(o, dict):
            return sum(size_of(k) + size_of(v) for k, v in o.items())
        else:
            return sys.getsizeof(o)
    return size_of(obj)

def benchmark_storage(params: DAAParams, U: int):
    issuer = Issuer(params)
    gpk, _, _ = issuer.setup()
    params.gpk = gpk

    # 预生成所有成员的 vst_points
    members_vst = {}
    provers = []
    for j in range(U):
        ID = f"user{j}"
        sk = secrets.token_bytes(16)
        prover = Prover(ID, params, sk)
        provers.append(prover)

        vst = []
        for i in range(params.E):
            seed = hmac_sha256(sk, ID.encode() + int.to_bytes(i, 4, 'big'))
            vp = hash_power(seed, params.N)
            vst.append(vp)
        members_vst[ID] = vst

    # 执行全局 join
    aux_dict = issuer.join_all(members_vst)
    for prover in provers:
        prover.receive_cred(aux_dict[prover.ID])

    # 生成一个示例 sigma 用于详细分析
    first_prover = provers[0]
    current_i = 0
    entry = first_prover.aux[current_i]
    seed = hmac_sha256(first_prover.sk, first_prover.ID.encode() + int.to_bytes(current_i, 4, 'big'))
    z = 0
    pw = hash_power(seed, z)

    sigma = {
        'pw': pw,
        'tag': entry['tag'],
        'sig': entry['sig'],
        'proof': entry['proof'],
        'i': current_i,
        'T': time.time(),
        'm': b"authenticated message",
        'subset': entry['subset'],
        'z': z
    }

    # === sigma 组件分解 ===
    sigma_components = {
        "pw (password)": len(sigma['pw']),
        "tag": len(sigma['tag']),
        "sig (RSA signature)": len(sigma['sig']),
        "proof (Merkle path)": sum(len(node) for node, _ in sigma['proof']) if sigma['proof'] else 0,
        "metadata (i, T, z, subset, m)": recursive_size({
            'i': sigma['i'], 'T': sigma['T'], 'z': sigma['z'], 'subset': sigma['subset'], 'm': sigma['m']
        }),
        "Python dict overhead": recursive_size(sigma) - sum([
            len(sigma['pw']), len(sigma['tag']), len(sigma['sig']),
            sum(len(node) for node, _ in sigma['proof']) if sigma['proof'] else 0,
            len(sigma['m'])
        ])
    }
    sigma_total_bytes = recursive_size(sigma)

    # === 系统组件 ===
    gvst_bits = issuer.bloom.num_bits if issuer.bloom else 0
    gvst_bytes = (gvst_bits + 7) // 8

    merkle_bytes = 0
    for mt in issuer.mt_by_subset:
        for level in mt.levels:
            for node in level:
                merkle_bytes += len(node)

    idtable_bytes = recursive_size(issuer.st_I)

    total_aux_bytes = sum(recursive_size(aux_dict[ID]) for ID in aux_dict)
    avg_aux_per_member_bytes = total_aux_bytes // U if U > 0 else 0

    # === 实体存储量 ===
    verifier_storage_bytes = gvst_bytes  # Verifier 只需 GVST
    attester_avg_storage_bytes = avg_aux_per_member_bytes  # 每个 Attester 的 Aux
    attesters_total_storage_bytes = total_aux_bytes
    issuer_storage_bytes = gvst_bytes + merkle_bytes + idtable_bytes
    system_total_bytes = issuer_storage_bytes + attesters_total_storage_bytes

    # === 格式化 ===
    def fmt_kb_mb(bytes_val: int) -> str:
        kb = bytes_val / 1024
        mb = kb / 1024
        return f"{kb:.3f} KB ({mb:.3f} MB)"

    def fmt_bytes_kb(bytes_val: int) -> str:
        kb = bytes_val / 1024
        return f"{bytes_val} bytes ({kb:.3f} KB)"

    print(f"\n=== Storage Benchmark (U={U}, E={params.E}, phi={params.phi}) ===\n")

    print("=== Single Sigma (Anonymous Credential) Component Breakdown ===")
    for comp, size in sigma_components.items():
        print(f"{comp:<40}: {fmt_bytes_kb(size)}")
    print(f"{'Total Sigma Size':<40}: {fmt_bytes_kb(sigma_total_bytes)}")
    print(f"{'':<40} ≈ {sigma_total_bytes / 1024:.3f} KB\n")

    print("=== Entity Storage Overhead ===")
    print(f"Verifier Storage (GVST only)             : {fmt_kb_mb(verifier_storage_bytes)}")
    print(f"Each Attester (Prover) Storage (Aux)     : {fmt_kb_mb(attester_avg_storage_bytes)}")
    print(f"All Attesters Total Storage (Aux)        : {fmt_kb_mb(attesters_total_storage_bytes)}")
    print(f"Issuer Storage (GVST + Merkle + IDTable) : {fmt_kb_mb(issuer_storage_bytes)}")
    print(f"System Overall Total Storage             : {fmt_kb_mb(system_total_bytes)}")

    print("\n=== Detailed Component Breakdown ===")
    print(f"GVST (Bloom Filter)                      : {fmt_kb_mb(gvst_bytes)}")
    print(f"Total Merkle Trees                       : {fmt_kb_mb(merkle_bytes)}")
    print(f"IDTable (Traceability)                   : {fmt_kb_mb(idtable_bytes)}")
    print(f"Total Aux Data (All Provers)             : {fmt_kb_mb(total_aux_bytes)}")

    print("\nNote: Verifier storage is constant (GVST only), independent of U and E.")
    print("      Attesters store only their own auxiliary data (distributed).")
    print("      Communication per authentication = Sigma size.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Storage Benchmark with Entity Breakdown")
    parser.add_argument('--U', type=int, default=100, help='Number of members')
    parser.add_argument('--E', type=int, default=60, help='Number of instances')
    parser.add_argument('--phi', type=int, default=8192, help='Number of subsets')
    parser.add_argument('--delta_T', type=float, default=300.0, help='Instance lifecycle Δ_T in seconds')
    parser.add_argument('--delta_e', type=float, default=300.0, help='Verification period Δ_e in seconds')
    parser.add_argument('--delta_s', type=float, default=5.0, help='Password generation interval Δ_s in seconds')
    args = parser.parse_args()

    T_s = time.time()
    T_e = T_s + args.E * args.delta_T
    N = int(args.delta_T / args.delta_s)

    params = DAAParams(
        lambda_sec=128,
        delta_e=args.delta_e,
        delta_T=args.delta_T,
        delta_s=args.delta_s,
        phi=args.phi,
        T_s=T_s,
        T_e=T_e,
        N=N,
        E=args.E,
        gpk=b'',
        hk=secrets.token_bytes(16)
    )

    benchmark_storage(params, args.U)