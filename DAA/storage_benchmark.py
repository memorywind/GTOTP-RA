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
    for j in range(U):
        ID = f"user{j}"
        sk = secrets.token_bytes(16)
        vst = []
        for i in range(params.E):
            seed = hmac_sha256(sk, ID.encode() + int.to_bytes(i, 4, 'big'))
            vp = hash_power(seed, params.N)
            vst.append(vp)
        members_vst[ID] = vst

    # 执行全局 join
    aux_dict = issuer.join_all(members_vst)

    # 生成一个示例 sigma 用于测量凭证大小
    example_prover = Prover("example", params, secrets.token_bytes(16))
    first_id = next(iter(aux_dict))
    example_prover.receive_cred(aux_dict[first_id])
    example_message = b"authenticated message"
    sigma = example_prover.sign(example_message)
    sigma_size_bytes = recursive_size(sigma)

    # === 各组件存储量计算 (字节) ===
    gvst_bits = issuer.bloom.num_bits if issuer.bloom else 0
    gvst_bytes = (gvst_bits + 7) // 8

    merkle_bytes = 0
    for mt in issuer.mt_by_subset:
        for level in mt.levels:
            for node in level:
                merkle_bytes += len(node)

    idtable_bytes = recursive_size(issuer.st_I)

    total_aux_bytes = 0
    for ID in aux_dict:
        total_aux_bytes += recursive_size(aux_dict[ID])

    avg_aux_per_member_bytes = total_aux_bytes // U if U > 0 else 0

    # === 汇总计算 ===
    issuer_total_bytes = gvst_bytes + merkle_bytes + idtable_bytes
    provers_total_bytes = total_aux_bytes
    system_total_bytes = issuer_total_bytes + provers_total_bytes

    # === 输出函数：KB + (MB) ===
    def fmt_kb_mb(bytes_val: int) -> str:
        kb = bytes_val / 1024
        mb = kb / 1024
        return f"{kb:.3f} KB ({mb:.3f} MB)"

    results = {
        "GVST (Bloom Filter) Size": fmt_kb_mb(gvst_bytes),
        "Total Merkle Trees Size": fmt_kb_mb(merkle_bytes),
        "IDTable Size": fmt_kb_mb(idtable_bytes),
        "Total Aux Data Size": fmt_kb_mb(total_aux_bytes),
        "Average Aux per Member": fmt_kb_mb(avg_aux_per_member_bytes),
        "Single Sigma Size": fmt_kb_mb(sigma_size_bytes),

        "Issuer Total Storage (GVST + Merkle + IDTable)": fmt_kb_mb(issuer_total_bytes),
        "Provers Total Storage (All Aux)": fmt_kb_mb(provers_total_bytes),
        "System Overall Total Storage": fmt_kb_mb(system_total_bytes),  # 重点
    }

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Storage Benchmark for DAA-GTOTP (KB + MB)")
    parser.add_argument('--U', type=int, default=100, help='Number of members (group size)')
    parser.add_argument('--E', type=int, default=60, help='Number of instances per member')
    parser.add_argument('--phi', type=int, default=8192, help='Number of Merkle tree subsets')
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

    print(f"\n=== Storage Benchmark (U={args.U}, E={args.E}, phi={args.phi}) ===")
    results = benchmark_storage(params, args.U)

    for key, value in results.items():
        print(f"{key:<55}: {value}")

    print("\nNote: Verifier only requires constant-size GVST.")
    print("      System Overall Total Storage includes issuer and all provers (KB and MB shown).")