# time_benchmark.py
import time
import secrets
import argparse
from DAA_GTOTP import *

def benchmark_time(params: DAAParams, repeat: int, U: int):
    # 预生成所有成员的 vst_points（避免重复计算）
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

    print(f"\n=== Time Benchmark (U={U}, E={params.E}, phi={params.phi}, repeat={repeat}) ===")
    print(f"{'Iter':<6} {'Setup (ms)':<12} {'Join Total (ms)':<18} {'- Entries+Sig (ms)':<22} {'- Shuffle+Subset (ms)':<22} {'- Merkle+Bloom+Aux (ms)':<25}")
    print(f"{'':<6} {'Sign Total (μs)':<18} {'- Time+z Calc (μs)':<22} {'- Seed+PW Gen (μs)':<22} {'- Sigma Assembly (μs)':<22}")
    print(f"{'':<6} {'Verify Total (ms)':<18} {'- Time Check (ms)':<22} {'- Sig + VP Recon (ms)':<22} {'- Merkle + Bloom (ms)':<22}")

    # 用于平均统计
    setup_times = []
    join_times = []
    join_sub1_times = []   # Entries 生成 + RSA 签名
    join_sub2_times = []   # Shuffle + 分子集
    join_sub3_times = []   # Merkle 构建 + Bloom 添加 + Aux 生成

    sign_times = []
    sign_sub1_times = []   # 时间窗口 + z 计算
    sign_sub2_times = []   # PRF 种子 + hash_power 生成 pw
    sign_sub3_times = []   # sigma 字典组装

    verify_times = []
    verify_sub1_times = [] # 时间窗口检查
    verify_sub2_times = [] # 签名验证 + VP 重构 + VP' 计算
    verify_sub3_times = [] # Merkle 证明验证 + Bloom 查询

    total_times = []  # 新增：每轮 Total

    for it in range(1, repeat + 1):
        # ==================== Setup ====================
        start = time.time()
        issuer = Issuer(params)
        gpk, _, _ = issuer.setup()
        params.gpk = gpk
        setup_ms = (time.time() - start) * 1000
        setup_times.append(setup_ms)

        # ==================== Join ====================
        start_join = time.time()

        # 子操作1: Entries 生成 + RSA 签名（最耗时部分）
        start = time.time()
        entries = []
        for ID, vst_points in members_vst.items():
            for i, vp in enumerate(vst_points):
                r = secrets.token_bytes(32)
                tag = sha256(ID.encode() + int.to_bytes(i, 4, 'big') + r)
                sig = issuer._rsa_sign(tag + int.to_bytes(i, 4, 'big'))
                vp_prime = sha256(vp + tag + int.to_bytes(i, 4, 'big'))
                entries.append((vp_prime, ID, i, r, tag, sig))
                issuer.st_I[tag.hex()] = {'ID': ID, 'i': i, 'r': r}
        join_sub1_ms = (time.time() - start) * 1000
        join_sub1_times.append(join_sub1_ms)

        # 子操作2: Shuffle + 分子集
        start = time.time()
        secrets.SystemRandom().shuffle(entries)
        subsets = [[] for _ in range(params.phi)]
        entry_locs = {}
        for idx, ent in enumerate(entries):
            subset_idx = idx % params.phi
            subsets[subset_idx].append(ent[0])
            entry_locs[(ent[1], ent[2])] = (subset_idx, len(subsets[subset_idx]) - 1, ent[3], ent[4], ent[5])
        join_sub2_ms = (time.time() - start) * 1000
        join_sub2_times.append(join_sub2_ms)

        # 子操作3: Merkle 构建 + Bloom 添加 + Aux 生成
        start = time.time()
        mts, roots = [], []
        for s in subsets:
            mt = MerkleTree(s)
            mts.append(mt)
            roots.append(mt.root)
        issuer.bloom = BloomFilter(capacity=params.phi * 2, error_rate=2**-40)
        for r in roots:
            issuer.bloom.add(r.hex())
        aux_dict = {}
        for ent in entries:
            ID, i = ent[1], ent[2]
            subset_idx, pos, r, tag, sig = entry_locs[(ID, i)]
            proof = mts[subset_idx].get_proof(pos)
            aux_dict.setdefault(ID, []).append({'i': i, 'r': r, 'tag': tag, 'sig': sig, 'proof': proof, 'subset': subset_idx})
        for prover in provers:
            prover.receive_cred(aux_dict[prover.ID])
        issuer.merkle_roots = roots
        issuer.mt_by_subset = mts
        join_sub3_ms = (time.time() - start) * 1000
        join_sub3_times.append(join_sub3_ms)

        join_total_ms = (time.time() - start_join) * 1000
        join_times.append(join_total_ms)

        # ==================== Sign ====================
        start_sign = time.time()

        # 子操作1: 时间窗口与 z 计算
        start = time.time()
        T = time.time()
        i = math.ceil((T - params.T_s) / params.delta_T) - 1
        Ti_start = params.T_s + i * params.delta_T
        z = int((T - Ti_start) / params.delta_s)
        z = max(0, min(z, params.N - 1))
        sign_sub1_us = (time.time() - start) * 1_000_000
        sign_sub1_times.append(sign_sub1_us)

        # 子操作2: 种子生成 + pw 计算
        start = time.time()
        seed = hmac_sha256(provers[0].sk, provers[0].ID.encode() + int.to_bytes(i, 4, 'big'))
        pw = hash_power(seed, z)
        sign_sub2_us = (time.time() - start) * 1_000_000
        sign_sub2_times.append(sign_sub2_us)

        # 子操作3: sigma 组装
        start = time.time()
        entry = provers[0].aux[i]
        sigma = {
            'pw': pw,
            'tag': entry['tag'],
            'sig': entry['sig'],
            'proof': entry['proof'],
            'i': i,
            'T': T,
            'm': b"message",
            'subset': entry['subset'],
            'z': z
        }
        sign_sub3_us = (time.time() - start) * 1_000_000
        sign_sub3_times.append(sign_sub3_us)

        sign_total_us = (time.time() - start_sign) * 1_000_000
        sign_times.append(sign_total_us)

        # ==================== Verify ====================
        verifier = Verifier(params, gpk, issuer.bloom, issuer.merkle_roots)

        start_verify = time.time()

        # 子操作1: 时间窗口检查
        start = time.time()
        grace = params.delta_s
        Ti_start = params.T_s + sigma['i'] * params.delta_T
        window_start = Ti_start + sigma['z'] * params.delta_s
        window_end = window_start + params.delta_s
        _ = (window_start - grace <= sigma['T'] <= window_end + grace)
        verify_sub1_ms = (time.time() - start) * 1000
        verify_sub1_times.append(verify_sub1_ms)

        # 子操作2: 签名验证 + VP 重构 + VP' 计算
        start = time.time()
        verifier.gpk.verify(
            sigma['sig'],
            sigma['tag'] + int.to_bytes(sigma['i'], 4, 'big'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        vp = hash_power(sigma['pw'], params.N - sigma['z'])
        vp_prime = sha256(vp + sigma['tag'] + int.to_bytes(sigma['i'], 4, 'big'))
        verify_sub2_ms = (time.time() - start) * 1000
        verify_sub2_times.append(verify_sub2_ms)

        # 子操作3: Merkle 验证 + Bloom 查询
        start = time.time()
        root = verifier.merkle_roots[sigma['subset']]
        MerkleTree.verify(vp_prime, sigma['proof'], root)
        _ = root.hex() in verifier.bloom
        verify_sub3_ms = (time.time() - start) * 1000
        verify_sub3_times.append(verify_sub3_ms)

        verify_total_ms = (time.time() - start_verify) * 1000
        verify_times.append(verify_total_ms)

        # ==================== Total ====================
        total_ms = setup_ms + join_total_ms + (sign_total_us / 1000) + verify_total_ms
        total_times.append(total_ms)

        # 打印本次迭代详情
        # 打印本次迭代
        print(f"{it:<6} {setup_ms:<12.3f} {join_total_ms:<18.3f} {join_sub1_ms:<20.3f} {join_sub2_ms:<20.3f} {join_sub3_ms:<22.3f}")
        print(f"{'':<6} {sign_total_us:<18.3f} {sign_sub1_us:<20.3f} {sign_sub2_us:<20.3f} {sign_sub3_us:<20.3f}")
        print(f"{'':<6} {verify_total_ms:<18.3f} {verify_sub1_ms:<20.3f} {verify_sub2_ms:<20.3f} {verify_sub3_ms:<22.3f} {total_ms:<12.3f}")

    # ==================== 平均值汇总 ====================
    print("\n" + "="*120)
    print("=== Average Results ===")
    print(f"Average Setup Time                : {sum(setup_times)/repeat:.3f} ms")
    print(f"Average Join Total                : {sum(join_times)/repeat:.3f} ms")
    print(f"  ├─ Entries + RSA Signatures     : {sum(join_sub1_times)/repeat:.3f} ms")
    print(f"  ├─ Shuffle + Subset Division    : {sum(join_sub2_times)/repeat:.3f} ms")
    print(f"  └─ Merkle + Bloom + Aux Gen     : {sum(join_sub3_times)/repeat:.3f} ms")

    print(f"Average Sign Total                : {sum(sign_times)/repeat:.3f} μs")
    print(f"  ├─ Time Window + z Calculation  : {sum(sign_sub1_times)/repeat:.3f} μs")
    print(f"  ├─ Seed PRF + PW Generation     : {sum(sign_sub2_times)/repeat:.3f} μs")
    print(f"  └─ Sigma Assembly               : {sum(sign_sub3_times)/repeat:.3f} μs")

    print(f"Average Verify Total              : {sum(verify_times)/repeat:.3f} ms")
    print(f"  ├─ Time Window Check            : {sum(verify_sub1_times)/repeat:.3f} ms")
    print(f"  ├─ Signature + VP Reconstruction: {sum(verify_sub2_times)/repeat:.3f} ms")
    print(f"  └─ Merkle Proof + Bloom Query   : {sum(verify_sub3_times)/repeat:.3f} ms")

    avg_total = sum(total_times) / repeat
    print(f"Average Total (Setup + Join + Sign + Verify): {avg_total:.3f} ms")
    print("="*140)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simplified Time Benchmark with 3 Sub-Ops per Algorithm")
    parser.add_argument('--U', type=int, default=100, help='Number of members')
    parser.add_argument('--E', type=int, default=288, help='Number of instances')
    parser.add_argument('--phi', type=int, default=8192, help='Number of subsets')
    parser.add_argument('--delta_T', type=float, default=300, help='Instance lifecycle (s)')
    parser.add_argument('--delta_e', type=float, default=300, help='Verification period (s)')
    parser.add_argument('--delta_s', type=float, default=5, help='Password interval (s)')
    parser.add_argument('--repeat', type=int, default=10, help='Number of repetitions')
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

    benchmark_time(params, args.repeat, args.U)