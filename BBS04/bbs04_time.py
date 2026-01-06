from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import time


# =======================================================
#  BBS04 Benchmark using Charm-Crypto (Corrected)
# =======================================================

def benchmark_bbs04():
    print("Initializing Charm-Crypto Group (SS512)...")

    # 使用 SS512 曲线 (对称双线性对，Type A)
    group = PairingGroup('SS512')

    runs = 1000
    print(f"Running benchmarks ({runs} iterations)...")

    # 1. 准备基准元素
    g1 = group.random(G1)
    g2 = group.random(G2)
    r = group.random(ZR)

    # ---------------------------------------------------
    # 测试 1: 指数运算 (Exponentiation / Scalar Mul)
    # 对应数学公式: g^x
    # ---------------------------------------------------
    start_time = time.time()
    for _ in range(runs):
        _ = g1 ** r
    end_time = time.time()

    # 计算单次耗时 (ms)
    t_exp = ((end_time - start_time) / runs) * 1000

    # ---------------------------------------------------
    # 测试 2: 双线性对 (Bilinear Pairing)
    # 对应数学公式: e(g1, g2)
    # ---------------------------------------------------
    # 【修正点】: 使用 standalone 的 pair() 函数，而不是 group.pair()
    start_time = time.time()
    for _ in range(runs):
        _ = pair(g1, g2)  # <--- 这里改了
    end_time = time.time()

    # 计算单次耗时 (ms)
    t_pair = ((end_time - start_time) / runs) * 1000

    print(f"\n[Charm-Crypto 基准实测]")
    print(f"  - 单次指数运算 (Exp) : {t_exp:.4f} ms")
    print(f"  - 单次双线性对 (Pair): {t_pair:.4f} ms")

    # ===================================================
    # BBS04 协议耗时估算
    # 基于 Boneh-Boyen-Shacham 04 论文标准操作数
    # Sign   ≈ 1 Pairing + 6 Exponentiations
    # Verify ≈ 3 Pairings + 6 Exponentiations
    # ===================================================

    bbs04_sign = (1 * t_pair) + (6 * t_exp)
    bbs04_verify = (3 * t_pair) + (6 * t_exp)

    print(f"\n" + "=" * 45)
    print(f"  BBS04 Performance (Simulated via Charm)")
    print(f"  (This data is close to C++ native speed)")
    print(f"=" * 45)
    print(f"  Sign Time   : {bbs04_sign:.4f} ms")
    print(f"  Verify Time : {bbs04_verify:.4f} ms")
    print(f"=" * 45)


if __name__ == "__main__":
    benchmark_bbs04()