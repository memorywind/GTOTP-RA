from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import time


# =======================================================
#  CL04 (Camenisch-Lysyanskaya) Benchmark & Size
#  Based on Pairing-based variant (Camenisch et al.)
# =======================================================

def simulate_cl04():
    # 保持和之前一致的曲线，确保对比公平
    group = PairingGroup('SS512')

    print("Running CL04 Simulation (Curve: SS512)...")
    runs = 1000

    # 1. 准备基准元素
    g1 = group.random(G1)
    g2 = group.random(G2)
    r = group.random(ZR)

    # ---------------------------------------------------
    # A. 测量基础运算耗时 (Time Benchmark)
    # ---------------------------------------------------
    # 1. 指数运算 (Exp)
    start = time.time()
    for _ in range(runs):
        _ = g1 ** r
    t_exp = ((time.time() - start) / runs) * 1000

    # 2. 双线性对 (Pairing) - 使用独立的 pair() 函数
    start = time.time()
    for _ in range(runs):
        _ = pair(g1, g2)
    t_pair = ((time.time() - start) / runs) * 1000

    print(f"\n[基础运算耗时]")
    print(f"  - Exp  : {t_exp:.4f} ms")
    print(f"  - Pair : {t_pair:.4f} ms")

    # ---------------------------------------------------
    # B. CL04 协议耗时估算 (Time Estimation)
    # DAA 场景下通常验证的是 ZKP
    # ---------------------------------------------------
    # Sign:   生成凭证 (Issuance)
    # Formula: ~1 Pairing + 5 Exponentiations
    cl04_sign = (1 * t_pair) + (5 * t_exp)

    # Verify: 验证匿名凭证的 ZKP
    # Formula: ~2 Pairings + 10 Exponentiations (保守估计)
    cl04_verify = (2 * t_pair) + (10 * t_exp)

    print(f"\n[CL04 时间性能 (估算)]")
    print(f"  - Sign Time   : {cl04_sign:.4f} ms")
    print(f"  - Verify Time : {cl04_verify:.4f} ms")

    # ---------------------------------------------------
    # C. CL04 签名大小估算 (Size Estimation)
    # ---------------------------------------------------
    # 结构: Randomized Signature (A_bar, B_bar, etc.) + ZKP responses
    # 典型大小: 4个 G1 元素 + 5个 Zr 标量
    # ---------------------------------------------------
    size_g1 = len(group.serialize(g1))
    size_zr = len(group.serialize(r))

    cl04_size = (4 * size_g1) + (5 * size_zr)

    print(f"\n[CL04 签名大小 (估算)]")
    print(f"  - Formula: 4 * G1({size_g1}B) + 5 * Zr({size_zr}B)")
    print(f"  - Total Size : {cl04_size} Bytes")


if __name__ == "__main__":
    simulate_cl04()