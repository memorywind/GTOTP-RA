from charm.toolbox.pairinggroup import PairingGroup, ZR, G1


def measure_bbs04_size():
    # 必须和你测速度时用的曲线一致 ('SS512')
    group = PairingGroup('SS512')

    print("正在测量基础元素大小 (Curve: SS512)...")

    # 1. 生成随机元素
    g1_element = group.random(G1)
    zr_element = group.random(ZR)

    # 2. 序列化并测量字节数 (这是最纯净的大小)
    # group.serialize() 会把元素转为 bytes
    size_g1 = len(group.serialize(g1_element))
    size_zr = len(group.serialize(zr_element))

    print(f"  - 单个 G1 元素大小: {size_g1} bytes")
    print(f"  - 单个 Z_p 标量大小: {size_zr} bytes")

    # 3. 套用 BBS04 公式
    # Signature = (T1, T2, T3, c, s_alpha, s_beta, s_x, s_delta1, s_delta2)
    # Total = 3 * G1 + 6 * Z_p
    total_size = (3 * size_g1) + (6 * size_zr)

    print(f"\n[BBS04 理论签名大小]")
    print(f"  Calculation: 3 * {size_g1} + 6 * {size_zr}")
    print(f"  Total Size : {total_size} bytes")


if __name__ == "__main__":
    measure_bbs04_size()