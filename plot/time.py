import matplotlib.pyplot as plt
import numpy as np

# --- 1. 数据录入 ---
schemes = ['Intel EPID', 'Ours (GTOTP)']

# 全部统一为毫秒 (ms)
# EPID Data
epid_sign = 19.50
epid_verify = 18.68

# Ours Data (注意：20.885us = 0.020885ms)
our_sign = 0.020885
our_verify = 0.099

sign_times = [epid_sign, our_sign]
verify_times = [epid_verify, our_verify]

# --- 2. 绘图设置 ---
x = np.arange(len(schemes))
width = 0.35

# 建议：使用学术风格的配色 (红色系对比蓝色系，或者深灰对比亮色)
fig, ax = plt.subplots(figsize=(8, 6))

# 绘制柱子
rects1 = ax.bar(x - width / 2, sign_times, width, label='Sign Time', color='#d62728', alpha=0.85, edgecolor='black')
rects2 = ax.bar(x + width / 2, verify_times, width, label='Verify Time', color='#1f77b4', alpha=0.85, edgecolor='black')

# --- 3. 关键：开启对数坐标 ---
# 因为差距是900倍，如果不开启log，你的柱子会像灰尘一样看不见
ax.set_yscale('log')

# --- 4. 标签与美化 ---
ax.set_ylabel('Time Cost (ms) - Log Scale', fontsize=12, fontweight='bold')
ax.set_title('Computation Cost Comparison (EPID vs. Ours)', fontsize=14, fontweight='bold', pad=15)
ax.set_xticks(x)
ax.set_xticklabels(schemes, fontsize=12)
ax.legend(fontsize=11)

# 设置Y轴范围，确保显示美观 (从0.01到100)
ax.set_ylim(0.01, 100)

# 网格线
ax.grid(True, which="major", axis="y", linestyle='--', alpha=0.7)


# --- 5. 自动标注数值 ---
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        # 格式化显示：如果是Ours，显示小数位多一点
        if height < 1:
            label_text = f'{height:.3f} ms'
        else:
            label_text = f'{height:.1f} ms'

        ax.annotate(label_text,
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 5),  # 垂直偏移
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10, fontweight='bold')


autolabel(rects1)
autolabel(rects2)

plt.tight_layout()
plt.show()