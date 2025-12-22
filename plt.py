import matplotlib.pyplot as plt
import numpy as np
import matplotlib

# 设置全局字体为Times New Roman
matplotlib.rcParams['font.family'] = 'Times New Roman'
matplotlib.rcParams['font.size'] = 11

# 数据准备
members = np.array([4, 128, 256, 512, 1024, 2048, 4096])
aux = np.array([2.6, 124.75, 266, 565, 1196, 2524, 5312])
merkle = np.array([0.43, 15.94, 31.94, 63.94, 127.94, 255.94, 511.94])
signature = np.array([0.361, 0.522, 0.555, 0.59, 0.62, 0.65, 0.684])
bloom_filter = 7.217  # 常量值

# 创建图表和子图
fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Storage Requirements Analysis by Number of Members',
             fontsize=16, fontweight='bold', fontname='Times New Roman')

# 图表1：Aux vs 成员数量（线性刻度）
ax1.plot(members, aux, 'o-', color='#1f77b4', linewidth=2.5, markersize=8,
         markerfacecolor='white', markeredgewidth=2)
ax1.set_title('Aux Storage Requirement', fontsize=14, fontweight='bold',
              fontname='Times New Roman')
ax1.set_xlabel('Number of Members', fontsize=12, fontname='Times New Roman')
ax1.set_ylabel('Storage Data Size', fontsize=12, fontname='Times New Roman')
ax1.grid(True, alpha=0.3, linestyle='--')
ax1.set_xscale('log', base=2)  # X轴使用log2刻度
ax1.set_xticks(members)
ax1.set_xticklabels(members, fontname='Times New Roman')
ax1.tick_params(axis='x', rotation=45)

# 添加数据标签
for x, y in zip(members, aux):
    ax1.annotate(f'{y:.1f}', (x, y), textcoords="offset points",
                 xytext=(0,10), ha='center', fontsize=9, fontname='Times New Roman')

# 图表2：Merkle Tree vs 成员数量（线性刻度）
ax2.plot(members, merkle, 's-', color='#ff7f0e', linewidth=2.5, markersize=8,
         markerfacecolor='white', markeredgewidth=2)
ax2.set_title('Merkle Tree Storage Requirement', fontsize=14, fontweight='bold',
              fontname='Times New Roman')
ax2.set_xlabel('Number of Members', fontsize=12, fontname='Times New Roman')
ax2.set_ylabel('Storage Data Size', fontsize=12, fontname='Times New Roman')
ax2.grid(True, alpha=0.3, linestyle='--')
ax2.set_xscale('log', base=2)
ax2.set_xticks(members)
ax2.set_xticklabels(members, fontname='Times New Roman')
ax2.tick_params(axis='x', rotation=45)

# 添加数据标签
for x, y in zip(members, merkle):
    ax2.annotate(f'{y:.2f}', (x, y), textcoords="offset points",
                 xytext=(0,10), ha='center', fontsize=9, fontname='Times New Roman')

# 图表3：Signature vs 成员数量（放大Y轴范围）
ax3.plot(members, signature, '^-', color='#2ca02c', linewidth=2.5, markersize=8,
         markerfacecolor='white', markeredgewidth=2)
ax3.set_title('Signature Storage Requirement (Zoomed View)', fontsize=14, fontweight='bold',
              fontname='Times New Roman')
ax3.set_xlabel('Number of Members', fontsize=12, fontname='Times New Roman')
ax3.set_ylabel('Storage Data Size', fontsize=12, fontname='Times New Roman')
ax3.grid(True, alpha=0.3, linestyle='--')
ax3.set_xscale('log', base=2)
ax3.set_xticks(members)
ax3.set_xticklabels(members, fontname='Times New Roman')
ax3.tick_params(axis='x', rotation=45)
ax3.set_ylim(0.35, 0.70)  # 放大Y轴范围以展示细节变化

# 添加数据标签
for x, y in zip(members, signature):
    ax3.annotate(f'{y:.3f}', (x, y), textcoords="offset points",
                 xytext=(0,10), ha='center', fontsize=9, fontname='Times New Roman')

# 图表4：Bloom Filter 常量值展示
ax4.bar(['Bloom Filter'], [bloom_filter], color='#9467bd', edgecolor='black', linewidth=2)
ax4.set_title('Bloom Filter Storage Requirement (Constant)', fontsize=14, fontweight='bold',
              fontname='Times New Roman')
ax4.set_ylabel('Storage Data Size', fontsize=12, fontname='Times New Roman')
ax4.grid(True, alpha=0.3, axis='y', linestyle='--')

# 在柱状图上添加数值
ax4.text(0, bloom_filter, f'{bloom_filter}', ha='center', va='bottom',
         fontsize=12, fontweight='bold', fontname='Times New Roman')

# 添加全局注释
plt.figtext(0.5, 0.01,
           'Note: X-axis (Number of Members) uses log2 scale for better visualization of power-of-2 growth patterns.',
           ha='center', fontsize=10, style='italic', fontname='Times New Roman')

# 设置所有坐标轴刻度标签字体
for ax in [ax1, ax2, ax3, ax4]:
    for label in (ax.get_xticklabels() + ax.get_yticklabels()):
        label.set_fontname('Times New Roman')
        label.set_fontsize(10)

# 调整布局并显示
plt.tight_layout(rect=[0, 0.03, 1, 0.97])
plt.show()

# 可选：保存图表
# plt.savefig('storage_analysis.png', dpi=300, bbox_inches='tight')