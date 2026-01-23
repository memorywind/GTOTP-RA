## GTOTP-DAA方案详细构造（带随机数的标签生成）

本节给出DAA-GTOTP方案的形式化算法描述。方案由五个多项式时间算法构成：系统初始化（Setup）、成员加入（Join）、凭证生成（Sign）、凭证验证（Verify）与身份追溯（Open）。

**系统初始化算法** $\mathsf{Setup}$ 由可信的发行方执行。输入安全参数 $\lambda$、协议起始时间 $T_s$、终止时间 $T_e$、GTOTP实例生命周期 $\Delta_T$ 以及口令生成间隔 $\Delta_e$。算法首先生成签名密钥对 $(\mathsf{isk}, \mathsf{ipk}) \leftarrow \mathsf{Sig.KeyGen}(1^\lambda)$，其中私钥 $\mathsf{isk}$ 由发行方秘密保存以供对标签进行签名，公钥 $\mathsf{ipk}$ 公开用于验证标签的合法性。随后，计算协议周期内所需的GTOTP实例总数 $E = \lceil (T_e - T_s) / \Delta_T \rceil$。算法初始化一个抗碰撞哈希函数 $H$ 并得到其密钥 $\mathsf{hk} \leftarrow H.\mathsf{Setup}(1^\lambda)$，同时采样一个随机置换密钥 $k_p \xleftarrow{\$} \{0,1\}^\lambda$，用于后续混淆验证点顺序。验证点子集数量 $\phi$ 被设定为一个常数，直接决定公开验证状态的大小。最终，算法输出公共参数 $\mathsf{pp} = (\mathsf{hk}, k_p, E, T_s, T_e, \Delta_e, \Delta_T, \phi, \mathsf{ipk})$ 以及发行方私钥 $\mathsf{isk}$。发行方同时初始化一个空的本地身份映射表 $\mathsf{IDTable}$。

**成员加入算法** $\mathsf{Join}$ 是一个两方交互协议，使证明者 $\mathsf{ID}_j$ 成为匿名群组一员。证明者首先生成一个伪随机函数（PRF）密钥 $\mathsf{sk}_j = k_{\mathsf{ID}_j} \xleftarrow{\$} \{0,1\}^\lambda$ 作为其长期私钥，并初始化两个本地状态集合：已使用实例集 $\mathsf{Used}_j = \varnothing$ 和可用实例集 $\mathsf{Available}_j = \{1, \ldots, E\}$。对于每一个实例 $i \in [1, E]$，证明者计算其对应的时间窗口 $[T_s + (i-1)\Delta_T, T_s + i\Delta_T]$，利用其私钥生成实例专属种子 $\mathsf{seed}_j^i = \mathsf{PRF}(\mathsf{sk}_j, \mathsf{ID}_j \| i)$，并据此计算出初始验证点 $\mathsf{vp}_j^i \leftarrow \mathsf{GTOTP.PInit}(\mathsf{seed}_j^i)$。证明者将所有验证点集合 $\mathsf{vst}_j = \{\mathsf{vp}_j^i\}_{i=1}^E$ 发送给发行方。

发行方收到证明者发送的验证点集合后，为每个实例生成唯一的匿名标签。具体而言，对于每个实例 $i$，发行方执行以下步骤：
1. 采样随机数 $r_j^i \xleftarrow{\$} \{0,1\}^\lambda$。
2. 计算标签：$tag_j^i = H(\mathsf{ID}_j \| i \| r_j^i)$。
3. 检查 $tag_j^i$ 是否已存在于身份映射表 $\mathsf{IDTable}$ 中（确保全局唯一性，若冲突则重新采样 $r_j^i$）。
4. 计算发行方签名 $\sigma_j^i \leftarrow \mathsf{Sig.Sign}(\mathsf{isk}, (tag_j^i, i))$，并将三元组 $(tag_j^i, i, \mathsf{ID}_j)$ 安全存储于本地映射表 $\mathsf{IDTable}$ 中。
5. 丢弃随机数 $r_j^i$（或可选地安全存储，但非必需）。
6. 计算绑定验证点 $\hat{\mathsf{vp}}_j^i = H(\mathsf{hk}, \mathsf{vp}_j^i \| tag_j^i \| \sigma_j^i \| i)$ 以将验证点、标签及其签名关联。

在所有成员的绑定验证点收集完毕后，发行方使用置换密钥 $k_p$ 将其随机打乱得到集合 $V'$，并将其划分为 $\phi$ 个大小相近的子集。对每个子集，发行方构建一棵Merkle树，记录其根节点 $\mathsf{rt}_t$，并为该子集中的每个绑定验证点生成对应的成员资格证明 $\pi_j^i$。最后，发行方初始化一个预设误判率 $\epsilon$ 的布隆过滤器 $\mathsf{BF}$，将所有Merkle树根插入其中，形成公开的、恒定大小的群组验证状态 $\mathsf{VST} = \mathsf{BF}$。发行方将成员专属的辅助信息 $\mathsf{Aux}_j = \{ (tag_j^i, \sigma_j^i, \pi_j^i) \}_{i=1}^E$ 安全地发送给证明者。证明者存储 $(\mathsf{sk}_j, \mathsf{Aux}_j, \mathsf{Used}_j, \mathsf{Available}_j)$ 以完成加入过程。

**凭证生成算法** $\mathsf{Sign}$ 在证明者需要于时间 $T$ 匿名证明其群组成员身份时运行。算法首先确认 $T$ 处于协议有效时间窗 $[T_s, T_e]$ 内。随后，计算当前时间 $T$ 对应的唯一实例索引 $i = \lceil (T - T_s) / \Delta_T \rceil$。若该实例索引 $i$ 不在证明者的可用实例集 $\mathsf{Available}_j$ 中，则算法中止，表明该实例已被使用或不可用；否则，证明者使用其私钥重构该实例的种子 $\mathsf{seed}_j^i = \mathsf{PRF}(\mathsf{sk}_j, \mathsf{ID}_j \| i)$，并调用 $\mathsf{GTOTP.PwGen}$ 生成与时间 $T$ 绑定的一次性口令 $\mathsf{pw}$。证明者从辅助信息 $\mathsf{Aux}_j$ 中取出与该实例对应的预生成标签 $tag_j^i$、发行方签名 $\sigma_j^i$ 和Merkle证明 $\pi_j^i$。在输出凭证前，算法更新本地状态，将实例 $i$ 从 $\mathsf{Available}_j$ 移至 $\mathsf{Used}_j$ 集合，确保其未来不会被重复使用。最终输出的匿名凭证为 $\sigma_T = (\mathsf{pw}, tag_j^i, \sigma_j^i, \pi_j^i, i, T)$。

值得注意的是，每个GTOTP实例在其生命周期 $\Delta_T$ 内仅能用于生成一次凭证。若证明者需在同一时间窗口内多次认证，可通过调整系统参数 $\Delta_T$ 缩短实例生命周期，从而增加实例数量以满足频繁认证需求。该设计在保证实例一次性使用的同时，通过参数配置平衡了认证频率与系统开销。

**凭证验证算法** $\mathsf{Verify}$ 供验证方检验一个凭证 $\sigma_T = (\mathsf{pw}, tag, \sigma, \pi, i, T)$ 的有效性。验证流程始于一系列基础检查：确认实例索引 $i$ 在合法范围 $[1, E]$ 内；确认凭证时间 $T$ 处于协议总时间窗 $[T_s, T_e]$ 内；确认 $T$ 同时位于实例 $i$ 的专属有效期 $[T_s + (i-1)\Delta_T, T_s + i\Delta_T]$ 内。为防止重放攻击，算法进一步验证 $T$ 是否属于以当前时间为基准的、长度为 $\Delta_e$ 的有效滑动时间窗口内。若任何一项检查失败，则立即拒绝该凭证。

通过基础检查后，验证方进行密码学验证。首先，验证发行方对标签的签名：计算 $\mathsf{Sig.Verify}(\mathsf{ipk}, (tag, i), \sigma)$，确保标签的合法性与实例绑定的真实性。随后，从口令 $\mathsf{pw}$ 推导出对应的验证点 $\mathsf{vp} = \mathsf{GTOTP.GetVP}(\mathsf{pw})$，并利用公共哈希密钥计算绑定验证点 $\hat{\mathsf{vp}} = H(\mathsf{hk}, \mathsf{vp} \| tag \| \sigma \| i)$。接着，使用提供的Merkle证明 $\pi$ 从 $\hat{\mathsf{vp}}$ 重构出Merkle树根 $\mathsf{rt}'$，并验证该证明的正确性。接下来，验证方查询公开的群组验证状态——布隆过滤器 $\mathsf{VST}$，检查 $\mathsf{rt}'$ 是否为其中一个已注册的合法树根。最后，调用 $\mathsf{GTOTP.Verify}$ 算法验证口令 $\mathsf{pw}$ 在时间 $T$ 的有效性。只有当所有步骤均成功通过时，验证算法输出 $1$，表示该凭证来自一个合法的匿名群组成员；否则输出 $0$。

**身份追溯算法** $\mathsf{Open}$ 仅在审计或法律要求等必要情况下，由可信发行方执行。算法输入为待追溯的凭证 $\sigma_T$ 和发行方私钥 $\mathsf{isk}$。发行方首先运行公开的 $\mathsf{Verify}$ 算法确认凭证的有效性。若验证失败，则输出特殊符号 $\bot$ 表示追溯失败。若凭证有效，发行方从中提取出标签 $tag$ 和实例索引 $i$，并在其本地安全存储的身份映射表 $\mathsf{IDTable}$ 中查找与该 $(tag, i)$ 对相关联的成员身份 $\mathsf{ID}_j$。若查找到匹配项，则输出 $\mathsf{ID}_j$，从而在保护日常匿名性的前提下实现了系统的可问责性；若未找到，同样输出 $\bot$。

## 安全性讨论（带随机数的标签生成）

采用随机数增强的标签生成机制 $tag_j^i = H(\mathsf{ID}_j \| i \| r_j^i)$ 在保持方案简洁高效的同时，进一步提升了安全性：

1. **增强的不可预测性**：随机数 $r_j^i$ 确保了每个标签在计算上是不可预测的，即使攻击者知道 $\mathsf{ID}_j$ 和 $i$，也无法计算出标签，因为缺少随机数。这防止了攻击者通过枚举身份尝试关联凭证与证明者。

2. **唯一性保证**：在抗碰撞哈希函数的安全性假设下，以及随机数的充分随机性，不同三元组 $(\mathsf{ID}_j, i, r_j^i)$ 产生相同 $tag_j^i$ 的概率可忽略。发行方通过 $\mathsf{IDTable}$ 检查可进一步确保全局唯一性。

3. **匿名性保护**：哈希函数的单向性确保从 $tag_j^i$ 无法恢复 $\mathsf{ID}_j$ 或 $r_j^i$。验证者仅能通过验证签名确认标签的合法性，但无法获取任何身份信息。此外，绑定验证点 $\hat{\mathsf{vp}}_j^i$ 进一步隐藏了标签与验证点的直接关联。

4. **不可链接性维持**：对于同一证明者，不同实例的标签因实例索引 $i$ 和随机数 $r_j^i$ 的不同而不同；对于不同证明者，即使实例索引相同，身份 $\mathsf{ID}_j$ 和随机数 $r_j^i$ 的差异也导致标签不同。因此，凭证中的标签不提供跨凭证的链接信息。

5. **前向安全性**：若证明者长期私钥 $\mathsf{sk}_j$ 泄露，攻击者可生成未来凭证，但无法改变过去凭证的标签。由于标签的生成独立于 $\mathsf{sk}_j$（仅依赖于 $\mathsf{ID}_j$、$i$ 和发行方生成的随机数），私钥泄露不影响过往凭证的匿名性。

6. **效率权衡**：相较于无随机数的版本，此设计增加了发行方生成随机数和计算哈希的微小开销，但避免了证明者进行群指数运算（如 $g^{r_j^i}$），整体仍保持高效。随机数生成后即丢弃，不增加存储负担。

7. **抗枚举攻击**：攻击者无法通过预计算或枚举尝试将观察到的标签与可能的身份关联，因为每个标签都包含了发行方生成的秘密随机数，且随机数不在任何地方公开。

综上所述，带随机数的标签生成设计在略微增加计算开销的情况下，提供了更强的安全保证，特别适用于对隐私保护要求极高的场景。