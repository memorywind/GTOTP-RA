## 引言

直接匿名证明（Direct Anonymous Attestation, DAA）作为一种能够平衡匿名性与可问责性的密码学原语，自提出以来便在可信计算与隐私保护领域扮演着关键角色。DAA 最早由 Brickell、Camenisch 和 Chen 引入，旨在为可信平台模块（TPM）等硬件安全模块提供一种既能保护用户隐私（设备匿名）又支持身份追溯的认证机制。其核心思想在于：设备首先向一个可信的发行方（Issuer）注册，获得一个群组凭证；随后，设备能够利用该凭证生成匿名签名，以证明自己属于某个合法群组，而验证者无法推断出具体是哪一个设备；仅在需要追责时，发行方可利用特殊密钥“打开”签名以揭示设备身份。这种特性使得 DAA 在匿名电子投票、隐私保护的位置服务、可信计算链等多个场景中展现出重要价值。

然而，尽管 DAA 在理论上具备了强安全属性，其在实际部署中仍面临严峻的效率与可扩展性挑战。传统 DAA 方案通常依赖于双线性对（Bilinear Pairing）等计算密集型密码学原语。例如，一个典型的 DAA 签名生成过程需要多次双线性对运算和模幂运算，这给资源受限的设备（如物联网传感器、嵌入式终端）带来了沉重的计算负担，难以满足高频率、低延迟的实时认证需求。此外，许多传统 DAA 方案的验证状态与群组成员数量呈线性关系，导致验证者需要维护大量的状态信息，这严重限制了其在大规模群组中的可扩展性。

近年来，研究者们尝试从不同角度优化 DAA 的效率与适用性。例如，基于格的 DAA 方案旨在提供后量子安全性，但其计算开销依然可观；一些工作尝试简化证明过程或借助硬件加速，但往往在安全性、通用性或部署成本上做出妥协。因此，如何在保持 DAA 核心安全属性的同时，大幅降低其计算与存储开销，使其能够适用于资源受限的大规模场景，仍然是一个开放且具挑战性的问题。

为应对上述挑战，本文提出一种基于群组时间一次性口令的直接匿名证明方案（DAA-GTOTP），旨在为上述挑战提供一个新颖而实用的解决方案。我们的核心思路是，利用 GTOTP（Group Time-based One-Time Passwords）这一新型密码原语的特性，将时间约束的一次性口令机制与高效的匿名群组认证相结合。GTOTP 是对传统 TOTP（基于时间的一次性口令的扩展，它允许多个群组成员在不泄露身份的前提下，生成可公开验证且具有严格时间有效性的凭证。与依赖双线性对的传统 DAA 相比，我们的方案具有以下突出优势：

1.  高效性：凭证生成与验证主要基于哈希运算和伪随机函数，避免了昂贵的双线性对运算，计算开销降低数个数量级，适合资源受限设备。
2.  常数级验证状态：通过Merkle树与布隆过滤器的巧妙结合，验证者只需维护恒定大小的群组验证状态，与群组成员数量无关，具备极佳的可扩展性。
3.  强隐私保护：生成的凭证不会泄露设备身份，且同一设备在不同时间生成的凭证不可关联，满足了 DAA 所要求的匿名性与不可链接性。
4.  可追溯性：发行方持有签名私钥并维护身份映射表，可在必要时通过查找映射表恢复设备身份，确保系统问责能力。
5.  内在速率限制：每个 GTOTP 实例仅能使用一次，且与时间窗口绑定，从而自然限制了证明者在单位时间内的最大凭证生成数量，有效防止凭证滥用与拒绝服务攻击。

为验证本方案的实际效能，我们在Raspberry Pi 4B硬件平台上实现了原型系统，并进行了全面的性能评估。实验结果表明，凭证生成仅需微秒级时间，验证时间在毫秒级，且通信开销极小。同时，我们提供了形式化的安全性分析，证明本方案满足 DAA 所需的强安全属性，包括匿名性、不可伪造性和可追溯性。

本文的主要贡献可概括为以下三个方面：

1.新模型与构造：首次提出了基于 GTOTP 的 DAA 方案，将时间约束口令与匿名群组认证相结合，为资源受限环境下的高效隐私保护认证提供了新思路。

2.详细构造：给出了完整的协议构造，包括系统初始化、成员加入、凭证生成与验证、身份追溯等算法，并提供了严格的安全性证明。

3.实现与评估：通过原型系统实现与性能评估，证实了本方案在保持强安全性的同时，具备实际部署的可行性与高效性。

## 相关工作

### **传统TOTP方案**

**基于时间的动态口令（TOTP）**作为一种轻量级、高效的双因素认证机制，已被工业界如Google Authenticator [1]、Duo [2]广泛采用。其安全基石建立在哈希函数的单向性之上。Lamport [3] 最早提出了基于哈希链的一次性密码本概念，为TOTP奠定了理论基础。后续研究，如Kogan等人的T/Key方案 [6]，通过引入严格的时间窗口约束，进一步增强了其对抗重放攻击的能力。Jin等人 [5] 则对哈希链TOTP方案进行了形式化安全证明，并创新性地将其用于“存活证明”（Proof of Aliveness）。

然而，这些传统TOTP方案在设计之初均围绕单一证明者与单一验证者的模型展开。验证者必须预先知道证明者的身份及其对应密钥，才能完成认证。这种设计模式导致其天然无法支持群体认证，更不具备身份隐私保护能力。尽管存在诸如事件驱动型OTP等变体，但它们仍未解决在群体场景下，如何让验证者在不知晓具体成员身份的情况下完成验证这一核心挑战。

### **强安全属性的群体匿名认证机制**

为满足群体场景下的匿名性与可问责性需求，密码学领域提出了群签名 [4]、环签名和直接匿名证明（DAA） [8] 等高级密码原语。**群签名**允许群体中的任一成员代表群体生成签名，验证者仅能验证签名出自该群体，而无法识别具体签名者；仅在发生争议时，由群管理员打开签名以揭示身份。**DAA** 可视为一种专为可信计算平台（如TPM）设计的特殊群签名方案，它通过一个可信的签发者（Issuer）执行“Join”协议来颁发匿名凭证，在提供强匿名性的同时支持成员撤销和身份追溯。

这类方案提供了可形式化证明的强安全属性，包括匿名性、不可链接性、可追溯性等。然而，其安全性通常建立在计算密集型密码学原语之上，例如双线性对运算或大整数模指数运算。例如，Emura等人 [13] 提出的支持时间绑定密钥的群签名方案，虽然功能完备，但每个签名与验证操作均涉及多次双线性对运算，开销巨大。经典的DAA方案 [8] 同样严重依赖双线性对。这些高昂的计算与通信成本，使得此类方案难以直接应用于处理器能力弱、能耗预算严格的物联网终端、移动传感器等大规模部署场景。

### 面向效率优化的轻量级认证方案

为缓解强安全方案与有限资源之间的矛盾，研究主要从两个方向进行探索：

一方面，部分工作致力于对现有强安全方案进行**工程优化与算法轻量化**，例如选择更快的椭圆曲线、采用预计算技术或优化配对计算流程 [9]。这类改进能在一定程度上提升性能，但并未改变方案底层依赖昂贵密码操作的本质，在极端受限的设备上其开销仍显过高。

另一方面，有研究尝试采用**全新的构造思路来寻求根本性的效率突破**，避免直接使用双线性对或复杂零知识证明。Yang等人 [7] 提出的**群组时间一次性口令（GTOTP）** 是这一方向的代表性成果。GTOTP创新地将非对称TOTP、Merkle树和布隆过滤器相结合，使验证者能够仅维护一个常数大小的群组验证状态（GVST），即可完成对匿名成员凭证的验证。其核心操作几乎全部由哈希函数和伪随机函数构成，实现了微秒级的凭证生成和毫秒级的验证，首次在**高效性**与**群体匿名认证**之间取得了卓越的平衡，并被成功应用于隐私保护的位置证明系统 [7]。

然而，现有GTOTP方案的研究尚未将其置于**标准化远程证明（RATS）架构**[12] 下进行系统性审视，也未将其高效机制明确地映射和适配为解决**直接匿名证明（DAA）** 在资源受限环境中面临的核心效率瓶颈问题。本工作正是致力于填补这一研究空白。

## Preliminary

### 直接匿名认证（DAA）

直接匿名证明是一种在可信计算等领域广泛应用的密码学协议，它允许群组成员（**证明者**）向**验证者**匿名地证明自己的成员身份，同时确保可信的**发行方**在必要时能够对滥用行为进行身份追溯。

DAA通常包含以下三类实体：

- **发行方**：负责创建群组、管理成员加入并签发成员凭证。在追溯阶段，发行方可利用其秘密信息打开匿名签名以揭露签名者身份。发行方通常被建模为可信实体。
- **证明者**：已成功加入群组的成员。他们能够利用自己的私钥和成员凭证，生成对消息的匿名签名（证明）。
- **验证者**：验证匿名签名有效性的实体。验证者可以确信签名来自合法群组成员，但无法得知具体是哪一个成员。

一个标准的 DAA 方案通常由以下六个概率多项式时间算法或协议交互构成：

* $\mathsf{Setup}(1^\lambda) \to (\mathsf{gpk}, \mathsf{ik}, \mathsf{st}_\mathcal{I})$：**系统建立算法**。输入安全参数 $\lambda$，由发行方执行。生成公开的群组公钥 $\mathsf{gpk}$、发行方的追溯私钥 $\mathsf{ik}$，以及发行方的初始内部状态 $\mathsf{st}_\mathcal{I}$。

* $\langle \mathcal{U}(\mathsf{gpk}), \mathcal{I}(\mathsf{gpk}, \mathsf{ik}, \mathsf{st}_\mathcal{I}) \rangle \to (\mathsf{cred}, \mathsf{sec}) / (\mathsf{st}_\mathcal{I}’)$：**成员加入协议**。这是证明者 $\mathcal{U}$ 与发行方 $\mathcal{I}$ 之间的一个交互式协议。成功执行后，证明者获得其私有的成员密钥 $\mathsf{sec}$ 和成员凭证 $\mathsf{cred}$；发行方更新其内部状态至 $\mathsf{st}_\mathcal{I}’$，并通常将证明者的身份信息安全地关联存储到其状态中。

* $\mathsf{Sign}(\mathsf{gpk}, \mathsf{sec}, \mathsf{cred}, m) \to \sigma$：**签名算法**。由证明者执行。输入群公钥、自身私钥、凭证以及待签名的消息 $m$，输出一个匿名签名 $\sigma$。

* $\mathsf{Verify}(\mathsf{gpk}, m, \sigma) \to 0/1$：**验证算法**。由验证者执行。输入群公钥、消息和签名，若签名有效则输出 $1$，否则输出 $0$。

* $\mathsf{Link}(\mathsf{gpk}, \sigma_1, \sigma_2) \to 0/1$：**链接算法**（可选，但常见）。这是一个公开算法，无需秘密信息。输入两个签名，若判定它们由同一证明者生成则输出 $1$，否则输出 $0$。此算法用于实现可控的匿名性。

* $\mathsf{Open}(\mathsf{ik}, \mathsf{st}_\mathcal{I}, \sigma, m) \to \mathsf{ID} / \bot$：**追溯算法**。由发行方秘密执行。输入追溯私钥、内部状态、待追溯的签名及其消息，输出签名者的真实身份 $\mathsf{ID}$，或无法追溯时输出 $\bot$。

  ![image-20251219113203915](C:\Users\WangHao\AppData\Roaming\Typora\typora-user-images\image-20251219113203915.png)

### 安全假设与定义

#### 安全假设

DAA-GTOTP的安全性依赖于以下密码学标准假设：

**假设1.伪随机函数安全性（PRF Security）**。设 $F: \mathcal{K} \times \mathcal{X} \to \mathcal{Y}$ 为一个伪随机函数。对于任何 PPT 攻击者 $\mathcal{A}$，其区分 $F_k(\cdot)$ 与真正随机函数 $\mathcal{R}(\cdot)$ 的优势可忽略不计：
$$
\mathsf{Adv}^{\mathsf{PRF}}_{\mathcal{A}}(\lambda) = \left| \Pr[\mathcal{A}^{F_k(\cdot)} = 1] - \Pr[\mathcal{A}^{\mathcal{R}(\cdot)} = 1] \right| \leq \mathsf{negl}(\lambda)
$$
其中 $k \xleftarrow{\$} \mathcal{K}$。该假设支撑着从证明者长期私钥 $\mathsf{sk}_j$ 生成各实例种子 $\mathsf{seed}_j^i$ 的过程。

**假设2. 数字签名不可伪造性（EUF-CMA Security）**。设 $\mathsf{Sig} = (\mathsf{KeyGen}, \mathsf{Sign}, \mathsf{Verify})$ 为一个数字签名方案。对于任何 PPT 攻击者 $\mathcal{A}$，即使在获得多个消息-签名对的自适应访问后，其成功伪造新消息有效签名的优势可忽略不计：
$$
\mathsf{Adv}^{\mathsf{EUF-CMA}}_{\mathcal{A}}(\lambda) = \Pr\left[
\begin{array}{l}
(\mathsf{pk}, \mathsf{sk}) \leftarrow \mathsf{KeyGen}(1^\lambda), \\
(m^*, \sigma^*) \leftarrow \mathcal{A}^{\mathsf{Sign}_{\mathsf{sk}}(\cdot)}(\mathsf{pk}): \\
\mathsf{Verify}_{\mathsf{pk}}(m^*, \sigma^*) = 1 \land m^* \notin Q
\end{array}
\right] \leq \mathsf{negl}(\lambda)
$$
其中 $Q$ 为 $\mathcal{A}$ 的签名查询集合。该假设确保发行方对标签 $(tag_j^i, i)$ 的签名 $\sigma_j^i$ 不可伪造，是凭证有效性的基础。

**假设3. 哈希函数抗碰撞性与原像抵抗性（Hash Collision Resistance and Preimage Resistance）。**哈希函数 $H: \{0,1\}^* \to \{0,1\}^\lambda$ 满足：

- **抗碰撞性**。

  对于任何PPT攻击者$\mathcal{A}$，
  $$
  \mathsf{Adv}^{\mathsf{CR}}_{H}(\mathcal{A})=\Pr[(x, x') \leftarrow \mathcal{A}(1^\lambda): x \neq x' \land H(x) = H(x')] \leq \mathsf{negl}(\lambda)
  $$

- **单向性**。对于任意PPT攻击者$\mathcal{A}$和随机样本$x \xleftarrow{\$} \{0,1\}^\lambda$，
$$
\mathsf{Adv}^{\mathsf{Pre}}_{H}(\mathcal{A}) = \Pr[y \leftarrow H(x),x' \leftarrow \mathcal{A}(y): H(x') = y] \leq \mathsf{negl}(\lambda)
$$

该假设确保标签 $tag_j^i = H(\mathsf{ID}_j \| i \| r_j^i)$ 的唯一性，并支撑Merkle树与绑定验证点 $\hat{\mathsf{vp}}_j^i$ 的安全性。

**假设4.Bloom 过滤器的误判率界限**。布隆过滤器 $\mathsf{BF}$ 的参数 $(m, k)$ 根据预设误判率 $\epsilon$ 和插入元素数量 $n = \phi$（Merkle树根的数量）设定，满足：

$$
\varepsilon = \left(1 - e^{-kn/m}\right)^k \leq 2^{-\kappa}
$$
其中 $\kappa$ 为统计安全参数（如 $\kappa=40$）。该参数选择确保在验证状态 $\mathsf{VST}$ 查询中出现假阳性的概率可忽略，且不影响系统安全性（仅可能导致拒绝合法证明，但不会接受非法证明）。

**假设5.时间同步假设（Bounded Clock Drift）**。系统中所有诚实参与方的本地时钟与全局参考时间的漂移 $\delta$ 有界，即 $|\delta| < \Delta_e / 2$，其中 $\Delta_e$ 为GTOTP口令生成间隔。该假设确保验证者能准确判断凭证中的时间 $T$ 是否落在当前有效的时间窗口内，防止因时钟偏差导致的拒绝或重放攻击窗口扩大。

**假设6.伪随机置换安全性（PRP Security）**。设 $\Pi: \mathcal{K} \times \{0,1\}^n \to \{0,1\}^n$ 是一个带密钥的置换族。对于任何 PPT 攻击者 $\mathcal{A}$，其在“真实置换”与“理想随机置换”之间的区分优势可忽略不计：
$$
\mathsf{Adv}_{\Pi}^{\mathsf{PRP}}(\mathcal{A}) = \left| \Pr_{k \xleftarrow{\$} \mathcal{K}} \left[ \mathcal{A}^{\Pi_k(\cdot)} = 1 \right] - \Pr_{P \xleftarrow{\$} \mathsf{Perm}(n)} \left[ \mathcal{A}^{P(\cdot)} = 1 \right] \right| \leq \mathsf{negl}(\lambda),
$$
其中 $\mathsf{Perm}(n)$ 表示所有定义在 $\{0,1\}^n$ 上的置换集合。在我们的方案中，发行方使用的置换 $\pi(k_p, \cdot)$ 被建模为这样一个伪随机置换。该假设是保障方案**匿名性**与**不可关联性**的关键基石之一：它确保了攻击者无法通过观察公开验证状态 $\mathsf{VST}$ 中验证点子集的划分模式（该模式由 $\pi(k_p, \cdot)$ 的输出决定），来获得任何有助于区分或链接不同证明者身份的统计信息或规律。

### 安全定义

为了形式化分析 DAA-GTOTP 的安全性，我们采用基于游戏的定义框架。设 $\mathcal{A}$ 为概率多项式时间（PPT）攻击者，$\mathcal{C}$ 为挑战者，$\lambda$ 为安全参数。

我们首先定义通用的**攻击者能力与预言机（Oracles）**。在所有安全游戏中，$\mathcal{C}$ 运行 $\mathsf{Setup}$ 初始化系统，并将公共参数 $\mathsf{pp}$ 发送给 $\mathcal{A}$。$\mathcal{A}$ 可自适应地访问以下预言机：

- $\mathcal{O}_{\mathsf{Join}}(\mathsf{ID}_j)$：模拟成员加入协议，将 $\mathsf{ID}_j$ 注册为合法成员。
- $\mathcal{O}_{\mathsf{Sign}}(\mathsf{ID}_j, T)$：返回成员 $\mathsf{ID}_j$ 在时间 $T$ 的有效凭证 $\sigma_T$。
- $\mathcal{O}_{\mathsf{Corrupt}}(\mathsf{ID}_j)$：返回成员 $\mathsf{ID}_j$ 的长期私钥 $\mathsf{sk}_j$ 及内部状态。
- $\mathcal{O}_{\mathsf{Open}}(\sigma)$：返回凭证 $\sigma$ 对应的成员身份 $\mathsf{ID}$ 或 $\bot$（仅在非匿名性游戏中开放）。

#### 可追溯性 (Traceability)

可追溯性要求任何通过验证的凭证必须能够被追踪到某个群成员。如果攻击者能够生成一个有效凭证，使得该凭证要么无法被追踪，要么追踪到一个未被腐化且未签署该凭证的诚实成员，则攻击成功。

**定义 1 (Traceability).** DAA-GTOTP 方案满足可追溯性，若对于任意 PPT 攻击者 $\mathcal{A}$，其在游戏 $\mathbf{Exp}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$ 中的优势 $\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$ 是可忽略的：

$$\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda) = \Pr\left[ \begin{array}{l} (\sigma^*, m^*) \leftarrow \mathcal{A}^{\mathcal{O}_{\mathsf{Join}}, \mathcal{O}_{\mathsf{Sign}}, \mathcal{O}_{\mathsf{Corrupt}}, \mathcal{O}_{\mathsf{Open}}}(\mathsf{pp}, \mathsf{ipk}); \\ \mathsf{Verify}(\mathsf{pp}, \sigma^*) = 1 \land (\sigma^* \notin Q_{\mathsf{Sign}}) \land \\ (\mathsf{ID}^* \leftarrow \mathsf{Open}(\mathsf{isk}, \sigma^*)) \text{ 满足: } \\ \quad 1.\ \mathsf{ID}^* = \bot; \text{ 或 } \\ \quad 2.\ \mathsf{ID}^* \notin L_{\mathsf{corrupt}} \end{array} \right] \leq \mathsf{negl}(\lambda)$$

其中 $Q_{\mathsf{Sign}}$ 是签名预言机的输出集合，$L_{\mathsf{corrupt}}$ 是被腐化成员的集合。

#### 匿名性 (Anonymity)

匿名性确保攻击者无法区分两个诚实成员生成的凭证。我们使用“左或右”（Left-or-Right）风格的定义。

**定义 2 (Anonymity).** DAA-GTOTP 方案满足匿名性，若对于任意 PPT 攻击者 $\mathcal{A}$，其在游戏 $\mathbf{Exp}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$ 中的优势 $\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$ 是可忽略的：

$$\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda) = \left| \Pr[b = b'] - \frac{1}{2} \right| \leq \mathsf{negl}(\lambda)$$

游戏过程如下：

1. $\mathcal{A}$ 选择两个未腐化的成员身份 $\mathsf{ID}_0, \mathsf{ID}_1$ 和时间 $T^*$。
2. $\mathcal{C}$ 随机选择 $b \in \{0,1\}$，计算 $\sigma^* \leftarrow \mathsf{Sign}(\mathsf{sk}_{\mathsf{ID}_b}, T^*)$ 并发送给 $\mathcal{A}$。
3. $\mathcal{A}$ 输出猜测位 $b'$。在此过程中，$\mathcal{A}$ 不能查询 $\mathcal{O}_{\mathsf{Corrupt}}(\mathsf{ID}_{0/1})$ 或 $\mathcal{O}_{\mathsf{Open}}(\sigma^*)$。

#### 不可关联性 (Unlinkability)

不可关联性要求攻击者无法判断两个不同的凭证是来自同一个成员还是两个不同的成员。

**定义 3 (Unlinkability)**. DAA-GTOTP 方案满足不可关联性，若对于任意 PPT 攻击者 $\mathcal{A}$，其优势 $\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Unlink}}(\lambda)$ 是可忽略的。

游戏设置与匿名性类似，区别在于挑战阶段：$\mathcal{A}$ 选择两个时间点 $T_1, T_2$。$\mathcal{C}$ 随机选择 $b \in \{0,1\}$。

- 若 $b=0$，$\mathcal{C}$ 生成同一成员 $\mathsf{ID}$ 的两个凭证 $(\sigma_{T_1}, \sigma_{T_2})$。

- 若 $b=1$，$\mathcal{C}$ 生成两个不同成员 $\mathsf{ID}_a, \mathsf{ID}_b$ 的凭证 $(\sigma_{T_1}, \sigma_{T_2})$。

  $\mathcal{A}$ 需猜测 $b$ 的值。

#### 速率限制 (Rate-Limiting)

速率限制是 GTOTP 的特有属性，涵盖了**抗重放性**。它要求成员在任意时间窗口 $\Delta_T$ 内最多生成一个有效凭证，且总凭证数不超过 $E$。

**定义 4 (Rate-Limiting).** DAA-GTOTP 方案满足速率限制，若不存在 PPT 攻击者 $\mathcal{A}$ 能够输出一个成员身份 $\mathsf{ID}^*$（诚实或腐化皆可）及一组有效凭证 $\Sigma = \{\sigma_1, \dots, \sigma_k\}$，使得 $\Sigma$ 满足以下任一条件：

1. **总量溢出**：$k > E$；
2. **窗口冲突**：存在 $\sigma_a, \sigma_b \in \Sigma$ 且 $a \neq b$，它们对应的时间戳 $T_a, T_b$ 映射到同一个实例索引 $i = \lceil (T - T_s)/\Delta_T \rceil$（包含 $T_a=T_b$ 的重放情况）。

#### 前向不可伪造性 (Forward Unforgeability)

鉴于方案特性，我们将前向安全性限定在不可伪造性层面。

**定义 5 (Forward Unforgeability).** DAA-GTOTP 方案满足前向不可伪造性，若对于任意 PPT 攻击者 $\mathcal{A}$，在时间 $t_{leak}$ 腐化成员 $\mathsf{ID}_j$ 获得私钥后，无法生成时间 $T < t_{leak}$ 的有效凭证 $\sigma_T$。即：

$$\mathsf{Adv}_{\mathcal{A}}^{\mathsf{F-Unforge}}(\lambda) = \Pr\left[ \begin{array}{l} \mathsf{sk}_j \leftarrow \mathcal{O}_{\mathsf{Corrupt}}(\mathsf{ID}_j) \text{ at } t_{leak}; \\ \sigma^* \leftarrow \mathcal{A}(\mathsf{sk}_j, T^*); \\ \text{s.t. } T^* < t_{leak} \land \mathsf{Verify}(\sigma^*) = 1 \end{array} \right] \leq \mathsf{negl}(\lambda)$$

## 协议定义与形式化描述

### 系统模型与参与方

本方案涉及三类核心实体，构成如图xxx所示的系统架构：

**定义1（参与方）**：
- **证明者（Attester）**：由$U$个可信实体$\mathcal{P} = \{\mathsf{ID}_1, \mathsf{ID}_2, \ldots, \mathsf{ID}_U\}$组成的匿名群体。每个成员$\mathsf{ID}_j$独立维护GTOTP秘密种子及验证状态，负责在本地生成时间约束的匿名认证凭证。
- **发行方（Issuer）**：可信第三方权威，负责：(1) 系统参数初始化；(2) 群组凭证颁发（对应GTOTP的群组验证状态GVST）；(3) 成员身份管理，具备在必要时揭示匿名成员身份的能力。
- **验证方（Verifier）**：接收并验证匿名凭证，确认证明者群体成员资格，但无法识别具体凭证生成者的实体。

### 语法定义

我们形式化定义GTOTP-DAA方案为五元组算法$\Pi_{\text{DAA-GTOTP}} = (\mathsf{Setup}, \mathsf{Join}, \mathsf{Sign}, \mathsf{Verify}, \mathsf{Open})$：

- $(\mathsf{pp}, \mathsf{isk}) \leftarrow \mathsf{Setup}(1^\lambda, T_s, T_e, \Delta T, \Delta e)$：系统初始化算法，输入安全参数$\lambda$、起始时间$T_s$、终止时间$T_e$、实例周期$\Delta T$和口令间隔$\Delta e$，输出公共参数$\mathsf{pp}$和发行方私钥$\mathsf{isk}$。
- $(\mathsf{VST}, \mathsf{Aux}_j, \mathsf{sk}_j) \leftarrow \mathsf{Join}(\mathsf{pp}, \mathsf{isk}, \mathsf{ID}_j)$：成员加入算法，输入$\mathsf{pp}$、$\mathsf{isk}$和身份$\mathsf{ID}_j$，输出群组验证状态$\mathsf{VST}$、成员辅助信息$\mathsf{Aux}_j$和秘密密钥$\mathsf{sk}_j$。
- $\sigma_T \leftarrow \mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_j, T)$：凭证生成算法，输入$\mathsf{pp}$、$\mathsf{sk}_j$和时间戳$T$，输出匿名凭证$\sigma_T$。
- $b \leftarrow \mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma_T)$：凭证验证算法，输入$\mathsf{pp}$、$\mathsf{VST}$和$\sigma_T$，输出验证结果$b \in \{0,1\}$。
- $\mathsf{ID}_j/\bot \leftarrow \mathsf{Open}(\mathsf{isk}, \sigma_T)$：身份追溯算法，输入$\mathsf{isk}$和$\sigma_T$，输出成员身份$\mathsf{ID}_j$或失败符号$\bot$。

**定义2（正确性）**：对于任意$\lambda \in \mathbb{N}$，任意$(\mathsf{pp}, \mathsf{isk}) \leftarrow \mathsf{Setup}(1^\lambda, \cdots)$，任意$\mathsf{ID}_j \in \mathcal{P}$，若$(\mathsf{VST}, \mathsf{Aux}_j, \mathsf{sk}_j) \leftarrow \mathsf{Join}(\mathsf{pp}, \mathsf{isk}, \mathsf{ID}_j)$，则对于所有合法时间戳$T \in [T_s, T_e]$，有：
$$\Pr\left[\mathsf{Verify}\big(\mathsf{pp}, \mathsf{VST}, \mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_j, T)\big) = 1\right] = 1.$$

### 威胁模型

我们采用标准DAA威胁模型，考虑一个存在主动攻击者的强安全环境。模型包含三类参与方：证明者（Attester）、验证者（Verifier）和发行方（Issuer）。攻击者被建模为一个概率多项式时间（PPT）算法，具备以下能力：

1. **完全控制公共信道**：攻击者可窃听、篡改、重放或任意注入证明者与验证者之间的所有通信消息。
2. **自适应交互能力**：攻击者能自适应地与证明者和验证者进行任意多次交互，包括发起会话、响应查询等。攻击者可腐化（corrupt）部分证明者，获取其内部状态（如私钥、实例使用状态等），并控制其行为。同时，攻击者也可充当验证者与诚实证明者交互，或充当证明者与诚实验证者交互。
3. **对发行方的假设**：发行方在系统初始化和身份追溯操作中被视为完全可信。攻击者无法腐化发行方，即发行方的私钥 $\mathsf{isk}$ 与身份映射表 $\mathsf{IDTable}$ 保持安全。发行方不会与攻击者串通，仅在收到合法请求时执行身份追溯操作。
4. **时间攻击能力**：攻击者可获取当前时间，并在任意时间点发起协议交互。攻击者可尝试重放攻击、时间窗口偏移攻击等与时间相关的攻击手段。

在此威胁模型下，所提出的GTOTP-DAA方案需满足以下核心安全属性：

- **可追溯性（Traceability）**：对于任何能够通过验证算法 $\mathsf{Verify}$ 的有效凭证 $\sigma_T$，持有追溯密钥 $\mathsf{isk}$ 的发行方均能通过执行 $\mathsf{Open}$ 算法成功追溯出生成该凭证的证明者身份。即使攻击者腐化了部分群组成员（获取了他们的私钥和状态），也无法生成一个无法追溯的有效凭证。此属性确保了系统的强问责能力。

- **匿名性（Anonymity）**：对于任意两个成功完成加入协议的诚实证明者（即未被腐化的证明者），攻击者无法区分一个有效凭证是由哪一个证明者所生成。形式化地，攻击者在选择两个诚实证明者后，获得其中一个证明者生成的凭证，无法以显著优势判断是哪个证明者生成的。即使攻击者能够自适应地选择时间戳并获取凭证，这一属性也应当成立。特别地，验证者仅能判定证明是否由合法群组成员生成，但无法推断具体生成者的身份。

- **不可关联性（Unlinkability）**：对于任意两个有效凭证 $\sigma_{T_1}$ 和 $\sigma_{T_2}$，攻击者无法判断它们是否由同一个证明者生成。即使攻击者腐化了部分证明者（不包括生成这两个凭证的证明者），只要发行方未被腐化，攻击者就无法以显著优势判断这两个凭证之间的关联性。这一属性保证了同一证明者在不同时间或不同会话中生成的凭证是不可关联的。

- **速率限制（Rate Limiting）**：本方案具备内在的频率限制特性，确保每个证明者在任意长度为 $\Delta_T$ 的时间窗口内最多只能生成一个有效凭证，且在整个协议周期 $[T_s, T_e]$ 内最多只能生成 $E$ 个有效凭证。即使攻击者腐化了证明者并控制其行为，也无法突破这一限制。形式化地，对于任意诚实或腐化的证明者 $\mathsf{ID}_j$，其在任意时间区间 $[t_1, t_2] \subseteq [T_s, T_e]$ 内生成的、能够通过验证的有效凭证集合 $\{\sigma_{T_k}\}$ 满足：
  1. 凭证数量上限：$|\{\sigma_{T_k}\}| \leq \min\left( E, \left\lceil \frac{t_2 - t_1}{\Delta_T} \right\rceil + 1 \right)$。
  2. 时间窗口唯一性：对于任意两个不同凭证 $\sigma_{T_a}, \sigma_{T_b}$，若 $|T_a - T_b| < \Delta_T$，则它们必须使用不同的实例。
  3. 实例耗尽限制：证明者生成的总有效凭证数不超过 $E$。该属性由实例一次性使用机制和实例总数限制保证。

此外，由于本方案引入了时间窗口和实例一次性使用机制，我们还需考虑以下扩展属性：

- **抗重放攻击（Resistance to Replay Attacks）**：任何有效的凭证 $\sigma_T$ 只能在当前有效的时间窗口内使用一次。攻击者无法重放一个过去有效的凭证，也无法在同一个时间窗口内重复使用同一个凭证。该属性由GTOTP的时间窗口机制与实例单次使用策略共同保障。

- **前向安全性（Forward Secrecy）**：若证明者的长期私钥 $\mathsf{sk}_j$ 在某个时间点被泄露，攻击者无法利用该私钥生成在私钥泄露之前的时间点的有效凭证，也无法将之前观察到的凭证与证明者关联起来。换言之，私钥泄露不影响过往凭证的匿名性与不可关联性。该属性由GTOTP口令的时间绑定特性及每个实例的独立随机标签保障。

---

## GTOTP-DAA方案详细构造

**算法1：$\mathsf{Setup}(1^\lambda, T_s, T_e, \Delta_T, \Delta_e)$**

> 输入安全参数 $\lambda$、协议起始时间 $T_s$、终止时间 $T_e$、GTOTP实例生命周期 $\Delta_T$ 以及口令生成间隔 $\Delta_e$。算法首先生成非对称加密密钥对 $(\mathsf{isk}, \mathsf{ipk}) \leftarrow \mathsf{PKE.KeyGen}(1^\lambda)$，其中私钥 $\mathsf{isk}$ 由发行方秘密保存以供追溯，公钥 $\mathsf{ipk}$ 公开。随后，计算协议周期内所需的GTOTP实例总数 $E = \lceil (T_e - T_s) / \Delta_T \rceil$。算法初始化一个抗碰撞哈希函数 $H$ 并得到其密钥 $\mathsf{hk} \leftarrow H.\mathsf{Setup}(1^\lambda)$，同时采样一个随机置换密钥 $k_p \xleftarrow{$} \{0,1\}^\lambda$，用于后续混淆验证点顺序。验证点子集数量 $\phi$ 被设定为一个常数，直接决定公开验证状态的大小。最终，算法输出公共参数 $\mathsf{pp} = (\mathsf{hk}, k_p, E, T_s, T_e, \Delta_e, \Delta_T, \phi, \mathsf{ipk})$ 以及发行方私钥 $\mathsf{isk}$。发行方同时初始化一个空的本地身份映射表 $\mathsf{IDTable}$。

---

**算法2：$\mathsf{Join}(\mathsf{pp}, \mathsf{isk}, \mathsf{ID}_j)$**

> 成员加入是一个两阶段交互协议，使证明者（Attester）$\mathsf{ID}_j$ 成为匿名群组的一员。
>
> **第一阶段：证明者本地初始化。** 证明者 $\mathsf{ID}_j$ 首先生成一个伪随机函数（PRF）密钥 $\mathsf{sk}_j = k_{\mathsf{ID}_j} \xleftarrow{$} \{0,1\}^\lambda$ 作为其长期私钥，并初始化两个本地状态集合：已使用实例集 $\mathsf{Used}_j = \varnothing$ 和可用实例集 $\mathsf{Available}_j = \{1, \ldots, E\}$。对于每一个实例 $i \in [1, E]$，证明者计算其对应的时间窗口 $[T_s + (i-1) \cdot \Delta_T, T_s + i \cdot \Delta_T]$，利用其私钥生成实例专属种子 $\mathsf{seed}_j^i = \mathsf{PRF}(\mathsf{sk}_j, \mathsf{ID}_j \| i)$，并据此计算出初始验证点 $\mathsf{vp}_j^i \leftarrow \mathsf{GTOTP.PInit}(\mathsf{seed}_j^i)$。证明者将所有验证点集合 $\mathsf{vst}_j = \{\mathsf{vp}_j^i\}_{i=1}^E$ 发送给发行方。
>
> **第二阶段：发行方颁发凭证。** 收到所有成员的验证点后，为每个实例生成实例生成唯一的匿名标签。具体地，
>
> 1. 采样随机数 $r_j^i \xleftarrow{\$} \{0,1\}^\lambda$
> 2. 结合证明者身份和实例索引，计算确定性标签：$tag_j^i = H(\mathsf{ID}_j \| i\|r_j^i)$。
> 3. 检查 $tag_j^i$ 是否已存在于身份映射表 $\mathsf{IDTable}$ 中（确保全局唯一性，若冲突则重新采样 $r_j^i$）。
> 4. 计算发行方签名 $\sigma_j^i \leftarrow \mathsf{Sig.Sign}(\mathsf{isk}, (tag_j^i, i))$，并将三元组 $(tag_j^i, i, \mathsf{ID}_j)$ 安全存储于本地映射表 $\mathsf{IDTable}$ 中。
> 5. 计算绑定验证点 $\hat{\mathsf{vp}}_j^i = H(\mathsf{hk}, \mathsf{vp}_j^i \| tag_j^i \| \sigma_j^i \| i)$ 以将验证点、标签及其签名关联。
>
> 对于每个实例 $i$，发行方检查$tag_j^i$是否已经存在于身份映射表 $\mathsf{IDTable}$ 中，（确保标签的唯一性）若存在，则要求证明者重新生成该实例的随机数$r_j^i$并重新计算$tag_j^i$，直到唯一为止。随后计算签名$\sigma_j^i = \mathsf{Sig.Sign}(\mathsf{isk}, (tag_j^i, i))$，并将三元组 $(tag_j^i, i, \mathsf{ID}_j)$ 安全存储于本地映射表 $\mathsf{IDTable}$ 中。随后，发行方计算绑定验证点 $\hat{\mathsf{vp}}_j^i = H(\mathsf{hk}, \mathsf{vp}_j^i \| tag_j^i \| \sigma_j^i\| i)$ 以将标签与验证点关联。
>
> 在所有成员的绑定验证点收集完毕后，发行方使用置换密钥 $k_p$ 通过置换函数 $\pi(k_p, \cdot)$ 随机打乱将其随机打乱得到集合 $V’= \pi(k_p, V)$，并将其划分为 $\phi$ 个大小相近的子集$\{V_t\}_{t=1}^\phi$。对每个子集$V_t$，发行方构建一棵Merkle树$\mathsf{MT}_t \leftarrow \mathsf{MT.Build}(V_t)$，记录其根节点 $\mathsf{rt}_t$，并为该子集$V_t$中的每个绑定验证点$\hat{\mathsf{vp}}_j^i$生成对应的成员资格证明 $\pi_j^i \leftarrow \mathsf{MT.GetProof}(\mathsf{MT}_t, \hat{\mathsf{vp}}_j^i)$。
>
> 最后，发行方初始化一个预设误判率 $\epsilon$ 的布隆过滤器 $\mathsf{BF}$，将所有Merkle树根 $\{\mathsf{rt}_t\}_{t=1}^\phi$插入其中，形成公开的、恒定大小为$O(\phi)$的群组验证状态 $\mathsf{VST} = \mathsf{BF}$。发行方将成员专属的辅助信息 $\mathsf{Aux}_j = { \{tag_j^i,\sigma_j^i, \pi_j^i\} }_{i=1}^E$ 安全地发送给证明者。证明者存储 $(\mathsf{sk}_j, \mathsf{Aux}_j, \mathsf{Used}_j, \mathsf{Available}_j)$ 以完成加入过程。

---

**算法3：$\mathsf{Sign}()$**

> $\mathsf{Sign}$ 在证明者需要于时间 $T$ 匿名证明其群组成员身份时运行。算法首先确认 $T$ 处于协议有效时间窗 $[T_s, T_e]$ 内。随后，计算当前时间 $T$ 对应的唯一实例索引 $i = \lceil (T - T_s) / \Delta_T \rceil$和该实例内的口令索引 $z = \lfloor (T - T_s - (i-1) \cdot \Delta T) / \Delta_e \rfloor$。若该实例索引 $i$ 不在证明者的可用实例集 $\mathsf{Available}_j$ 中，则算法中止，表明该实例已被使用或不可用；否则，证明者使用其私钥重构该实例的种子 $\mathsf{seed}_j^i = \mathsf{PRF}(\mathsf{sk}_j, \mathsf{ID}_j | i)$，并调用 $\mathsf{GTOTP.PwGen}$ 生成与时间 $T$ 绑定的一次性口令 $\mathsf{pw}_j^{i,z} \leftarrow \mathsf{GTOTP.PwGen}(\mathsf{seed}_j^i, T)$。证明者从辅助信息 $\mathsf{Aux}_j$ 中取出与该实例对应的预生成标签 $tag_j^i$ ,发行方签名$\sigma_j^i$和Merkle证明 $\pi_j^i$。在输出凭证前，算法更新本地状态，将实例 $i$ 从 $\mathsf{Available}_j$ 移至 $\mathsf{Used}_j$ 集合，确保其未来不会被重复使用。最终输出的匿名凭证为 $\sigma_T = (\mathsf{pw}_j^{i,z}, tag_j^i,\sigma_j^i, \pi_j^i, i, T)$。
>
> 值得注意的是，每个GTOTP实例在其生命周期 $\Delta T$ 内仅能用于生成一次凭证。若证明者需在同一时间窗口内多次认证，可通过调整系统参数 $\Delta T$ 缩短实例生命周期，从而增加实例数量以满足频繁认证需求。
>
> **算法4：$\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma_T)$**

> 验证者（Verifier）收到凭证 $\sigma_T = (\mathsf{pw}, tag,\sigma, \pi, i,T)$ 后，执行以下步骤验证其有效性：
>
> 1.  **时间有效性检查**：计算窗口索引$k = \lfloor (T_{\text{now}} - T_s) / \Delta_e \rfloor$,若$T \notin [T_s + k \cdot \Delta e, T_s + (k+1) \cdot \Delta e]$，返回0。以此确认 $T$ 处于当前有效的时间窗口内，防止重放攻击。
> 2.  标签签名验证：计算 $\mathsf{Sig.Verify}(\mathsf{ipk}, (tag, i), \sigma)$，确保标签的合法性与实例绑定的真实性，若不通过则直接返回0；
> 3.  **验证点重构**：计算实例索引 $i = \lceil (T - T_s) / \Delta T \rceil$，从口令 $\mathsf{pw}$ 推导出验证点 $\mathsf{vp}=\mathsf{GTOTP.GetVP}(\mathsf{pw})$，并计算其绑定形式 $\hat{\mathsf{vp}} = H(\mathsf{hk}, \mathsf{vp} \| tag\|\sigma \| i)$。
> 4.  **成员资格证明验证**：利用 Merkle 证明 $\pi$，从 $\hat{\mathsf{vp}}$ 重构出一个 Merkle 树根节点 $\mathsf{rt}’$。
> 5.  **群组资格验证**：查询布隆过滤器 $\mathsf{VST}$，检查 $\mathsf{rt}’$ 是否为一个已注册的合法根节点，若$\mathsf{BF.Query}(\mathsf{VST}, \mathsf{rt}') = 0$，返回0。
> 6.  **口令有效性验证**：调用 $\mathsf{GTOTP.Verify}$ 验证口令 $\mathsf{pw}$ 在时间 $T$ 的有效性。若$\mathsf{GTOTP.Verify}(\mathsf{pw}, T) = 0$，返回0
>
> 当且仅当所有检查均通过时，验证算法输出 $b=1$，表示凭证来自一个合法的匿名群组成员。
>
> **算法5：$\mathsf{Open}(\mathsf{isk}, \sigma_T)$**

> 在审计或法律要求等必要情况下，由可信发行方执行。算法输入为待追溯的凭证 $\sigma_T$ 和发行方私钥 $\mathsf{isk}$。发行方首先运行公开的 $\mathsf{Verify}$ 算法确认凭证的有效性。若验证失败，则输出 $\bot$ 。若凭证有效，发行方从中提取出标签 $tag$ 和实例索引 $i$，并在其本地安全存储的身份映射表 $\mathsf{IDTable}$ 中查找与该 $(tag, i)$ 对相关联的成员身份 $\mathsf{ID}_j$。若查找到匹配项，则输出 $\mathsf{ID}_j$，从而在保护日常匿名性的前提下实现了系统的可问责性。

> ### 设计 rationale 与安全属性
>
> 本方案的核心设计思想在于利用 GTOTP 提供高效、时间绑定的匿名令牌，并通过 Merkle 树和布隆过滤器将成员验证状态压缩为常数大小。**匿名性** 由以下机制共同保障：1) GTOTP 口令本身不包含身份信息；2) 验证点在构建群组状态前被随机置换，打破了与成员的直接关联；3) 布隆过滤器仅支持成员查询，不会泄露树根之间的结构关系。**不可伪造性** 建立在底层 GTOTP 方案、抗碰撞哈希函数和 Merkle 树的安全性之上。**可追溯性** 则由发行方通过签名机制和身份映射表来实现。**速率限制** 由实例一次性使用机制和时间窗口绑定自然实现。
>
> ### 效率分析
>
> 如表 1 所示，本方案在效率上具有显著优势。凭证生成仅涉及 PRF 和哈希运算，在实验环境中平均耗时约 4.12 微秒。验证过程虽然涉及 Merkle 证明验证（$O(\log(UE/\phi))$ 次哈希），但由于哈希运算极快，且 $\phi$ 的选取可以平衡树的高度，整体验证时间仍在毫秒级。最关键的是，验证者无需维护与成员数量 $U$ 或时间实例 $E$ 成比例的线性状态，仅需存储一个固定大小的布隆过滤器，这使本方案特别适用于大规模部署场景。
>
## 安全性分析

本节形式化证明 DAA-GTOTP 方案满足第 \ref{sec:security-definitions} 节中定义的安全属性。我们的证明依赖于底层密码学原语的安全性：伪随机函数 $F$ (PRF)、数字签名方案 $\mathsf{Sig}$ (EUF-CMA)、哈希函数 $H$ (抗碰撞和抗原像) 以及伪随机置换 $\Pi$ (PRP)。我们在随机预言机模型（ROM）下对方案进行分析。

### 可追溯性证明

**定理 1.** 若 $H$ 是抗碰撞且抗原像的，$\mathsf{Sig}$ 满足 EUF-CMA 安全性，且 $F$ 是安全的 PRF，则 DAA-GTOTP 满足可追溯性（定义 1）。

证明：

我们采用反证法。假设存在 PPT 敌手 $\mathcal{A}$ 能以不可忽略的优势赢得 $\mathbf{Exp}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$。我们构造一个模拟器 $\mathcal{B}$，利用 $\mathcal{A}$ 的能力来攻破底层的某个困难假设。

$\mathcal{B}$ 设置系统环境并模拟发行方（Issuer）。$\mathcal{B}$ 将签名方案 $\mathsf{Sig}$ 的挑战公钥 $\mathsf{pk}^*$ 嵌入到系统参数 $\mathsf{ipk}$ 中。$\mathcal{B}$ 通过维护内部列表来模拟预言机 $\mathcal{O}_{\mathsf{Join}}$、$\mathcal{O}_{\mathsf{Sign}}$ 和随机预言机。当 $\mathcal{A}$ 输出一个伪造凭证 $\sigma^* = (\mathsf{pw}^*, tag^*, \sigma_{iss}^*, \pi^*, i^*, T^*)$ 时，我们考虑三种互斥的情况：

1. **情况 1 (签名伪造)：** 对 $(tag^*, i^*)$ 的组合从未被 $\mathcal{B}$ 在任何 $\mathcal{O}_{\mathsf{Join}}$ 查询中签名过，但 $\sigma_{iss}^*$ 是 $\mathsf{pk}^*$ 下的有效签名。此时，$\mathcal{B}$ 输出 $((tag^*, i^*), \sigma_{iss}^*)$ 作为对 $\mathsf{Sig}$ 的有效伪造，从而攻破 EUF-CMA 安全性。
2. **情况 2 (哈希碰撞)：** $\sigma_{iss}^*$ 是 $\mathcal{B}$ 之前生成的某个 $(tag, i)$ 的有效签名，但 $tag^* \neq tag$。由于 $\mathsf{Verify}$ 检查绑定关系 $\hat{\mathsf{vp}} = H(\dots \| tag \| \dots)$，有效的验证意味着 $H$ 发生了碰撞。$\mathcal{B}$ 输出该碰撞，攻破 $H$ 的抗碰撞性。
3. **情况 3 (冒充诚实成员)：** $(tag^*, i^*)$ 对应于一个诚实成员 $\mathsf{ID}^*$（记录在 $\mathcal{B}$ 的表中），且 $\mathsf{ID}^*$ 未被腐化。要使 $\sigma^*$ 有效，$\mathsf{pw}^*$ 必须能通过基于 $\mathsf{ID}^*$ 种子派生的验证点的验证。由于 $\mathcal{A}$ 不知道 $\mathsf{sk}_{\mathsf{ID}^*}$，生成有效的 $\mathsf{pw}^*$ 需要区分 PRF 输出 $\mathsf{seed}_{\mathsf{ID}^*}^i$ 与随机值，或逆转哈希链。这攻破了 PRF 的安全性或 $H$ 的单向性。

由于所有情况都意味着攻破了标准的密码学假设，$\mathcal{A}$ 的优势必须是可忽略的。

### 匿名性证明

**定理 2.** 若 $\Pi$ 是安全的 PRP，$F$ 是安全的 PRF，且 $H$ 被建模为随机预言机，则 DAA-GTOTP 满足匿名性（定义 2）。

证明：

我们使用一系列混合游戏（Hybrid Games）$\mathbf{G}_0, \dots, \mathbf{G}_3$ 进行证明。令 $\Pr[\mathbf{G}_k]$ 表示 $\mathcal{A}$ 在游戏 $k$ 中获胜的概率。

- **游戏 $\mathbf{G}_0$：** 真实的匿名性游戏 $\mathbf{Exp}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$。
- **游戏 $\mathbf{G}_1$：** 与 $\mathbf{G}_0$ 相同，但在 Setup 阶段，用于混淆验证点的置换 $\pi(k_p, \cdot)$ 被替换为真随机置换。根据 PRP 假设，$|\Pr[\mathbf{G}_0] - \Pr[\mathbf{G}_1]| \leq \mathsf{Adv}_{\Pi}^{\mathsf{PRP}}(\lambda)$。
- **游戏 $\mathbf{G}_2$：** 在挑战阶段，我们将挑战凭证中的标签 $tag^*$ 替换为从 $\{0,1\}^\lambda$ 中均匀选取的随机字符串。由于 $tag^* = H(\mathsf{ID}_b \| i \| r)$ 包含随机数 $r$ 且 $H$ 是随机预言机，若 $\mathcal{A}$ 未查询过该特定输入，则分布是不可区分的。因此，$|\Pr[\mathbf{G}_1] - \Pr[\mathbf{G}_2]| \leq \mathsf{negl}(\lambda)$。
- **游戏 $\mathbf{G}_3$：** 我们将挑战中的一次性口令 $\mathsf{pw}^*$ 替换为随机字符串。由于 $\mathsf{pw}^*$ 派生自 $F(\mathsf{sk}_{\mathsf{ID}_b}, \cdot)$ 生成的种子，根据 $F$ 的 PRF 安全性，这是不可区分的。因此，$|\Pr[\mathbf{G}_2] - \Pr[\mathbf{G}_3]| \leq \mathsf{Adv}_{F}^{\mathsf{PRF}}(\lambda)$。

在 $\mathbf{G}_3$ 中，挑战凭证 $\sigma^*$ 完全由独立于比特 $b$ 的随机值组成。因此，$\mathcal{A}$ 在 $\mathbf{G}_3$ 中的优势正好为 0。累加各步骤的差异可知总优势是可忽略的。

### 不可关联性证明

**定理 3.** 在与定理 2 相同的假设下，DAA-GTOTP 满足不可关联性（定义 3）。

证明：

证明过程与匿名性证明类似。我们构造类似的混合游戏序列。

- 在 **游戏 $\mathbf{G}_0$** 中，$\mathcal{A}$ 收到真实凭证 $(\sigma_1, \sigma_2)$。

- 在 **游戏 $\mathbf{G}_1$** 中，验证状态的置换被理想化（PRP）。

- 在 **游戏 $\mathbf{G}_2$** 中，两个凭证中的标签 $tag_1, tag_2$ 被替换为独立的随机字符串（RO 模型）。

- 在 游戏 $\mathbf{G}_3$ 中，口令 $\mathsf{pw}_1, \mathsf{pw}_2$ 被替换为独立的随机字符串（PRF）。

  在 $\mathbf{G}_3$ 中，无论凭证对 $(\sigma_1, \sigma_2)$ 是来自同一个 $\mathsf{ID}$ 还是不同的 $\mathsf{ID}$，它们都由独立的随机值组成。因此，不可关联性的优势是可忽略的。

### 速率限制证明

**定理 4.** 若 $F$ 是安全的 PRF，则 DAA-GTOTP 满足速率限制（定义 4）。

证明：

速率限制属性通过时间片与协议实例之间的确定性映射强制执行。

1. **总量界限 ($E$)：** 在 $\mathsf{Join}$ 期间，成员被分发了正好 $E$ 个实例令牌。由于这些实例的种子是通过 $\mathsf{seed}^i = F(\mathsf{sk}, i)$ 派生的，敌手无法在不攻破 PRF 或伪造发行方对无效索引签名的情况下生成索引 $i > E$ 的有效种子。

2. 窗口唯一性： 函数 $i(T) = \lceil (T - T_s)/\Delta_T \rceil$ 将任意时间 $T$ 映射到唯一的实例索引 $i$。要为同一个窗口 $i$ 生成两个不同的凭证 $\sigma_a, \sigma_b$，敌手必须从同一个一次性实例种子生成两个有效的口令/标签。根据 GTOTP 的构造，一个种子对于特定时间只能生成一条有效的哈希链路径。在同一时间 $T$ 重用实例构成重放（被验证者检查阻止），而在同一窗口内的不同时间 $T_a, T_b$ 生成凭证需要相同的实例索引 $i$，这在诚实证明者逻辑中被标记为“已使用”。即使被腐化，实例令牌 $i$ 的数学唯一性防止了在不破坏底层认证标签绑定的情况下为槽位 $i$ 生成超过 1 个的独立有效凭证。

   因此，破坏速率限制的概率是可忽略的。

### 前向不可伪造性证明

**定理 5.** DAA-GTOTP 满足前向不可伪造性（定义 5）。

证明：

假设敌手 $\mathcal{A}$ 在时间 $t_{leak}$ 腐化 $\mathsf{ID}_j$ 并获得 $\mathsf{sk}_j$。$\mathcal{A}$ 试图伪造一个时间 $T^* < t_{leak}$ 的凭证 $\sigma^*$。

虽然 $\mathcal{A}$ 可以使用 $\mathsf{sk}_j$ 派生过去时间 $T^*$ 的正确种子 $\mathsf{seed}_{\mathsf{ID}_j}^{i^*}$，但 DAA-GTOTP 中凭证的有效性严格绑定于验证者的当前时间。

验证算法 $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma^*)$ 包含一个时间有效性检查：

$$\text{若 } T^* \notin [T_{now} - \delta, T_{now} + \delta], \text{ 返回 } 0.$$

由于 $T^* < t_{leak} \leq T_{now}$（假设攻击发生在泄露后），任何与当前时间同步的诚实验证者都会因过期而拒绝时间戳 $T^*$。$\mathcal{A}$ 无法将 $T^*$ 更新为当前时间 $T_{now}$，因为一次性口令 $\mathsf{pw}^*$ 通过 GTOTP 生成函数在密码学上绑定于 $T^*$。更改 $T^*$ 需要为 $T_{now}$ 生成新口令，这将构成对当前时间的有效签名（在腐化后是允许的），而不是对过去时间范围的伪造。

因此，$\mathcal{A}$ 无法生成被接受为过去时间 $T^*$ 的有效证明的凭证。

## 实验表现分析

### 理论效率分析

本节从理论层面对 DAA-GTOTP 协议的计算复杂度与存储开销进行渐进分析，论证其在大规模群组场景下的可扩展性。

#### 计算开销

我们将协议的计算开销分为初始化、凭证生成与验证三个关键阶段进行分析。

**初始化阶段**： 包含一次性离线操作：系统参数生成（$\mathsf{Setup}$）和成员加入（$\mathsf{Join}$）。$\mathsf{Setup}$ 算法生成加密密钥对、哈希函数密钥和置换密钥，计算实例总数 $E$，复杂度为 $O(1)$。$\mathsf{Join}$ 协议中，发行方为每个成员的 $E$ 个实例生成标签、签名，构建绑定验证点集合，并通过随机置换将其划分为 $\phi$ 个子集，为每个子集构建 Merkle 树，最后将所有 Merkle 树根插入 Bloom 过滤器形成公开验证状态 $\mathsf{VST}$。该阶段总时间复杂度为 $O(U \cdot E)$。

**凭证生成阶段**： 由证明者在需要认证时执行 $\mathsf{Sign}$ 算法。证明者生成凭证的过程仅涉及有限次数的哈希函数调用（用于 Merkle 路径检索）与 PRF 运算（用于 GTOTP 口令生成）。由于哈希路径长度 $h \approx \lceil \log_2(UE/\phi) \rceil$ 是由系统参数确定的常数，且不随单次认证请求变化，因此凭证生成的计算复杂度为 $O(1)$。

**验证阶段**： 验证者的核心任务是重构验证点并校验 Merkle 成员资格证明。该过程涉及 $h$ 次哈希运算以及 $k$ 次布隆过滤器哈希映射。因此，验证算法的时间复杂度为 $O(\log(UE/\phi))$。这意味着验证开销随系统规模（总实例数 $UE$）呈对数增长，而非线性增长，从而具备极佳的理论可扩展性。

#### 存储开销

本协议的另一核心优势在于其紧凑的存储开销。以下对各参与方在GTOTP-DAA方案中的存储复杂度进行建模与分析。

**凭证大小**：单个匿名凭证 $\sigma_T$ 由一次性口令 $\mathsf{pw}$、匿名标签 $tag$、发行方签名 $\sigma$、Merkle 成员资格证明 $\pi$、实例索引 $i$ 和时间戳 $T$ 构成。设 $s_{pw}$、$s_{tag}$、$s_{sig}$ 和 $s_{hash}$ 分别表示口令、标签、签名和哈希值的字节长度，$s_{meta}$ 为元数据（索引和时间戳）的字节开销。令 $h \approx \lceil \log_2 (UE/\phi) \rceil$ 为 Merkle 证明的路径长度,$s_{bool}$为证明中的方向信息的存储开销。凭证的原始大小可近似为：
$$
S_{\sigma}^{\text{raw}} \approx s_{pw} + s_{tag} + s_{sig} + h \cdot (s_{hash}+s_{bool}) + s_{meta}.
$$
凭证大小 $S_{\sigma}^{\text{raw}}$ 为 $\Theta(1)$ 常数级别，独立于系统总成员数 $U$ 和实例总数 $E$。这确保了通信开销的可预测性。

**验证状态（Verifier）**：验证者需维护公开的群组验证状态 $\mathsf{VST}$，这是一个存储了 $\phi$ 个 Merkle 树根的布隆过滤器。设目标误判率为 $\varepsilon$，待插入元素数 $n = \phi$，则布隆过滤器所需位数组大小 $m$ 及字节开销为：
$$
m = -\frac{n \ln \varepsilon}{(\ln 2)^2}, \quad S_{\mathsf{VST}}^{\text{bytes}} = \left\lceil \frac{m}{8} \right\rceil.
$$
其存储开销为 $O(\phi)$，与子集数量成线性关系，而与总成员数 $U$ 无关。这部分存储是恒定且微小的，使得验证者可以轻松部署于资源受限的边缘设备。

**Merkle 树（Issuer）**：发行方在初始化阶段为每个子集构建一棵 Merkle 树。设每个子集平均包含 $\ell = \lceil UE / \phi \rceil$ 个叶子节点（绑定验证点），则每棵树约有 $2\ell - 1$ 个节点。所有 $\phi$ 棵 Merkle 树的总节点数 $N_{\text{merkle}}$ 及总存储开销 $S_{\text{merkle}}$ 可近似为：
$$
N_{\text{merkle}} \approx 2UE - \phi, \quad S_{\text{merkle}} \approx (2UE - \phi) \cdot s_{hash}.
$$
该组件的规模随总实例数 $UE$ 线性增长 $O(UE)$。这是发行方的主要离线存储开销，但因其仅在系统初始化时计算一次，且通常由具备较强存储能力的后端服务器承担，故是可接受的。

**辅助信息（Attester）**：每个证明者 $\mathsf{ID}_j$ 需本地安全存储其辅助信息 $\mathsf{Aux}_j$，其中包含其全部 $E$ 个实例对应的三元组 $(tag_j^i, \sigma_j^i, \pi_j^i)$。单个证明者的辅助信息大小 $S_{\mathsf{aux}}^{\text{per}}$ 及系统总辅助信息大小 $S_{\mathsf{aux}}^{\text{total}}$ 为：
$$
S_{\mathsf{aux}}^{\text{per}} = E \cdot \left( s_{tag} + s_{sig} + h \cdot s_{hash} \right), \quad S_{\mathsf{aux}}^{\text{total}} = U \cdot S_{\mathsf{aux}}^{\text{per}}.
$$
显然，$S_{\mathsf{aux}}^{\text{total}} = \Theta(U \cdot E)$ 与系统总实例数呈线性关系，这是分布式存储开销的主要部分。

**身份映射表（Issuer）**：发行方还需安全存储本地身份映射表 $\mathsf{IDTable}$，记录每个 $(tag_j^i, i, \mathsf{ID}_j)$ 三元组以供追溯。其存储开销同样为 $O(U \cdot E)$，与总实例数线性相关，但这是可信发行方可承担的机密存储。

### 实验表现分析

为了全面评估 DAA-GTOTP 在实际部署中的效能，我们在配备 Intel Core i9 处理器与 16GB 内存的环境下（Ubuntu 22.04 LTS），对本方案进行了完整的原型实现与基准测试。为了建立具有说服力的性能基线，我们选取了三种基于双线性对（Bilinear Pairing）的代表性方案进行对比：作为工业界直接匿名证明标准的 **Intel EPID** 、基于短群签名的经典方案 **BBS04** 以及广泛应用于匿名凭证系统的 **CL04** 方案 。其中，Intel EPID 基于官方 C++ SDK 评测，BBS04 与 CL04 则基于 Charm-Crypto 框架实现；为确保比较的公平性与严谨性，我们对 BBS04 采用了 Boneh 等人提出的单次配对验证优化算法，并对 CL04 实现了标准的零知识证明验证流程。

为评估DAA-GTTOP的可扩展性，我们考虑成员规模 $U$ 为 4、100 与 200 三种场景，口令生成间隔 $\Delta_e = 5$ 秒，实例生命周期 $\Delta T = 5$ 分钟。所有性能数据均来自 1000 次独立测量的平均值。

#### 计算开销

计算效率是衡量认证协议在资源受限设备上可行性的核心指标。实验结果（详见图 X）显示，DAA-GTOTP 在签名生成与验证阶段均展现出相对于传统方案的数量级性能优势。具体而言，在初始化阶段，但得益于高效的哈希计算和并行化构建，实测在 $U=4$、$E=288$（对应 24 小时协议时长）的规模下，总初始化时间低于 0.5 秒。这显著优于传统基于双线性对的 DAA 方案，后者通常需要数秒甚至数分钟的初始化时间。

在签名生成阶段，Intel EPID 与 CL04 由于涉及复杂的群运算与零知识证明构造，其耗时分别高达 19.50 ms 与 8.50 ms；即便是结构相对精简的 BBS04 方案，其签名耗时仍需约 4.20 ms。相比之下，得益于底层全哈希（Hash-only）的轻量化设计，在典型设置下(U=100,E=288,$\phi$=8192)本方案的签名生成时间仅为  $46\mu s$，实现了约 90 至 400 倍的性能提升。这意味着在同等能耗预算下，物联网终端使用本方案可支持更高频次的认证请求。

在验证阶段，性能差异更为显著。传统方案的验证过程通常受限于昂贵的双线性对运算：Intel EPID 与 CL04 的验证耗时均超过 16 ms；即便是经过极致优化、仅需一次配对运算的 BBS04 方案，其验证耗时仍维持在 6.50 ms 左右。与之形成鲜明对比的是，DAA-GTOTP 利用高效的 Merkle 证明与布隆过滤器查询，将单次验证耗时压缩至 0.01 ms，比经过极致优化的 BBS04 快约 **40倍**，比 Intel EPID 快约 **120倍**。这种微秒级的验证能力使得网关设备在面对高并发接入请求时，能够以极低的 CPU 占用率完成合法性校验，从而有效缓解了由计算耗尽导致的拒绝服务（DoS）攻击风险。

#### 通信与存储开销

在通信开销方面，我们观察到明显的时空权衡（Space-Time Trade-off）特征。由于 BBS04 和 Intel EPID 依赖于椭圆曲线的代数结构，其生成的签名尺寸非常紧凑，分别仅为 380 字节与 569 字节。而本方案为了实现无配对运算的高效验证，生成的凭证需包含 Merkle 认证路径与一次性口令，导致凭证尺寸约为 564 字节。然而，在现代物联网架构中，这种权衡具有极高的实用价值：在典型的 Wi-Fi 或 5G 网络环境下，传输额外 0.6 KB 数据引入的延迟（微秒级）远小于方案在计算层面节省的数十毫秒时间。更重要的是，对于能量受限的传感器节点，无线发送 1KB 数据所需的能耗通常远低于 CPU 满载运行 20ms 进行复杂数学运算的能耗，因此本方案在系统整体能效上依然占据优势。

此外，本方案在可扩展性方面表现优异。与传统 DAA 方案验证状态随撤销成员数量线性增长不同，DAA-GTOTP 的验证者仅需维护一个大小恒定的布隆过滤器（约 58 KB，针对 $\phi=8192$ 规模），即可支持任意规模的群组成员验证。这种常数级的存储特性，结合微秒级的验证速度，证实了本方案在大规模、高动态的物联网场景中具有超越传统基于双线性对方案的实际部署潜力。