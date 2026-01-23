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

**图解**：
1.  **初始化阶段**：发行方运行 $\mathsf{Setup}$，生成系统全局参数。
2.  **加入阶段**：证明者与发行方通过交互式协议 $\mathsf{Join}$，安全地获得其成员密钥和凭证，其身份信息被发行方秘密关联存储。
3.  **认证阶段**：证明者使用其密钥对消息（或认证挑战）生成匿名签名 $\sigma$。验证者使用公开的 $\mathsf{Verify}$ 算法验证 $\sigma$ 的有效性，但无法获知其具体身份。
4.  **追溯阶段**：在发生争议或滥用时，授权方可将签名提交给发行方，后者运行 $\mathsf{Open}$ 算法，利用其秘密信息揭示签名者的身份。

一个安全的 DAA 方案需满足以下核心安全属性：
*   **匿名性与不可关联性**：对于验证者或任何外部攻击者，在多项式时间内，无法区分一个有效签名来自哪个诚实成员，也无法判断两个签名是否来自同一成员（除非使用 $\mathsf{Link}$ 算法且结果为真）。
*   **可追溯性**：任何能通过 $\mathsf{Verify}$ 的有效签名（即使在部分成员被腐化的协作下产生），只要发行方保持诚实，都能被 $\mathsf{Open}$ 算法成功追溯到其生成者。
*   **不可伪造性**：任何非群组成员都无法产生能通过验证的有效签名。

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

基于第4.3节所述的威胁模型，我们对GTOTP-DAA方案必须满足的核心安全属性进行形式化定义。每个属性均以安全游戏（security game）的形式给出，描述攻击者 $\mathcal{A}$ 与挑战者 $\mathcal{C}$ 之间的交互。

#### **可追溯性**

可追溯性确保任何有效凭证均能被可信发行方追溯到其生成者，即使攻击者腐化了部分群组成员。该安全游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$ 定义如下：

1. **初始化**：挑战者 $\mathcal{C}$ 运行 $\mathsf{Setup}(1^\lambda)$ 生成公共参数 $\mathsf{pp}$ 和发行方私钥 $\mathsf{isk}$。$\mathcal{C}$ 将 $\mathsf{pp}$ 发送给攻击者 $\mathcal{A}$，并秘密保存 $\mathsf{isk}$。$\mathcal{C}$ 初始化空的群组成员列表 $L_{\mathsf{honest}}$（诚实证明者）和 $L_{\mathsf{corrupt}}$（腐化证明者），以及空的凭证查询记录 $Q_{\mathsf{sign}}$。
2. **查询阶段**：$\mathcal{A}$ 可以自适应地进行以下查询：

   -  $\mathsf{Join}$ 查询：$\mathcal{A}$ 指定一个证明者身份 $\mathsf{ID}_j$。$\mathcal{C}$ 模拟 $\mathsf{Join}$ 协议，将 $\mathsf{ID}_j$ 加入 $L_{\mathsf{honest}}$，并为 $\mathcal{A}$ 模拟协议视图（但不泄露 $\mathsf{sk}_j$ 或 $\mathsf{Aux}_j$，除非后续被腐化）。
   -  $\mathsf{Corrupt}$ 查询：$\mathcal{A}$ 指定 $L_{\mathsf{honest}}$ 中的一个 $\mathsf{ID}_j$。$\mathcal{C}$ 将该证明者从 $L_{\mathsf{honest}}$ 移至 $L_{\mathsf{corrupt}}$，并将其完整内部状态 $(\mathsf{sk}_j, \mathsf{Aux}_j, \mathsf{Used}_j, \mathsf{Available}_j)$ 返回给 $\mathcal{A}$。
   -  $\mathsf{Sign}$ 查询：$\mathcal{A}$ 指定一个诚实证明者 $\mathsf{ID}_j \in L_{\mathsf{honest}}$ 和一个时间 $T$。$\mathcal{C}$ 运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_j, T)$ 生成凭证 $\sigma_T$，将 $(\mathsf{ID}_j, T, \sigma_T)$ 加入 $Q_{\mathsf{sign}}$，并将 $\sigma_T$ 返回给 $\mathcal{A}$。
   -  $\mathsf{Verify}$ 查询：$\mathcal{A}$ 提交一个凭证 $\sigma_T$，$\mathcal{C}$ 运行 $\mathsf{Verify}$ 并返回结果。
3. **伪造**：最终，$\mathcal{A}$ 输出一个凭证 $\sigma_T^* = (\mathsf{pw}^*, tag^*, \sigma^*, \pi^*, i^*, T^*)$。
4. **获胜条件**：$\mathcal{A}$ 赢得游戏，如果：

   - $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma_T^*) = 1$，即凭证有效；
   - 运行 $\mathsf{Open}(\mathsf{isk}, \sigma_T^*)$ 得到 $\mathsf{ID}^*$，但 $\mathsf{ID}^* \notin L_{\mathsf{corrupt}}$（即追溯到未腐化证明者），并且 $(\mathsf{ID}^*, T^*, \cdot) \notin Q_{\mathsf{sign}}$（即该证明者未在时间 $T^*$ 被查询过签名）；
   - 或者，$\mathsf{Open}(\mathsf{isk}, \sigma_T^*) = \bot$（追溯失败）。

定义1.可追溯性。GTOTP-DAA方案满足可追溯性，如果对于所有PPT攻击者 $\mathcal{A}$，其优势
$$
\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda) = \Pr\left[ \mathbf{Game}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda) = 1 \right] \leq \mathsf{negl}(\lambda).
$$

#### 匿名性

匿名性确保攻击者无法区分一个有效凭证是由两个诚实证明者中的哪一个生成的。该安全游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$ 定义如下：

1. 初始化：同 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$，$\mathcal{C}$ 生成 $(\mathsf{pp}, \mathsf{isk})$，发送 $\mathsf{pp}$ 给 $\mathcal{A}$。
2. 查询阶段：$\mathcal{A}$ 可以自适应地进行 $\mathsf{Join}$、$\mathsf{Corrupt}$、$\mathsf{Sign}$、$\mathsf{Verify}$ 查询，$\mathcal{C}$ 相应回应。$\mathcal{C}$ 维护列表 $L_{\mathsf{honest}}$、$L_{\mathsf{corrupt}}$ 和 $Q_{\mathsf{sign}}$。
3. 挑战：$\mathcal{A}$ 选择两个诚实证明者 $\mathsf{ID}_0, \mathsf{ID}_1 \in L_{\mathsf{honest}}$ 和一个时间 $T^*$，满足两个证明者的实例 $i^* = \lceil (T^* - T_s) / \Delta_T \rceil$ 均可用（即在 $\mathsf{Available}$ 集合中）。$\mathcal{C}$ 随机选择 $b \xleftarrow{\$} \{0,1\}$，运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_{\mathsf{ID}_b}, T^*)$ 生成挑战凭证 $\sigma_{T^*}^*$，并将其发送给 $\mathcal{A}$。$\mathcal{C}$ 将实例 $i^*$ 从 $\mathsf{ID}_b$ 的可用集合移至已用集合。
4. 查询阶段2：$\mathcal{A}$ 可以继续查询，但不能对 $\mathsf{ID}_0$ 或 $\mathsf{ID}_1$ 在实例 $i^*$ 上（即时间窗口 $[T_s + (i^*-1)\Delta_T, T_s + i^*\Delta_T)$ 内）进行 $\mathsf{Sign}$ 查询，也不能腐化 $\mathsf{ID}_0$ 或 $\mathsf{ID}_1$。
5. 猜测：$\mathcal{A}$ 输出一个猜测比特 $b'$。
6. 获胜条件：$\mathcal{A}$ 赢得游戏，如果 $b' = b$。

定义2.匿名性。GTOTP-DAA方案满足匿名性，如果对于所有PPT攻击者 $\mathcal{A}$，其优势

$$
\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda) = \left| \Pr\left[ \mathbf{Game}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda) = 1 \right] - \frac{1}{2} \right| \leq \mathsf{negl}(\lambda).
$$

#### 不可关联性

不可关联性确保攻击者无法判断两个有效凭证是否来自同一证明者。该安全游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Unlink}}(\lambda)$ 定义如下：

1. 初始化与查询阶段：同 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$。
2. 挑战：$\mathcal{A}$ 选择两个诚实证明者 $\mathsf{ID}_0, \mathsf{ID}_1 \in L_{\mathsf{honest}}$ 和两个时间 $T_0, T_1$，满足：
   - 对于 $a \in \{0,1\}$，证明者 $\mathsf{ID}_a$ 在时间 $T_a$ 对应的实例 $i_a$ 可用；
   - $T_0$ 和 $T_1$ 对应的实例 $i_0$ 和 $i_1$ 不同（$i_0 \neq i_1$）

     $\mathcal{C}$ 随机选择 $b \xleftarrow{\$} \{0,1\}$，然后：
     
     - 如果 $b=0$，$\mathcal{C}$ 运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_{\mathsf{ID}_0}, T_0)$ 得到 $\sigma_0$，运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_{\mathsf{ID}_1}, T_1)$ 得到 $\sigma_1$。
     - 如果 $b=1$，$\mathcal{C}$ 运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_{\mathsf{ID}_0}, T_1)$ 得到 $\sigma_0$，运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_{\mathsf{ID}_1}, T_0)$ 得到 $\sigma_1$。
     
     $\mathcal{C}$ 将 $(\sigma_0, \sigma_1)$ 发送给 $\mathcal{A}$。$\mathcal{C}$ 相应更新两个证明者的实例使用状态。

3. 查询阶段2：$\mathcal{A}$ 可以继续查询，但不能腐化 $\mathsf{ID}_0$ 或 $\mathsf{ID}_1$，也不能对这两个证明者在挑战实例 $i_0, i_1$ 上进行 $\mathsf{Sign}$ 查询。
4. 猜测：$\mathcal{A}$ 输出一个猜测比特 $b'$。
5. 获胜条件：$\mathcal{A}$ 赢得游戏，如果 $b' = b$。

定义3.不可关联性。GTOTP-DAA方案满足不可关联性，如果对于所有PPT攻击者 $\mathcal{A}$，其优势
$$
\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Unlink}}(\lambda) = \left| \Pr\left[ \mathbf{Game}_{\mathcal{A}}^{\mathsf{Unlink}}(\lambda) = 1 \right] - \frac{1}{2} \right| \leq \mathsf{negl}(\lambda).
$$

#### 速率限制

速率限制确保每个证明者在任意 $\Delta_T$ 时间窗口内最多生成一个有效凭证，且总凭证数不超过 $E$。该安全游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Rate}}(\lambda)$ 定义如下：

1. 初始化与查询阶段：同 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$。
2. 伪造：最终，$\mathcal{A}$ 输出一个证明者身份 $\mathsf{ID}^*$（可以是诚实或腐化的）和一个有效凭证集合 $\{\sigma_{T_k}\}_{k=1}^M$，其中每个 $\sigma_{T_k}$ 满足 $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma_{T_k}) = 1$，且根据 $\mathsf{Open}$ 算法（或 $\mathcal{A}$ 直接声明）这些凭证均由 $\mathsf{ID}^*$ 生成。
3. 获胜条件：$\mathcal{A}$ 赢得游戏，如果存在以下任一情况：
   1. $M > E$（超过实例总数限制）；
   2. 存在两个凭证 $\sigma_{T_a}, \sigma_{T_b}$ 满足 $|T_a - T_b| < \Delta_T$ 但使用了相同的实例索引 $i$（违反时间窗口唯一性）；
   3. 存在两个凭证 $\sigma_{T_a}, \sigma_{T_b}$ 满足 $|T_a - T_b| < \Delta_T$ 且 $T_a \neq T_b$，但它们的实例索引 $i_a = i_b$（即同一窗口内多次使用同一实例）。

定义4.速率限制。GTOTP-DAA方案满足速率限制，如果对于所有PPT攻击者 $\mathcal{A}$，其优势

$$
\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Rate}}(\lambda) = \Pr\left[ \mathbf{Game}_{\mathcal{A}}^{\mathsf{Rate}}(\lambda) = 1 \right] \leq \mathsf{negl}(\lambda).
$$

#### 抗重放性

抗重放攻击确保任何有效凭证只能在当前有效时间窗口内使用一次。该属性是速率限制的自然推论，但可单独形式化如下：

定义5.抗重放性。GTOTP-DAA方案满足抗重放攻击，如果对于任何PPT攻击者 $\mathcal{A}$，给定一个在时间 $T$ 生成的有效凭证 $\sigma_T$，$\mathcal{A}$ 无法在时间 $T'$ 使得 $\lceil (T' - T_s) / \Delta_T \rceil = \lceil (T - T_s) / \Delta_T \rceil$（即同一实例窗口内）成功使 $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma_T) = 1$，除非 $\mathcal{A}$ 重新生成凭证（即使用不同的 $T'$ 和对应的一次性口令）。形式化地，在 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Replay}}(\lambda)$ 中，$\mathcal{A}$ 在获得若干有效凭证后，输出一个时间 $T'$ 和一个凭证 $\sigma$，若 $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma) = 1$ 且 $\sigma$ 与之前某个凭证 $\sigma_T$ 在相同实例窗口但 $T' \neq T$，则 $\mathcal{A}$ 获胜。其优势应可忽略。

#### 前向安全性

前向安全性确保即使证明者的长期私钥 $\mathsf{sk}_j$ 在时间 $t_{\mathsf{leak}}$ 泄露，攻击者也无法：（1）生成在 $t_{\mathsf{leak}}$ 之前时间点的有效凭证；（2）将 $t_{\mathsf{leak}}$ 之前观察到的凭证与 $\mathsf{ID}_j$ 关联。该安全游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{FS}}(\lambda)$ 定义如下：

1. 初始化与查询阶段1：同 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$。
2. 挑战与泄露：$\mathcal{A}$ 选择一个诚实证明者 $\mathsf{ID}^* \in L_{\mathsf{honest}}$ 和一个时间 $T^* < t_{\mathsf{leak}}$（$t_{\mathsf{leak}}$ 由 $\mathcal{A}$ 在游戏后期指定）。$\mathcal{C}$ 运行 $\mathsf{Sign}(\mathsf{pp}, \mathsf{sk}_{\mathsf{ID}^*}, T^*)$ 生成挑战凭证 $\sigma_{T^*}^*$ 发送给 $\mathcal{A}$。随后，在时间 $t_{\mathsf{leak}}$，$\mathcal{A}$ 可以腐化 $\mathsf{ID}^*$，获得 $\mathsf{sk}_{\mathsf{ID}^*}$ 及当前状态。
3. 查询阶段2：$\mathcal{A}$ 可以继续查询，但不能对 $\mathsf{ID}^*$ 在 $T^*$ 对应实例进行 $\mathsf{Sign}$ 查询（已使用）。
4. 伪造与关联：$\mathcal{A}$ 输出一个比特 $b'$（试图猜测 $\sigma_{T^*}^*$ 是否属于 $\mathsf{ID}^*$）或输出一个在时间 $T' < t_{\mathsf{leak}}$ 的凭证 $\sigma_{T'}$。
5. 获胜条件：$\mathcal{A}$ 赢得游戏，如果：
   1. $b'$ 正确指出了 $\sigma_{T^*}^*$ 是否由 $\mathsf{ID}^*$ 生成（关联性攻击成功）；
   2. $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma_{T'}) = 1$ 且 $\mathsf{Open}(\mathsf{isk}, \sigma_{T'}) = \mathsf{ID}^*$，但 $T' \neq T^*$ 且 $(\mathsf{ID}^*, T', \cdot) \notin Q_{\mathsf{sign}}$（伪造过去时间点的凭证）。

定义6.前向安全性。GTOTP-DAA方案满足前向安全性，如果对于所有PPT攻击者 $\mathcal{A}$，其优势

$$
\mathsf{Adv}_{\mathcal{A}}^{\mathsf{FS}}(\lambda) = \Pr\left[ \mathbf{Game}_{\mathcal{A}}^{\mathsf{FS}}(\lambda) = 1 \right] \leq \mathsf{negl}(\lambda).
$$

上述定义共同构成了GTOTP-DAA方案完整的安全属性框架。后续的安全证明将基于这些游戏展开，将方案的安全性归约到第3.2.1节的密码学假设上。

### 简化的安全定义

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

#### 3. 不可关联性 (Unlinkability)

不可关联性要求攻击者无法判断两个不同的凭证是来自同一个成员还是两个不同的成员。

**定义 3 (Unlinkability)**. DAA-GTOTP 方案满足不可关联性，若对于任意 PPT 攻击者 $\mathcal{A}$，其优势 $\mathsf{Adv}_{\mathcal{A}}^{\mathsf{Unlink}}(\lambda)$ 是可忽略的。

游戏设置与匿名性类似，区别在于挑战阶段：$\mathcal{A}$ 选择两个时间点 $T_1, T_2$。$\mathcal{C}$ 随机选择 $b \in \{0,1\}$。

- 若 $b=0$，$\mathcal{C}$ 生成同一成员 $\mathsf{ID}$ 的两个凭证 $(\sigma_{T_1}, \sigma_{T_2})$。

- 若 $b=1$，$\mathcal{C}$ 生成两个不同成员 $\mathsf{ID}_a, \mathsf{ID}_b$ 的凭证 $(\sigma_{T_1}, \sigma_{T_2})$。

  $\mathcal{A}$ 需猜测 $b$ 的值。

#### 4. 速率限制 (Rate-Limiting)

速率限制是 GTOTP 的特有属性，涵盖了**抗重放性**。它要求成员在任意时间窗口 $\Delta_T$ 内最多生成一个有效凭证，且总凭证数不超过 $E$。

**定义 4 (Rate-Limiting).** DAA-GTOTP 方案满足速率限制，若不存在 PPT 攻击者 $\mathcal{A}$ 能够输出一个成员身份 $\mathsf{ID}^*$（诚实或腐化皆可）及一组有效凭证 $\Sigma = \{\sigma_1, \dots, \sigma_k\}$，使得 $\Sigma$ 满足以下任一条件：

1. **总量溢出**：$k > E$；
2. **窗口冲突**：存在 $\sigma_a, \sigma_b \in \Sigma$ 且 $a \neq b$，它们对应的时间戳 $T_a, T_b$ 映射到同一个实例索引 $i = \lceil (T - T_s)/\Delta_T \rceil$（包含 $T_a=T_b$ 的重放情况）。

#### 5. 前向不可伪造性 (Forward Unforgeability)

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
## 理论与实验分析

### 安全性分析


本节将对GTOTP-DAA方案进行严格的形式化安全性分析。我们将证明该方案满足第~\ref{sec:security-definitions} 节中定义的所有核心安全属性。每个属性的证明均通过归约（reduction）到第~\ref{sec:assumptions} 节中列出的密码学假设。

\subsection{可追溯性（Traceability）证明}

\textbf{定理 1.} 在随机预言机模型（ROM）下，假设哈希函数 $H$ 具有抗碰撞性和原像抵抗性，数字签名方案 $\mathsf{Sig}$ 满足 EUF-CMA 安全性，伪随机函数 $F$ 是安全的，则 GTOTP-DAA 方案满足可追溯性。

\begin{proof}
我们通过反证法证明。假设存在一个 PPT 攻击者 $\mathcal{A}$ 能够以不可忽略的优势 $\epsilon$ 赢得可追溯性游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$。我们将构造一个模拟器 $\mathcal{B}$，利用 $\mathcal{A}$ 的能力来攻破底层密码学假设之一。

$\mathcal{B}$ 的构造如下：

\begin{enumerate}
    \item $\mathcal{B}$ 接收到数字签名方案 $\mathsf{Sig}$ 的挑战公钥 $\mathsf{pk}^*$（对应于 EUF-CMA 游戏中的挑战者）。
    \item $\mathcal{B}$ 运行 $\mathsf{Setup}$ 算法，但使用 $\mathsf{pk}^*$ 作为发行方的公钥 $\mathsf{ipk}$。这意味着 $\mathcal{B}$ 不知道对应的私钥 $\mathsf{isk}$（即 EUF-CMA 挑战中的签名私钥）。
    \item $\mathcal{B}$ 模拟随机预言机 $H$ 和所有其他算法，维护相应的列表以保持一致性。
    \item 当 $\mathcal{A}$ 进行 $\mathsf{Join}$ 查询时，$\mathcal{B}$ 模拟证明者和发行方之间的交互。对于每个实例 $i$，$\mathcal{B}$ 生成 $tag_j^i$ 和签名 $\sigma_j^i$ 时，向自己的签名预言机查询 $(tag_j^i, i)$ 的签名，并将结果作为 $\sigma_j^i$。同时，$\mathcal{B}$ 在本地记录映射关系。
    \item 当 $\mathcal{A}$ 进行 $\mathsf{Corrupt}$ 查询时，$\mathcal{B}$ 返回对应证明者的所有状态（这些状态是 $\mathcal{B}$ 在模拟加入协议时生成的）。
    \item 当 $\mathcal{A}$ 进行 $\mathsf{Sign}$ 和 $\mathsf{Verify}$ 查询时，$\mathcal{B}$ 可以完美模拟，因为它知道所有秘密状态（除了签名私钥，但签名可以通过查询签名预言机获得）。
    \item 最终，$\mathcal{A}$ 输出一个伪造的凭证 $\sigma_T^* = (\mathsf{pw}^*, tag^*, \sigma^*, \pi^*, i^*, T^*)$，满足游戏获胜条件。
\end{enumerate}

我们分析 $\mathcal{A}$ 成功伪造的几种情况：

\begin{enumerate}
    \item \textbf{情况 1：} $\sigma_T^*$ 中的签名 $\sigma^*$ 是一个对 $(tag^*, i^*)$ 的有效签名，但 $(tag^*, i^*)$ 从未被 $\mathcal{B}$ 的签名预言机签名过。那么 $\mathcal{B}$ 可以输出 $(tag^*, i^*)$ 和 $\sigma^*$ 作为对数字签名方案 $\mathsf{Sig}$ 的伪造，从而攻破 EUF-CMA 安全性。
    \item \textbf{情况 2：} $\sigma_T^*$ 中的签名 $\sigma^*$ 是对某个已签名过的 $(tag, i)$ 的签名，但 $tag^*$ 与 $tag$ 不同。由于签名验证通过，且签名方案是确定性的，这不可能发生（除非发生哈希碰撞）。若发生，则 $\mathcal{B}$ 可找到哈希碰撞。
    \item \textbf{情况 3：} $\sigma_T^*$ 中的 $tag^*$ 和 $i^*$ 与某个已签名的对相同，但 $\mathsf{Open}$ 算法追溯到的身份 $\mathsf{ID}^*$ 未被腐化，且该证明者未在 $T^*$ 被查询过签名。这进一步分为两种情况：
    \begin{itemize}
        \item $tag^*$ 不在 $\mathcal{B}$ 维护的映射表中。但根据方案，每个合法标签都是由发行方在加入协议中生成的，并存储在 $\mathsf{IDTable}$ 中。因此，这要么是哈希原像攻击（如果 $tag^*$ 对应某个 $H(\mathsf{ID}_j \| i \| r)$ 但 $(\mathsf{ID}_j, i, r)$ 未知），要么是 $\mathcal{B}$ 模拟错误。
        \item $tag^*$ 在映射表中，但对应的证明者 $\mathsf{ID}^*$ 未被腐化且未在 $T^*$ 被查询。然而，凭证中的 $\mathsf{pw}^*$ 必须是由 $\mathsf{ID}^*$ 的种子生成的正确一次性口令，否则验证将失败。由于 $\mathsf{ID}^*$ 未被腐化，其种子 $\mathsf{seed}_j^i$ 对 $\mathcal{A}$ 是未知的。$\mathcal{A}$ 能够生成正确的 $\mathsf{pw}^*$ 意味着它攻破了 GTOTP 的口令生成机制，这归约到 PRF 的安全性（种子是 PRF 的输出）或哈希函数的原像抵抗性（如果口令生成涉及哈希）。
    \end{itemize}
\end{enumerate}

因此，$\mathcal{A}$ 的成功必然导致 $\mathcal{B}$ 攻破数字签名、哈希函数或 PRF 的安全性之一。这与我们的假设矛盾，故方案满足可追溯性。
\end{proof}

\subsection{匿名性（Anonymity）证明}

\textbf{定理 2.} 在随机预言机模型（ROM）下，假设伪随机置换 $\Pi$ 是安全的，伪随机函数 $F$ 是安全的，哈希函数 $H$ 被建模为随机预言机，则 GTOTP-DAA 方案满足匿名性。

\begin{proof}
我们通过一系列混合游戏（hybrid games）来证明。假设 $\mathcal{A}$ 是一个能够以优势 $\epsilon$ 区分两个诚实证明者的 PPT 攻击者。

\begin{itemize}
    \item \textbf{Game 0:} 原始的匿名性游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$。
    \item \textbf{Game 1:} 与 Game 0 相同，只是在挑战阶段，挑战者不使用真实的置换 $\pi(k_p, \cdot)$ 来划分验证点子集，而是使用一个真正的随机置换。由于 $\pi$ 被建模为伪随机置换（PRP），任何能够区分 Game 0 和 Game 1 的敌手都可以用来攻破 PRP 安全性。因此，$|\Pr[\text{Game 1}] - \Pr[\text{Game 0}]| \leq \mathsf{negl}_1(\lambda)$。
    \item \textbf{Game 2:} 在 Game 1 中，验证点子集的划分已经是随机的。现在，我们修改挑战凭证的生成：在挑战阶段，挑战凭证中的标签 $tag^*$ 被替换为一个随机字符串（来自与标签相同分布的均匀随机串）。由于标签由 $H(\mathsf{ID}_b \| i^* \| r)$ 计算，且 $H$ 是随机预言机，而 $r$ 是随机的，只要敌手未查询过 $H$ 在这个输入上的值，标签就是随机的。任何能够区分 Game 2 和 Game 1 的敌手都可以用来寻找哈希原像或攻破 PRF（因为 $\mathsf{ID}_b$ 和 $i^*$ 可能被用于其他查询）。因此，$|\Pr[\text{Game 2}] - \Pr[\text{Game 1}]| \leq \mathsf{negl}_2(\lambda)$。
    \item \textbf{Game 3:} 在 Game 2 中，标签已经是随机的。现在，我们修改挑战凭证中的一次性口令 $\mathsf{pw}^*$，用一个来自相同分布但独立随机的字符串代替。由于口令是由 $\mathsf{GTOTP.PwGen}$ 生成的，其安全性依赖于 PRF 和哈希函数。任何能够区分 Game 3 和 Game 2 的敌手都可以用来攻破 PRF 的安全性（因为种子 $\mathsf{seed}_j^i$ 是 PRF 的输出）或随机预言机的性质。因此，$|\Pr[\text{Game 3}] - \Pr[\text{Game 2}]| \leq \mathsf{negl}_3(\lambda)$。
\end{itemize}

在 Game 3 中，挑战凭证的所有组件（标签、签名、口令、Merkle证明）要么是随机的，要么与挑战比特 $b$ 无关。因此，敌手在 Game 3 中的优势为 0。通过混合引理，敌手在原始游戏中的优势 $\epsilon \leq \mathsf{negl}_1 + \mathsf{negl}_2 + \mathsf{negl}_3$，即可忽略。因此，方案满足匿名性。
\end{proof}

\subsection{不可关联性（Unlinkability）证明}

\textbf{定理 3.} 在随机预言机模型（ROM）下，假设伪随机置换 $\Pi$ 是安全的，伪随机函数 $F$ 是安全的，哈希函数 $H$ 被建模为随机预言机，则 GTOTP-DAA 方案满足不可关联性。

\begin{proof}
不可关联性的证明与匿名性证明类似，因为两个凭证之间的关联性本质上要求敌手能够判断它们是否来自同一个证明者。我们同样通过混合游戏来证明。

考虑不可关联性游戏 $\mathbf{Game}_{\mathcal{A}}^{\mathsf{Unlink}}(\lambda)$。我们构建一系列混合游戏，逐步将挑战凭证对替换为独立随机的组件。

\begin{itemize}
    \item \textbf{Game 0:} 原始游戏。
    \item \textbf{Game 1:} 将置换 $\pi(k_p, \cdot)$ 替换为真正的随机置换。由 PRP 安全性，敌手无法区分。
    \item \textbf{Game 2:} 将两个挑战凭证中的标签 $tag_0, tag_1$ 替换为两个独立的随机字符串。由随机预言机和 PRF 安全性，敌手无法区分。
    \item \textbf{Game 3:} 将两个挑战凭证中的一次性口令 $\mathsf{pw}_0, \mathsf{pw}_1$ 替换为独立的随机字符串。由 PRF 和随机预言机，敌手无法区分。
\end{itemize}

在 Game 3 中，两个挑战凭证的标签和口令都是独立随机的，因此它们不包含任何关于生成者的信息。敌手无法判断它们是否来自同一证明者，优势为 0。通过混合引理，敌手在原始游戏中的优势可忽略。
\end{proof}

\subsection{速率限制（Rate Limiting）证明}

\textbf{定理 4.} 在伪随机函数 $F$ 是安全的假设下，GTOTP-DAA 方案满足速率限制。

\begin{proof}
速率限制属性直接由方案的设计保证，特别是实例的一次性使用机制和实例总数限制。我们分析攻击者可能突破速率限制的几种方式：

\begin{enumerate}
    \item \textbf{超过实例总数 $E$：} 每个证明者在加入时被分配 $E$ 个实例，每个实例只能用于生成一个凭证（使用后即标记为已用）。由于实例种子由 PRF 生成，攻击者无法在不知道证明者私钥的情况下生成额外的实例。即使攻击者腐化了证明者并获取其私钥，它也只能使用这 $E$ 个实例，因为实例总数在系统建立时固定。因此，任何证明者生成的凭证数不超过 $E$。
    \item \textbf{在同一时间窗口 $\Delta_T$ 内生成多个凭证：} 每个时间窗口对应一个唯一的实例索引 $i$。在签名算法中，证明者使用当前时间 $T$ 计算出实例索引 $i$，并检查该实例是否可用。如果可用，则使用该实例生成凭证，并将该实例标记为已用。因此，同一实例不能再次使用。由于一个时间窗口只对应一个实例，所以在同一时间窗口内无法生成两个凭证（除非使用不同的实例，但同一时间窗口只对应一个实例索引）。因此，每个证明者在任意 $\Delta_T$ 时间窗口内最多生成一个凭证。
    \item \textbf{在稍有不同的时间点但间隔小于 $\Delta_T$ 生成多个凭证：} 若两个时间点 $T_a$ 和 $T_b$ 满足 $|T_a - T_b| < \Delta_T$，则它们可能属于同一个实例窗口（如果 $T_a$ 和 $T_b$ 在同一个窗口内），或者属于相邻窗口。如果属于同一个窗口，则如上所述，只能生成一个凭证。如果属于相邻窗口，则对应不同的实例，可以生成两个凭证。但这并不违反速率限制，因为速率限制只要求同一窗口内最多一个凭证，而对不同窗口没有限制。并且，由于实例不同，生成的凭证自然使用不同的实例索引，满足定义。
\end{enumerate}

因此，任何 PPT 攻击者都无法以不可忽略的概率突破速率限制。速率限制的安全性依赖于 PRF 的安全性，因为实例种子由 PRF 生成，攻击者无法伪造或预测未腐化证明者的实例种子。
\end{proof}

\subsection{抗重放攻击（Resistance to Replay Attacks）证明}

\textbf{定理 5.} GTOTP-DAA 方案满足抗重放攻击。

\begin{proof}
抗重放攻击是速率限制的直接推论。方案中每个凭证与一个特定的时间 $T$ 绑定，并且验证者会检查 $T$ 是否在当前有效的时间窗口内。由于时间窗口是不断向前推进的，过去的凭证无法通过验证，因为其时间 $T$ 不在当前窗口内。

具体而言，验证算法中的时间有效性检查（步骤1）确保只有当前时间窗口内的凭证才被接受。攻击者试图重放一个过去有效的凭证时，该凭证的时间 $T$ 将不在当前窗口内，因此验证失败。

此外，即使攻击者在同一时间窗口内重放刚刚窃听到的凭证，由于该凭证已经被使用（可能已经被验证者记录），验证者可以通过记录已使用凭证的标签或哈希来拒绝重复的验证请求。但即使没有这种记录，方案本身也不能防止同一凭证在同一窗口内被验证多次（尽管这通常被认为是一种重放）。然而，我们的速率限制属性保证了同一证明者无法在同一窗口内生成两个凭证，但攻击者可能重放同一个凭证多次。若要防止这种重放，验证者需要维护已验证凭证的短期状态（例如，在一个时间窗口内记录所有验证过的标签）。但这不是方案本身的安全属性，而是部署时的策略。因此，我们主要关注的是跨时间窗口的重放攻击，这由时间窗口机制有效防止。
\end{proof}

\subsection{前向安全性（Forward Secrecy）证明}

\textbf{定理 6.} 在伪随机函数 $F$ 是安全的，且哈希函数 $H$ 具有原像抵抗性的假设下，GTOTP-DAA 方案满足前向安全性。

\begin{proof}
前向安全性要求即使证明者的长期私钥 $\mathsf{sk}_j$ 在时间 $t_{\mathsf{leak}}$ 泄露，攻击者也无法生成 $t_{\mathsf{leak}}$ 之前的有效凭证，也无法将之前观察到的凭证与证明者关联。

\begin{enumerate}
    \item \textbf{无法生成过去的凭证：} 对于时间 $T < t_{\mathsf{leak}}$，生成有效凭证需要知道对应实例的一次性口令 $\mathsf{pw}_j^{i,z}$，而该口令由实例种子 $\mathsf{seed}_j^i = \mathsf{PRF}(\mathsf{sk}_j, \mathsf{ID}_j \| i)$ 生成。虽然攻击者在泄露后获得了 $\mathsf{sk}_j$，但过去的口令已经过期（不在当前时间窗口），并且攻击者无法改变时间。但是，如果攻击者想要伪造一个过去时间 $T$ 的凭证，它需要生成该时间对应的口令。由于 PRF 是确定性的，攻击者可以用 $\mathsf{sk}_j$ 计算种子，然后生成口令。然而，这要求攻击者知道 $\mathsf{ID}_j$（通常公开）和实例索引 $i$。但是，即使攻击者可以生成过去的口令，这个凭证的时间 $T$ 已经不在当前有效窗口，因此无法通过验证。也就是说，攻击者可以生成一个“有效”的凭证，但它只在过去的时间有效，而现在验证不会通过。因此，攻击者无法生成现在有效的过去凭证。此外，如果攻击者试图将一个过去观察到的凭证与 $\mathsf{ID}_j$ 关联，它需要能够从凭证中提取出标签 $tag_j^i$ 并映射到 $\mathsf{ID}_j$，但这需要发行方的映射表 $\mathsf{IDTable}$ 或能够从标签反推身份。标签是 $H(\mathsf{ID}_j \| i \| r)$，在随机预言机模型下，不知道 $r$ 的情况下无法恢复 $\mathsf{ID}_j$。即使知道 $\mathsf{sk}_j$，攻击者也无法恢复 $r$，因为 $r$ 是在加入协议中由发行方生成的随机数，并未包含在 $\mathsf{sk}_j$ 中。因此，泄露 $\mathsf{sk}_j$ 不会帮助攻击者将过去的凭证与身份关联。
    \item \textbf{无法关联过去的凭证：} 假设攻击者在泄露前观察到某个凭证 $\sigma_T$，泄露后获得了 $\mathsf{sk}_j$。攻击者想要判断 $\sigma_T$ 是否属于 $\mathsf{ID}_j$。由于凭证中的标签 $tag$ 是 $H(\mathsf{ID}_j \| i \| r)$，攻击者可以尝试计算所有可能的 $i$ 和 $r$ 来验证是否等于 $tag$，但这需要知道 $r$，而 $r$ 是保密的。攻击者也可以尝试使用 $\mathsf{sk}_j$ 计算种子，然后生成口令并与凭证中的口令比较。但凭证中的口令是一次性的，且与时间 $T$ 绑定。攻击者可以计算 $\mathsf{seed}_j^i$ 和 $\mathsf{pw}_j^{i,z}$，如果匹配，则关联成功。但是，这要求攻击者知道 $i$ 和 $z$（即实例索引和口令索引），这些可以从凭证中的 $i$ 和 $T$ 得到。因此，攻击者确实可以验证一个已知凭证是否由 $\mathsf{ID}_j$ 生成，如果攻击者拥有该凭证的全部信息（包括 $i, T$）。然而，在前向安全性游戏中，挑战凭证 $\sigma_{T^*}^*$ 是在泄露前生成的，攻击者需要判断它是否属于 $\mathsf{ID}^*$。如果攻击者获得了 $\mathsf{sk}_{\mathsf{ID}^*}$，它就可以如上述方法进行验证。因此，我们的方案似乎不满足传统的“前向匿名性”（即密钥泄露后仍保持匿名）。但是，请注意，我们的前向安全性定义（定义6）包含了关联性攻击：攻击者输出一个比特猜测 $\sigma_{T^*}^*$ 是否属于 $\mathsf{ID}^*$。如果攻击者通过泄露的私钥可以验证，那么它就能以优势 1 赢得游戏。因此，我们需要重新审视前向安全性的定义。

    实际上，在许多群签名和DAA方案中，前向安全性通常指的是“后向匿名性”（backward anonymity），即成员密钥泄露不会影响泄露前生成的签名的匿名性。但在我们的定义中，我们要求即使密钥泄露，攻击者也不能将之前的签名与身份关联。这通常需要每个签名使用临时密钥（ephemeral key），并且临时密钥与长期密钥无关。在我们的方案中，每个实例的种子是由长期密钥通过 PRF 生成的，因此一旦长期密钥泄露，所有实例的种子都可能被推导出来，从而可能关联过去的签名。因此，严格来说，我们的方案不满足传统意义上的前向匿名性。
    
    然而，我们注意到，在我们的方案中，即使攻击者知道了 $\mathsf{sk}_j$，要关联一个过去的凭证，它还需要知道该凭证对应哪个实例 $i$。凭证中包含 $i$，所以攻击者确实可以关联。但是，如果攻击者没有保留过去凭证的 $i$，它可能无法关联。此外，我们的前向安全性定义中还包括了“无法生成过去时间点的有效凭证”，这部分仍然是满足的，因为即使生成了，也无法通过当前验证。
    
    因此，我们需要修正前向安全性的定义或结论。一个更合理的主张是：我们的方案在长期私钥泄露后，不会影响过去凭证的不可伪造性（即攻击者无法伪造过去时间点的有效凭证），但可能会影响匿名性（因为攻击者可以通过计算验证过去凭证是否由某个泄露密钥的证明者生成）。为了获得完整的前向匿名性，我们需要修改方案，使实例种子与长期密钥无关，例如每个实例使用独立的随机种子，并在加入时用发行方的公钥加密传输。但这会增加开销。
    
    鉴于上述分析，我们调整定理6的陈述：GTOTP-DAA方案满足前向安全性中的不可伪造性部分，但不保证密钥泄露后的匿名性。如果希望获得完整的前向安全性，需要对方案进行增强，但这超出了本文的范围。
\end{enumerate}

因此，我们得出结论：在现有方案下，长期私钥的泄露不会导致过去凭证被伪造（因为即使伪造了也无法通过当前验证），但可能会影响过去凭证的匿名性。我们将其作为一个开放问题，留待未来工作。
\end{proof}

\subsection{总结}
综上所述，GTOTP-DAA方案在标准密码学假设下满足可追溯性、匿名性、不可关联性、速率限制和抗重放攻击。对于前向安全性，方案提供了部分保障（防止伪造过去凭证），但在密钥泄露后可能无法维持过去凭证的匿名性。在实际部署中，如果前向匿名性至关重要，建议采用增强方案，例如定期更新成员密钥或使用前向安全的密钥演化机制。

### 安全性分析简化

本节形式化证明 DAA-GTOTP 方案满足第 \ref{sec:security-definitions} 节中定义的安全属性。我们的证明依赖于底层密码学原语的安全性：伪随机函数 $F$ (PRF)、数字签名方案 $\mathsf{Sig}$ (EUF-CMA)、哈希函数 $H$ (抗碰撞和抗原像) 以及伪随机置换 $\Pi$ (PRP)。我们在随机预言机模型（ROM）下对方案进行分析。

#### 可追溯性证明

**定理 1.** 若 $H$ 是抗碰撞且抗原像的，$\mathsf{Sig}$ 满足 EUF-CMA 安全性，且 $F$ 是安全的 PRF，则 DAA-GTOTP 满足可追溯性（定义 1）。

证明：

我们采用反证法。假设存在 PPT 敌手 $\mathcal{A}$ 能以不可忽略的优势赢得 $\mathbf{Exp}_{\mathcal{A}}^{\mathsf{Trace}}(\lambda)$。我们构造一个模拟器 $\mathcal{B}$，利用 $\mathcal{A}$ 的能力来攻破底层的某个困难假设。

$\mathcal{B}$ 设置系统环境并模拟发行方（Issuer）。$\mathcal{B}$ 将签名方案 $\mathsf{Sig}$ 的挑战公钥 $\mathsf{pk}^*$ 嵌入到系统参数 $\mathsf{ipk}$ 中。$\mathcal{B}$ 通过维护内部列表来模拟预言机 $\mathcal{O}_{\mathsf{Join}}$、$\mathcal{O}_{\mathsf{Sign}}$ 和随机预言机。当 $\mathcal{A}$ 输出一个伪造凭证 $\sigma^* = (\mathsf{pw}^*, tag^*, \sigma_{iss}^*, \pi^*, i^*, T^*)$ 时，我们考虑三种互斥的情况：

1. **情况 1 (签名伪造)：** 对 $(tag^*, i^*)$ 的组合从未被 $\mathcal{B}$ 在任何 $\mathcal{O}_{\mathsf{Join}}$ 查询中签名过，但 $\sigma_{iss}^*$ 是 $\mathsf{pk}^*$ 下的有效签名。此时，$\mathcal{B}$ 输出 $((tag^*, i^*), \sigma_{iss}^*)$ 作为对 $\mathsf{Sig}$ 的有效伪造，从而攻破 EUF-CMA 安全性。
2. **情况 2 (哈希碰撞)：** $\sigma_{iss}^*$ 是 $\mathcal{B}$ 之前生成的某个 $(tag, i)$ 的有效签名，但 $tag^* \neq tag$。由于 $\mathsf{Verify}$ 检查绑定关系 $\hat{\mathsf{vp}} = H(\dots \| tag \| \dots)$，有效的验证意味着 $H$ 发生了碰撞。$\mathcal{B}$ 输出该碰撞，攻破 $H$ 的抗碰撞性。
3. **情况 3 (冒充诚实成员)：** $(tag^*, i^*)$ 对应于一个诚实成员 $\mathsf{ID}^*$（记录在 $\mathcal{B}$ 的表中），且 $\mathsf{ID}^*$ 未被腐化。要使 $\sigma^*$ 有效，$\mathsf{pw}^*$ 必须能通过基于 $\mathsf{ID}^*$ 种子派生的验证点的验证。由于 $\mathcal{A}$ 不知道 $\mathsf{sk}_{\mathsf{ID}^*}$，生成有效的 $\mathsf{pw}^*$ 需要区分 PRF 输出 $\mathsf{seed}_{\mathsf{ID}^*}^i$ 与随机值，或逆转哈希链。这攻破了 PRF 的安全性或 $H$ 的单向性。

由于所有情况都意味着攻破了标准的密码学假设，$\mathcal{A}$ 的优势必须是可忽略的。

#### 匿名性证明

**定理 2.** 若 $\Pi$ 是安全的 PRP，$F$ 是安全的 PRF，且 $H$ 被建模为随机预言机，则 DAA-GTOTP 满足匿名性（定义 2）。

证明：

我们使用一系列混合游戏（Hybrid Games）$\mathbf{G}_0, \dots, \mathbf{G}_3$ 进行证明。令 $\Pr[\mathbf{G}_k]$ 表示 $\mathcal{A}$ 在游戏 $k$ 中获胜的概率。

- **游戏 $\mathbf{G}_0$：** 真实的匿名性游戏 $\mathbf{Exp}_{\mathcal{A}}^{\mathsf{Anon}}(\lambda)$。
- **游戏 $\mathbf{G}_1$：** 与 $\mathbf{G}_0$ 相同，但在 Setup 阶段，用于混淆验证点的置换 $\pi(k_p, \cdot)$ 被替换为真随机置换。根据 PRP 假设，$|\Pr[\mathbf{G}_0] - \Pr[\mathbf{G}_1]| \leq \mathsf{Adv}_{\Pi}^{\mathsf{PRP}}(\lambda)$。
- **游戏 $\mathbf{G}_2$：** 在挑战阶段，我们将挑战凭证中的标签 $tag^*$ 替换为从 $\{0,1\}^\lambda$ 中均匀选取的随机字符串。由于 $tag^* = H(\mathsf{ID}_b \| i \| r)$ 包含随机数 $r$ 且 $H$ 是随机预言机，若 $\mathcal{A}$ 未查询过该特定输入，则分布是不可区分的。因此，$|\Pr[\mathbf{G}_1] - \Pr[\mathbf{G}_2]| \leq \mathsf{negl}(\lambda)$。
- **游戏 $\mathbf{G}_3$：** 我们将挑战中的一次性口令 $\mathsf{pw}^*$ 替换为随机字符串。由于 $\mathsf{pw}^*$ 派生自 $F(\mathsf{sk}_{\mathsf{ID}_b}, \cdot)$ 生成的种子，根据 $F$ 的 PRF 安全性，这是不可区分的。因此，$|\Pr[\mathbf{G}_2] - \Pr[\mathbf{G}_3]| \leq \mathsf{Adv}_{F}^{\mathsf{PRF}}(\lambda)$。

在 $\mathbf{G}_3$ 中，挑战凭证 $\sigma^*$ 完全由独立于比特 $b$ 的随机值组成。因此，$\mathcal{A}$ 在 $\mathbf{G}_3$ 中的优势正好为 0。累加各步骤的差异可知总优势是可忽略的。

#### 不可关联性证明

**定理 3.** 在与定理 2 相同的假设下，DAA-GTOTP 满足不可关联性（定义 3）。

证明：

证明过程与匿名性证明类似。我们构造类似的混合游戏序列。

- 在 **游戏 $\mathbf{G}_0$** 中，$\mathcal{A}$ 收到真实凭证 $(\sigma_1, \sigma_2)$。

- 在 **游戏 $\mathbf{G}_1$** 中，验证状态的置换被理想化（PRP）。

- 在 **游戏 $\mathbf{G}_2$** 中，两个凭证中的标签 $tag_1, tag_2$ 被替换为独立的随机字符串（RO 模型）。

- 在 游戏 $\mathbf{G}_3$ 中，口令 $\mathsf{pw}_1, \mathsf{pw}_2$ 被替换为独立的随机字符串（PRF）。

  在 $\mathbf{G}_3$ 中，无论凭证对 $(\sigma_1, \sigma_2)$ 是来自同一个 $\mathsf{ID}$ 还是不同的 $\mathsf{ID}$，它们都由独立的随机值组成。因此，不可关联性的优势是可忽略的。

#### 速率限制证明

**定理 4.** 若 $F$ 是安全的 PRF，则 DAA-GTOTP 满足速率限制（定义 4）。

证明：

速率限制属性通过时间片与协议实例之间的确定性映射强制执行。

1. **总量界限 ($E$)：** 在 $\mathsf{Join}$ 期间，成员被分发了正好 $E$ 个实例令牌。由于这些实例的种子是通过 $\mathsf{seed}^i = F(\mathsf{sk}, i)$ 派生的，敌手无法在不攻破 PRF 或伪造发行方对无效索引签名的情况下生成索引 $i > E$ 的有效种子。

2. 窗口唯一性： 函数 $i(T) = \lceil (T - T_s)/\Delta_T \rceil$ 将任意时间 $T$ 映射到唯一的实例索引 $i$。要为同一个窗口 $i$ 生成两个不同的凭证 $\sigma_a, \sigma_b$，敌手必须从同一个一次性实例种子生成两个有效的口令/标签。根据 GTOTP 的构造，一个种子对于特定时间只能生成一条有效的哈希链路径。在同一时间 $T$ 重用实例构成重放（被验证者检查阻止），而在同一窗口内的不同时间 $T_a, T_b$ 生成凭证需要相同的实例索引 $i$，这在诚实证明者逻辑中被标记为“已使用”。即使被腐化，实例令牌 $i$ 的数学唯一性防止了在不破坏底层认证标签绑定的情况下为槽位 $i$ 生成超过 1 个的独立有效凭证。

   因此，破坏速率限制的概率是可忽略的。

#### 前向不可伪造性证明

**定理 5.** DAA-GTOTP 满足前向不可伪造性（定义 5）。

证明：

假设敌手 $\mathcal{A}$ 在时间 $t_{leak}$ 腐化 $\mathsf{ID}_j$ 并获得 $\mathsf{sk}_j$。$\mathcal{A}$ 试图伪造一个时间 $T^* < t_{leak}$ 的凭证 $\sigma^*$。

虽然 $\mathcal{A}$ 可以使用 $\mathsf{sk}_j$ 派生过去时间 $T^*$ 的正确种子 $\mathsf{seed}_{\mathsf{ID}_j}^{i^*}$，但 DAA-GTOTP 中凭证的有效性严格绑定于验证者的当前时间。

验证算法 $\mathsf{Verify}(\mathsf{pp}, \mathsf{VST}, \sigma^*)$ 包含一个时间有效性检查：

$$\text{若 } T^* \notin [T_{now} - \delta, T_{now} + \delta], \text{ 返回 } 0.$$

由于 $T^* < t_{leak} \leq T_{now}$（假设攻击发生在泄露后），任何与当前时间同步的诚实验证者都会因过期而拒绝时间戳 $T^*$。$\mathcal{A}$ 无法将 $T^*$ 更新为当前时间 $T_{now}$，因为一次性口令 $\mathsf{pw}^*$ 通过 GTOTP 生成函数在密码学上绑定于 $T^*$。更改 $T^*$ 需要为 $T_{now}$ 生成新口令，这将构成对当前时间的有效签名（在腐化后是允许的），而不是对过去时间范围的伪造。

因此，$\mathcal{A}$ 无法生成被接受为过去时间 $T^*$ 的有效证明的凭证。

### 实验表现分析

#### 时间性能分析

协议的时间性能主要体现在系统初始化、凭证生成与验证三个阶段。为评估可扩展性，我们考虑成员规模 $U$ 为 4、100 与 200 三种场景，口令生成间隔 $\Delta_e = 5$ 秒，实例生命周期 $\Delta_T = 5$ 分钟。所有性能数据均来自 1000 次独立测量的平均值。

**初始化阶段**： 包含一次性离线操作：系统参数生成（$\mathsf{Setup}$）和成员加入（$\mathsf{Join}$）。$\mathsf{Setup}$ 算法生成加密密钥对、哈希函数密钥和置换密钥，计算实例总数 $E$，复杂度为 $O(1)$。$\mathsf{Join}$ 协议中，发行方为每个成员的 $E$ 个实例生成标签、签名，构建绑定验证点集合，并通过随机置换将其划分为 $\phi$ 个子集，为每个子集构建 Merkle 树，最后将所有 Merkle 树根插入 Bloom 过滤器形成公开验证状态 $\mathsf{VST}$。该阶段总时间复杂度为 $O(U \cdot E)$，但得益于高效的哈希计算和并行化构建，实测在 $U=4$、$E=288$（对应 24 小时协议时长）的规模下，总初始化时间低于 0.5 秒。这显著优于传统基于双线性对的 DAA 方案，后者通常需要数秒甚至数分钟的初始化时间。

**凭证生成阶段**： 由证明者在需要认证时执行 $\mathsf{Sign}$ 算法。证明者计算当前时间对应的实例索引和口令索引，通过 PRF 重构实例种子，生成 GTOTP 一次性口令，并检索预存的标签、签名和 Merkle 证明。该过程仅涉及常数次哈希、PRF 计算和内存访问，时间复杂度为 $O(1)$。实测单次凭证生成时间稳定在 $20\mu s$ 左右，其中GTOTP口令计算约占 $77\%$，时间窗和凭证组装运算约占 $20\%$。此微秒级延迟确保方案可用于车联网、工业物联网等高实时性场景。

**验证阶段**： 由验证者执行 $\mathsf{Verify}$ 算法，包含六个步骤：时间有效性检查、标签签名验证、验证点重构、Merkle 证明验证、Bloom 过滤器查询和 GTOTP 口令验证。验证点重构（从口令推导验证点并计算其绑定形式）是主要开销源，占总时间的81.3%。Merkle 证明验证需要 $h \approx \lceil \log_2(UE/\phi) \rceil$ 次哈希运算，Bloom 过滤器查询需 $k$ 次哈希运算（$k$ 为哈希函数个数），两者共同贡献约16.4% 的开销。实验测得单次验证总时间约为 $91\mu s$，随系统规模呈对数增长 $O(\log(UE))$。与传统 DAA 方案的毫秒级验证相比，本方案实现了两个数量级的性能提升。

#### 存储开销分析

本协议的另一核心优势在于其紧凑的存储开销。以下对各参与方在GTOTP-DAA方案中的存储复杂度进行建模与分析。

**凭证大小**：单个匿名凭证 $\sigma_T$ 由一次性口令 $\mathsf{pw}$、匿名标签 $tag$、发行方签名 $\sigma$、Merkle 成员资格证明 $\pi$、实例索引 $i$ 和时间戳 $T$ 构成。设 $s_{pw}$、$s_{tag}$、$s_{sig}$ 和 $s_{hash}$ 分别表示口令、标签、签名和哈希值的字节长度，$s_{meta}$ 为元数据（索引和时间戳）的字节开销。令 $h \approx \lceil \log_2 (UE/\phi) \rceil$ 为 Merkle 证明的路径长度,$s_{bool}$为证明中恒为1字节的方向信息的存储开销。凭证的原始大小可近似为：
$$
S_{\sigma}^{\text{raw}} \approx s_{pw} + s_{tag} + s_{sig} + h \cdot (s_{hash}+s_{bool}) + s_{meta}.
$$
凭证大小 $S_{\sigma}^{\text{raw}}$ 为 $\Theta(1)$ 常数级别，独立于系统总成员数 $U$ 和实例总数 $E$。这确保了通信开销的可预测性。在实际配置（$U=100$, $E=288$, $\phi=8192$）下，典型凭证大小约为 $0.551$ KB，其中 Merkle 证明占比约 $11.3\%$，发行方签名占比约 $45.4\%$。

**验证状态（Verifier）**：验证者需维护公开的群组验证状态 $\mathsf{VST}$，这是一个存储了 $\phi$ 个 Merkle 树根的布隆过滤器。设目标误判率为 $\varepsilon$，待插入元素数 $n = \phi$，则布隆过滤器所需位数组大小 $m$ 及字节开销为：
$$
m = -\frac{n \ln \varepsilon}{(\ln 2)^2}, \quad S_{\mathsf{VST}}^{\text{bytes}} = \left\lceil \frac{m}{8} \right\rceil.
$$
其存储开销为 $O(\phi)$，与子集数量成线性关系，而与总成员数 $U$ 无关。在 $\phi=8192$、$\varepsilon=2^{-40}$ 的典型参数下，$S_{\mathsf{GVST}}^{\text{bytes}} \approx 57.71$ KB。这部分存储是恒定且微小的，使得验证者可以轻松部署于资源受限的边缘设备。

**Merkle 树（Issuer）**：发行方在初始化阶段为每个子集构建一棵 Merkle 树。设每个子集平均包含 $\ell = \lceil UE / \phi \rceil$ 个叶子节点（绑定验证点），则每棵树约有 $2\ell - 1$ 个节点。所有 $\phi$ 棵 Merkle 树的总节点数 $N_{\text{merkle}}$ 及总存储开销 $S_{\text{merkle}}$ 可近似为：
$$
N_{\text{merkle}} \approx 2UE - \phi, \quad S_{\text{merkle}} \approx (2UE - \phi) \cdot s_{hash}.
$$
该组件的规模随总实例数 $UE$ 线性增长 $O(UE)$。例如，在 $U=100$、$E=288$、$\phi=8192$ 的场景下，$S_{\text{merkle}} \approx 1.629$ MB。这是发行方的主要离线存储开销，但因其仅在系统初始化时计算一次，且通常由具备较强存储能力的后端服务器承担，故是可接受的。

**辅助信息（Attester）**：每个证明者 $\mathsf{ID}_j$ 需本地安全存储其辅助信息 $\mathsf{Aux}_j$，其中包含其全部 $E$ 个实例对应的三元组 $(tag_j^i, \sigma_j^i, \pi_j^i)$。单个证明者的辅助信息大小 $S_{\mathsf{aux}}^{\text{per}}$ 及系统总辅助信息大小 $S_{\mathsf{aux}}^{\text{total}}$ 为：
$$
S_{\mathsf{aux}}^{\text{per}} = E \cdot \left( s_{tag} + s_{sig} + h \cdot s_{hash} \right), \quad S_{\mathsf{aux}}^{\text{total}} = U \cdot S_{\mathsf{aux}}^{\text{per}}.
$$
显然，$S_{\mathsf{aux}}^{\text{total}} = \Theta(U \cdot E)$ 与系统总实例数呈线性关系，这是分布式存储开销的主要部分。在典型配置下，每个证明者约需存储 $123.501$KB（$E=288$时），对于现代物联网设备（通常具备 MB 级别的安全存储）而言是可行的。

**身份映射表（Issuer）**：发行方还需安全存储本地身份映射表 $\mathsf{IDTable}$，记录每个 $(tag_j^i, i, \mathsf{ID}_j)$ 三元组以供追溯。其存储开销同样为 $O(U \cdot E)$，与总实例数线性相关，但这是可信发行方可承担的机密存储。

系统的总存储开销是分布式的，不同参与方承担不同部分：

- 验证者：常数开销 $O(\phi)$，仅约 57.71 KB。
- 证明者：线性开销 $O(E)$，每个成员约几十至数百 KB。
- 发行者：线性开销 $O(U \cdot E)$，仅为 MB 量级（离线可接受）。

核心优势在于，负担最重的线性存储开销由（资源相对丰富的）发行方和（众多但仅存储自身数据的）证明者分担，而验证者——通常是系统吞吐量的瓶颈和资源最受限的实体（如网关、边缘设备）——其存储开销被压缩至常数级别，且仅为 KB 大小。这种不对称的存储分布是 GTOTP-DAA 方案可扩展性的关键。

实测表明，在支持 $U=100$ 名成员、持续 $24$ 小时（$E=288$）的系统中，验证者仅需约 $57.71$ KB 内存即可完成验证，这比传统基于双线性对的 DAA 方案（验证状态常达 MB 级以上）降低了三个数量级。同时，每个证明者约 $123.5$ KB 的本地存储成本，也远低于传统方案中需要存储庞大群公钥和自身复杂密钥材料的开销。

综上所述，GTOTP-DAA 方案通过创新的密码学结构设计，实现了存储开销的优化分配：将可扩展性瓶颈——验证者的开销降至常数级，同时将线性开销转移至可离线管理或众多节点分担的环节。这使得该方案特别适合在成员规模大、验证者资源受限的物联网、车联网等场景中部署。