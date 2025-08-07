# 基于GTOTP的群签名远程证明协议

## 前置内容

### 布隆过滤器



### Merkle树

### GTOTP

GTOTP（Group Time-based One-Time Password）是对传统TOTP（Time-based One-Time Password）方案的扩展，旨在实现群体认证同时保护用户隐私。与TOTP类似，GTOTP允许证明者在一个预定的时间窗口内生成一次性密码，但其创新之处在于，证明者能够在不透露自身身份的情况下，证明自己是某个群体的成员。这一扩展使得GTOTP在需要群体认证且保护隐私的应用场景中具有广泛的适用性。

在GTOTP的实现中，每个群体成员使用其私密密钥生成多个TOTP实例，每个实例的有效期非常短。每个TOTP实例通过哈希链生成一次性密码。在TOTP中，密码是通过哈希链的头部随机生成的，并通过不断的哈希运算生成后续的密码。验证者可以通过验证点验证密码的有效性，而无需知道生成该密码的成员身份。

GTOTP将这一过程扩展至群体认证。在群体认证中，每个成员会生成多个TOTP实例，并且每个实例会在固定的时间窗口内生成一次性密码。为了避免群体成员的身份信息泄露，GTOTP采用了匿名性技术。具体来说，GTOTP使用Merkle树和Bloom过滤器来管理所有成员的验证点。Merkle树允许将多个成员的验证点合并为一个树状结构，而Bloom过滤器则用于存储和查询这些验证点的状态，从而大大减少了存储开销。通过这些技术，验证者只需要检查密码是否在Merkle树的根节点中，而不需要知道具体的成员身份。

在GTOTP的密码验证过程中，验证者首先接收到证明者发送的密码以及相应的验证点。验证者利用Merkle树的证明路径验证密码的有效性，并通过Bloom过滤器检查该验证点是否存在。验证成功后，验证者确认该密码是有效的，且它确实由群体成员生成。

GTOTP方案还包括群体成员的身份追溯功能。如果需要，群体管理者可以通过相应的密钥和验证点恢复密码生成者的身份。这样，GTOTP不仅能提供群体认证，还能在特定情况下实现身份追溯，确保系统的可追责性。

上述过程由这个由七种 (𝖲𝖾𝗍𝗎𝗉,𝖨𝗇𝗂𝗍,𝖦𝖵ST𝖦𝖾𝗇,𝖦𝖾𝗍𝖲𝖽,𝖯W𝖦𝖾𝗇,𝖵𝖾𝗋𝗂𝖿𝗒,𝖮𝗉𝖾𝗇) 算法组成，详细描述如下：

- $(pms, \kappa_{RA}) \leftarrow \text{Setup}(1^\kappa, T_s, T_e, \Delta_e, \Delta_s)$：该算法为系统核心配置流程，由 RA 执行。输入安全参数 $1^\kappa$、协议协议运行的时间边界 $T_s$ 和 $T_e$、验证周期 $\Delta_e$ 和密码生成间隔 $\Delta_s$ ，输出系统参数 $pms$ 和 $RA$ 的密钥 $k_{RA} \xleftarrow{\$} \mathcal{K}_{RA}$， $\mathcal{K}_{RA}$ 是RA密钥的所属空间。
- $(sk_{ID_j}, vst_{ID_j}) \leftarrow \text{PInit}(ID_j)$：此为成员注册算法，由群成员执行。以成员身份标识 $ID_j$ 作为输入，生成并输出该成员的私钥 $sk_{ID_j} \xleftarrow{\$} \mathcal{K}_{GTOTP}$ （$\mathcal{K}_{GTOTP}$是私钥对应的空间）以及 $ID_j$ 的初始验证状态 $vst_{ID_j}$。
- $(vst_G, \{Ax_{ID_j}\}_{j \in [U]}) \leftarrow \text{GVSTGen}(GP, \{vst_{ID_j}\}_{j \in [U]})$：该算法为群组验证状态构建流程，由 RA 执行。输入群成员集合 $\text{GP}$ 及各成员的验证状态$\{vst_{ID_j}\}_{j \in [U]}$（$[U]$为成员索引范围）, 输出群组验证状态$vst_G$ 和为每个成员生成的辅助数据 $\{Ax_{ID_j}\}_{j \in [U]}$。
- $sdi_{ID_j} \leftarrow \text{GetSD}(sk_{ID_j}, T)$：此为一次性密码种子生成算法，由群成员执行。输入成员私钥 $sk_{ID_j} \in \mathcal{S}_{GTOTP}$ 和时间槽 $T$ （其中 $\mathcal{S}_{GTOTP}$ 是一个密钥空间），输出对应时间槽 $T$ 的密码生成种子 $sd_{\text{ID}_j}^{i}$。
- $pw_{ID_j}^{i,z} \leftarrow \text{PwGen}(sdi_{ID_j}, T)$：该算法为密码生成流程，由群成员执行。输入时间槽T对应的种子 $sdi_{ID_j}$ 和时间槽 $T$ ，输出带索引的一次性密码 $pw_{ID_j}^{i,z}$，其中 $z$ 为第 $i $个验证周期内的密码序号。
- $\{0, 1\} \leftarrow \text{Verify}(vst_G, pw_{ID_j}^{i,z}, T)$：此为密码有效性校验算法，由验证者执行。输入群组验证状态 $vst_G$、待验证密码 $pw_{ID_j}^{i,z}$ 和时间槽 $T$ ，若密码有效则输出 1，否则输出 0 。
- $ID_j \leftarrow \text{Open}(\kappa_{RA}, pw_{ID_j}^{i,z}, T)$：该算法为身份提取流程，由 RA 执行。输入 RA 密钥 $k_{RA}$、目标密码 $pw_{ID_j}^{i,z}$ 和时间槽 $T$ ，成功提取身份时输出 $ID_j$，否则输出 $\perp$。

## 协议定义与符号说明

在本节中，我们构建了一种基于 GTOTP 的群签名式远程证明协议，它将 GTOTP 的时间绑定特性与群验证逻辑结合，扩展到设备远程证明场景。通过该协议，待证明设备（Attester）可向 TCB 可信群体提交状态报告，群体成员验证报告后生成带时间戳的凭证，最终验证者（RP）能通过凭证确认设备可信性，且无法获知具体生成凭证的群体成员身份。

该协议的核心价值体现在三个方面：一是仅 TCB 群体成员可生成有效的认证凭证，确保验证来源可信；二是验证者只需确认凭证合法性，无需知晓具体签名成员，保护群体隐私；三是注册机构（RA）可在必要时追溯签名者身份，实现可追责。

### 系统模型

XXXX涉及四类核心参与实体：

- **Attester**：需证明自身可信性的设备或平台，生成包含平台状态（如硬件度量值、软件完整性）的远程证明报告； 
- **TCB Group（群体验证者）**：由$U$个可信实体$\{ID_1,ID_2,...,ID_U\}$组成的群体，每个成员独立维护GTOTP种子及验证状态，负责在本地验证Attester报告并生成匿名认证凭证；
- **Relying Party（RP，最终验证者）**：通过接收并验证匿名凭证，确认Attester的可信性但无法识别具体签名成员；
-  **Registration Authority（RA，注册机构）**：承担系统初始化、成员注册及身份追踪职责，仅持有用于解密身份信息的私钥，不参与具体验证过程。 

我们假设RA受到系统所有参与者的信任，并作为证书颁发机构对成员的信息（例如，组验证状态）进行数字签名。考虑具有以下子协议的GTOTP远程证明方案：

- $report \leftarrow \text{ReportGen}(nonce\|measurement\|t)$：此报告生成算法由Attester运行。它以远程证明挑战随机数$nonce$、自身配置的测量值$measurement$和报告生成时间戳作为输入。它输出能够反应自身运行状态的报告$report$。
- $\{0,1\}\leftarrow \text{CheckReport}(report)$：此报告验证算法由TCB组成员$ID_j$运行。它以远程证明报告$report$作为输入，如果报告验证通过则输出1，否则输出0。
- $\pi_{j,t} \leftarrow \text{MT.GetProof}(MT_t,vp'_{ID_j,i})$：此Merkle证明获取算法由RA运行。它以当前验证点和验证点所处的Merkle树作为输入，输出此验证点在该Merkle树中的Merkle证明。
- $vp_{ID_j}^i \leftarrow \text{GTOTP.GetVP}(pw_{ID_j}^{i,t})$：此验证点获取算法由TCB组成员$ID_j$运行。它以口令作为输入，输出该口令所处TOTP实例的验证点。

给定 $(pms, \kappa_{RA}) \leftarrow \text{Setup}(1^\kappa, T_s, T_e, \Delta_e, \Delta_s)$，$((sk_{ID_j}, vst_{ID_j}) \leftarrow \text{PInit}(ID_j))_{ID_j \in GP}$ 和 $GVST(\{Ax_{ID_j}\}_{j \in [U]}) \leftarrow \text{GVSTGen}(GP, \{vst_{ID_j}\}_{j \in [U]})$，如果对于Attester所产生的$report$，$\text{CheckReport}(report)$输出1，并且对于所有 $ID_j \in GP$ 和时间槽 $T \in [T_s, T_e]$，$\text{Verify}(vst_G, \text{PwGen}(sd_{ID_j}, T), T)$ 输出 1，则基于 GTOTP的远程证明方案是正确的。

### 核心符号与密码学原语

|        符号         |                             含义                             |
| :-----------------: | :----------------------------------------------------------: |
|     $1^\lambda$     |                           安全参数                           |
|        $T_s$        |                         系统起始时间                         |
|        $T_e$        |                      协议有效期截止时间                      |
|     $\Delta e$      |                       口令生成时间间隔                       |
|     $\Delta T$      |                      GTOTP 实例生命周期                      |
|         $H$         |                        抗碰撞哈希函数                        |
|   $seed_{ID_j}^i$   |             TCB 成员$ID_j$在实例$i$的 GTOTP 种子             |
|  $pw_{ID_j}^{i,t}$  | $ID_j$在$t$时刻生成的一次性口令$(pw_{ID_j}^{i,t}=\text{GTOTP}(seed_{ID_j}^i,t))$ |
|     $Enc(ID_j)$     | RA 用公钥加密的成员身份$Enc(ID_i)=\text{PKEnc}(pk_{RA},ID_{j})$ |
|    $vp_{ID_j}^i$    | 初始验证点，$vp_{ID_j}^i=\text{GTOTP.PInit}(seed_{ID_j}^i)$，（TOTP 实例的哈希链终点） |
| $vp_{ID_j,i}^{\\'}$ | 构建Merkle树的验证点($vp'_{ID_j,i}=H(vp_{ID_j}^i||Enc(ID_j)||i)$) |
|     $\pi_(i,t)$     |              $vp_{i,t}$在 Merkle 树中的路径证明              |
|   $\sigma_{i,t}$    | 群签名结构($\sigma_{i,t}=(pw_{i,t},Enc(ID_i),\pi_{i,t},t)$)  |
|        $MT$         |                          Merkle 树                           |
|        $BF$         |                          布隆过滤器                          |
|        $PRF$        | 伪随机函数（密钥空间$\mathcal{K}_{\text{PRF}}$，生成种子及确保随机性） |

### 威胁模型

我们基于GTOTP的群签名式远程证明方案，核心目标是在保障TCB组成员身份不泄露的前提下，完成远程证明。该方案需满足三个关键安全要求：可追溯性、匿名性以及报告完整性。需要说明的是，虽然不排除个别TCB成员被攻击者渗透，但我们默认多数成员在验证Attester报告并生成签名时会遵循规则、保持诚实。验证者会如实对签名进行验证，并将结果应用于实际决策，且不会与攻击者勾结。注册机构作为可信核心，仅在必要场景下进行身份追溯，不参与具体验证环节，同时不存在与其他参与方串通的可能。在通信安全方面，TCB成员与RA之间的交互通过安全通道完成，而Attester向TCB成员提交报告、TCB成员向RP发送签名的过程，可能面临攻击者的干预——比如信息被拦截、篡改，或是被恶意重放。

我们的威胁模型为预期的方案提供了以下安全要求：

- **可追溯性**：任何经验证有效的群签名，都必须能被RA通过解密加密身份$\text{C}_{ID_j}$追溯到具体的TCB成员。这意味着攻击者即使伪造出通过验证的签名，也无法逃避追责——要么签名能被追溯到某个真实成员（若该成员被腐蚀），要么因无法关联到合法身份而被判定为无效。同时，该特性确保TCB成员不能通过篡改签名结构（如伪造路径证明、替换加密身份）规避责任，为恶意行为提供约束。   
-  **匿名性**：验证者RP仅能确认签名来自TCB群体中的合法成员，无法通过签名中的信息（如一次性口令、Merkle路径证明、时间戳）推断出具体生成者的身份。这一特性通过“随机置换验证点和加密身份绑定”实现：RA在构建Merkle树时打乱验证点顺序，隐藏成员与验证点的对应关系；同时，$\text{C}_{ID_j}$仅能被RA解密，RP无法从签名中提取真实身份，从而保护TCB成员的隐私不被泄露。    
- **报告完整性**：Attester生成的平台状态报告在传输和验证过程中必须保持完整，不能被攻击者篡改。TCB成员仅为通过本地验证的报告生成签名，且签名与报告内容通过“种子绑定机制”关联（$seed_{ID_j}^i$由报告、身份及时间共同生成）。这确保攻击者无法通过篡改报告内容，如伪造可信状态诱导TCB成员生成签名，也无法替换报告后复用原有签名，从源头保证远程证明的可信度。

简单来说，可追溯性意味着任何通过验证的签名，都能被RA准确关联到对应的TCB成员，避免出现签名无法溯源或被伪造的情况；匿名性确保RP仅能确认签名来自合法的TCB群体，无法知晓具体是哪个成员生成的签名；报告完整性则保证Attester提交的平台状态报告，从生成到被TCB成员验证的整个过程中未被篡改，只有真实可信的报告才能触发TCB成员生成签名。

## GTOTP-RA

在本节中，我们将介绍基于GTOTP的远程证明方案。



### 协议详细构造

本协议通过 7 个核心算法实现群签名式远程证明，各算法的输入、处理逻辑及输出如下：

 **算法 1：Setup（系统初始化）**

Setup 算法由 RA 执行，用于完成系统参数初始化与密钥生成。输入为安全参数$1^\lambda$、系统起始时间$T_s$、协议截止时间$T_e$、口令生成间隔$\Delta e$及实例生命周期$\Delta T$。首先，RA 生成自身的非对称密钥对$(pk_{RA},sk_{RA})$，其中$pk_{RA}$用于加密 TCB 成员身份，$sk_{RA}$由 RA 秘密持有以用于后续身份追踪。

其次，基于输入的时间参数计算核心控制参数：口令数量$N=\lceil(T_e-T_s)/\Delta e\rceil$（用于确定单个 GTOTP 实例内的口令总数），GTOTP 实例数量$E=\lceil(T_e-T_s)/\Delta T\rceil$（用于划分协议运行周期，每个实例对应一个生命周期）。随后，RA 初始化哈希函数参数$hk\leftarrow H.\text{Setup}(1^\lambda)$（用于后续验证点计算），采样置换密钥$k_p\leftarrow\{0,1\}^\lambda$（用于打乱验证点顺序以增强匿名性），并设置验证点子集数量$\phi$（根据安全性需求与效率权衡确定，通常取 10）。

最终，RA 输出系统公共参数$pms=(hk,k_p,N,E,T_s,T_e,\Delta e,\Delta T,\phi,pk_{RA})$及自身私钥$sk_{RA}$，其中$pms$对所有参与方公开，$sk_{RA}$由 RA 保密存储。

> [!NOTE]
>
> Setup 算法由 RA 执行，用于完成系统参数初始化与密钥生成，输入为安全参数\(1^\lambda\)、系统起始时间\(T_s\)、协议截止时间\(T_e\)、口令生成间隔\(\Delta e\)及实例生命周期\(\Delta T\) 。RA 先生成自身非对称密钥对\((pk_{RA}, sk_{RA})\)，其中\(pk_{RA}\)用于加密 TCB 成员身份，\(sk_{RA}\)由 RA 秘密持有，用于后续身份追踪 。
>
> 基于输入的时间参数，RA 计算核心控制参数，口令数量\(N = \lceil (T_e - T_s)/\Delta e \rceil\)（用于确定单个 GTOTP 实例内的口令总数），GTOTP 实例数量\(E = \lceil (T_e - T_s)/\Delta T \rceil\)（用于划分协议运行周期，每个实例对应一个生命周期） 。之后，RA 初始化哈希函数参数\(hk \leftarrow H.Setup(1^\lambda)\)（用于后续验证点计算），采样置换密钥\(k_p \leftarrow \{0,1\}^\lambda\)（用于打乱验证点顺序以增强匿名性），并设置验证点子集数量\(\phi\)（根据安全性需求与效率权衡确定，通常取 10） 。
>
> 最终，RA 输出系统公共参数\(pms = (hk, k_p, N, E, T_s, T_e, \Delta e, \Delta T, \phi, pk_{RA})\)及自身私钥\(sk_{RA}\)，其中pms对所有参与方公开，\(sk_{RA}\)由 RA 保密存储 。

**算法 2：PInit（TCB 成员初始化）**

PInit 算法由 TCB 成员执行，用于完成本地密钥与验证状态的初始化。输入为成员自身身份$ID_j$及系统公共参数$pms$。

首先，成员$ID_j$生成自身的伪随机函数密钥$k_{ID_j}\leftarrow\mathcal{K}_{\text{PRF}}$，该密钥作为成员私钥用于后续种子生成，需秘密存储。其次，针对协议周期内的$E$个 GTOTP 实例，成员分别初始化实例参数：对每个$i\in[1,E]$,($i=\lceil (T-T_s) / \Delta T \rceil$)，计算实例$i$的时间范围为$T_{i,\text{start}}=T_s+(i-1)\cdot\Delta T$至$T_{i,\text{end}}=T_s+i\cdot\Delta T$，并初始化实例参数$pms_i\leftarrow\textsf{GTOTP}.\text{Setup}(1^\lambda,T_{i,\text{start}},T_{i,\text{end}},\Delta e)$，确保每个实例仅在其生命周期内有效。

随后，成员为每个实例生成种子与初始验证点：对$i\in[1,E]$，种子$seed_{j,i}$通过伪随机函数生成（即$seed_{ID_j}^i=\text{PRF}(k_{ID_j},ID_j\|i)$），该种子绑定成员身份与实例索引以确保唯一性；初始验证点$vp_{ID_j}^i$由 GTOTP 初始化算法生成（即$vp_{ID_j}^i=\textsf{GTOTP.PInit}(seed_{ID_j}^i)$），作为实例$i$的初始承诺。

最终，成员输出自身私钥$sk_j=k_{ID_j}$（本地秘密存储）及验证状态$vst_j=\{vp_{ID_j}^i \}_{i\in[1,E]}$（用于后续群体验证状态构建）。

> [!NOTE]
>
> PInit 算法由 TCB 成员执行，用于完成本地密钥与验证状态的初始化，输入为成员自身身份 $ID_j$ 及系统公共参数 $pms$ 。 
>
> TCB 成员生成自身伪随机函数密钥 $k_{ID_j} \leftarrow \mathcal{K}_{\text{PRF}}$ ，该密钥作为成员私钥用于后续种子生成，需秘密存储。针对协议周期内的 $E$ 个 GTOTP 实例，成员为每个 $i \in [1, E]$初始化实例参数：计算实例 $i$ 的时间范围为 $T_{i,\text{start}} = T_s + (i - 1)\cdot\Delta T$ 至 $T_{i,\text{end}} = T_s + i \cdot \Delta T$ ，并执行 $pms_i \leftarrow \text{GTOTP.Setup}(1^\lambda, T_{i,\text{start}}, T_{i,\text{end}}, \Delta e)$ ，保证每个实例仅在其生命周期内有效 。 
>
> 对于每个 $i \in [1, E]$ ，成员通过伪随机函数生成种子$seed_{ID_j}^i = \text{PRF}(k_{ID_j}, ID_j \| i)$ ，该种子绑定成员身份与实例索引以确保唯一性；利用 GTOTP 初始化算法生成初始验证点 $vp_{ID_j}^i = \text{GTOTP.PInit}(seed_{ID_j}^i)$ ，作为实例 $i$ 的初始承诺 。 成员输出自身私钥 $sk_j = k_{ID_j}$，本地秘密存储 ，以及验证状态 $vst_j = \{ vp_{ID_j}^i \}_{i \in [1, E]}$用于后续群体验证状态构建  。

**算法 3：GVSTGen（群体验证状态生成）**

GVSTGen 算法由 RA 执行，用于整合所有 TCB 成员的验证状态并生成群体级验证信息。输入为系统参数$pms$、RA 私钥$sk_{RA}$及所有成员的验证状态$\{vst_j\}_{j\in[1,U]}$。

首先，RA 为每个成员生成加密身份并绑定验证点：对每个$j\in[1,U]$及$i\in[1,E]$，RA 用$pk_{RA}$加密成员身份得到$Enc(ID_j)=\text{PKEnc}(pk_{RA},ID_j)$（由于加密算法的随机性，不同成员或同一成员的不同实例对应的$Enc(ID_j)$均不相同）；随后将验证点与加密身份、实例索引绑定，生成$vp'_{ID_j,i}=H(hk,vp_{ID_j}^i\|Enc(ID_j)\|i)$，确保验证点与成员身份的唯一关联。

其次，RA 对验证点进行打乱与分组：收集所有绑定后的验证点形成集合$V=\{vp'_{ID_j,i}\mid j\in[1,U],i\in[1,E]\}$，用置换密钥$k_p$对V进行随机置换得到$V'=\pi(k_p,V)$（隐藏验证点与成员的对应关系），再将$V'$划分为$\phi$个子集$V_1,V_2,...,V_\phi$（每个子集大小大致相等）。

接着，RA 构建 Merkle 树与布隆过滤器：对每个子集$V_t(t\in[1,\phi])$，构建 Merkle 树$MT_t\leftarrow\text{MT.Build}(V_t)$并记录根节点$Root_t$；为每个验证点$vp'_{ID_j,i}\in V_t$生成路径证明$\pi_{j,i}=\textsf{MT.GetProof}(MT_t,vp'_{ID_j,i})$；初始化布隆过滤器$\textsf{BF}\leftarrow\textsf{BF.Init}(\epsilon,\phi)$（$\epsilon$为预设误判率），并将所有 Merkle 根节点插入BF（即$\textsf{BF.Insert}(BF,Root_t)$对所有$t\in[1,\phi]$）。

最终，RA 向每个成员$ID_j$发送辅助信息$ax_j=\{Enc(ID_j),\pi_{j,i}\}_{i\in[1,E]}$（成员本地存储），并输出群体验证状态$vst_{\text{GP}}=\textsf{BF}$（公开用于验证，大小为$O(\phi)$的常数级）。

> [!NOTE]
>
> GVSTGen算法由RA执行，用于整合所有TCB成员的验证状态并生成群体级验证信息，输入为系统参数$pms$、RA私钥$sk_{RA}$及所有成员的验证状态$\{vst_j\}_{j \in [1,U]}$ 。   
>
> RA为每个成员生成加密身份并绑定验证点，针对每个$j \in [1,U]$及$i \in [1,E]$ ，以$pk_{RA}$加密成员身份得到$Enc(ID_j) = \text{PKEnc}(pk_{RA}, ID_j)$（因加密算法随机性，不同场景下加密结果存在差异 ）；随后将验证点与加密身份、实例索引绑定，生成$vp'_{ID_j,i} = H(hk, vp^i_{ID_j} \parallel \text{Enc}(ID_j) \parallel i)$，确保验证点与成员身份唯一关联 。   
>
> RA收集所有绑定后的验证点形成集合$V = \{vp'_{ID_j,i} \mid j \in [1,U], i \in [1,E]\}$ ，通过置换密钥$k_p$对$V$随机置换得到$V' = \pi(k_p, V)$以隐藏验证点与成员对应关系），再将$V'$划分为大小大致相等的$\phi$个子集$V_1, V_2, \dots, V_\phi$ 。   
>
> 针对每个子集$V_t(t \in [1,\phi])$ ，RA构建Merkle树$MT_t \leftarrow \text{MT.Build}(V_t)$并记录根节点$Root_t$；为每个验证点$vp'_{ID_j,i} \in V_t$生成路径证明$\pi_{j,i} = \text{MT.GetProof}(MT_t, vp'_{ID_j,i})$；初始化布隆过滤器$BF \leftarrow \text{BF.Init}(\epsilon, \phi)$（$\epsilon$为预设误判率 ），并将所有Merkle根节点插入$BF$（执行$\text{BF.Insert}(BF, Root_t)$覆盖所有$t \in [1,\phi]$ ） 。RA向每个成员$ID_j$发送辅助信息$Aux_j = \{\text{Enc}(ID_j), \pi_{j,i}\}_{i \in [1,E]}$（成员本地存储 ）；同时输出群体验证状态$vst_{GP} = BF$，公开用于验证，规模为$O(\phi)$常数级  。

**算法 4：ReportGen（Attester 生成报告）**

ReportGen 算法由 Attester 执行，用于生成包含平台状态的远程证明报告。输入为当前时间$t$及平台度量值$m$（如硬件配置、固件版本、运行进程哈希等表征平台可信状态的数据）。

Attester 将来自Relying Party的随机数$nonce$、当前时间$t$及度量值$m$生成反映自身运行状态的报告$\text{report} \leftarrow \textsf{ReportGen}(\text{nonce} \|\text{measurement}\| t)$；最终将$report$发送给 TCB 群体的部分或全部成员，请求验证。

**算法 5：PwGen（TCB 成员生成签名）**

PwGen 算法由 TCB 成员执行，用于在验证报告后生成群签名。输入为成员私钥$sk_j$、辅助信息$ax_j$、Attester 发送的报告$report$及当前时间$t$。

首先，成员验证报告合法性：通过预设的$\text{CheckReport}$函数检查$report$中的度量值$m$是否符合可信标准（如与基准值匹配），若验证失败则终止流程。若报告合法，成员生成 GTOTP 口令：先确定当前时间对应的实例索引$i=\lceil(t-T_s)/\Delta T\rceil$（定位至对应的 GTOTP 实例）；再基于报告、身份及时间生成种子$seed_{ID_j}^i=\text{PRF}(sk_j,ID_j\|i)$（绑定报告内容与生成时间，确保口令与特定报告关联）；最后调用 GTOTP 生成算法得到一次性口令$pw_{ID_j}^{i,t}=\textsf{GTOTP.Gen}(seed_{ID_j}^i,t)$。

随后，成员生成验证点$vp'_{ID_j,i}=H(hk,\textsf{GTOTP.GetVP}(pw_{ID_j}^{i,t})\|Enc(ID_j)\|i)$（从$ax_j$中提取$Enc(ID_j)$），并从$ax_j$中获取该验证点对应的 Merkle 路径证明$\pi_{j,t}$。

最终，成员将口令、加密身份、路径证明及时间戳整合为群签名$\sigma=(pw_{ID_j}^{i,t},Enc(ID_j),\pi_{j,t},t)$，并发送给 Relying Party。

> [!NOTE]
>
> PwGen 算法由 TCB 成员执行，用于在验证报告后生成群签名。输入为成员私钥$sk_j$、辅助信息$Ax_j$、Attester 发送的报告$report$及当前时间$t$。 
>
> TCB 成员先调用预设的$\text{CheckReport}$函数检查$report$中的度量值$m$是否符合可信标准（若验证不通过则直接终止流程；验证通过后，通过计算$i=\lceil(t-T_s)/\Delta T\rceil$定位至对应的 GTOTP 实例；，再基于身份与实例索引生成种子$seed_{ID_j}^i=\text{PRF}(sk_j,ID_j\|i)$；随后调用 GTOTP 生成算法，得到一次性口令$pw_{ID_j}^{i,t}=\textsf{GTOTP.Gen}(seed_{ID_j}^i,t)$。 
>
>  在此基础上，成员进一步生成验证点$vp'_{ID_j,i}=H(hk,\textsf{GTOTP.GetVP}(pw_{ID_j}^{i,t})\|Enc(ID_j)\|i)$（从$Ax_j$中提取$Enc(ID_j)$），并从$Ax_j$中获取该验证点对应的 Merkle 路径证明$\pi_{j,t}$。 成员将口令、加密身份、路径证明及时间戳整合为群签名$\sigma=(pw_{ID_j}^{i,t},Enc(ID_j),\pi_{j,t},t)$，并发送给 Relying Party。

**算法 6：Verify（RP 验证签名）**

Verify 算法由 Relying Party 执行，用于验证群签名的合法性。输入为群签名$\sigma=(pw,Enc(ID),\pi,t)$、群体验证状态$vst_{\text{GP}}=\textsf{BF}$及当前时间$t_{\text{now}}$。

首先，RP 解析签名得到$pw,Enc(ID),\pi,t$，并执行时间窗口验证：计算当前时间对应的口令窗口索引$k=\lceil(t_{\text{now}}-T_s)/\Delta e\rceil$，确定窗口范围为$t_{\text{start}}=T_s+k\cdot\Delta_e$至$t_{\text{end}}=t_{\text{start}}+\Delta e$；若$t$不在该范围内（即口令已过期或未生效），则直接输出验证失败（$vr=0$）。

若时间验证通过，先确定该口令对应的实例索引$i=\lceil(t-T_s)/\Delta T\rceil$,RP 计算验证点$\hat{vp}=H(hk,\textsf{GTOTP.GetVP}(pw)\|Enc(ID)\|i)$，并使用路径证明$\pi$重建 Merkle 根节点$\hat{Root}=\textsf{MT.Verify}(\hat{vp},\pi)$。

随后，RP 查询布隆过滤器检查$\hat{Root}$是否为群体合法根节点（即$\textsf{BF.Query}(\textsf{BF},\hat{Root})$），若查询失败则输出$vr=0$。若所有验证步骤均通过，RP 输出$vr=1$（表示签名合法，Attester 可信）。

**算法 7：Open（RA 追踪身份）**

Open 算法由 RA 执行，用于在需要追责时追踪签名者身份，仅在签名已通过 Verify 验证（即$vr=1$）时执行。输入为有效签名$\sigma$及 RA 私钥$sk_{RA}$。

RA 从$\sigma$中提取加密身份$Enc(ID)$，并使用$sk_{RA}$解密得到签名者身份$ID_j=\text{PKDec}(sk_{RA},Enc(ID))$。最终输出$ID_j$，实现对签名者的责任追溯。
