# 设计说明 — 赛道B 蓝队检测引擎

## 1. 目标与约束

构建一个**离线、确定性**的 agent skill 检测引擎，满足赛道B排名接口与约束：

| 约束 | 实现 |
|------|------|
| 输入 `/data/skills/{skill_id}/` | `loader.discover_skills` 遍历子目录 |
| 输出 `/output/results.jsonl` | `run_engine.run` 原子写出，每行一对象 |
| 字段仅 `skill_id/verdict/confidence/category/evidence`（接口规范 §3） | `run_engine._dump_line` 固定键序 |
| 无出网、禁外部 LLM/API | 引擎只 `import` 标准库；`urllib` 仅存在于 `selftest/` 取数脚本；无 LLM → **Token 消耗 = 0** |
| 确定性 | 排序遍历、`PYTHONHASHSEED=0`、冻结权重、无 `random`、仅用 `time.monotonic` 做预算守卫（不影响判定） |
| 资源 4 vCPU / 8GB / 30min / 镜像≤10G（§4） | 单遍扫描、预编译有界 regex、流式写出；实测 ~11 ms/skill、峰值内存 <1 MiB；全局 28 分钟预算守卫见 §7 |

排名只看**密封 holdout**，且公开数据集 `yoonholee/agent-skill-malware` 是**单一 2026‑02 ClawHub 活动**。因此核心设计原则：**把攻击模式抽象为「行为类」，绝不硬编码品牌串**（`openclaw`/特定账号/特定 IP/特定域名字面量）。`engine/` 下任何文件都不含这些活动特异字符串（负控见自测）。

## 2. 总体架构

分层三段流水线（借鉴 SkillSieve 的分层 triage，但**全确定性、无 LLM**）：

```
Layer 0  加载/归一化   loader + normalize(NFKC/零宽/同形字) + entropy + manifest(结构化解析)
Layer 1  静态行为信号  signals = 行为类 regex + prose 注入 + manifest 结构化 + 混淆(同形字/递归解码)
Layer 1.5 误报抑制     suppress  ->  扣分 / 丢弃 / 确证链封底
Layer 2  确定性语义    跨文件 split-logic + ml(冻结统计模型，只增召回)
Layer 2.5 灰区语义门控  semantic  ->  仅对 suspicious 上调：意图×能力不符 + (可选)离线注入分类器
裁决                  scoring  ->  r 分数 -> 三档 verdict（含灰区）+ confidence
归类                  categorize -> 证据加权(最高权重信号)选单一 AST 主类
证据                  evidence  -> 中文 evidence + 真实片段引用
输出边界              run_engine -> category 转大写 ASTxx/空串 + 5 字段固定键序 + 流式落盘
```

数据流：`run_engine.analyze_skill` → `loader.load_skill`（含 `manifest.parse`）→ `signals.scan`（regex + `manifest.scan`）→ `scoring.score`（内部 `suppress` + `ml` + 灰区 `semantic`）→ `categorize` → `evidence.build` → `run_engine._to_ast_label` + `scoring.confidence`。

> **设计依据**：真实 agent-skill 攻击中 91% 把 prompt injection 与代码结合（Snyk ToxicSkills），且大量攻击是 SKILL.md 自然语言指令操纵（OWASP **AST08 Poor Scanning**），manifest 层面的过度授权/弱隔离/更新漂移又对应 **AST03/06/07**。因此本引擎在原「shell/代码行为类」之外，新增 **prose 注入检测**、**manifest 结构化分析** 与 **混淆还原**，覆盖完整的 OWASP Agentic Skills Top 10（AST09 治理类除外，永不单独输出）。

## 3. 检测信号（行为类，泛化非品牌）

信号集中定义于 [engine/constants.py](../engine/constants.py) 的 `SIGNALS`，编译于 [engine/signals.py](../engine/signals.py)。分 6 个 tier，其中 A–D 参与「协同加分」：

| Tier | 含义 | 代表信号（行为类） |
|------|------|-------------------|
| A 执行原语 | RCE / 反弹 shell / 解码执行 | `S_pipe_to_shell`（`curl…\|bash`）、`S_decode_pipe_shell`、`S_decode_exec_call`、`S_reverse_shell`、`S_dynamic_exec` |
| B 伪造前置社工 | 虚假依赖诱导下载执行 | `S_fake_prereq_phrase`（强迫话术×下载指令共现）、`S_external_binary_run`、`S_password_archive` |
| C 外联/外泄 | 匿名托管 / 回连 / 凭据外泄 | `S_paste_host`、`S_exfil_endpoint`、`S_ip_literal_url`、`S_cred_harvest_egress` |
| D 持久化 | 自启/驻留写入 | `S_persistence_write`（bashrc/authorized_keys/cron/LaunchAgents/Run 键…） |
| B2 **prose 注入** | 自然语言指令操纵（劫持代理） | `S_instruction_override`（“忽略先前指令”）、`S_role_mode_hijack`（开发者模式/DAN）、`S_safety_neutralization`（关闭安全检查/“别告知用户”）、`S_covert_instruction`（隐蔽执行）、`S_data_exfil_instruction`（指令级读密钥并外发，ast01）、`S_conditional_trigger`（时间炸弹） |
| E 供应链/元数据/反序列化 | 弱修饰 | `S_unsafe_deser`(ast05)、`S_unpinned_dep`(ast02)、`S_impersonation`(ast04) |
| **manifest 结构化** | 解析 manifest.json/skill.json/frontmatter | `S_over_privileged`/`S_unrestricted_network`/`S_identity_file_write`(ast03)、`S_typosquat`/`S_metadata_mismatch`(ast04)、`S_weak_isolation`(ast06)、`S_update_drift`(ast07)、`S_cross_platform_reuse`(ast10) |
| F 混淆 | 修饰 + 还原 | `S_high_entropy_blob`、`S_zero_width`、`S_homoglyph`（西里尔/希腊同形字，**还原后回扫**揭出真实原语）、`S_decoded_payload`（base64/hex 解码后含执行原语） |
| L2 跨文件 | 分离式载荷 | `S_split_logic`（SKILL.md 干净但辅助脚本含原语） |

**prose 注入映射**：纯 prose 注入（无代码原语）→ **AST08**（符合 OWASP「Poor Scanning＝自然语言指令操纵」定义）；prose + 代码原语（如读密钥并 curl 外发）→ 由证据加权归类升为 **AST01**。这直接补上原引擎对“真实 agent-skill 主流攻击面”的盲区。

**混淆还原**：`normalize.deconfuse` 把同形字映回拉丁字母后重扫执行原语，使 `сurl … | bash`（西里尔 с）被识别为 `curl|bash`；`entropy.iter_decoded_candidates` 对 base64/hex blob 有界解码再扫 `PRIMITIVE_PATTERN`，揭出 `echo <blob> | base64 -d | bash` 中隐藏的载荷。

**manifest 结构化**：`manifest.parse` 容错解析 JSON 清单与 SKILL.md YAML frontmatter（解析失败回退原始文本子串扫描，绝不抛异常），`manifest.scan` 据 OWASP 每类的可静态信号产出 AST03/04/06/07/10 信号——这是原引擎完全缺失、同时压制召回与可解释性的关键缺口。结构类信号权重适中：单独命中通常落 `suspicious`（= 仅过度授权/更新漂移的灰类正确判定），但仍提供正确 AST 类别。

**共现（co-occurrence）**是降误报的关键：多数高危信号要求两类模式在 `window` 字符内同时出现（如「解码」近邻「执行」、「凭据读取」近邻「网络发送」、「强迫话术」近邻「下载二进制」），单独一个良性 token 不会触发。

**泛化举例**：数据集里的 `glot.io` 被抽象为「匿名/原始脚本托管类」（含 `*.vercel.app`/`*.workers.dev`/`pastebin/raw`/`transfer.sh` 等）；`openclaw` 解压口令被抽象为「密码保护压缩包+必须运行」；特定恶意 IP 被抽象为「IP 字面量 URL」。这样即便 holdout 换了品牌/域名/IP，行为特征依旧命中。

## 4. 评分与三档裁决

实现见 [engine/scoring.py](../engine/scoring.py)。

1. **去重**：每个信号 id 只计一次（防同一话术重复刷分，保特异度）。
2. **加权求和** `base = Σ weight`。
3. **协同加分**：A/B/C/D 中 ≥2 个不同 tier 触发 → `+SYNERGY_BONUS(15)`。这编码了“组合即恶意”——伪造前置(B)+外部托管(C)+解码执行(A) 远比任一单项危险。
4. **抑制**（`suppress.py`）：DeFi/安全工具语境扣分、私网/环回 IP 与官方域丢弃；但**确证 Tier‑A 链**（反弹 shell、解码执行、凭据外泄、持久化）设有**封底**，抑制不能把它压到恶意阈值以下。
5. `r = clamp(base + synergy − penalty, 0, 100)`。
6. **三档阈值**：`r<18` benign；`18≤r<45` suspicious；`r≥45` malicious。
7. **ML 召回增强**：冻结统计模型给出 `ml_score∈[0,1]`，当 `ml_score≥0.80` 且当前非 malicious 时**上调一档**。ML **只增不减、且永不单独定恶意**，避免对单活动过拟合直接误判。
8. **灰区语义门控**（`semantic.promote`）：仅当 verdict 为 `suspicious` 时，若“声称用途无害”（manifest 描述为格式化/笔记/转换等）却携带**强危害能力**（反弹 shell/解码执行/凭据外泄/指令级外发/隐藏解码载荷/`curl|bash`）→ 上调为 malicious。这就是 MalSkillBench 指出的「权限/行为是否被宣称用途证成」语义判别器，纯规则与词袋 ML 都抓不到。**只上调、不下调，任何异常即 no-op**；时间预算耗尽（`fast`）时跳过。另含可选的离线注入分类器钩子（`engine/models/` 存在 ONNX 时启用，缺省静默禁用 → 镜像零依赖、性能不受影响）。

**为何这样设阈值（对齐计分维度，并经 `calibrate.py` 在留出三类集上扫优）**：
- **F2 偏召回**：恶意阈 45 ≈ 单条强 A/B + 任一佐证即过线，协同加分保证真实杀链过线。
- **特异度**：良性顶 18 仍高于孤立弱/修饰信号，单弱信号留 benign（实测特异度 0.946，与 20 持平、无损）。
- **灰区(18–45)**：把 `BENIGN_MAX` 由 20 降到 18 在不损特异度的前提下把更多结构类灰样本从 benign 拉回 suspicious（F2_B 0.79→0.88）。
- **双重计分假设对冲**：官方对 `suspicious` 如何计分未知，`calibrate.py` 同时报告 F2_A（恶意为正）与 F2_B（恶意+可疑为正）并选稳健解。

阈值（18/45）经 [selftest/calibrate.py](../selftest/calibrate.py) 网格扫优选定，目标函数为 `0.5·F2_A + 0.3·F2_B + 0.2·特异度`（偏召回）。

## 5. AST 类别归类

实现见 [engine/categorize.py](../engine/categorize.py)。**证据加权选类**：取**最高权重触发信号**的类别为主类，平手再按 AST 严重度优先级、最后按信号 id 决定（确定性）。

> **为什么从“优先级表”改为“证据加权”**：旧版总取最高严重度类别，而 `ast01` 排第一——任何一个 ast01 弱信号都会压过一整簇 ast02/03/05 强证据，导致几乎一切都归 **AST01**，可解释性卡在 ~0.50（这正是原引擎可解释性失分主因）。改为“最高权重信号定类”后：依赖冒充为主→AST02、过度授权为主→AST03、反序列化→AST05、纯 prose 注入→AST08，而真正的高权重 RCE/外发仍正确归 AST01。留出集上可解释性由 0.50 升至 ~0.82。

- **AST09（无治理）永不作为独立类别输出**——治理/策略修饰，不构成可复现有害行为类别（符合赛事规则）。
- 内部小写 `ast01..ast10` 驱动选类/证据；**输出边界 `run_engine._to_ast_label` 转大写 `AST01..AST10`**，精确匹配 §3 可解释性评分；`scoring` 的证据排序与本选类同键（权重优先），保证 verdict/category/evidence 三者一致。
- benign verdict → `category=""`；ML‑only 正例（无规则信号）回退 `AST01`。

**OWASP Agentic Skills Top 10 对齐**（已核对官方 `OWASP/www-project-agentic-skills-top-10`）：AST01 恶意Skill / AST02 供应链 / AST03 过度授权 / AST04 不安全元数据 / **AST05 不安全反序列化** / AST06 弱隔离 / AST07 更新漂移 / AST08 弱扫描(自然语言指令操纵) / AST09 无治理(不输出) / AST10 跨平台复用。引擎对每一类（除 AST09）均有专属检测信号。

## 5.1 置信度（confidence，§3 必填字段）

实现见 `scoring.confidence`。confidence 表达对**裁决本身**的确定度（而非风险分 r 的线性映射），范围 `[0,1]`：

- **malicious**：随 r 从阈值 45 的 0.60 升至 r≥90 的 ~0.99。
- **benign**：随 r 从 0 的 0.95 降至阈值 20 的 0.55（越干净越自信）。
- **suspicious（灰区）**：固定 0.45，刻意低置信，呼应灰区的内在模糊。
- **ML 拉升的正例**：置信度抬到 ≥0.65（模型对正例形成佐证）。
- 边界兜底：空内容 benign→0.9；逐 skill 异常 suspicious→0.4。

## 6. 证据生成（中文）

实现见 [engine/evidence.py](../engine/evidence.py)，模板集中在 `constants.EVIDENCE_TEMPLATES`。

- 结构：①裁决框定句 ②按优先级取前 1–3 个触发信号，每个用模板 + **真实匹配片段**（折叠空白、≤80 字、`「」`包裹、绝不改写）③协同链说明 ④抑制降级说明 ⑤AST 归类说明。
- 片段是引擎实际命中的子串，主办方可据此回溯文件核验，最大化**可解释性**维度。
- benign 给诚实简短说明，**绝不编造指标**；空内容给“内容为空”说明。
- 硬上限 400 字，避免泄露超长 blob、保持信息密度。

## 7. 鲁棒性（operational_robustness）

- **每 skill 独立 try/except**：异常 → `suspicious + ast08 + 复核说明`，绝不中断整轮。
- **流式落盘（对齐 §4「超时按已完成部分计分」）**：`run_engine.run` 逐 skill 写出并按 `FLUSH_EVERY` 刷盘，即便 30 分钟墙上被杀，已完成的每一行都在盘上仍计分（旧版「结尾一次性原子写」在超时即丢失全部输出→0 分，已修正）。
- **全局时间预算守卫**：`time.monotonic` 追踪用时，超过 `MAX_RUNTIME_SECONDS`（28 min）后剩余样本走规则‑only 快路（跳过灰区语义/可选模型），保证整轮完成且每个 skill 都有结果行。
- **行数对账**：先 `discover_skills` 枚举全部子目录，逐个产出，保证 `输出行数 == skill 数`（空/不可读目录也出 benign 行）。
- **读上限**：单文件 ≤2 MiB、单 skill ≤8 MiB、扫描文本 ≤600k 字符，超出截断标记。
- **编码兜底**：字节读取，UTF‑8 失败转 `errors=replace`；NUL 比例 >1% 判二进制并跳过内容扫描（捆绑 `.exe/.dmg` 记为弱信号）。manifest 解析失败回退原始文本扫描，绝不抛异常。
- **确定性**：目录/文件名排序遍历、regex 文件序、固定 JSON 键序、`ensure_ascii=False`。
- **ReDoS 防护**：所有 regex 使用有界量词，无嵌套 `(.*)+`；同形字扫描与递归解码均有计数/字节上限。

## 8. 机器学习增强（混合路线）

- **训练（离线，仅开发机）**：[selftest/train_model.py](../selftest/train_model.py) 用 scikit‑learn 训练 `TF‑IDF(1–2gram, l2) + LogisticRegression(balanced)`。
- **去品牌**：向量化前 scrub 活动特异 token（见 `SCRUB`），让模型学**行为词**（curl/bash/base64/password/prerequisite…）而非品牌串。
- **多样化正类（关键提升）**：合成恶意语料 [selftest/gen_malicious.py](../selftest/gen_malicious.py) 扩到 16 个去品牌攻击原型，新增 **prompt 注入、指令级外泄、同形字 RCE、隐藏解码载荷、身份文件投毒** 等（覆盖 AST01/02/03/05/08/10），直接修复原引擎对 prose 注入等主流攻击面的召回盲区。
- **多样化负类**：并入 ~5000 条与训练活动无关的真实良性 SKILL.md（`LittleDinoC/agent-skills`），打破单活动过拟合。
- **真实标注校验**：`selftest/fetch_realbench.py` 拉取 `protectskills/MaliciousAgentSkillsBench`（157 例确认恶意，MIT）做类别分布校验——其分布（AST01≈71%、AST08/注入≈24%、AST03≈5%）印证本引擎的检测重心；公开仓库正文已脱敏，故用于校验而非检测训练。全部数据来源见 [docs/DATA_SOURCES.md](DATA_SOURCES.md)。
- **GroupKFold**：按 skill 家族分组交叉验证（~3864 家族），避免在近重复改包上自欺，给出诚实泛化估计。
- **冻结**：导出 `vocabulary/idf/coef/intercept/scrub/ngram_max` 到 [engine/model.json](../engine/model.json)。
- **运行时（纯 stdlib）**：[engine/ml.py](../engine/ml.py) 用纯 Python 复刻 TF‑IDF + 逻辑回归推理 → **镜像零三方依赖、完全确定性**。`train_model.py` 内置 parity check 校验纯 Python 推理与 sklearn 概率一致。
- **降级**：`model.json` 缺失/损坏时 `predict→0.0`，引擎自动退化为规则‑only 仍完全可用。

## 9. 已知局限与防过拟合声明

- 运行时载荷（仅在执行期从远端拉取的二进制）无法被静态分析穷尽——这是静态检测的固有边界；引擎以「下载+执行目的地+管道执行」组合特征逼近。
- 公开数据集为单活动，**样本内自测分数高估 holdout**。引擎的设计目标是泛化到行为类而非记忆该活动，自测报告对此明确警示。
- DeFi/安全工具是主要误报源，已通过 `suppress.py` 语境降权处理，并保留确证链封底以防漏报真实恶意。

## 10. 关键文件索引

| 文件 | 职责 |
|------|------|
| [engine/constants.py](../engine/constants.py) | 全部权重/阈值/regex/AST优先级/抑制表/manifest表/证据模板（唯一调参面） |
| [engine/signals.py](../engine/signals.py) | 编译信号、扫描 SkillDoc（regex + 同形字还原 + 递归解码 + manifest） |
| [engine/manifest.py](../engine/manifest.py) | manifest.json/skill.json/frontmatter 容错解析 + AST03/04/06/07/10 结构化信号 |
| [engine/scoring.py](../engine/scoring.py) | 加权+协同+抑制+ML融合+灰区语义+三档裁决 |
| [engine/semantic.py](../engine/semantic.py) | 灰区门控：意图×能力不符提升 + 可选离线注入分类器（缺省 no-op） |
| [engine/normalize.py](../engine/normalize.py) | NFKC/零宽剥离/同形字检测与还原(deconfuse) |
| [engine/categorize.py](../engine/categorize.py) | 证据加权(最高权重信号)选单一 AST 主类 |
| [engine/evidence.py](../engine/evidence.py) | 中文证据生成 |
| [engine/run_engine.py](../engine/run_engine.py) | 入口、遍历、流式写出、时间预算、崩溃隔离 |
| [engine/ml.py](../engine/ml.py) | 冻结模型纯 stdlib 推理 |
| [engine/wordpiece.py](../engine/wordpiece.py) | 可选 ONNX 路径的纯 stdlib WordPiece 分词器（无模型时不加载） |
