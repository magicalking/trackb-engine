# 设计说明 — 赛道B 蓝队检测引擎

## 1. 目标与约束

构建一个**离线、确定性**的 agent skill 检测引擎，满足赛道B排名接口与约束：

| 约束 | 实现 |
|------|------|
| 输入 `/data/skills/{skill_id}/` | `loader.discover_skills` 遍历子目录 |
| 输出 `/output/results.jsonl` | `run_engine.run` 原子写出，每行一对象 |
| 字段仅 `skill_id/verdict/confidence/category/evidence`（接口规范 §3） | `run_engine._dump_line` 固定键序 |
| 无出网、禁外部 LLM/API | 引擎只 `import` 标准库；`urllib` 仅存在于 `selftest/fetch_dataset.py` |
| 确定性 | 排序遍历、`PYTHONHASHSEED=0`、冻结权重、无 `random`/时间依赖 |
| 性能 `t_ref=600s`/`m_ref=4096MB` | 单遍扫描、预编译有界 regex、流式写出 |

排名只看**密封 holdout**，且公开数据集 `yoonholee/agent-skill-malware` 是**单一 2026‑02 ClawHub 活动**。因此核心设计原则：**把攻击模式抽象为「行为类」，绝不硬编码品牌串**（`openclaw`/特定账号/特定 IP/特定域名字面量）。`engine/` 下任何文件都不含这些活动特异字符串（负控见自测）。

## 2. 总体架构

分层三段流水线（借鉴 SkillSieve 的分层 triage，但**全确定性、无 LLM**）：

```
Layer 0  加载/归一化   loader + normalize + entropy
Layer 1  静态行为信号  signals  ->  去重加权
Layer 1.5 误报抑制     suppress  ->  扣分 / 丢弃 / 确证链封底
Layer 2  确定性语义    signals(跨文件: split-logic)  +  ml(冻结统计模型)
裁决                  scoring  ->  r 分数 -> 三档 verdict（含灰区）+ confidence
归类                  categorize -> 单一 AST 主类（AST 优先级表）
证据                  evidence  -> 中文 evidence + 真实片段引用
输出边界              run_engine -> category 转大写 ASTxx/空串 + 5 字段固定键序
```

数据流：`run_engine.analyze_skill` → `loader.load_skill` → `signals.scan` → `scoring.score`（内部调用 `suppress` + `ml`）→ `categorize` → `evidence.build` → `run_engine._to_ast_label` + `scoring.confidence`。

## 3. 检测信号（行为类，泛化非品牌）

信号集中定义于 [engine/constants.py](../engine/constants.py) 的 `SIGNALS`，编译于 [engine/signals.py](../engine/signals.py)。分 6 个 tier，其中 A–D 参与「协同加分」：

| Tier | 含义 | 代表信号（行为类） |
|------|------|-------------------|
| A 执行原语 | RCE / 反弹 shell / 解码执行 | `S_pipe_to_shell`（`curl…\|bash`）、`S_decode_pipe_shell`、`S_decode_exec_call`、`S_reverse_shell`、`S_dynamic_exec` |
| B 伪造前置社工 | 虚假依赖诱导下载执行 | `S_fake_prereq_phrase`（强迫话术×下载指令共现）、`S_external_binary_run`、`S_password_archive` |
| C 外联/外泄 | 匿名托管 / 回连 / 凭据外泄 | `S_paste_host`、`S_exfil_endpoint`、`S_ip_literal_url`、`S_cred_harvest_egress` |
| D 持久化 | 自启/驻留写入 | `S_persistence_write`（bashrc/authorized_keys/cron/LaunchAgents/Run 键…） |
| E 供应链/元数据/反序列化 | 弱修饰 | `S_unsafe_deser`(ast05)、`S_unpinned_dep`(ast02)、`S_impersonation`(ast04) |
| F 混淆 | 修饰信号 | `S_high_entropy_blob`、`S_zero_width` |
| L2 跨文件 | 分离式载荷 | `S_split_logic`（SKILL.md 干净但辅助脚本含原语） |

**共现（co-occurrence）**是降误报的关键：多数高危信号要求两类模式在 `window` 字符内同时出现（如「解码」近邻「执行」、「凭据读取」近邻「网络发送」、「强迫话术」近邻「下载二进制」），单独一个良性 token 不会触发。

**泛化举例**：数据集里的 `glot.io` 被抽象为「匿名/原始脚本托管类」（含 `*.vercel.app`/`*.workers.dev`/`pastebin/raw`/`transfer.sh` 等）；`openclaw` 解压口令被抽象为「密码保护压缩包+必须运行」；特定恶意 IP 被抽象为「IP 字面量 URL」。这样即便 holdout 换了品牌/域名/IP，行为特征依旧命中。

## 4. 评分与三档裁决

实现见 [engine/scoring.py](../engine/scoring.py)。

1. **去重**：每个信号 id 只计一次（防同一话术重复刷分，保特异度）。
2. **加权求和** `base = Σ weight`。
3. **协同加分**：A/B/C/D 中 ≥2 个不同 tier 触发 → `+SYNERGY_BONUS(15)`。这编码了“组合即恶意”——伪造前置(B)+外部托管(C)+解码执行(A) 远比任一单项危险。
4. **抑制**（`suppress.py`）：DeFi/安全工具语境扣分、私网/环回 IP 与官方域丢弃；但**确证 Tier‑A 链**（反弹 shell、解码执行、凭据外泄、持久化）设有**封底**，抑制不能把它压到恶意阈值以下。
5. `r = clamp(base + synergy − penalty, 0, 100)`。
6. **三档阈值**：`r<20` benign；`20≤r<45` suspicious；`r≥45` malicious。
7. **ML 召回增强**：冻结统计模型给出 `ml_score∈[0,1]`，当 `ml_score≥0.80` 且当前非 malicious 时**上调一档**（benign→suspicious→malicious）。ML **只增不减、且永不单独定恶意**，避免对单活动过拟合直接误判，最坏只把良性推到“可疑”（半计分），对特异度伤害可控。

**为何这样设阈值**（对齐计分维度）：
- **F2 偏召回**：恶意阈 45 ≈ 单条强 A/B + 任一佐证即过线，协同加分保证真实杀链过线。
- **特异度**：良性顶 20 高于孤立弱/修饰信号（未固定依赖 14、孤立熵 blob 14），单弱信号留 benign。
- **灰区(20–45) 故意拉宽**：半计分规则下，对真正模糊样本给 `suspicious` 是正期望（保证 0.5 分，优于乱猜 malicious 的 0 分＋特异度惩罚），直接服务 `gray_handling`。

阈值（20/45）是**唯一调参旋钮**，`run_selftest.py` 在 ±5 网格上扫优并记录所选（见自测报告）。

## 5. AST 类别归类

实现见 [engine/categorize.py](../engine/categorize.py)。从触发信号集合按**优先级表**取最高严重度的单一类别：

`ast01 恶意Skill > ast05 反序列化 > ast02 供应链 > ast04 元数据 > ast03 过度授权 > ast10 跨平台复用 > ast08 弱扫描 > ast06 弱隔离 > ast07 更新漂移`

- **AST09（无治理）永不作为独立类别输出**——它是治理/策略修饰，不构成可复现有害行为类别（符合赛事规则）。
- 数据集主体（伪造前置二进制社工 + RCE + 凭据窃取 + 反弹 shell）归 **AST01**，与 OWASP 定义一致。
- 内部以小写 `ast01..ast10` 驱动优先级/证据；**输出边界 `run_engine._to_ast_label` 统一转大写 `AST01..AST10`**，以精确匹配 §3 可解释性评分。
- benign verdict → `category=""`（良性无 AST 主类）；ML‑only 正例（无规则信号）回退到 `AST01`。

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
- **行数对账**：先 `discover_skills` 枚举全部子目录，逐个产出，保证 `输出行数 == skill 数`（空/不可读目录也出 benign 行）。
- **读上限**：单文件 ≤2 MiB、单 skill ≤8 MiB、扫描文本 ≤600k 字符，超出截断标记。
- **编码兜底**：字节读取，UTF‑8 失败转 `errors=replace`；NUL 比例 >1% 判二进制并跳过内容扫描（捆绑 `.exe/.dmg` 记为弱信号）。
- **确定性**：目录/文件名排序遍历、regex 文件序、固定 JSON 键序、`ensure_ascii=False`、临时文件 `os.replace` 原子落盘。
- **ReDoS 防护**：所有 regex 使用有界量词，无嵌套 `(.*)+`。

## 8. 机器学习增强（混合路线）

- **训练（离线，仅开发机）**：[selftest/train_model.py](../selftest/train_model.py) 用 scikit‑learn 训练 `TF‑IDF(1–2gram, l2) + LogisticRegression(balanced)`。
- **去品牌**：向量化前 scrub 活动特异 token（见 `SCRUB`），让模型学**行为词**（curl/bash/base64/password/prerequisite…）而非品牌串。
- **多样化负类**：并入 2000 条与训练活动无关的真实良性 SKILL.md（`LittleDinoC/agent-skills`），打破单活动过拟合，使 ML 不再把常规安装/配置话术误升级。全部数据来源见 [docs/DATA_SOURCES.md](DATA_SOURCES.md)。
- **GroupKFold**：按 skill 家族分组交叉验证（1910 家族），避免在近重复改包上自欺，给出诚实泛化估计。
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
| [engine/constants.py](../engine/constants.py) | 全部权重/阈值/regex/AST优先级/抑制表/证据模板（唯一调参面） |
| [engine/signals.py](../engine/signals.py) | 编译信号、扫描 SkillDoc |
| [engine/scoring.py](../engine/scoring.py) | 加权+协同+抑制+ML融合+三档裁决 |
| [engine/categorize.py](../engine/categorize.py) | 单一 AST 主类选择（小写，输出边界转大写 category） |
| [engine/evidence.py](../engine/evidence.py) | 中文证据生成 |
| [engine/run_engine.py](../engine/run_engine.py) | 入口、遍历、原子写出、崩溃隔离 |
| [engine/ml.py](../engine/ml.py) | 冻结模型纯 stdlib 推理 |
