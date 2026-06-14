# 训练/评估数据来源清单（已逐一核验可访问）

> 每条均通过实际拉取页面/rows API 核验存在与可加载，非凭记忆罗列。用于打破单活动过拟合。
> 当前已接入：`yoonholee/agent-skill-malware`（主语料）+ `LittleDinoC/agent-skills`（多样化良性，训练负类 + 留出泛化评估）。其余为后续可选增量。

## A. 同形态 agent-skill 语料（最相关）

| 数据集 | 平台 | 内容 | 类别 | 访问 | 价值 | 状态 |
|------|------|------|------|------|:--:|------|
| `yoonholee/agent-skill-malware` | HF | 347 条 `content`(SKILL.md)+label | 恶/良 | rows API,无需鉴权 | 主语料 | ✅ 已用 |
| `LittleDinoC/agent-skills` | HF | **61,650** 条真实 SKILL.md(`content`) | 良性 | rows API/parquet,MIT | ⭐ 负类与泛化 | ✅ 已用(取样3000) |
| `AgentSkillPrivacy/SkillLeakBench` | HF | 520 技能,83 恶意+437 脆弱+分类法 | 标注 | rows API(**仅元数据,无全文**) | 标签/模式词典 | 待用 |
| `protectskills/MaliciousAgentSkillsBench` | GH | 98k 清单 + **157 确认恶意**(Pattern/Severity) | 标注 | `data/malicious_skills.csv`,MIT(**正文脱敏**) | 类别分布校验 | ✅ 已用(`fetch_realbench.py`,类别分布校验) |
| `snyk-labs/toxicskills-goof` | GH | 10 个真实恶意 SKILL.md(独立活动) | 恶意 | GitHub API/raw | 独立真实检验 | ✅ 已用 |
| 合成恶意(`gen_malicious.py`) | 本地 | **960** 去品牌样例,16 原型,覆盖 AST01/02/03/05/08/10(含 prose 注入/同形字/解码载荷/身份投毒) | 恶意 | 本地生成(确定性) | ⭐ 正类多样化 | ✅ 已用(768训练+192留出) |
| 合成灰类(`gen_malicious.py`) | 本地 | 160 结构类样例(过度授权/仿冒/弱隔离/更新漂移) | 可疑 | 本地生成 | 类别+灰区评估 | ✅ 已用(留出) |
| Datadog `malicious-software-packages-dataset` | GH | 28k 恶意包(含 **AI-Skills 切片**+npm/PyPI) | 恶意 | git clone,zip 口令`infected` | AST02 供应链 | 待用 |

## B. 批量真实良性技能（负类，GitHub 可整库 clone）

| 仓库 | 规模 | 许可 | 价值 |
|------|------|------|:--:|
| `anthropics/skills` | 官方,目录化 SKILL.md | 多为 Apache‑2.0（4 个文档技能为 source‑available） | ⭐5 权威负类 |
| `alirezarezvani/claude-skills` | ~337,17 领域 | MIT | ⭐5 一次 clone 量大 |
| `ComposioHQ/awesome-claude-skills` | 大量(含 78 SaaS) | Apache‑2.0 | ⭐5 真实可整库 |
| `K-Dense-AI/scientific-agent-skills` | ~140 科研域 | MIT | 4 词汇多样性 |
| `addyosmani/agent-skills` | 24 工程 | MIT | 4 高质量 |
| `gl0bal01/malware-analysis-claude-skills` | 6 防御技能 | MIT | 3 **硬负样本**(安全主题但良性) |

> 用法：整库 clone → 取各技能目录的 `SKILL.md` 作良性负类（注意跨仓库去重，部分镜像 `anthropics/skills`）。

## C. 迁移/辅助信号（NL 恶意 / 行为 / 供应链，非同形态）

| 数据集 | 平台 | 内容 | 许可 | 价值 |
|------|------|------|------|:--:|
| `TrustAIRLab/in-the-wild-jailbreak-prompts` | HF | 15,140(1,405 越狱) | MIT | NL 社工信号 | ✅ 已用(854 正类) |
| `deepset/prompt-injections` | HF | 662,`text`/`label` | Apache‑2.0 | 注入信号(小) | ✅ 已用(255 正类) |
| `jackhhao/jailbreak-classification` | HF | 1,306,均衡 | Apache‑2.0 | 注入信号 | ✅ 已用(185 正类) |
| `darkknight25/Reverse_Shell_Payloads_Dataset` | HF | 反弹shell 载荷(含`obfuscated`旗标) | MIT | 行为/混淆信号 |
| `bmlien/mitre-bash-commands` | HF | 700,ATT&CK 标注 | 未注明 | 行为词典 |
| `aelhalili/bash-commands-dataset` | HF | 840 良性命令 | — | 行为负类配重 |
| `Fa2y/Malicious-PowerShell-Dataset` | GH | 恶意 .ps1(~25% 混淆) | 未注明(慎用) | 行为正类 |
| `cyberprince/reverse-shell-payloads-dataset` | Kaggle | 多语言反弹shell | MIT | 行为(**需 Kaggle token**) |

## D. 已核验但不可用（诚实记录）

- `TongxiQu/agent-skill-malware` — 与 `yoonholee` **完全重复**(347 同源)，跳过。
- SkillSieve 仓库(`xiaohou521/skillsieve`,arxiv 2604.06550) — **GitHub 404**，基准未公开。
- arxiv 2602.06547「野外恶意 agent 技能」— 工件**尚未公开**(承诺 Zenodo DOI)。
- `obaydata/claude-agent-skills-benchmark`(2 条 PDF)、`filizOsMini/agent-skills`(1 条玩具)、`ShawnLi02/FORTIS_*`(无可加载表) — 无用。

## E. 凭据/获取提示

- HF(A/C 多数)：无需鉴权，`load_dataset(...)` 或 rows API；可选 HF token 提速。
- Kaggle(C 部分)：需账号 + `~/.kaggle/kaggle.json`，`kaggle datasets download -d <slug>`。
- GitHub(B、部分 A)：`git clone`；Datadog zip 口令 `infected`。

> **C 组接入（2026‑06‑14）**：`selftest/fetch_inject.py` 取上述三个 HF 注入/越狱语料的**真实攻击话术**，把每条 NL prompt（正、负）**包裹进去品牌 SKILL.md 模板**（复用 `gen_malicious` 脚手架，正负同壳→壳标签中性，避免「短祈使句=恶意」的风格泄漏），正类→malicious、负类→benign。共 1294 正类(deepset255+jackhhao185+in‑the‑wild854)+1197 负类；落 `inject_real_train.jsonl.gz`(2233=1036 mal+1197 ben)+`inject_real_eval.jsonl.gz`(258 留出正类)。代理极不稳(SSL EOF/429)，靠 10 次指数退避重试拉全；全程 gzip 内存处理(Defender 安全)。目的：把冻结 ML 从「背合成指纹」转向「学真实注入语言」。

## F. 接入脚本

- `selftest/fetch_extra.py [n]` — 取 `LittleDinoC/agent-skills` 多样化良性，分训练扩充/留出(固定首 1000)两份（gz）。
- `selftest/gen_malicious.py [n]` — 生成去品牌合成恶意（覆盖 AST01/02/05/08/10），分训练/留出。
- `selftest/fetch_malicious_real.py` — 取 `snyk-labs/toxicskills-goof` 真实恶意（独立活动检验）。
- `selftest/eval_benign.py` — 留出多样化良性误报率/特异度，并归因到具体信号（用于定位过度触发规则）。
- `selftest/eval_malicious.py` — 留出合成 + 真实恶意召回（按攻击类型），用于定位漏检。
- `selftest/train_model.py` — 自动并入 `benign_diverse_train.jsonl.gz` + `malicious_synth_train.jsonl.gz` 重训并冻结 `model.json`（GroupKFold 诚实评估 + parity 校验）。
- `selftest/fetch_realbench.py` — 取 `protectskills/MaliciousAgentSkillsBench` 的 157 例确认恶意标签（Pattern→AST 映射），内存解析 gz 落盘，用于类别分布校验。
- `selftest/fetch_inject.py` — 取 `deepset/prompt-injections`+`jackhhao/jailbreak-classification`+`TrustAIRLab/in-the-wild-jailbreak-prompts` 真实注入/越狱话术，包裹进去品牌 SKILL.md（正负同壳），分训练增强/留出正类两份（gz）。HF splits 自动发现 + 10 次退避重试。
- `selftest/eval_official_like.py` — 官方式留出评测：三类混淆矩阵 + F2(两种 suspicious 计分假设) + 类别精确匹配 + 完成率/时延（统一标尺）。
- `selftest/calibrate.py` — 阈值网格扫优（BENIGN_MAX/MAL_MIN），目标 `0.5·F2_A+0.3·F2_B+0.2·特异度`（偏召回），选定 18/45。

## G. 设计所依据的研究/开源（方法论出处）

> 以下为本次能力升级（prose 注入检测、manifest 结构化、混淆还原、灰区语义门控、阈值标定）的研究依据，便于复核/whitepaper。

- **OWASP Agentic Skills Top 10**（`OWASP/www-project-agentic-skills-top-10`，CC‑BY‑SA‑4.0）— 权威 AST01–10 定义与每类可静态检测信号（AST03 通配权限/`network:true`/写 SOUL.md·MEMORY.md·AGENTS.md；AST05 不安全反序列化；AST07 语义版本而非 content_hash；AST08 自然语言指令操纵）。引擎类别与之逐一对齐。
- **SkillSieve**（arXiv 2604.06550）— 分层 triage（L1 纯静态即 0.989 召回）启发本引擎「召回向静态层」+ 灰区门控（L1→L2）。
- **MalSkillBench**（arXiv 2606.07131）— 指出纯规则/静态在指令级注入上召回崩塌、难点是「权限/行为是否被宣称用途证成」的语义关系 → 据此实现 `semantic.py` 意图×能力不符判别。
- **Snyk ToxicSkills**（snyk.io/blog/toxicskills…）— 91% 恶意技能将 prompt injection 与代码结合、具体 prose 触发语 → prose 注入信号集来源。
- **MaliciousAgentSkillsBench**（`protectskills/…`，MIT）— 157 例确认恶意的真实类别分布校验。
