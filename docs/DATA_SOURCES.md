# 训练/评估数据来源清单（已逐一核验可访问）

> 每条均通过实际拉取页面/rows API 核验存在与可加载，非凭记忆罗列。用于打破单活动过拟合。
> 当前已接入：`yoonholee/agent-skill-malware`（主语料）+ `LittleDinoC/agent-skills`（多样化良性，训练负类 + 留出泛化评估）。其余为后续可选增量。

## A. 同形态 agent-skill 语料（最相关）

| 数据集 | 平台 | 内容 | 类别 | 访问 | 价值 | 状态 |
|------|------|------|------|------|:--:|------|
| `yoonholee/agent-skill-malware` | HF | 347 条 `content`(SKILL.md)+label | 恶/良 | rows API,无需鉴权 | 主语料 | ✅ 已用 |
| `LittleDinoC/agent-skills` | HF | **61,650** 条真实 SKILL.md(`content`) | 良性 | rows API/parquet,MIT | ⭐ 负类与泛化 | ✅ 已用(取样3000) |
| `AgentSkillPrivacy/SkillLeakBench` | HF | 520 技能,83 恶意+437 脆弱+分类法 | 标注 | rows API(**仅元数据,无全文**) | 标签/模式词典 | 待用 |
| `ProtectSkills/MaliciousAgentSkillsBench` | HF+GH | MalSkillBench:98k 清单+157 恶意模式 | 标注 | CSV(**正文需按URL外取,部分脱敏**) | 恶意模式 | 待用(离线不便) |
| `snyk-labs/toxicskills-goof` | GH | 10 个真实恶意 SKILL.md(独立活动) | 恶意 | GitHub API/raw | 独立真实检验 | ✅ 已用 |
| 合成恶意(`gen_malicious.py`) | 本地 | 600 去品牌样例,覆盖 AST01/02/05/08/10 | 恶意 | 本地生成(确定性) | ⭐ 正类多样化 | ✅ 已用(480训练+120留出) |
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
| `TrustAIRLab/in-the-wild-jailbreak-prompts` | HF | 15,140(1,405 越狱) | MIT | NL 社工信号 |
| `deepset/prompt-injections` | HF | 662,`text`/`label` | Apache‑2.0 | 注入信号(小) |
| `jackhhao/jailbreak-classification` | HF | 1,306,均衡 | Apache‑2.0 | 注入信号 |
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

## F. 接入脚本

- `selftest/fetch_extra.py [n]` — 取 `LittleDinoC/agent-skills` 多样化良性，分训练扩充/留出(固定首 1000)两份（gz）。
- `selftest/gen_malicious.py [n]` — 生成去品牌合成恶意（覆盖 AST01/02/05/08/10），分训练/留出。
- `selftest/fetch_malicious_real.py` — 取 `snyk-labs/toxicskills-goof` 真实恶意（独立活动检验）。
- `selftest/eval_benign.py` — 留出多样化良性误报率/特异度，并归因到具体信号（用于定位过度触发规则）。
- `selftest/eval_malicious.py` — 留出合成 + 真实恶意召回（按攻击类型），用于定位漏检。
- `selftest/train_model.py` — 自动并入 `benign_diverse_train.jsonl.gz` + `malicious_synth_train.jsonl.gz` 重训并冻结 `model.json`。
