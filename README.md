# Track B 蓝队检测引擎 (trackb-engine)

离线、确定性的 AI agent skill 恶意检测引擎。对每个 skill 按赛道B接口规范 §3 输出 `skill_id / verdict / confidence / category / evidence`（`category` 为大写 OWASP AST 主类 `AST01..AST10`，良性为空串），面向「AI 安全 Skill 挑战赛 · 赛道B」评测接口。

- **离线 / 确定性**：运行时只用 Python 标准库，无网络、无外部 LLM/API、无随机性。
- **混合检测**：行为类规则核心（证据 + AST 归类 + 鲁棒性）＋ 冻结的轻量统计模型（召回增强，纯 stdlib 推理）。
- **抗过拟合**：信号是「行为类」而非品牌串；ML 训练前去品牌、按家族 GroupKFold 验证。

## 快速开始（仅需 Python 3.11）

```powershell
python selftest/fetch_dataset.py        # 下载主自测语料（联网）
python selftest/fetch_extra.py 3000      # 下载多样化良性(LittleDinoC) 训练扩充+留出评估（联网）
pip install scikit-learn                 # 仅训练用，不进镜像
python selftest/train_model.py           # 训练并冻结 -> engine/model.json（自动并入多样化负类）
python selftest/run_selftest.py          # 数据集自测：指标/schema/确定性/性能
python selftest/eval_benign.py           # 多样化良性留出：误报率/特异度泛化评估
python selftest/run_robustness.py        # 边界鲁棒性用例
```

数据来源清单见 [docs/DATA_SOURCES.md](docs/DATA_SOURCES.md)。

按排名接口直接运行：

```powershell
python -m engine.run_engine --input <skills_root> --output <results.jsonl>
```

## 容器（提交用）

```bash
docker build -f docker/Dockerfile -t trackb-engine:1.0.0 .
docker run --rm --network none -v "$PWD/skills:/data/skills:ro" -v "$PWD/out:/output" trackb-engine:1.0.0
```

获取 digest 与提交细节见 [docs/SUBMISSION.md](docs/SUBMISSION.md)。

## 目录结构

```
engine/        运行时引擎（纯 stdlib）
  constants.py   唯一调参面：权重/阈值/regex/AST优先级/抑制表/证据模板
  loader.py      skill 发现与健壮加载
  normalize.py   NFKC 归一 + 零宽字符检测
  entropy.py     高熵 blob 检测
  signals.py     行为类信号编译与扫描
  suppress.py    误报抑制（DeFi/安全工具/官方域/确证链封底）
  ml.py          冻结模型的纯 stdlib TF-IDF + 逻辑回归推理
  scoring.py     加权+协同+抑制+ML融合+三档裁决
  categorize.py  单一 AST 主类选择（AST 优先级表），输出边界转大写 category
  evidence.py    中文 evidence 生成
  run_engine.py  入口：遍历、原子写出、崩溃隔离
  model.json     冻结 ML 权重（train_model.py 产物）
selftest/      自测/训练/鲁棒性脚本（含唯一的联网脚本）
docker/        Dockerfile + entrypoint
docs/          DESIGN / SELFTEST_REPORT / PERFORMANCE_REPORT / SUBMISSION
```

## 文档

- 设计说明：[docs/DESIGN.md](docs/DESIGN.md)
- 自测报告：[docs/SELFTEST_REPORT.md](docs/SELFTEST_REPORT.md)
- 性能报告：[docs/PERFORMANCE_REPORT.md](docs/PERFORMANCE_REPORT.md)
- 提交指南：[docs/SUBMISSION.md](docs/SUBMISSION.md)

## 输出示例

```json
{"skill_id":"demo-001","verdict":"malicious","confidence":0.99,"category":"AST01","evidence":"判定为恶意：检测到可复现的有害行为指标。以“必须先安装/运行某前置程序，否则无法工作”的话术（「will not work without our agent」）制造虚假依赖… 归类：恶意 Skill (Malicious Skills)。"}
```

> 安全提醒：所有 skill 样本视为不可信。引擎只做静态文本分析，**绝不执行**样本内任何命令。
