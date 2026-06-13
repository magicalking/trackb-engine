# 提交与打包指南 — 赛道B

## 0. 提交清单（对照赛事要求）

| 内容 | 本仓库对应 | 状态 |
|------|-----------|------|
| 容器镜像（固定 `image_digest: sha256:…`） | `docker/Dockerfile` 构建 | 见 §2 |
| 存储引用 `image_ref` | 推送到镜像仓库后取得 | 见 §2 |
| 源代码（供审查） | `engine/` + `selftest/` | ✅ |
| 设计说明 | [docs/DESIGN.md](DESIGN.md) | ✅ |
| 自测报告（deny-all/无出网下跑通） | [docs/SELFTEST_REPORT.md](SELFTEST_REPORT.md) | ✅ |
| 性能报告（运行时间/峰值内存对照阈值） | [docs/PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md) | ✅ |

## 1. 运行接口（与排名一致）

- 输入：`/data/skills/{skill_id}/`（每个子目录一个 skill，内含 `SKILL.md` 及可选辅助文件）
- 输出：`/output/results.jsonl`，每行一个 JSON 对象，字段**仅**（接口规范 §3）：
  - `skill_id`、`verdict`（benign/suspicious/malicious）、`confidence`（0.0–1.0）、`category`（大写 `AST01..AST10`；良性为空串 `""`）、`evidence`（中文证据）
- **不输出**兼容模式字段（`evidence_score`/`consistency_score`/`schema_valid`/`vocabulary_keyword_found`）。
- **不输出** `AST09`（治理修饰，非独立有害类别）。

## 2. 构建镜像并获取 digest

> 本机当前未安装 Docker。以下命令在任意装有 Docker 的环境执行（在仓库根目录 `trackb-engine/`）。

```bash
# 1) 构建（确定性、离线运行；构建阶段不需要联网装包）
docker build -f docker/Dockerfile -t trackb-engine:1.0.0 .

# 2) 本地无出网自测（模拟排名环境）
docker run --rm --network none \
  -v "$PWD/selftest/work/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  trackb-engine:1.0.0
cat out/results.jsonl | head

# 3) 推送到你的镜像仓库，获得带 digest 的引用
docker tag trackb-engine:1.0.0 <registry>/<repo>/trackb-engine:1.0.0
docker push <registry>/<repo>/trackb-engine:1.0.0

# 4) 取内容摘要 sha256（写入提交表单的 image_digest）
docker inspect --format='{{index .RepoDigests 0}}' <registry>/<repo>/trackb-engine:1.0.0
#   形如 <registry>/<repo>/trackb-engine@sha256:abcd... -> 取 sha256:abcd...
```

提交表单：`image_digest` 填 `sha256:…`；`image_ref` 填存储 URI/拉取引用（`<registry>/<repo>/trackb-engine@sha256:…`）。

> 提示：可变 tag 不能作为排名依据，务必提交 **digest**。同一 digest + 同一 scorer 快照重跑不重复扣排名配额。

## 3. 不依赖 Docker 的本地验证（仅需 Python 3.11）

```powershell
# 下载自测语料（唯一联网步骤）
python selftest/fetch_dataset.py
# 训练并冻结 ML 模型 -> engine/model.json（需 pip install scikit-learn，仅开发用）
python selftest/train_model.py
# 端到端自测：指标 + schema 校验 + 确定性 + 性能
python selftest/run_selftest.py
# 鲁棒性边界用例
python selftest/run_robustness.py
# 直接按排名接口跑
python -m engine.run_engine --input selftest/work/skills --output out/results.jsonl
```

> `engine/model.json` 应随镜像一并提交（已 `COPY engine/ /app/engine/`）。若未训练，引擎自动退化为规则‑only 仍可运行，但召回略降。

## 4. 配额与无效提交自检（上传前）

- 赛道B：10 次排名提交/队/天；同 digest + 同快照重跑不重复扣次。
- 上传前自检：
  - [ ] `results.jsonl` 每行合法 JSON、UTF‑8、非空行
  - [ ] 仅 5 个字段（`skill_id/verdict/confidence/category/evidence`），无兼容模式历史分数字段
  - [ ] `category` 为大写 `AST01..AST10` 或空串，且不含 `AST09`；`confidence` 在 0.0–1.0
  - [ ] 镜像用 **digest** 提交（非可变 tag）
  - [ ] 镜像在 `--network none` 下能跑通
  - [ ] 性能在 `t_max=7200s`/`m_max=16384MB` 内（实测见性能报告）

## 5. 申诉

对结果异议：平台首页底部邮箱申诉，提供 `attempt_id` 与理由。申诉触发复核/重算，不保证改分。

## 6. 安全与合规

- 所有 skill 样本视为不可信，仅在隔离环境处理；引擎本身不执行样本内任何命令，只做静态文本分析。
- 引擎运行时零网络、零外部 LLM/API，符合无出网排名约束。
