# Splunk Security Content → Sigma Converter

将 [Splunk security_content](https://github.com/splunk/security_content) 检测规则批量转换为 [Sigma](https://github.com/SigmaHQ/sigma) 规则。

## 转换统计

| 指标 | 数量 | 比例 |
|------|------|------|
| 总规则数 | 2,117 | 100% |
| 成功转换 | 1,917 | 90.6% |
| 跳过 | 200 | 9.4% |

跳过的规则均不适合 Sigma 单事件匹配模型：统计基线（eventstats/streamstats）、时间窗口聚合（bucket/bin）、多事件关联（transaction）、元关联评分（Risk datamodel）、外部数据引用（inputlookup）。

## 快速开始

```bash
# 一键更新 + 转换
./update.sh

# 或者手动分步执行
git clone https://github.com/splunk/security_content.git /tmp/security_content
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## 更新流程

```bash
./update.sh          # 拉取最新 security_content 并转换，显示增量
./update.sh --no-pull  # 跳过 git pull，仅重新转换
```

GitHub Actions 每天 UTC 6:00 自动运行，检测上游 security_content 变更后自动提交更新。

## 架构

```
splunk_detection.yml
       │
       ▼
spl_parser.py      ← 手写 Tokenizer + 递归下降解析器，构建 SPL AST
       │
       ▼
macro_resolver.py  ← 加载 171 个宏，分类：数据源 / 进程过滤 / 工具 / 复杂
       │
       ▼
classifier.py      ← 判断可转换性：提取首段搜索条件，忽略后续复杂处理
       │
       ▼
sigma_generator.py ← CIM→Sigma 字段映射，构建 SigmaRule，输出 YAML
       │
       ▼
   output/          ← 按 SigmaHQ 规范组织的目录结构
```

核心原则：不用正则解析 SPL，不用硬编码字符串替换。通过 AST 遍历完成所有转换。

## 输出结构

按 [SigmaHQ 规范](https://github.com/SigmaHQ/sigma/tree/master/rules) 组织：

```
output/
├── windows/{process_creation,registry/registry_event,builtin/*,file,...}
├── linux/{process_creation,auditd,file_event}
├── cloud/{aws/*,azure,m365,gcp}
├── network/{dns,cisco,zeek,suricata}
├── web/{webserver_generic,proxy_generic}
├── identity/{okta,cisco_duo}
└── application/{github,splunk,crowdstrike}
```

## 文件

| 文件 | 职责 |
|------|------|
| `main.py` | 入口，编排转换流水线 |
| `spl_parser.py` | Tokenizer + 递归下降 SPL 解析器 → AST |
| `macro_resolver.py` | 加载/分类/展开宏 |
| `mappings.py` | CIM→Sigma 字段映射 + 数据模型→logsource |
| `classifier.py` | 判断可转换性，提取搜索条件 |
| `sigma_generator.py` | 构建 SigmaRule，输出 YAML，管理目录 |
| `update.sh` | 拉取最新 security_content + 转换 + 增量统计 |
| `requirements.txt` | pyyaml, pysigma, lark |
