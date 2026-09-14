# 语义文档：dsh-cyber-range（OverTheWire 靶场攻坚工具集）

| 项 | 值 |
|----|----|
| 能力名 | dsh-cyber-range（插件内 `name = 'cyber-range'`；组合行 id `agent-cyber-range`） |
| 主副本路径 | `self-plugins/dsh-cyber-range/docs/semantic.md` |
| 实现落点 | `self-plugins/dsh-cyber-range/src/index.ts` |
| 版本 | v0.1.1（package.json；README 正文写 v0.1.0，属遗留文案） |
| 状态 | **draft**（补课文档，验收条目待线上复核） |
| 依赖服务 | `inject = ['tools']` |
| 外部依赖 | WSL Ubuntu（`wsl.exe -d Ubuntu`）+ `curl` / `sshpass` / `ssh` / `nc`；提权通道 = clash 代理（`proxyHost:proxyPort`） |

---

## 1 · 定位与反定位

**定位**：把 OverTheWire 系列（Bandit / Natas / Leviathan / Maze）攻坚中**反复手写的临时脚本**固化为 3 个可复用 DSH 工具
（HTTP 直连请求 / SSH 命令执行 / 通用 SQL 盲注引擎），让模型面对靶场任务直接调用，而不是每次从零拼 curl 与 python 单行脚本。

**反定位（本文不管什么）**：
- 不管利用原语的**生成**（payload 矩阵、JWT 伪造、序列化串）——那属于 `dsh-exploit-kit`（`xp_*`）；本插件管「**投递与取回**」
- 不管靶场部署（Docker 起 Juice Shop 等）——那属于技能 `cyber-range`
- 不管通用抓取/搜索（那属于 `dsh-search-pro`）
- **不是** 漏洞扫描器：本插件不判断目标是否有漏洞，只按模型给定的条件发请求/跑盲注

## 2 · 术语表

| 术语 | 含义 |
|------|------|
| otw | OverTheWire（授权靶场组织，本插件的**唯一**授权目标域） |
| 盲注（blind） | 不直接回显数据，只能通过「真/假」信号逐字符推断——时间盲注看耗时，布尔盲注看响应文本 |
| `{COND}` 占位 | `otw_blind` 的注入模板里被替换为条件 SQL 的位置（如 `natas18" AND IF({COND}, SLEEP(2), 1) -- `） |
| 中位数抗抖 | 每次判定发 3 个样本取中位数（time）或多数命中（bool），抵消网络抖动 |
| 直连 vs 代理 | `otw_request` 走 WSL `curl --noproxy "*"`；`otw_ssh` 走 `nc -X connect -x host:port` CONNECT 隧道 |
| `defaultResolveIp` | 配置项，用于 WSL DNS 故障时把主机名解析到固定 IP（**当前实现未消费**，见 §10 U1） |

## 3 · 概念模型

```
模型（爱丽丝）
  │  otw_request / otw_ssh / otw_blind
  ▼
dsh-cyber-range/src/index.ts
  ├─ spawnWsl(cmd, timeoutMs)  ── spawn('wsl.exe', ['-d','Ubuntu','--','bash','-c',cmd])
  │     └─ 复用 WSL 工具链与网络通道（web 进程自身网络受限）
  ├─ otw_request  → curl -s --noproxy "*" --max-time 20 [--resolve] [-u] [-b] [-A] [-d] -w '\n%{http_code}' URL
  │     └─ stdout 末行 = http_code，其余 = body（>maxBodyChars 截断）
  ├─ otw_ssh      → sshpass -p PASS ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15
  │                 -o ProxyCommand='nc -X connect -x PH:PP %h %p' user@host -p port 'command'
  └─ otw_blind    → blindExtract()：URL → headers(Basic auth / Host) → 逐位置 ASCII 二分
        └─ blindProbe() → rawHttp()（node:http 直连，GET/POST，20s 超时）
        └─ 每步 3 样本：time → 中位数 > max(1200, sleepSec*1000*0.6)；bool → ≥2 命中 trueText

外部世界：授权靶场主机（natas*.labs.overthewire.org / bandit.labs.overthewire.org 等）
```

不变量（invariants）：
1. **I1 WSL 是唯一提权通道**：`otw_request` 与 `otw_ssh` 都经 `spawnWsl` 执行（web 进程直连会被网络限制/被墙），可用 grep `spawnWsl(` 判真假（命中 3 = 1 处定义 + 2 处调用）。
2. **I2 盲注只走 `{COND}` 模板**：注入值 = `template.replace('{COND}', cond)`，条件恒为 `ASCII(SUBSTRING(expr,pos,1)) >|= N`——**永不**用 `LIKE` 通配符（规避 `%`/`_` 陷阱）。
3. **I3 判定必为多次采样**：`probe()` 内固定 3 次请求（`queries` 计数按请求数累加，非按判定数）。
4. **I4 参数化、非单关**：无任何关卡专属硬编码（natas 级别只出现在**描述与示例**里，不出现在逻辑分支）。
5. **I5 失败不抛**：`otw_request`/`otw_blind` 捕获异常后返回结构化 `error`；`spawnWsl` 永不 reject（`error` 事件转 `{ok:false}`）。

## 4 · 契约

### 4.1 配置（`Config` schema）
| 字段 | 默认 | 说明 |
|------|------|------|
| `enabled` | `true` | 插件开关（声明存在；`apply` 内未再判，挂载即注册） |
| `defaultResolveIp` | 无（`required(false)`） | 预期为「默认直连 IP」，**实现未读取** |
| `proxyHost` | `127.0.0.1` | SSH CONNECT 隧道代理主机 |
| `proxyPort` | `16888` | 代理端口（clash 混合端口） |

### 4.2 工具签名与裁决表
| 工具 | 关键入参 | 关键出参 | 裁决要点 |
|------|---------|---------|---------|
| `otw_request` | `host`(必需)、`user`/`pass`、`path`(默认`/`)、`method`(默认GET)、`data`、`cookie`、`userAgent`、`resolveIp`、`maxBodyChars`(默认12000) | `{status, body, truncated, error?}` | WSL 执行失败 → `status:0` + `stderr[:500]`；body 超限 → `truncated:true` 并截断 |
| `otw_ssh` | `host`/`user`/`pass`/`command`(必需)、`port`(默认**2220**) | `{ok, stdout, stderr, exitCode}` | 直接透传 `spawnWsl` 结果；代理取 `config.proxyHost/proxyPort` |
| `otw_blind` | `url`/`injectParam`/`template`/`expr`(必需)、`method`(默认POST)、`data`、`condType`(默认`ascii_gt`)、`mode`(默认`time`)、`sleepSec`(默认2)、`trueText`、`maxLen`(默认40)、`charset`(默认`alnum`) | `{result, queries, error?}` | 提取到字符集外/越界即 **break**（提前收束）；异常 → 返回已提取前缀 + `error` |

`blindExtract` 裁决表（纯逻辑）：
| 输入状态 | 裁决 | 依据 |
|---------|------|------|
| `mode='time'` 且 3 样本中位数 > 阈值 | 该位判定为「真」 | 时间侧信道 |
| `mode='bool'` 且 ≥2/3 样本含 `trueText` | 判定为「真」 | 多数投票 |
| ASCII 二分收敛值 `hi` 落在 `[csMin, csMax]` 之外 | 停止提取（视为字符串结束） | 越界即终止 |
| 解出的字符不在字符集内 | 停止提取 | 防幻读 |
| `charset='printable'` | 字符集 = ASCII 32–126（95 个） | 可打印全字符 |

### 4.3 调用点清单 `[MUST]`
| 调用方 | 调用点（文件:符号） | 时机 |
|-------|------------------|------|
| web profile 组合 | `.dsh/profiles/web/cordis.patch.yml` 行 `id: agent-cyber-range` / `name: dsh-cyber-range`（无 config） | web 启动挂载 |
| 插件本体 | `src/index.ts:apply(ctx, config)` → `ctx.tools.register(defineTool({name:'otw_request'…}))` | 挂载时注册 |
| 插件本体 | `src/index.ts:apply` → `ctx.tools.register('otw_ssh'…)` / `ctx.tools.register('otw_blind'…)` | 挂载时注册 |
| 插件本体 | `src/index.ts:(ctx as any).on('ready', …)` → `ctx.logger('dsh-cyber-range').info('ready: otw_request / otw_ssh / otw_blind')` | 宿主 ready 事件（**不落盘**，不作证据） |
| `otw_request` | `src/index.ts:execute` → 拼接 `curlCmd` → `spawnWsl(curlCmd, 30000)` | 每次调用 |
| `otw_ssh` | `src/index.ts:execute` → `sshExec({...})` → `spawnWsl(sshCmd, opts.timeoutMs ?? 60000)` | 每次调用 |
| `otw_blind` | `src/index.ts:execute` → `blindExtract({...})` → `blindProbe()` → `rawHttp()`（`node:http`） | 每次调用 |
| 模型（爱丽丝） | 攻防主链：`dsh-exploit-kit` 生成 payload → 本插件 `otw_request`/`otw_ssh` 投递 → 观察 → 下一跳 | 靶场攻坚 |
| 技能（间接） | 技能 `cyber-range` / `binary-exploitation-wargame` 描述的流程引用本工具面 | 方法论层 |

## 5 · 边界与信任

- 能力边界 ≠ 沙箱：本插件**不做授权校验**——给它任意 host 就会发请求/连 SSH。「仅限授权靶场」是**纪律**，不是技术约束（与 `dsh-exploit-kit` 同款声明）。
- 不越界清单：不做端口扫描、不做口令爆破（`otw_ssh` 需现成凭据）、不落盘凭据、不写任何文件。
- 失败面：
  - `spawnWsl` 超时/错误 → **放行 + 报错**（`{ok:false}` 或 `error` 字段），绝不静默。
  - `rawHttp` 失败 → `blindExtract` 捕获 → 返回**已提取前缀** + `error`（部分成果不丢弃）。
  - 密码含单引号 → 会破坏 `sshpass -p '...'` 引号结构（未转义，已知脆弱点；`otw_request` 对 `data`/`userAgent` 做 `'\''` 转义，但 `pass` 未做）。

## 6 · 与既有机制的关系

- 与 **AGENTS.md §5.1（命令默认走 WSL2）**：本插件把该准则固化成工具——`spawnWsl` 即 §5.1 的实现体。
- 与 **`dsh-exploit-kit`**：互补且严格分工——exploit-kit = 生成（纯本地、不触网），cyber-range = 投递（真触网）。
- 与 **§5.22（机制自证）**：当前只有 `ctx.logger` 的 ready 行（**不落盘**），本能力**缺侧车轨迹**——`blindExtract` 的 `queries` 计数只回给调用者，未沉淀为可 `tail` 的证据（§10 U2）。
- 与 **§5.11**：改 `src/index.ts` 后必须 `pnpm build`，让 `lib/index.js` mtime 更新并被预检看到。

**生效判据（改代码后怎么证明真的生效）**：
1. 构建产物新：`self-plugins/dsh-cyber-range/lib/index.js` 的 mtime **晚于**当前 web 进程启动时间（§5.11 进程级口径）。
2. 工具面在场：本会话能列出 `otw_request` / `otw_ssh` / `otw_blind` 三个工具（`plugin_inspect dsh-cyber-range` 显示 mounted）。
3. 行为可答：`otw_request` 对任意可达主机返回**真实 HTTP 状态码**（非 `status:0`）；`status:0` + `error` 即代表通道（WSL/curl）有问题。
4. 反证：`grep -c "spawnWsl(" src/index.ts` = 3（1 定义 + 2 调用：`otw_request`、`sshExec`），若新增网络路径却不走它，说明语义已漂移。

**回退**：`git revert` 本仓库最近一次提交 → `pnpm build` → 预检 → 哨兵重启 web；本插件无状态、无落盘，回退无数据迁移成本。

## 7 · 可证伪验收清单

| # | 可证伪命题 | 证据（单测名/命令/日志行/HTTP） | 状态 |
|---|-----------|------------------------------|------|
| A1 | 工具面恰好 3 个 `otw_*` | `grep -c "name: 'otw_" src/index.ts` = 3 | 待验收 |
| A2 | HTTP 路径经 WSL curl 且禁代理 | `grep -n -- "--noproxy" src/index.ts` 命中，且 `otw_request` 不含 `httpRequest(` | 待验收 |
| A3 | 基本请求可用 | `otw_request host=natas0.natas.labs.overthewire.org user=natas0 pass=natas0` → `status:200`，body 含 `natas1` | 待验收（需联网） |
| A4 | Basic auth 自动装配 | 上例 401→200 的差异（不带 user 应得 401） | 待验收 |
| A5 | SSH 走代理隧道 | `otw_ssh host=bandit.labs.overthewire.org user=bandit0 pass=bandit0 command=id` → `ok:true` 且 stdout 含 `uid=` | 待验收（依赖 clash 16888） |
| A6 | 盲注 3 样本中位数 | 对一个已知时间的靶场页跑 `otw_blind`，`queries` ≈ 3×判定数（二分 log2(62)≈6 → 每位 ≈18） | 待验收 |
| A7 | 越界即收束 | `maxLen=40` 提取到空/短串时提前返回而非跑满 40 位 | 待验收 |
| A8 | 失败不抛异常 | 把 `host` 指向不可达域 → 返回带 `error` 的结构化结果，调用不抛 | 待验收 |

## 8 · 与实现的关系

- 主实现：`self-plugins/dsh-cyber-range/src/index.ts`（341 行，单文件；含 `rawHttp` / `spawnWsl` / `sshExec` / `blindProbe` / `blindExtract` 5 个内部函数）。
- 同语义副本：无（`dsh-exploit-kit` 是**分工相邻**而非同语义）。
- 未实现/未验证部分**显式标注**：
  - `Config.enabled` 与 `Config.defaultResolveIp` 在 `apply` 内**未被消费**（ENABLED 只由组合行 `disabled` 控制）。
  - 无 `tests/`：A1–A8 全部**待验收**。
  - `otw_blind` 的 `condType='like_prefix'` 分支实现与 `ascii_gt` **完全相同**（源码注释说明用 ASCII 比较规避 LIKE 陷阱）——即三个 condType 其实只有两种行为。

## 9 · 实践修订记录

- **2026-09-14 补课：本插件此前无语义文档（可维护性工程）**
  - 语义**被确认**：3 工具面 / WSL 为唯一提权通道 / 盲注恒用 ASCII 比较 / 每次判定 3 样本。
  - 语义**被补充**：`otw_ssh` 默认端口 2220、`proxyHost/proxyPort` 默认 `127.0.0.1:16888`、`maxBodyChars` 默认 12000——此前只存在于源码默认值里。
  - 语义**被修正**：README 写「v0.1.0」而 `package.json` 是 `0.1.1`；以 package.json 为准（文档记差异，不改源）。
  - 教训：「配置项存在 ≠ 配置项生效」（`defaultResolveIp` 从声明到实现从未被消费）——语义文档必须写「谁读它」，否则未来读者会以为它有效。

## 10 · 未决问题

- **U1 `defaultResolveIp` 死配置**：预期是「缺省用固定 IP 解析」，实现里 `otw_request` 只认 `args.resolveIp`。倾向：要么让 `execute` 回退读 `config.defaultResolveIp`，要么删字段（需主人裁决，本轮只记录不动源）。
- **U2 缺侧车轨迹**：`otw_blind` 的每次探测（耗时/判定/字符）未落盘，事后无法回答「它为什么提取出这个串」。倾向：按 §5.22 落 `<DSH_HOME>/cyber-range-trace.jsonl`。
- **U3 凭据转义**：`sshpass -p '<pass>'` 未做 `'\''` 转义，密码含单引号会断——靶场密码通常是字母数字，风险低但应修。
- **U4 授权边界靠纪律**：是否给工具加「host 白名单」（只允许 `*.overthewire.org`）？倾向：**不加**（会阻碍主人授权的其他靶场），保持纪律约束。
