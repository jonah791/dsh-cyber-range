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

### 4.4 自证轨迹契约（可维护性 S4 · 2026-09-14）

**落盘路径（单一真源）**：`<DSH_HOME>/cyber-range-trace.jsonl`，写入者是
`src/trace.ts:resolveHome()`（`DSH_HOME` 环境变量 → 回退 `homedir()/.dsh`）+ `tracePath(home)`。
**一行一阶段**（单行 JSON，`atMs` 单调），可 `tail` / `grep`。

**行 schema**（`src/trace.ts:TraceEntry`；固定键序 `serializeTraceEntry` 锁住）：

| 字段 | 类型 | 出现阶段 | 含义 |
|------|------|---------|------|
| `atMs` | number | 全部 | 写入时刻（ms epoch） |
| `phase` | `'begin' \| 'end'` | 全部 | **阶段枚举**：一次调用恒为 `begin` → `end` 两行 |
| `action` | `'request' \| 'ssh' \| 'blind'` | 全部 | 动作类型（Q2） |
| `build` | string | 全部 | `<package.version>@<lib/index.js mtime ms>`（Q1：线上跑的是哪个构建；版本会说谎，mtime 不会） |
| `pid` | number | 全部 | 进程 pid（web / watch 两侧都可能跑同一插件） |
| `target` | string? | 全部 | 目标：`host`，或 `url` 的 `<hostname><pathname>`（**结构化剥掉凭据**） |
| `params` | string? | `begin` | 参数摘要（脱敏；敏感键只记 `<N chars>`） |
| `cmdShape` | string? | `begin` | 命令形态（**已 `scrub` + 截断 240 字符**；`otw_blind` 走 HTTP 直连故无此字段） |
| `durationMs` | number | 全部 | `begin`=0；`end`=全程实耗（Q5） |
| `ok` | boolean? | `end` | **通道级**成功（`ok:false` 显式失败，或 `error` 非空）；HTTP 401 仍算通（应用层由 `status` 表达） |
| `status` / `exitCode` | number? | `end` | curl `-w` 状态码 / 子进程退出码 |
| `stdoutBytes` / `stderrBytes` / `bodyBytes` | number? | `end` | 量级（**不落正文**） |
| `queries` | number? | `end` | 盲注查询次数（Q4：`otw_blind` 的结果质量） |
| `error` | string? | `end` | `classifyBreak()` 分类前缀 + 截断 200 的**已 scrub** 文本（仅在失败时出现） |

**断点分类枚举**（`classifyBreak`，可 grep）：
`http-timeout`（超时）→ `wsl-spawn`（wsl.exe 起不来）→ `http-error`（连接/DNS/重置）→
`wsl-exit`（非零退出/curl 错误）→ `empty`（空错误）→ `other`。

**隐私红线（本插件的硬约束）**：`pass` / `user` / `cookie` / `token` / `authorization` / `secret` /
`hash` / `data` / `command` / `form` **只记 `<N chars>`，一个字都不落盘**；`url` 里的
`user:pass@` 由 `summarizeUrl` **结构性剥离**；`cmdShape` 与 `error` 落盘前再过 `scrub(text, secrets)`
——秘密值全部来自本次参数（`collectSecrets`），故替换是**完备**的。
`userAgent` / `resolveIp` / `expr` / `template` 等业务键**保留**（排障要看，非凭据）。

**调用点清单**：
| 调用方 | 调用点（文件:符号） | 时机 |
|-------|------------------|------|
| 单一切面 | `src/index.ts:apply` → `reg(tool)`（三个工具**全部**经它注册，轨迹接线只此一处） | 挂载时注册 |
| 接线 | `src/index.ts:TRACE_SPEC`（`otw_request`/`otw_ssh`/`otw_blind` → action + `targetOf` + `cmdOf`） | 每次调用 |
| 落盘 | `src/trace.ts:tracedExecute` → `safeTrace` → `appendTraceEntry`（吞错返回 bool） | 每次调用两行 |
| 读取 | `src/trace.ts:readTraceEntries`（坏行/半行/空行/缺失/目录 → 空数组） | 诊断时 |

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
- 与 **§5.22（机制自证）**：~~当前只有 `ctx.logger` 的 ready 行（**不落盘**），本能力**缺侧车轨迹**~~
  → **2026-09-14 已闭环**：`src/trace.ts` + `<DSH_HOME>/cyber-range-trace.jsonl`（契约见 §4.4），
  `ctx.logger` 的 ready 行仍**不作证据**（宿主 logger 不落盘）。`blindExtract` 的 `queries` 计数一并沉淀。
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
| A7 | ~~越界即收束~~ **原命题已被证伪并订正**：越界**不会**提前返回，而是补 `0` 到 maxLen | 见下方 A12 与 §9「A7 命题订正」——`maxLen` 必须由调用方给准 | **已实测（2026-09-14，命题翻转）** |
| A8 | 失败不抛异常 | 把 `host` 指向不可达域 → 返回带 `error` 的结构化结果，调用不抛 | 待验收 |
| A9 | 命令拼装注入防线（WSL bash 逃逸） | `npm test` → `tests/shell-contract.test.mjs`：静态守卫要求命令模板内每个 `${…}` 必为 `shellQuote(...)` 或已转义别名；**尸体样本**（修复前的 5 处裸内插）必须全被拦下 | **已实测（2026-09-14，39/39 pass）** |
| A10 | 命令拼装集中在 `logic.ts`，接线层无裸命令文本 | `npm test` → 断言 `src/index.ts` 不含 `sshpass`/`curl -s`/`ProxyCommand`/`StrictHostKeyChecking` | **已实测（2026-09-14）** |
| A11 | 纯逻辑（命令拼装/输出解析/二分判定）有失败路径覆盖 | `npm test` → `tests/logic.test.mjs`：非法百分号编码抛 `URIError`、单行输出 status=0、超长 body 截断、空字符集回落 32/126、probe 抛错保留已提取前缀、时间盲注空样本判假 | **已实测（2026-09-14）** |
| A12 | 二分提取的终止语义（三条停 + `0` 填充） | `npm test` → `maxLen=目标长度` 得完整串；`maxLen` 偏大得尾随 `0`；字符码 > csMax 或落字符集空隙则终止 | **已实测（2026-09-14）** |
| A13 | `logic.ts` 保持纯逻辑（可离线单测） | `npm test` → 断言 `src/logic.ts` 不含 `child_process`、不含 `httpRequest`/`fetch(` | **已实测（2026-09-14）** |
| A14 | 轨迹落盘路径可预测且锚定 `DSH_HOME` | `node -e "import('./lib/trace.js').then(m=>console.log(m.tracePath(m.resolveHome({DSH_HOME:'X'},'/h'))))"` → `X/cyber-range-trace.jsonl` | **已实测（2026-09-14）** |
| A15 | 观测不反噬：不可写路径返回 `false` 且不抛、返回值/异常传播不变 | `npm test` → `tests/trace.test.mjs`「尸体测试」「观测失败不反噬」「异常原样重抛（同一对象）」 | **已实测（2026-09-14）** |
| A16 | 隐私红线：口令/用户名/cookie/URL 内嵌凭据/远程命令**绝不出现在落盘行里** | `npm test` → 隐私尸体测试：喂 `<secret>` 参数 → 断言文件内搜不到，且 `pass=<N chars>` 出现 | **已实测（2026-09-14）** |
| A17 | 线上自证（五问一条命令可答） | `tail -3 <DSH_HOME>/cyber-range-trace.jsonl` → `build` / `action`+`target`+`params` / `ok`+`exitCode` / `durationMs` 一齐可见 | **待线上验收**（需一次真实工具调用） |
| A18 | **接线守卫：`otw_blind` 的 `target` 必须过 `summarizeUrl`**（URL 内嵌凭据不得落盘） | `npm test` → `tests/trace.test.mjs`「接线守卫（尸体测试）」：静态断言 `otw_blind` 的 `targetOf` 块含 `summarizeUrl(`，且裸内插形态（修复前写法）**不存在** | **已实测（2026-09-14，60/60）** |

## 8 · 与实现的关系

- 主实现：`self-plugins/dsh-cyber-range/src/index.ts`（接线与 IO：`rawHttp` / `spawnWsl` / `sshExec` / `blindProbe` / `blindExtract`）+ `src/logic.ts`（**纯逻辑层**：`shellQuote` / `buildCurlCmd` / `parseCurlOutput` / `buildSshCmd` / `buildPostBody` / `buildGetPath` / `basicAuthOf` / `normalizeCharset` / `charsetBounds` / `buildCond` / `bisectExtract` / `judgeProbe` / `defaultSleepThresholdMs`）。
- 同语义副本：无（`dsh-exploit-kit` 是**分工相邻**而非同语义）。
- 未实现/未验证部分**显式标注**：
  - `Config.enabled` 与 `Config.defaultResolveIp` 在 `apply` 内**未被消费**（ENABLED 只由组合行 `disabled` 控制）。
  - **单测（2026-09-14 补课已补）**：`tests/logic.test.mjs`（30）+ `tests/shell-contract.test.mjs`（9）= **39/39 全过**；`npm test` 一条命令可复跑。A1–A8 仍需**真实网络/靶场**的线上验收（离线单测不能替代）。
  - `otw_blind` 的 `condType='like_prefix'` 分支实现与 `ascii_gt` **完全相同**（源码注释说明用 ASCII 比较规避 LIKE 陷阱）——即三个 condType 其实只有两种行为；已由单测钉住。
  - `bisectExtract` 的**终止语义**已由单测钉住（见 A12 与 §10 U5）：算法不感知字符串结尾，`maxLen` 给大了会尾随补 `0`。

## 9 · 实践修订记录

- **2026-09-14 · 自证轨迹层（可维护性 S4，零业务行为变更）**
  - **缺口（原文 §6/§10 U2 已登记）**：三个工具都经 WSL bash 出击，却只有 `ctx.logger` 的 ready 行
    （宿主 logger **不落盘**）⇒ 事后无法回答「谁发起了哪一发、命令长什么样、断在哪一级、花了多久」。
  - **补的语义（新契约）**：新增 `src/trace.ts`（纯函数 + 薄 IO）+ `<DSH_HOME>/cyber-range-trace.jsonl`
    （`begin`/`end` 两行一次调用），契约与调用点清单见 §4.4；切面**只有一处**——
    `src/index.ts:apply` 的 `reg()`（三个工具全部经它注册），不在三个 `execute` 里各改一遍。
  - **补的语义（隐私红线，此前无此约束）**：口令/用户名/cookie/token/hash/data/远程命令
    **只记长度**；`url` 内嵌凭据**结构性剥离**；`cmdShape`/`error` 落盘前过 `scrub()`。
    动机：本插件刚修过「凭据裸内插进 bash」的高危缺陷——**取证手段不能变成新的泄漏面**。
  - **语义被补充（此前无人知道）**：`ok` 字段是**通道级**语义（HTTP 401 也算「通」），
    应用层结果由 `status` 单独表达——两者不得互相掩盖（进化规则 1「语义精确性」）。
  - **行为变更清单**：**无**。工具签名/参数/返回值/render 逐字不变；`tracedExecute` 只做「落两行 + 原样转发」，
    且异常**原样重抛同一个对象**（不是包装后的 Error）——由单测钉住。
  - **测试**：`tests/trace.test.mjs`（21 条）——含尸体测试、隐私尸体测试、注入时钟耗时断言、
    坏行/半行/空行/缺失文件/目录路径的解析退化。全仓 39 → **60/60**。
  - **⚠ 端到端冒烟测试当场抓到我自己的一个真缺陷（已修 + 加静态守卫）**：`otw_blind` 的 `TRACE_SPEC.targetOf`
    最初写的是「原样返回 `args.url`」——而该工具的 `url` **允许内嵌 `user:pass@`**（`basicAuthOf` 会把它转成
    Basic auth）⇒ `target` 字段会把**凭据写进轨迹**。单元测试全绿也发现不了它（纯函数 `summarizeUrl` 是对的，
    错在**接线**）。修法：`targetOf` 改为 `summarizeUrl(a['url'])`；并加**接线静态守卫**（A18）——
    判据「会落盘的 URL 必须过 `summarizeUrl`」与 `shell-contract` 的「进 bash 的串必须过 `shellQuote`」同构。
    **教训：纯函数单测覆盖不到接线错误，必须有一条端到端冒烟（挂载 + 真调一次 + 看落盘行）。**
  - **未决**：轨迹**无轮转**（当前按日/按月手删）；线上自证（A17）待一次真实调用。

- **2026-09-14 · 命令注入缺陷（curl / ssh 命令的半吊子转义，已修 + 加机器守卫）**
  - **症状**：`otw_request` 的 curl 命令与 `otw_ssh` 的 ssh 命令由模板字符串拼成，
    其中 `userAgent`/`data` 做了 `'` → `'\''` 转义，而 **`user`/`pass`/`cookie`/`host`/`path`/`resolveIp`/
    `command`/代理地址 原样内插**（`-u '${user}:${pass}'`、`-b '${cookie}'`、`'http://${host}${path}'`、
    `sshpass -p '${pass}'` … `'${command}'`）。命令最终由 **WSL 内的 `bash -c`** 执行，
    故 `cookie = "x'; <任意命令>; '"` 即等于在本机 WSL 内执行任意命令。
  - **证伪证据（修前）**：`tests/logic.test.mjs` 的注入防线断言在原形态上真实失败
    （`assertNoEscape`：`-b '${HOSTILE}'` 原样出现在命令里），并由 `tests/shell-contract.test.mjs`
    的尸体测试独立复核（修复前的 5 处裸内插样本必须被静态守卫全部拦下）。
  - **修复**：新增 `src/logic.ts:shellQuote()`（单一真源的 bash 单引号转义），
    `buildCurlCmd`/`buildSshCmd` 的**每一个**外来串统一过它；`ProxyCommand=` 前缀留在引号外（与修复前逐字一致）。
  - **语义被补充（新不变量）**：**任何进入 `bash -c` 命令串的外来字符串必须先 `shellQuote()`**——
    由静态守卫机器锁住（`tests/shell-contract.test.mjs`）。
  - **行为变更清单**：正常输入下产物**逐字节一致**，唯二差异是 `--resolve` 的值与 ssh 的 `user@host`/`-p <port>`
    从「无引号」变为「单引号包裹」——**shell argv 语义不变**（仍是同一个参数），且这两处此前也是未转义面。
  - **教训（与 `dsh-blue-team` 同型，已回写技能 `dsh-plugin-testability`）**：
    **同类调用点只护住一处 = 半吊子防线**。作者已为 `userAgent`/`data` 写了转义，却没覆盖同一模板里的另外 5 个变量——
    引入转义 helper 后必须**逐个调用点**断言，而不是「有一个用例过了就算防线在」。

- **2026-09-14 · A7 命题订正（文档预期写错，不是代码错）**
  - 原 A7 写「`maxLen=40` 提取到空/短串时**提前返回**而非跑满 40 位」——**实测为假**。
    真实语义：SQL 侧 `ASCII(SUBSTRING(...))` 越界返回 `0` ⇒ 条件恒假 ⇒ 二分收敛到字符集最小值 `'0'`，
    而 `'0'` 在 `alnum` 内 ⇒ **继续追加**，直到跑满 `maxLen`。
  - 处置：**订正文档命题**（A7 翻转 + A12 钉住真实语义 + U5 登记），不在代码里凑答案——
    这与 search-pro 的 `decodeDdgUrl` 教训同源：*先判「代码错还是预期错」*。

- **2026-09-14 · 逻辑可测试化（纯函数抽取，零行为变更）**
  - **语义被确认**：`buildCurlCmd`/`buildSshCmd`/`parseCurlOutput`/`buildPostBody`/`buildGetPath`/
    `basicAuthOf`/`normalizeCharset`/`charsetBounds`/`buildCond`/`bisectExtract`/`judgeProbe` 从 `index.ts` 的内联逻辑搬入
    `src/logic.ts`，逐条对齐原实现；`blindExtract` 保留 `{result, queries, error?}` 外壳与
    「抛错时返回已提取前缀」的语义（由 `bisectExtract` 内部 catch 实现）。
  - **语义被补充（此前无人知道的真实语义）**：`parseCurlOutput` 单行输出 → `status=0` 且 body=整串；
    `buildCurlCmd` 空串 `path` 会产出 `http://host`（`??` 不兜空串）；`buildPostBody` 无 `=` 的段以空值加入、
    重复键由最后 `set` 覆盖；`judgeProbe` 的 time 模式单样本判假（`sorted[1] ?? 0`）；
    `basicAuthOf`/`buildPostBody` 遇非法百分号编码抛 `URIError`（不静默）。
  - **语义被修正（我自己的预期错）**：首版把「目标为空串 → 结果为空」写进断言，实测是**补 `0`**（同 A7 订正）。

- **2026-09-14 补课：本插件此前无语义文档（可维护性工程）**
  - 语义**被确认**：3 工具面 / WSL 为唯一提权通道 / 盲注恒用 ASCII 比较 / 每次判定 3 样本。
  - 语义**被补充**：`otw_ssh` 默认端口 2220、`proxyHost/proxyPort` 默认 `127.0.0.1:16888`、`maxBodyChars` 默认 12000——此前只存在于源码默认值里。
  - 语义**被修正**：README 写「v0.1.0」而 `package.json` 是 `0.1.1`；以 package.json 为准（文档记差异，不改源）。
  - 教训：「配置项存在 ≠ 配置项生效」（`defaultResolveIp` 从声明到实现从未被消费）——语义文档必须写「谁读它」，否则未来读者会以为它有效。

## 10 · 未决问题

- **U1 `defaultResolveIp` 死配置**：预期是「缺省用固定 IP 解析」，实现里 `otw_request` 只认 `args.resolveIp`。倾向：要么让 `execute` 回退读 `config.defaultResolveIp`，要么删字段（需主人裁决，本轮只记录不动源）。
- **U2 缺侧车轨迹（✅ 2026-09-14 已闭环）**：已落 `<DSH_HOME>/cyber-range-trace.jsonl`（契约 §4.4）。
  遗留子项：轨迹**无轮转/无上限**（长期运行会单文件增长）——倾向按 §5.22 的既有做法留给运维层或加 `keepN` 轮转，**未决**。
- **U3 凭据转义（✅ 2026-09-14 已闭环，且范围远大于原判）**：原文写「`sshpass -p '<pass>'` 未转义，风险低但应修」。
  实测**不止 pass**：curl 与 ssh 两条命令共 **7 个外来字段**未转义（`user`/`pass`/`cookie`/`host`/`path`/`resolveIp`/`command`
  + 代理地址），且命令由 **WSL bash** 执行 ⇒ 不是「密码含单引号会断」，而是**可逃逸执行任意命令**。
  已修（统一 `shellQuote`）+ 静态守卫锁死；风险等级由「低」更正为**高**（已消除）。
- **U5 `bisectExtract` 不感知字符串结尾（2026-09-14 补课实测登记，未决）**：`maxLen` 给大了会尾随补 `0`
  （见 §9「A7 命题订正」）。倾向：加一个终止条件——例如每位先测 `LENGTH(expr) >= pos`，或把
  「收敛到 csMin 且字符为 `0`」视为结束信号。**需真实靶场验证后由主人裁决**（改的是提取语义，不能靠单测猜）。
- **U4 授权边界靠纪律**：是否给工具加「host 白名单」（只允许 `*.overthewire.org`）？倾向：**不加**（会阻碍主人授权的其他靶场），保持纪律约束。
