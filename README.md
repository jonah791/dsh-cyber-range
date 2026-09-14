<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: OverTheWire 在线靶场攻坚工具集：otw_request（HTTP 直连请求）/ otw_blind（通用 SQL 盲注引擎）/ otw_ssh（SSH 命令执行）——把 CTF 攻坚的临时脚本资产化为可复用工具
  inject: 'tools'
  tools: otw_request, otw_ssh, otw_blind（3 个）
  runtime: host-only
  envDeps: WSL Ubuntu（curl/ssh/sshpass/nc）+ 可达授权靶场网络（HTTP 代理可选，SSH 走 CONNECT 隧道）
  boundary: 仅限 OverTheWire 等明确授权靶场；不判断目标是否有漏洞，只按模型给定条件发请求；能力边界 ≠ 沙箱
  compat: cordis ^4.0.1 / schemastery ^3.18.1-rc.1 / dsh-tools ^0.1.0-rc.6
-->
# dsh-cyber-range

<p align="center">
  <a href="https://github.com/jonah791/dsh-cyber-range"><img src="https://img.shields.io/badge/version-0.1.2-blue" alt="version"></a>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/TypeScript-3178C6" alt="TypeScript">
  <img src="https://img.shields.io/badge/tests-60%20passed-brightgreen" alt="tests">
</p>

**一句话**：把 OverTheWire 系列（Bandit / Natas / Leviathan / Maze）攻坚时**反复手写的临时脚本**固化成 3 个可复用工具——HTTP 直连请求、SSH 命令执行、通用 SQL 盲注引擎。

**为什么值得用**：攻关联调最贵的是「每次从零拼 curl、拼 sshpass 命令、现写一个 python 盲注单行」。这里把它们变成**有契约的工具**：盲注内置 3 样本中位数抗抖动（网络一抖就误判是盲注最大的坑）、HTTP 直连绕开代理环境变量（Natas 实测 0.6s vs 走代理 1.5s+）、每次出击落一行脱敏轨迹（口令/cookie/命令正文**一个字都不落盘**）。

## 能力

| 工具 | 用途 |
|------|------|
| `otw_request` | HTTP 直连请求（`curl --noproxy "*"`，Basic auth + Host header + cookie + 自定义 UA + `resolveIp` 强制解析）。入参：`host`(必需) / `user` / `pass` / `path` / `method` / `data` / `cookie` / `userAgent` / `resolveIp` / `maxBodyChars`(默认 12000)；出参 `{status, body, truncated, error?}` |
| `otw_ssh` | SSH 命令执行（`sshpass` + clash CONNECT 隧道 `nc -X connect -x <proxyHost>:<proxyPort>`，直连被墙时的标准通道）。入参：`host`/`user`/`pass`/`command`(必需) + `port`(默认 2220)；出参 `{ok, stdout, stderr, exitCode}` |
| `otw_blind` | 通用 SQL 盲注引擎：按注入模板（`{COND}` 占位）+ 条件（`ascii_gt` 二分 / `ascii_eq` 线性）逐字符提取。`mode=time`（SLEEP 判定，3 次取中位数）或 `mode=bool`（响应含 `trueText`，≥2/3 多数投票）。出参 `{result, queries, error?}` |

## 快速开始

**1) 装依赖**（自研插件家园 `self-plugins/`，在目标 profile 的 `package.json` 加 link 依赖）：

```jsonc
"dsh-cyber-range": "link:<工作区>/self-plugins/dsh-cyber-range"
```

**2) 挂组合**（web profile patch 行；默认配置即可用）：

```yaml
- insert:
    - id: agent-cyber-range
      name: dsh-cyber-range
```

需要走 SSH 隧道时再补 `config: { proxyHost: 127.0.0.1, proxyPort: 16888 }`。

**3) 30 秒验证**（不碰任何目标，纯离线）：对 `otw_request` 传一个不可达 host → 应返回 `{status: 0, error: "…"}`（**结构化错误，不是异常**）；再 `grep -c "spawnWsl(" src/index.ts` = 3（1 处定义 + 2 处调用）。工具列表里能看到 `otw_request` / `otw_ssh` / `otw_blind` 即挂载成功。

## 配置

| 项 | 默认 | 说明 |
|----|------|------|
| `enabled` | `true` | 插件开关（声明存在；`apply` 内不再判，挂载即注册三个工具） |
| `defaultResolveIp` | 未设 | 预期为「默认直连 IP」，**当前实现未读取**（语义文档 §10 U1，如实标注） |
| `proxyHost` | `127.0.0.1` | SSH CONNECT 隧道代理主机 |
| `proxyPort` | `16888` | 代理端口（clash 混合端口） |

## 落盘与自证（出问题时先看这里）

每次工具调用落 **2 行** JSONL 到 **`<DSH_HOME>/cyber-range-trace.jsonl`**（`DSH_HOME` 缺省 `~/.dsh`）：

| 阶段 | 含义 |
|------|------|
| `begin` | 收到调用（`action` / `target` / `params` 脱敏摘要 / `cmdShape` 命令形态） |
| `end` | 调用结束（`ok` / `status` / `exitCode` / `stdoutBytes` / `stderrBytes` / `bodyBytes` / `queries` / `durationMs` / 失败时 `error` = `classifyBreak` 断点分类） |

`action` 枚举即三条出击路径：`request`（otw_request）/ `ssh`（otw_ssh）/ `blind`（otw_blind）。

**一条命令答五问**：

```bash
tail -2 "$DSH_HOME/cyber-range-trace.jsonl"
# ① 跑的是哪个构建   → build = "<版本>@<lib/index.js mtime ms>" + pid（web / watch 两侧都可能跑）
# ② 谁发起 / 打哪里  → action + target（host 或 hostname+path）+ params（脱敏摘要）
# ③ 断在哪一段      → phase 枚举（begin/end）+ error 断点分类；有 begin 无 end = 进程/超时中断
# ④ 结果质量        → ok / status / exitCode / stdoutBytes / bodyBytes / queries（查询次数）
# ⑤ 耗时与预算      → durationMs vs 工具内的 30s（request）/ 60s（ssh）超时预算
```

**隐私红线**：口令 / 用户名 / cookie / token / POST 表单体 / 远程命令正文**一个字都不落盘**——敏感键只记 `<N chars>`，`url` 里的 `user:pass@` 结构化剥离只留 host+path，其余文本落盘前再过一遍 `scrub()`（用本次参数里收集到的秘密值替换，双保险）。**观测绝不反噬主流程**：全部 IO 失败吞错并返回 `false`，摘要函数自身抛错一律吞掉，绝不改变工具返回值。

## 生效判据与回退

**生效判据**（三选一，按可靠性排序）：
1. **进程级**：`tail -1 "$DSH_HOME/cyber-range-trace.jsonl"` 里 `build` 的 mtime **等于** `self-plugins/dsh-cyber-range/lib/index.js` 的 mtime ⇒ 进程在跑当前构建；
2. **生态级**：`plugin_boot_status` 的 `liveNow` 含本插件，或 `plugin_inspect dsh-cyber-range` 显示 mounted；
3. **行为级**：工具列表里有 `otw_request` / `otw_ssh` / `otw_blind`，且调用后轨迹文件 `mtime` 前进。

> 注意：**重新构建 ≠ 生效**——`lib/index.js` mtime 新只证明「构建过」，**进程启动时间晚于产物 mtime** 才算「在跑它」。改完源码必须 `npm run build` 并让预检看到新产物（`hasUnverifiedBuilds()` 同口径）。

**回退**：
- 源码级：`git -C self-plugins/dsh-cyber-range revert <commit>` → `npm run build` → `preflight_check` → 哨兵重启；
- 组合级：patch 里给 `agent-cyber-range` 行加 `disabled: true`（或移除该行）→ 哨兵重启；
- 运行期：无需回退（本插件无持久业务状态；`cyber-range-trace.jsonl` 可随时删除）。

## 测试

```bash
npm run build && npm test        # build = tsc；test = node --test "tests/*.test.mjs"
```

**60 例离线测试全绿**（2026-09-14 实测 `# pass 60 / # fail 0`），跑 `lib/` 产物（与运行时同源）：

- `tests/logic.test.mjs` — 盲注纯逻辑：二分收敛、越界即停、字符集外停（防幻读）、`printable` 字符集边界、curl/ssh 命令拼接、Basic auth 与 URL 内嵌凭据解析
- `tests/shell-contract.test.mjs` — shell 契约与**注入防护**：命令拼接的引号/转义语义（含命令注入修复后的回归用例）
- `tests/trace.test.mjs` — 轨迹层：路径解析（`DSH_HOME` 优先 / 缺省 `~/.dsh`）、脱敏完备性、`classifyBreak` 断点分类、**尸体测试**（不可写路径 → 返回 `false` 且不抛）、接线守卫（`otw_blind` 的 `target` 必须过 URL 凭据剥离）

**离线单测不需要网络、不需要 WSL、更不需要靶场**——纯逻辑与序列化层零 IO。真机路径（WSL 内 curl/ssh/sshpass 实跑、靶场连通性）**没有离线单测**，属于线上探针范围。

## 设计要点

- **I1 WSL 是唯一提权通道**：`otw_request` / `otw_ssh` 都经 `spawnWsl` 执行（web 进程自身网络受限/被墙）——`grep -c "spawnWsl(" src/index.ts` 恒为 3。改执行链路时不得绕过该通道。
- **I2 盲注只走 `{COND}` 模板**：条件恒为 `ASCII(SUBSTRING(expr,pos,1)) >|= N` 的精确比较，**永不用 `LIKE` 通配符**（规避 `%`/`_` 通配符陷阱导致的静默错判）。
- **I3 判定必为多次采样**：每次判定固定发 3 个请求（`queries` 计数按**请求数**累加，不是判定数）——time 模式取中位数、bool 模式多数投票，这是网络抖动下不产生幻读的关键。
- **I4 参数化、非单关**：无任何关卡专属硬编码，关卡名只出现在描述与示例里，不出现在逻辑分支——同一套工具适用于任意靶场。
- **I5 失败不抛**：`spawnWsl` 永不 reject（`error` 事件转 `{ok:false}`），工具捕获异常后返回结构化 `error`；盲注异常时返回**已提取前缀** + `error`，不丢进度。

### 安全边界（重要）

- **授权边界**：仅用于 OverTheWire 等**明确授权**的靶场与自建靶机。本插件**不是漏洞扫描器**——它不判断目标是否存在漏洞，只按模型给定的条件发请求、跑盲注；能否用、对谁用，责任在调用方。
- **能力边界 ≠ 沙箱**：工具经 WSL 执行 curl/ssh 命令，不校验目标是否在授权范围内。请勿在受限会话中向不受控目标暴露本工具面。
- 与 `dsh-exploit-kit` 的分工：本插件管「**投递与取回**」，`xp_*` 管「**原语生成**」（payload 矩阵 / JWT 伪造 / 序列化串）。

## 相关文档

| 文档 | 内容 |
|------|------|
| [`docs/semantic.md`](docs/semantic.md) | **权威契约**：定位与反定位、术语表、概念模型与不变量（I1–I5）、契约（配置/工具裁决表/调用点清单/**自证轨迹契约**）、边界与信任、可证伪验收清单、实践修订记录、未决问题 |
| [alice-digital-life](https://github.com/jonah791/alice-digital-life) | 本插件所属生态的中心索引（全部自研插件） |
| 技能 `cyber-range` | 攻防靶场实战方法论（靶场部署、打穿三步曲、反编译取证） |
| 技能 `binary-exploitation-wargame` | 二进制利用闯关方法论（OverTheWire Maze/Utumno 实战蒸馏） |
| 姊妹插件 `dsh-exploit-kit` | 利用原语库（`xp_*`）——与本插件构成「生成 ↔ 投递」两段 |

## License

MIT © jonah791

---

本插件属于我的数字生命爱丽丝（[alice-digital-life](https://github.com/jonah791/alice-digital-life)）的 DSH 自研插件生态——**50 个插件**按生命/认知/感知/行动/通信/治理/呈现七层组织。
