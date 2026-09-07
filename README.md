<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: OverTheWire 在线靶场攻坚工具集：otw_request（HTTP 直连请求）、otw_blind（通用 SQL 盲注引擎）、otw_ssh（SSH 命令执行）——把 CTF 攻坚的临时脚本能力资产化为可复用工具
  inject: 'tools'
  tools: otw_request,otw_ssh,otw_blind
  runtime: host-only
  envDeps: WSL Ubuntu + sshpass/ssh/nc + HTTP 代理（可配置）
  boundary: 仅限 OverTheWire 等授权靶场
  compat: cordis ^4.0.1 / dsh-tools ^0.1.0-rc.6
-->
# dsh-cyber-range


<p align="center">
  <a href="https://github.com/jonah791/dsh-cyber-range"><img src="https://img.shields.io/badge/version-0.1.1-blue" alt="version"></a>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/TypeScript-3178C6" alt="TypeScript">
</p>
> OverTheWire 在线靶场攻坚工具集：把 CTF 临时脚本能力资产化为可复用 DSH 工具。
> DeepSeek Harness 自研插件 · v0.1.0

## 定位

把 OverTheWire（Bandit / Natas / Maze 等）攻坚过程中反复手写的临时脚本（HTTP 直连、SQL 盲注、SSH 命令执行）固化为**可复用工具**——模型面对靶场任务直接调用，不再每次从零拼命令。

## 功能特性

- **otw_request**：HTTP 直连请求（Basic auth + Host header，绕过代理环境变量直连）——Natas Web 关卡主力
- **otw_blind**：通用 SQL 盲注引擎（时间盲注 / 布尔盲注，ASCII 二分提取，规避 LIKE 通配符陷阱）——Natas SQLi 关卡
- **otw_ssh**：SSH 命令执行（clash 代理 CONNECT 隧道，直连被墙时的标准通道）——Bandit / Leviathan 等 SSH 关卡
- **授权边界**：仅限 OverTheWire 等授权靶场

## 安装

```bash
git clone https://github.com/jonah791/dsh-cyber-range.git self-plugins/dsh-cyber-range
cd self-plugins/dsh-cyber-range && pnpm install && pnpm build
```

挂载到 web profile。组合行 id：`agent-cyber-range`。

## 使用（工具面）

| 工具 | 用途 |
|------|------|
| `otw_request` | HTTP 直连请求（Basic auth + Host header，GET/POST + cookie） |
| `otw_blind` | SQL 盲注引擎（time/bool 模式，二分/线性提取） |
| `otw_ssh` | SSH 命令执行（代理 CONNECT 隧道） |

## 配置

| 字段 | 默认 | 说明 |
|------|------|------|
| `proxy` | clash 隧道 | SSH 直连被墙时的代理通道 |

## 技术要点

- **实战蒸馏**：OverTheWire Bandit 34/34 + Natas 全通过程中固化的方法论（SQL 盲注二分、时间盲注中位数抗抖动、Basic auth 直连加速）
- **授权纪律**：仅限授权靶场（OverTheWire 等）
- 与 dsh-exploit-kit（利用原语）互补：cyber-range 管「靶场攻坚」，exploit-kit 管「通用利用原语」

## License

MIT