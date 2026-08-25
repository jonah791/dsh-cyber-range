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

OverTheWire 在线靶场攻坚工具集：otw_request（HTTP 直连请求）、otw_blind（通用 SQL 盲注引擎）、otw_ssh（SSH 命令执行）——把 CTF 攻坚的临时脚本能力资产化为可复用工具
