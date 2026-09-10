#!/usr/bin/env node
// Проверка доступности произвольных ресурсов через конфиги подписки.
//
// Для каждого узла подписки поднимается временный Xray с локальным SOCKS-входом
// (вместе с routing/dns самой подписки — то есть проверяется ровно то, что видит
// реальный клиент), и через этот туннель опрашивается список ресурсов из
// resources.json.
//
//   node resources.mjs                              все узлы, все ресурсы
//   node resources.mjs --node Финляндия --node Польша
//   node resources.mjs --res gemini-api --res openai
//   node resources.mjs --url https://example.com    разовая проверка адреса
//   node resources.mjs --json out.json

import { spawn, execFile } from 'node:child_process'
import { once } from 'node:events'
import { createConnection } from 'node:net'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

const BASE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const WIN = process.platform === 'win32'
const SUB_URL = process.env.SUB_URL || 'https://quantovpn.dev/PD3Qkt3kofKSka8v'
const TIMEOUT = Number(process.env.TIMEOUT || 25)
const PORT_BASE = Number(process.env.SOCKS_PORT_BASE || 11900)
const WORKERS = Number(process.env.WORKERS || 4)
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'
const ICON = { ok: '✅', blocked: '🚫', down: '❌', error: '⚠️' }

function xrayBin () {
  const candidates = [
    process.env.XRAY_BIN,
    path.join(BASE, 'bin', WIN ? 'xray.exe' : 'xray'),
    'C:\\Program Files\\FlyFrogLLC\\Happ\\core\\xray.exe',
    '/usr/local/bin/xray'
  ]
  for (const c of candidates) if (c && existsSync(c)) return c
  throw new Error('не найден бинарник Xray — задайте XRAY_BIN')
}

function args () {
  const out = { node: [], res: [], url: [], sub: SUB_URL, json: null, via: process.env.VIA_SOCKS || '' }
  const argv = process.argv.slice(2)
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--node' || a === '--res' || a === '--url') out[a.slice(2)].push(argv[++i])
    else if (a === '--sub') out.sub = argv[++i]
    else if (a === '--via') out.via = argv[++i]
    else if (a === '--json') out.json = argv[++i]
    else throw new Error(`неизвестный аргумент ${a}`)
  }
  return out
}

async function fetchSubscription (url) {
  const resp = await fetch(url, { headers: { 'user-agent': 'Happ/1.0' } })
  if (!resp.ok) throw new Error(`подписка отдала ${resp.status}`)
  const data = await resp.json()
  if (!Array.isArray(data)) throw new Error('подписка вернула не список конфигов')
  return data
}

function freePort (start, taken) {
  for (let p = start; p < start + 300; p++) if (!taken.has(p)) { taken.add(p); return p }
  throw new Error('нет свободных портов под SOCKS')
}

const sleep = ms => new Promise(r => setTimeout(r, ms))

async function waitPort (port, deadlineMs = 10000) {
  const end = Date.now() + deadlineMs
  while (Date.now() < end) {
    const ok = await new Promise(resolve => {
      const s = createConnection({ host: '127.0.0.1', port })
      s.setTimeout(500)
      s.on('connect', () => { s.destroy(); resolve(true) })
      s.on('error', () => resolve(false))
      s.on('timeout', () => { s.destroy(); resolve(false) })
    })
    if (ok) return true
    await sleep(200)
  }
  return false
}

// Запрос через SOCKS узла. В curl на Windows нет HTTP/2, но для проб хватает 1.1.
function curl (res, port) {
  const t = res.timeout || TIMEOUT
  const cmd = [
    '-sS', '-m', String(t),
    '--socks5-hostname', `127.0.0.1:${port}`,
    '-o', '-', '-w', '\n<<HTTP:%{http_code}>>',
    '-A', res.ua || UA
  ]
  if (res.follow) cmd.push('-L', '--max-redirs', '5')
  for (const h of res.headers || []) cmd.push('-H', h)
  cmd.push(res.url)
  return new Promise(resolve => {
    execFile('curl', cmd, { timeout: (t + 10) * 1000, maxBuffer: 8 << 20 }, (err, stdout, stderr) => {
      const out = String(stdout || '')
      const m = out.match(/<<HTTP:(\d+)>>\s*$/)
      // code 0 = curl не получил ответа (не встал туннель, таймаут) — причина в stderr
      if (!m || m[1] === '000' || m[1] === '0') resolve({ code: null, body: out, err: (String(stderr || '').trim() || (err && err.message) || 'нет ответа').slice(0, 120) })
      else resolve({ code: Number(m[1]), body: out.slice(0, m.index).slice(0, 20000), err: '' })
    })
  })
}

function classify (res, { code, body, err }) {
  if (code === null) return { status: 'down', note: err || 'нет ответа' }
  const low = body.toLowerCase()
  for (const marker of res.block_markers || []) {
    if (low.includes(marker.toLowerCase())) return { status: 'blocked', note: `${code} · ${marker}` }
  }
  if ((res.block_status || []).includes(code)) return { status: 'blocked', note: String(code) }
  const okMarkers = res.ok_markers || []
  if (okMarkers.length && okMarkers.some(m => low.includes(m.toLowerCase()))) return { status: 'ok', note: String(code) }
  if ((res.ok_status || [200]).includes(code)) return { status: 'ok', note: String(code) }
  return { status: 'error', note: `неожиданный ${code}` }
}

function nodeAddress (entry) {
  for (const ob of entry.outbounds || []) {
    if (['vless', 'vmess', 'trojan', 'shadowsocks'].includes(ob.protocol)) {
      const peers = ob.settings?.vnext || ob.settings?.servers || []
      if (peers.length) return `${peers[0].address}:${peers[0].port}`
    }
  }
  return '?'
}

function xrayError (logPath) {
  try {
    const lines = readFileSync(logPath, 'utf8').split(/\r?\n/).slice(-200)
    for (let i = lines.length - 1; i >= 0; i--) {
      if (/failed|rejected|refused|timeout|unauthenticated/i.test(lines[i])) {
        return lines[i].split(' > ').pop().trim().slice(0, 110)
      }
    }
  } catch {}
  return ''
}

// Если у машины нет прямого выхода в интернет (типичный случай рабочего ПК за
// VPN-клиентом), Xray не дозвонится до узла. Тогда его исходящие заворачиваются
// в уже работающий локальный SOCKS: --via 127.0.0.1:10808. Выходной IP при этом
// всё равно узла — цепочка только доставляет до него.
function chainVia (outbounds, via) {
  if (!via) return outbounds
  const [host, port] = via.replace(/^socks5?:\/\//, '').split(':')
  const chained = outbounds.map(ob => {
    if (!['vless', 'vmess', 'trojan', 'shadowsocks'].includes(ob.protocol)) return ob
    const ss = { ...(ob.streamSettings || {}) }
    ss.sockopt = { ...(ss.sockopt || {}), dialerProxy: 'via-local' }
    return { ...ob, streamSettings: ss }
  })
  chained.push({
    tag: 'via-local',
    protocol: 'socks',
    settings: { servers: [{ address: host, port: Number(port || 1080) }] }
  })
  return chained
}

async function checkNode (entry, resources, taken, via) {
  const row = { node: entry.remarks || 'без имени', addr: nodeAddress(entry), results: {} }
  const port = freePort(PORT_BASE, taken)
  const dir = mkdtempSync(path.join(tmpdir(), 'rescheck-'))
  const cfgPath = path.join(dir, 'config.json')
  const logPath = path.join(dir, 'xray.log')

  const cfg = {
    log: { loglevel: 'info', access: logPath, error: logPath },
    inbounds: [{ tag: 'socks-in', listen: '127.0.0.1', port, protocol: 'socks', settings: { udp: true, auth: 'noauth' } }],
    outbounds: chainVia(entry.outbounds || [], via)
  }
  if (entry.dns) cfg.dns = entry.dns
  if (entry.routing) cfg.routing = entry.routing        // правила подписки сохраняем
  writeFileSync(cfgPath, JSON.stringify(cfg))

  let proc
  try {
    proc = spawn(xrayBin(), ['run', '-c', cfgPath], { stdio: 'ignore', windowsHide: true })
    proc.on('error', () => {})
    if (!await waitPort(port)) {
      row.error = 'Xray не поднял локальный порт: ' + (xrayError(logPath) || 'см. лог')
      return row
    }
    for (const res of resources) {
      const r = await curl(res, port)
      const verdict = classify(res, r)
      if (verdict.status === 'down' && !r.err) verdict.note = xrayError(logPath) || verdict.note
      row.results[res.id] = verdict
      if (res.extract && r.code !== null) {
        const m = r.body.match(new RegExp(res.extract))
        if (m) row.exit = (m.length > 1 ? m.slice(1).filter(Boolean).join(' ') : m[0])
      }
    }
  } catch (e) {
    row.error = `ошибка запуска Xray: ${e.message}`
  } finally {
    if (proc && proc.exitCode === null) { proc.kill('SIGKILL'); await Promise.race([once(proc, 'exit'), sleep(3000)]) }
    rmSync(dir, { recursive: true, force: true })
  }
  return row
}

// Простой пул: несколько узлов одновременно, каждый со своим Xray.
async function pool (items, limit, fn) {
  const out = new Array(items.length)
  let next = 0
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i], i) }
  }))
  return out
}

function render (rows, resources) {
  const width = Math.max(...rows.map(r => [...r.node].length)) + 2
  const cell = s => String(s).padEnd(11)
  const lines = [' '.repeat(width) + resources.map(r => cell(r.id.slice(0, 10))).join('')]
  for (const row of rows) {
    const cells = resources.map(r => cell(row.results[r.id] ? ICON[row.results[r.id].status] || '·' : '·')).join('')
    const tail = row.error ? `  ${ICON.error} ${row.error}` : (row.exit ? `  ${row.exit}` : '')
    lines.push(row.node.padEnd(width - ([...row.node].length - row.node.length)) + cells + tail)
  }
  lines.push('')
  for (const row of rows) {
    const bad = Object.entries(row.results).filter(([, v]) => v.status !== 'ok')
    if (bad.length) {
      lines.push(`${row.node}:`)
      for (const [id, v] of bad) lines.push(`    ${ICON[v.status]} ${id} — ${v.note}`)
    }
  }
  return lines.join('\n')
}

async function main () {
  const a = args()
  let resources = JSON.parse(readFileSync(process.env.RESOURCES_FILE || path.join(BASE, 'resources.json'), 'utf8'))
  if (a.res.length) {
    resources = resources.filter(r => a.res.includes(r.id))
    if (!resources.length) throw new Error('ни один ресурс не подошёл под --res')
  }
  for (const url of a.url) resources.push({ id: new URL(url).hostname.replace(/^www\./, ''), url, ok_status: [200, 301, 302] })

  let entries = await fetchSubscription(a.sub)
  if (a.node.length) {
    entries = entries.filter(e => a.node.some(n => (e.remarks || '').toLowerCase().includes(n.toLowerCase())))
    if (!entries.length) throw new Error('ни один узел не подошёл под --node')
  }

  console.error(`узлов: ${entries.length}, ресурсов: ${resources.length}`)
  const taken = new Set()
  const rows = await pool(entries, WORKERS, e => checkNode(e, resources, taken, a.via))
  console.log(render(rows, resources))
  if (a.json) writeFileSync(a.json, JSON.stringify(rows, null, 2))
}

main().catch(e => { console.error(e.message); process.exit(1) })
