/**
 * Parser for modern proxy sharing links: vless://, vmess://, trojan://, ss://
 */

export interface ParsedNodeLink {
  protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks'
  server: string
  username?: string
  password?: string
  name?: string
  raw: string
}

function decodeBase64(str: string): string {
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/')
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(normalized + padding)
  const bytes = Uint8Array.from(binary, (m) => m.codePointAt(0) ?? 0)
  return new TextDecoder().decode(bytes)
}

export function parseNodeLink(link: string): ParsedNodeLink | null {
  const raw = link.trim()
  if (!raw) return null

  // VMess base64 JSON
  if (raw.startsWith('vmess://') && !/^vmess:\/\/[^@]+@[^:]+:\d+/i.test(raw)) {
    try {
      const b64Part = raw.slice(8).split('#')[0]
      const jsonStr = decodeBase64(b64Part)
      const data = JSON.parse(jsonStr)
      const host = String(data.add || '').trim()
      const port = Number(data.port || 443)
      if (!host || !port) return null

      return {
        protocol: 'vmess',
        server: `${host}:${port}`,
        username: data.id ? String(data.id) : undefined,
        name: data.ps ? String(data.ps).trim() : undefined,
        raw,
      }
    } catch {
      return null
    }
  }

  // URL-like schemes: vless://, trojan://, vmess://, ss://
  const match = raw.match(/^([a-zA-Z0-9_-]+):\/\/([^/?#]+)(?:\?[^#]*)?(?:#(.*))?$/)
  if (!match) return null

  const scheme = match[1].toLowerCase()
  if (!['vless', 'vmess', 'trojan', 'ss', 'shadowsocks'].includes(scheme)) {
    return null
  }

  const protocol: ParsedNodeLink['protocol'] =
    scheme === 'ss' || scheme === 'shadowsocks'
      ? 'shadowsocks'
      : (scheme as ParsedNodeLink['protocol'])

  let name: string | undefined
  if (match[3]) {
    try {
      name = decodeURIComponent(match[3]).trim()
    } catch {
      name = match[3].trim()
    }
  }

  let authority = match[2]
  let userinfo = ''
  if (authority.includes('@')) {
    const parts = authority.split('@')
    userinfo = parts.slice(0, -1).join('@')
    authority = parts[parts.length - 1]
  }

  userinfo = decodeURIComponent(userinfo)

  let username: string | undefined
  let password: string | undefined

  if (protocol === 'shadowsocks') {
    if (!userinfo && authority && !authority.includes(':')) {
      try {
        const decoded = decodeBase64(authority)
        if (decoded.includes('@')) {
          const parts = decoded.split('@')
          userinfo = parts[0]
          authority = parts[1]
        }
      } catch {
        // pass
      }
    }
    if (userinfo.includes(':')) {
      const parts = userinfo.split(':')
      password = parts.slice(1).join(':')
    } else {
      password = userinfo
    }
  } else if (protocol === 'trojan') {
    password = userinfo || undefined
  } else {
    username = userinfo || undefined
  }

  let host = authority
  let port = 443
  if (authority.includes(':')) {
    const lastColon = authority.lastIndexOf(':')
    host = authority.slice(0, lastColon).replace(/^\[|\]$/g, '')
    const parsedPort = parseInt(authority.slice(lastColon + 1), 10)
    if (!isNaN(parsedPort)) {
      port = parsedPort
    }
  } else {
    host = host.replace(/^\[|\]$/g, '')
  }

  if (!host) return null

  return {
    protocol,
    server: `${host}:${port}`,
    username,
    password,
    name: name || undefined,
    raw,
  }
}
