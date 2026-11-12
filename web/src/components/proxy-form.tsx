'use client'

import { useState } from 'react'
import { LoaderCircle } from 'lucide-react'
import { useI18n } from '@/components/i18n-provider'
import { Modal } from '@/components/modal'
import { proxyAuthenticationError } from '@/lib/proxy-auth'
import { ProxyProtocolHelp } from '@/components/proxy-protocol-help'
import { isStaleWrite, proxiesAPI, type LibraryProxy } from '@/lib/api'
import { parseNodeLink } from '@/lib/node-parser'

export function ProxyForm({ proxy, onClose, onSaved, onReload }: {
  proxy: LibraryProxy | null
  onClose: () => void
  onSaved: (proxy: LibraryProxy) => void
  onReload: () => Promise<void>
}) {
  const { t } = useI18n()
  const [name, setName] = useState(proxy?.name ?? '')
  const [type, setType] = useState(proxy?.type ?? 'http')
  const [server, setServer] = useState(proxy?.server ?? '')
  const [username, setUsername] = useState(proxy?.username ?? '')
  const [password, setPassword] = useState('')
  const [clearPassword, setClearPassword] = useState(false)
  const [country, setCountry] = useState(proxy?.country ?? '')
  const [nodeLink, setNodeLink] = useState(proxy?.node_link ?? '')
  const [importLink, setImportLink] = useState('')
  const [importedNode, setImportedNode] = useState<{ protocol: string; server: string; name?: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [stale, setStale] = useState(false)

  const authenticationError = proxyAuthenticationError(type, username, clearPassword ? '' : password, !!(proxy?.has_password && !clearPassword))

  function handleImportNodeLink(val: string) {
    setImportLink(val)
    const parsed = parseNodeLink(val)
    if (parsed) {
      setType(parsed.protocol)
      setServer(parsed.server)
      if (parsed.username) setUsername(parsed.username)
      if (parsed.password) setPassword(parsed.password)
      if (parsed.name && !name.trim()) setName(parsed.name)
      setNodeLink(parsed.raw)
      setImportedNode({ protocol: parsed.protocol.toUpperCase(), server: parsed.server, name: parsed.name })
    }
  }

  async function save(event: React.FormEvent) {
    event.preventDefault()
    if (saving) return
    if (authenticationError) { setError(t(authenticationError)); return }
    if (!name.trim() || !server.trim()) { setError(t('Enter a name and proxy server.')); return }
    if ((password || (proxy?.has_password && !clearPassword)) && !username) {
      if (!['vless', 'vmess', 'trojan', 'shadowsocks'].includes(type)) {
        setError(t('A password requires a username. Enter a username or remove the stored password.'))
        return
      }
    }
    setSaving(true); setError(null); setStale(false)
    const data: Record<string, unknown> = {
      name: name.trim(),
      type,
      server: server.trim(),
      username: username || null,
      country: country.trim().toUpperCase() || null,
      node_link: nodeLink || null,
    }
    if (clearPassword) data.password = null
    else if (password) data.password = password
    if (proxy) data.row_version = proxy.row_version
    try {
      const saved = proxy ? await proxiesAPI.update(proxy.id, data) : await proxiesAPI.create(data)
      setPassword('')
      onSaved(saved)
    } catch (err) {
      setStale(isStaleWrite(err))
      setError(isStaleWrite(err) ? t('This proxy changed elsewhere. Your draft is preserved. Reload the saved proxy before editing again.') : t(err instanceof Error ? err.message : 'Could not save proxy'))
    } finally { setSaving(false) }
  }

  return <Modal open title={proxy ? t('Edit library proxy') : t('New library proxy')} onClose={() => { if (!saving) onClose() }} width={540} footer={<>
    <button className="btn btn-default" onClick={onClose} disabled={saving}>{t('Cancel')}</button>
    <button type="submit" form="library-proxy-form" className="btn btn-primary" disabled={saving || stale || !!authenticationError}>{saving && <LoaderCircle size={13} className="animate-spin motion-reduce:animate-none" aria-hidden="true" />}{saving ? t('Saving…') : proxy ? t('Save changes') : t('Create proxy')}</button>
  </>}>
    <form id="library-proxy-form" className="flex flex-col gap-4" onSubmit={save}>
      <p className="text-ink-dim">{t('Library changes apply only to future assignments. Profiles keep their current proxy settings until you explicitly assign again.')}</p>
      <div>
        <label className="field-label" htmlFor="lp-import-link">{t('Quick import node link')}</label>
        <input
          id="lp-import-link"
          className="field font-mono text-[12px]"
          value={importLink}
          onChange={event => handleImportNodeLink(event.target.value)}
          placeholder={t('Paste vless://, vmess:// or trojan:// link')}
          autoComplete="off"
        />
        {importedNode && (
          <p className="mt-1 text-[12px] text-accent">
            {t('Imported {protocol} node: {server}', { protocol: importedNode.protocol, server: importedNode.server })}
            {importedNode.name ? ` (${importedNode.name})` : ''}
          </p>
        )}
      </div>
      <div><label className="field-label" htmlFor="lp-name">{t('Name')}</label><input id="lp-name" className="field" value={name} onChange={event => setName(event.target.value)} maxLength={255} data-modal-autofocus required /></div>
      <div className="grid grid-cols-[100px_1fr] gap-3">
        <div><label className="field-label" htmlFor="lp-type">{t('Type')}</label><select id="lp-type" className="field" value={type} onChange={event => setType(event.target.value)} aria-describedby="lp-type-help"><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks4">SOCKS4</option><option value="socks5">SOCKS5</option><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option></select></div>
        <div><label className="field-label" htmlFor="lp-server">{t('Server')}</label><input id="lp-server" className="field font-mono" value={server} onChange={event => setServer(event.target.value)} placeholder="host:port" maxLength={512} required autoComplete="off" aria-describedby="lp-server-help" /><p id="lp-server-help" className="mt-1 text-ink-dim">{t('Host and port only. Use brackets for IPv6: [::1]:8080.')}</p></div>
      </div>
      <ProxyProtocolHelp type={type} id="lp-type-help" />
      <div className="grid grid-cols-2 gap-3">
        <div><label className="field-label" htmlFor="lp-user">{t('Username')}</label><input id="lp-user" className="field" value={username} onChange={event => setUsername(event.target.value)} maxLength={255} autoComplete="off" /></div>
        <div><label className="field-label" htmlFor="lp-country">{t('Country (optional)')}</label><input id="lp-country" className="field uppercase" value={country} onChange={event => setCountry(event.target.value)} maxLength={64} placeholder="DE" /></div>
      </div>
      <div>
        <label className="field-label" htmlFor="lp-password">{proxy?.has_password ? t('Replace password') : t('Password (optional)')}</label>
        <input id="lp-password" className="field" type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="new-password" maxLength={4096} disabled={clearPassword} aria-describedby="lp-password-help" />
        <p id="lp-password-help" className="mt-1 text-ink-dim">{proxy?.has_password ? t('A password is stored but never displayed. Leave this blank to keep it.') : t('Passwords require encryption to be configured on this instance.')}</p>
        {proxy?.has_password && <label className="mt-2 flex items-center gap-2"><input type="checkbox" checked={clearPassword} onChange={event => { setClearPassword(event.target.checked); setPassword('') }} />{t('Remove stored password')}</label>}
      </div>
      {authenticationError && <p role="alert" className="text-danger">{t(authenticationError)}</p>}
      {type === 'socks5' && <p className="text-ink-dim">{t('SOCKS5 authentication is handled automatically by a local relay. No extension or manual browser setup is needed.')}</p>}
      {['vless', 'vmess', 'trojan'].includes(type) && <p className="text-ink-dim">{t('This node is bridged automatically by a local sing-box sidecar to an ephemeral SOCKS5 port.')}</p>}
      {error && <div role="alert" className="rounded-md border border-line bg-raised p-3"><p className="break-words text-danger">{error}</p>{stale && <><p className="mt-1 text-ink-dim">{t('Reloading replaces this draft with the latest saved values and clears the password field.')}</p><button type="button" className="btn btn-default mt-2" onClick={onReload}>{t('Reload saved proxy')}</button></>}</div>}
    </form>
  </Modal>
}
