import test from 'node:test'
import assert from 'node:assert/strict'
import { parseNodeLink } from '../src/lib/node-parser'

test('parseNodeLink correctly parses vless reality links', () => {
  const link =
    'vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#TestVLESS'
  const parsed = parseNodeLink(link)
  assert.ok(parsed)
  assert.equal(parsed.protocol, 'vless')
  assert.equal(parsed.server, '1.2.3.4:443')
  assert.equal(parsed.username, 'a3b68078-d428-48fe-a78b-4b2a33f44534')
  assert.equal(parsed.name, 'TestVLESS')
})

test('parseNodeLink correctly parses trojan links', () => {
  const link = 'trojan://password123@example.com:443?security=tls&sni=example.com#MyTrojan'
  const parsed = parseNodeLink(link)
  assert.ok(parsed)
  assert.equal(parsed.protocol, 'trojan')
  assert.equal(parsed.server, 'example.com:443')
  assert.equal(parsed.password, 'password123')
  assert.equal(parsed.name, 'MyTrojan')
})

test('parseNodeLink correctly parses base64 vmess links', () => {
  const vmessObj = {
    v: '2',
    ps: 'MyVMess',
    add: '9.8.7.6',
    port: 8443,
    id: 'uuid-1234-5678',
    aid: 0,
    scy: 'auto',
    net: 'ws',
    type: 'none',
    host: 'ws.example.com',
    path: '/ws',
    tls: 'tls',
  }
  const b64 = Buffer.from(JSON.stringify(vmessObj)).toString('base64')
  const parsed = parseNodeLink(`vmess://${b64}`)
  assert.ok(parsed)
  assert.equal(parsed.protocol, 'vmess')
  assert.equal(parsed.server, '9.8.7.6:8443')
  assert.equal(parsed.username, 'uuid-1234-5678')
  assert.equal(parsed.name, 'MyVMess')
})

test('parseNodeLink returns null for invalid links', () => {
  assert.equal(parseNodeLink(''), null)
  assert.equal(parseNodeLink('http://not-a-node'), null)
  assert.equal(parseNodeLink('invalid://link'), null)
})
