'use strict'

const test = require('tape')
const fastURI = require('..')

const HOST_ERROR = 'URI host is malformed.'

const malformedLiterals = [
  '::not-valid',
  'fc00::not-hex',
  'fe80::not-hex',
  '1:2:3',
  '1:2:3:4:5:6:7',
  '1:2:3:4:5:6:7:8:9',
  '1::2::3',
  '1:::2',
  ':::1',
  '12345::',
  '1:2:3:4:5:6:7::8',
  '::ffff:192.0.2.999',
  '::ffff:192.0.2',
  '::ffff:192.168.001.1',
  '::192.0.2.1:1',
  '1:2:3:4:5:192.0.2.1::',
  'v.foo',
  'v1.',
  'v1.foo%25bar',
  'v1.K',
  'fe80::1%25',
  'fe80::1%25eth 0',
  'fe80::1%25eth%ZZ',
  'fe80::1%25K',
  'not-an-ip'
]

test('malformed bracketed IP literals fail without being rewritten', (t) => {
  for (const literal of malformedLiterals) {
    const uri = `http://[${literal}]/private`
    const parsed = fastURI.parse(uri)

    t.equal(parsed.error, HOST_ERROR, `parse rejects ${literal}`)
    t.equal(parsed.host, `[${literal.toLowerCase()}]`, `parse does not truncate ${literal}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${literal}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${literal}`)
  }
  t.end()
})

test('resolve throws for malformed bracketed IP literals', (t) => {
  for (const literal of malformedLiterals) {
    const uri = `http://[${literal}]/private`

    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI host is malformed\./,
      `rejects malformed base ${literal}`
    )
    t.throws(
      () => fastURI.resolve('http://example.com/', uri),
      /URI host is malformed\./,
      `rejects malformed relative input ${literal}`
    )
  }
  t.end()
})

test('valid IPv6, IPvFuture, embedded IPv4, and zone forms normalize safely', (t) => {
  const cases = [
    ['http://[::]/', 'http://[::]/', '::'],
    ['http://[::1]/', 'http://[::1]/', '::1'],
    ['http://[1::]/', 'http://[1::]/', '1::'],
    ['http://[2001:0DB8::0001]/', 'http://[2001:db8::1]/', '2001:db8::1'],
    ['http://[0:0:0:0:0:0:0:0]/', 'http://[::]/', '::'],
    ['http://[::ffff:192.0.2.1]/', 'http://[::ffff:192.0.2.1]/', '::ffff:192.0.2.1'],
    ['http://[1:2:3:4:5:6:192.0.2.1]/', 'http://[1:2:3:4:5:6:192.0.2.1]/', '1:2:3:4:5:6:192.0.2.1'],
    ['http://[fe80::A%25EN1]/', 'http://[fe80::a%25EN1]/', 'fe80::a%EN1'],
    ['http://[fe80::a%en1]/', 'http://[fe80::a%25en1]/', 'fe80::a%en1'],
    ['http://[fe80::a%25eth%2D0]/', 'http://[fe80::a%25eth%2D0]/', 'fe80::a%eth%2D0'],
    ['http://[v1.example]/', 'http://[v1.example]/', '[v1.example]'],
    ['http://[vF.A:b]/', 'http://[vf.a:b]/', '[vf.a:b]']
  ]

  for (const [uri, normalized, host] of cases) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, undefined, `${uri} parses without error`)
    t.equal(parsed.host, host, `${uri} has the expected host`)
    t.equal(fastURI.normalize(uri), normalized, `${uri} normalizes safely`)
  }
  t.end()
})

const PATH_ERROR = 'URI path must start with "/" when authority is present.'

// RFC 3986 allows "[" and "]" in a host only as the delimiters of an IP
// literal, so a host carrying either without being exactly "[...]" is
// malformed and must be rejected instead of being handled as a reg-name: an
// unterminated "[fe80::1", a stray "evil.com]", or a bracket smuggled in after
// the userinfo delimiter would otherwise reach the IDN/WHATWG hostname parser,
// which repairs some of them into a different host (SSRF / origin-allowlist
// bypass), and reaches nothing at all for a scheme with no handler, leaving
// those inputs accepted outright.
// Each entry is [uri, host as parsed, expected error].
const strayBracketHosts = [
  // Unterminated opening bracket. The authority guard for a path that does not
  // start with "/" claims the error message first here, but the host guard is
  // what marks the authority malformed.
  ['http://[fe80::1/private', '[fe80', PATH_ERROR],
  ['http://[fe80', '[fe80', HOST_ERROR],
  ['http://[', '[', HOST_ERROR],
  ['http://[not-an-ip', '[not-an-ip', HOST_ERROR],
  ['http://[日本', '[日本', HOST_ERROR],
  // Stray closing bracket on an otherwise ordinary reg-name.
  ['http://evil.com]/private', 'evil.com]', HOST_ERROR],
  // Bracket smuggled in right after the userinfo delimiter, so the host fast-uri
  // parses differs from the one a lenient engine resolves.
  ['http://user@[@127.0.0.1:8123/admin', '[@127.0.0.1', HOST_ERROR],
  ['http://user@]127.0.0.1:8123/admin', ']127.0.0.1', HOST_ERROR],
  ['http://user@prefix[@127.0.0.1:8123/admin', 'prefix[@127.0.0.1', HOST_ERROR],
  ['http://user@prefix]@127.0.0.1:8123/admin', 'prefix]@127.0.0.1', HOST_ERROR],
  // No scheme handler, so the IDN conversion never runs: the host guard is the
  // only thing that can reject this one.
  ['foo://[evil.com/private', '[evil.com', HOST_ERROR]
]

// The host guard must reject on its own, not as a side effect of the IDN
// conversion, so every case is checked with IRI support both off and on.
const modes = [
  { name: 'default', options: undefined },
  { name: 'unicodeSupport', options: { unicodeSupport: true } }
]

/**
 * @param {() => unknown} fn
 * @returns {string|undefined}
 */
function caughtMessage (fn) {
  try {
    fn()
  } catch (error) {
    return /** @type {Error} */ (error).message
  }
  return undefined
}

test('hosts with unbalanced or misplaced IP-literal brackets are rejected', (t) => {
  for (const { name, options } of modes) {
    for (const [uri, host, error] of strayBracketHosts) {
      const parsed = fastURI.parse(uri, options)

      t.equal(parsed.error, error, `${name}: parse rejects ${uri}`)
      t.equal(parsed.host, host, `${name}: parse does not rewrite the host of ${uri}`)
      t.equal(fastURI.normalize(uri, options), uri, `${name}: normalize preserves ${uri}`)
      t.equal(fastURI.equal(uri, uri, options), false, `${name}: equal rejects ${uri}`)
    }
  }
  t.end()
})

test('resolve throws for hosts with unbalanced or misplaced IP-literal brackets', (t) => {
  for (const { name, options } of modes) {
    for (const [uri, , error] of strayBracketHosts) {
      t.equal(
        caughtMessage(() => fastURI.resolve(uri, 'child', options)),
        error,
        `${name}: rejects malformed base ${uri}`
      )
      t.equal(
        caughtMessage(() => fastURI.resolve('http://example.com/', uri, options)),
        error,
        `${name}: rejects malformed relative input ${uri}`
      )
    }
  }
  t.end()
})
