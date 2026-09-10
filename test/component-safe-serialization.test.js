'use strict'

const test = require('tape')
const fastURI = require('..')

// RFC 3986 defines the port as `*DIGIT`, so anything else in a component object
// is not a port at all. Recomposing such a value verbatim lets it terminate the
// authority and smuggle in a different one: a port of "@127.0.0.1:8124" turns
// `{ host: 'trusted.example', port }` into "http://trusted.example:@127.0.0.1:8124/app",
// which every URL consumer resolves to 127.0.0.1 (SSRF / origin-allowlist
// bypass), and "/", "?" or "#" in a port similarly injects a path, query or
// fragment. Serialization must fail closed instead of emitting the injected URI.
test('port serialization rejects non-digit values', (t) => {
  const malformedPorts = [
    '@127.0.0.1:8124',
    '8080@evil.example',
    '8080/path',
    '8080?query',
    '8080#fragment',
    '8080:9000',
    '-1',
    '1.5',
    1.5,
    NaN,
    Infinity,
    // Arabic-Indic digit one (U+0661): a Unicode "digit" that is not an ASCII
    // DIGIT. Built from its code point so the source file stays ASCII-only.
    String.fromCharCode(0x0661)
  ]

  for (const port of malformedPorts) {
    t.throws(
      () => fastURI.serialize({ scheme: 'http', host: 'trusted.example', port, path: '/app' }),
      /URI port is malformed\./,
      String(port)
    )
  }

  t.throws(
    () => fastURI.normalize({ scheme: 'http', host: 'trusted.example', port: '@evil.example' }),
    /URI port is malformed\./,
    'object normalization rejects a malformed port'
  )
  t.equal(
    fastURI.equal(
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' },
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' }
    ),
    false,
    'object equality fails closed for a malformed port'
  )
  t.end()
})

test('port serialization preserves RFC 3986 digit values', (t) => {
  const validPorts = [
    [8080, '8080'],
    ['8080', '8080'],
    ['00080', '00080'],
    ['', '']
  ]

  for (const [port, expected] of validPorts) {
    t.equal(
      fastURI.serialize({ scheme: 'uri', host: 'example.test', port }),
      `uri://example.test:${expected}`,
      JSON.stringify(port)
    )
  }
  t.end()
})
