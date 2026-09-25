import test from 'node:test';
import assert from 'node:assert/strict';
import { createPkce, safeOrigin, validDeviceCode, validVerificationUrl } from '../orin.mjs';

test('safeOrigin only permits HTTPS or explicit loopback', () => {
  assert.equal(safeOrigin('https://orinai.org'), 'https://orinai.org');
  assert.equal(safeOrigin('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
  assert.throws(() => safeOrigin('http://example.com'), /HTTPS/);
  assert.throws(() => safeOrigin('https://user:pass@orinai.org'), /credentials/);
  assert.throws(() => safeOrigin('https://orinai.org?x=1'), /credentials/);
});

test('PKCE verifier and S256 challenge have the expected shapes', () => {
  const first = createPkce();
  const second = createPkce();
  assert.match(first.verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.match(first.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.verifier, second.verifier);
  assert.notEqual(first.challenge, second.challenge);
});

test('device and verification values are validated before use', () => {
  assert.equal(validDeviceCode('a'.repeat(43)), true);
  assert.equal(validDeviceCode('short'), false);
  assert.equal(validDeviceCode(`${'a'.repeat(42)}+`), false);
  assert.equal(validVerificationUrl('https://orinai.org/#device-auth', 'https://orinai.org'), true);
  assert.equal(validVerificationUrl('https://evil.example/device', 'https://orinai.org'), false);
  assert.equal(validVerificationUrl('http://orinai.org/#device-auth', 'https://orinai.org'), false);
});
