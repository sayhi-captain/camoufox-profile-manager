import test from 'node:test'
import assert from 'node:assert/strict'
import { isDesktopClient } from '../src/lib/environment.js'

test('isDesktopClient returns false when not in pywebview', () => {
  // In node environment without pywebview or query params
  assert.equal(isDesktopClient(), false)
})

test('isDesktopClient detects pywebview on window', () => {
  const originalWindow = globalThis.window
  try {
    ;(globalThis as any).window = {
      pywebview: {},
      sessionStorage: { getItem: () => null, setItem: () => {} },
      location: { search: '' },
    }
    assert.equal(isDesktopClient(), true)
  } finally {
    ;(globalThis as any).window = originalWindow
  }
})

test('isDesktopClient detects desktop query param', () => {
  const originalWindow = globalThis.window
  try {
    let stored: string | null = null
    ;(globalThis as any).window = {
      sessionStorage: {
        getItem: (k: string) => (k === 'cpm_is_desktop' ? stored : null),
        setItem: (k: string, v: string) => {
          if (k === 'cpm_is_desktop') stored = v
        },
      },
      location: { search: '?desktop=1' },
    }
    assert.equal(isDesktopClient(), true)
    assert.equal(stored, '1')
  } finally {
    ;(globalThis as any).window = originalWindow
  }
})
