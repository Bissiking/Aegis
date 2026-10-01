import { describe, expect, it } from 'vitest'
import { peekProfile, putProfile, takeProfile } from './profileStore'
import type { CreatedDevice } from './api'

function payload(id: string): CreatedDevice {
  return {
    device: { id, user_id: 'usr_1', server_id: 'srv_1', name: 'phone', platform: '', status: 'active', created_at: 0, updated_at: 0, revoked_at: null, last_seen_at: null, effective_state: 'active' },
    peer: {},
    profile: {
      filename: 'phone.conf',
      conf: '[Interface]\nPrivateKey = SECRET-PRIVATE-KEY\nAddress = 10.77.0.2/32\n',
      qr_png_base64: 'AAAA',
      one_time_only: true,
      server_name: 'primary',
      allowed_ip: '10.77.0.2/32',
      public_key: 'PUB',
      expires_at: null,
      dns: '1.1.1.1',
      endpoint: 'vpn.example.org:51820',
    },
  }
}

describe('profile delivery store', () => {
  it('keeps the payload in memory only and serves it once', () => {
    putProfile('dev_1', payload('dev_1'))
    expect(peekProfile('dev_1')?.profile.public_key).toBe('PUB')

    const taken = takeProfile('dev_1')
    expect(taken?.profile.conf).toContain('SECRET-PRIVATE-KEY')
    // Second read: the key is gone.
    expect(takeProfile('dev_1')).toBeUndefined()
    expect(peekProfile('dev_1')).toBeUndefined()
  })

  it('isolates payloads per device', () => {
    putProfile('dev_a', payload('dev_a'))
    putProfile('dev_b', payload('dev_b'))
    takeProfile('dev_a')
    expect(peekProfile('dev_a')).toBeUndefined()
    expect(peekProfile('dev_b')).toBeDefined()
  })
})
