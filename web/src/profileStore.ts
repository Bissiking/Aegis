import type { CreatedDevice } from './api'

// In-memory, single-view storage for a freshly delivered profile.
//
// The private key must never be persisted: not in the database, not in
// localStorage/sessionStorage, not in the URL. It lives in a JS variable for
// the lifetime of the confirmation view only.
const store = new Map<string, CreatedDevice>()

export function putProfile(deviceId: string, payload: CreatedDevice) {
  store.set(deviceId, payload)
}

// takeProfile returns the payload and forgets it: a delivered configuration
// can be displayed only once.
export function takeProfile(deviceId: string): CreatedDevice | undefined {
  const payload = store.get(deviceId)
  store.delete(deviceId)
  return payload
}

export function peekProfile(deviceId: string): CreatedDevice | undefined {
  return store.get(deviceId)
}
