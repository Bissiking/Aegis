import { createContext, useContext } from 'react'
import type { Meta, User } from './api'

export interface AuthState {
  user: User | null
  loading: boolean
  meta: Meta | null
  refresh: () => Promise<void>
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const AuthCtx = createContext<AuthState>(null as unknown as AuthState)

export function useAuth(): AuthState {
  return useContext(AuthCtx)
}
