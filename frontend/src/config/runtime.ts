import { resolveRuntimeConfig } from './runtimeConfig'

export const runtimeConfig = resolveRuntimeConfig(import.meta.env)
