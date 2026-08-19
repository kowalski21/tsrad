/** Small environment-based configuration helpers for twelve-factor apps. */
import { Client, type ClientOptions } from './client.js';
import { Server, type ServerOptions } from './server.js';

export interface RadiusEnv {
  [key: string]: string | undefined;
  RADIUS_SERVER?: string;
  RADIUS_SECRET?: string;
  RADIUS_SECRET_ENCODING?: 'utf8' | 'base64' | 'hex';
  RADIUS_AUTH_PORT?: string;
  RADIUS_ACCT_PORT?: string;
  RADIUS_COA_PORT?: string;
  RADIUS_TIMEOUT?: string;
  RADIUS_RETRIES?: string;
  RADIUS_ADDRESSES?: string;
}

function numberEnv(env: RadiusEnv, key: keyof RadiusEnv, fallback: number): number {
  const value = env[key];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${String(key)} must be a non-negative integer`);
  }
  return parsed;
}

function required(env: RadiusEnv, key: keyof RadiusEnv): string {
  const value = env[key];
  if (!value) throw new Error(`${String(key)} is required`);
  return value;
}

export function secretFromEnv(env: RadiusEnv = process.env): Buffer {
  const value = required(env, 'RADIUS_SECRET');
  return Buffer.from(value, env.RADIUS_SECRET_ENCODING ?? 'utf8');
}

export function clientOptionsFromEnv(
  env: RadiusEnv = process.env,
  extra: Partial<ClientOptions> = {},
): ClientOptions {
  return {
    server: required(env, 'RADIUS_SERVER'),
    secret: secretFromEnv(env),
    authport: numberEnv(env, 'RADIUS_AUTH_PORT', 1812),
    acctport: numberEnv(env, 'RADIUS_ACCT_PORT', 1813),
    coaport: numberEnv(env, 'RADIUS_COA_PORT', 3799),
    timeout: numberEnv(env, 'RADIUS_TIMEOUT', 5),
    retries: numberEnv(env, 'RADIUS_RETRIES', 3),
    ...extra,
  };
}

export function serverOptionsFromEnv(
  env: RadiusEnv = process.env,
  extra: ServerOptions = {},
): ServerOptions {
  return {
    addresses: env.RADIUS_ADDRESSES?.split(',').map(v => v.trim()).filter(Boolean)
      ?? ['0.0.0.0'],
    authport: numberEnv(env, 'RADIUS_AUTH_PORT', 1812),
    acctport: numberEnv(env, 'RADIUS_ACCT_PORT', 1813),
    coaport: numberEnv(env, 'RADIUS_COA_PORT', 3799),
    ...extra,
  };
}

export function createClientFromEnv(
  env: RadiusEnv = process.env,
  extra: Partial<ClientOptions> = {},
): Client {
  return new Client(clientOptionsFromEnv(env, extra));
}

export function createServerFromEnv(
  env: RadiusEnv = process.env,
  extra: ServerOptions = {},
): Server {
  return new Server(serverOptionsFromEnv(env, extra));
}
