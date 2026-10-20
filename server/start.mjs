import {rmSync, statSync} from 'node:fs';
import {upstash} from '../lib/relay.mjs';
import {publicSend, relayServer} from './relay.mjs';
import {valkey} from './valkey.mjs';

// `node server/start.mjs` runs a self-hosted relay. AGENTCHAT_LISTEN is a socket path, a bare port (this machine only) or host:port.
// Storage is Valkey or Redis when AGENTCHAT_VALKEY is set (a socket path or host:port), otherwise the Upstash variables.
// AGENTCHAT_PROXY_HOPS counts the proxies in front that append X-Forwarded-For; with none, the header is ignored.
const env = process.env, listen = env.AGENTCHAT_LISTEN ?? '8787';
const redis = env.AGENTCHAT_VALKEY ? valkey(env.AGENTCHAT_VALKEY, {user: env.AGENTCHAT_VALKEY_USER, password: env.AGENTCHAT_VALKEY_PASSWORD}) : upstash();
const ownerKeys = (env.AGENTCHAT_OWNER_KEYS ?? '').split(',').map(s => s.trim()).filter(Boolean);
const server = relayServer({redis, ownerKeys, send: publicSend}, {base: env.AGENTCHAT_PUBLIC_URL, trustedProxyHops: Number(env.AGENTCHAT_PROXY_HOPS ?? 0)});

server.on('listening', () => {
  const where = server.address();
  console.log(`agentchat relay on ${typeof where === 'string' ? where : `${where.address}:${where.port}`}, storing in ${env.AGENTCHAT_VALKEY ? 'Valkey' : 'Upstash'}`);
});
if (listen.includes('/')) {
  if (statSync(listen, {throwIfNoEntry: false})?.isSocket()) rmSync(listen);
  server.listen(listen);
} else if (/^\d+$/.test(listen)) server.listen(Number(listen), '127.0.0.1');
else server.listen(Number(listen.slice(listen.lastIndexOf(':') + 1)), listen.slice(0, listen.lastIndexOf(':')).replace(/^\[|\]$/g, ''));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
