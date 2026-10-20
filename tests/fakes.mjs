import {generateKeyPairSync, randomBytes, sign} from 'node:crypto';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInvitesHandler} from '../api/invites.js';
import {createKeysHandler} from '../api/keys.js';
import {createMessagesHandler} from '../api/messages.js';
import {createNotifyHandler} from '../api/notify.js';
import {createSpacesHandler} from '../api/spaces.js';
import {ApprovalError} from '../lib/approval.mjs';
import {createNode} from '../lib/node.mjs';
import {b64, identityFromSeed, unb64} from '../lib/wire.mjs';

export const RELAY = 'https://relay.test';

export function memoryRedis(clock = () => Date.now()) {
  const data = new Map(), expires = new Map();
  const live = key => {
    if (expires.has(key) && expires.get(key) <= clock()) { data.delete(key); expires.delete(key); }
    return data.get(key);
  };
  const of = (key, make) => { let value = live(key); if (value === undefined) data.set(key, value = make()); return value; };
  const span = (length, start, stop) => [Number(start), Number(stop) < 0 ? length + Number(stop) + 1 : Number(stop) + 1];
  const commands = {
    PING: () => 'PONG',
    GET: key => live(key) ?? null,
    SET(key, value, ...options) {
      if (options.includes('NX') && live(key) !== undefined) return null;
      if (options.includes('XX') && live(key) === undefined) return null;
      data.set(key, String(value));
      const ex = options.indexOf('EX');
      if (ex >= 0) expires.set(key, clock() + Number(options[ex + 1]) * 1000); else expires.delete(key);
      return 'OK';
    },
    GETDEL: key => { const value = live(key) ?? null; data.delete(key); return value; },
    DEL: (...keys) => keys.filter(key => data.delete(key)).length,
    EXISTS: (...keys) => keys.filter(key => live(key) !== undefined).length,
    MGET: (...keys) => keys.map(key => live(key) ?? null),
    INCR: key => commands.INCRBY(key, 1),
    INCRBY: (key, by) => { const value = Number(live(key) ?? 0) + Number(by); data.set(key, String(value)); return value; },
    EXPIRE: (key, seconds) => (live(key) === undefined ? 0 : (expires.set(key, clock() + Number(seconds) * 1000), 1)),
    ZADD: (key, score, member) => (of(key, () => new Map()).set(member, Number(score)), 1),
    ZRANGE: (key, start, stop) => { const sorted = [...(live(key) ?? new Map())].sort((a, b) => a[1] - b[1]).map(([m]) => m); return sorted.slice(...span(sorted.length, start, stop)); },
    ZREM: (key, ...members) => members.filter(m => live(key)?.delete(m)).length,
    ZCARD: key => live(key)?.size ?? 0,
    ZREMRANGEBYSCORE: (key, min, max) => { let n = 0; for (const [m, s] of live(key) ?? []) if (s >= Number(min) && s <= Number(max)) live(key).delete(m), n++; return n; },
    SADD: (key, ...members) => { const set = of(key, () => new Set()); return members.filter(m => !set.has(m) && set.add(m)).length; },
    SREM: (key, ...members) => members.filter(m => live(key)?.delete(m)).length,
    SMEMBERS: key => [...(live(key) ?? [])],
    SISMEMBER: (key, member) => (live(key)?.has(member) ? 1 : 0),
    RPUSH: (key, ...values) => of(key, () => []).push(...values.map(String)),
    LRANGE: (key, start, stop) => { const list = live(key) ?? []; return list.slice(...span(list.length, start, stop)); },
    LLEN: key => (live(key) ?? []).length,
  };
  const redis = async (command, ...args) => {
    if (!commands[command]) throw new Error(`fake redis has no ${command}`);
    return commands[command](...args);
  };
  redis.data = data;
  return redis;
}

export function relayFetch(deps) {
  const routes = {'/api/keys': createKeysHandler(deps), '/api/messages': createMessagesHandler(deps), '/api/spaces': createSpacesHandler(deps), '/api/invites': createInvitesHandler(deps), '/api/notify': createNotifyHandler(deps)};
  return async (url, init = {}) => {
    const request = new Request(url, init);
    const route = routes[new URL(request.url).pathname];
    return route ? route.fetch(request) : new Response('{"error":"Not found"}', {status: 404});
  };
}

export function memoryKeystore() {
  const secrets = new Map();
  return {get: async account => secrets.get(account) ?? null, set: async (account, secret) => void secrets.set(account, secret), remove: async account => void secrets.delete(account), secrets};
}

// Stands in for the Secure Enclave helper: signs with an in-memory P-256 key and records every prompt it was asked to show.
export function softwareApprover() {
  const {privateKey, publicKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const jwk = publicKey.export({format: 'jwk'});
  const approver = {
    prompts: [], fail: null,
    publicKey: b64(Buffer.concat([Buffer.from([4]), unb64(jwk.x), unb64(jwk.y)])),
    create: async () => ({tier: 'software', public_key: approver.publicKey, blob: ''}),
    async sign(payload, labels) {
      approver.prompts.push({payload: JSON.parse(payload), labels});
      if (approver.fail) throw new ApprovalError(approver.fail, approver.fail === 'no-interaction' ? 'Touch ID cannot be shown from this process' : 'Touch ID was cancelled');
      return b64(sign('sha256', Buffer.from(payload), {key: privateKey, dsaEncoding: 'ieee-p1363'}));
    },
  };
  return approver;
}

// Records the relay's outbound alert requests; `respond` decides each one's HTTP status (or throws).
export function hookCatcher() {
  const catcher = {calls: [], respond: () => 202};
  catcher.send = async (url, init) => {
    catcher.calls.push({url, init});
    return new Response(null, {status: await catcher.respond(url, init)});
  };
  return catcher;
}

export function network({send = hookCatcher().send} = {}) {
  const redis = memoryRedis(), owners = [];
  const fetch = relayFetch({redis, ownerKeys: owners, send});
  const open = async (keystore = memoryKeystore(), approver = softwareApprover(), home = mkdtempSync(join(tmpdir(), 'agentchat-test-'))) =>
    Object.assign(await createNode({home, keystore, approver, fetch}), {approver, keystore, home});
  return {
    redis, fetch, owners, open,
    async owner(handle) {
      const keystore = memoryKeystore(), seed = randomBytes(32);
      await keystore.set('identity', b64(seed));
      owners.push(identityFromSeed(seed).ik);
      const node = await open(keystore);
      await node.joinOwner({handle, relay: RELAY});
      return node;
    },
    async invited(inviter, handle) {
      const {code} = await inviter.invite();
      const node = await open();
      await node.join(code, {as: handle});
      await inviter.sync();
      return node;
    },
  };
}
