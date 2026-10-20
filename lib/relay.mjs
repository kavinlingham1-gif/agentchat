import {checkApproval, now, readRecord, readRequestAuth, verifyRequest} from './wire.mjs';

export function upstash({url = process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL, token = process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN} = {}) {
  return async (...command) => {
    const response = await fetch(url, {method: 'POST', headers: {authorization: `Bearer ${token}`}, body: JSON.stringify(command)});
    const body = await response.json().catch(() => ({}));
    if (!response.ok || body.error) throw new Error(`redis ${command[0]}: ${body.error ?? response.status}`);
    return body.result;
  };
}

export class Refusal extends Error { constructor(status, message) { super(message); this.status = status; } }
export const refuse = (status, message) => { throw new Refusal(status, message); };
const json = (body, status = 200) => new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json', 'cache-control': 'no-store'}});

export async function readKeys(redis, handle) {
  const stored = await redis('GET', `rec:${handle}`);
  return stored ? readRecord(JSON.parse(stored), handle) : null;
}

export function hookProblem(url, key) {
  let parsed;
  try { parsed = new URL(url); } catch { return 'That alert URL is not a valid URL'; }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || url.length > 500) return 'Alerts need a plain https:// URL of at most 500 characters';
  const host = parsed.hostname.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || host === 'localhost' || /\.(local|internal|localhost)$/.test(host) || !host.includes('.')) return 'Alerts must go to a public host name, not an IP address or a local name';
  if (key !== undefined && key !== null && !/^[\x21-\x7e]{1,256}$/.test(key)) return 'The alert key must be 1 to 256 printable characters without spaces';
  return null;
}

// Wakes a handle's agent at most once per unread batch: the gate is cleared when the inbox is read, when an alert fails, or after 30 minutes. Never throws.
export async function alert(ctx, handle) {
  try {
    const stored = await ctx.redis('GET', `hook:${handle}`);
    if (!stored) return null;
    const hook = JSON.parse(stored), at = ctx.clock();
    if (await ctx.redis('SET', `pinged:${handle}`, String(at), 'NX', 'EX', 1800) !== 'OK') return null;
    const hour = `alerts:${handle}:${Math.floor(at / 3600)}`, count = await ctx.redis('INCR', hour);
    if (count === 1) await ctx.redis('EXPIRE', hour, 7200);
    let last;
    if (count > 20) last = {skipped: 'hourly cap', at};
    else {
      try {
        const response = await ctx.send(hook.url, {method: 'POST', headers: {'content-type': 'application/json', ...(hook.key ? {authorization: `Bearer ${hook.key}`} : {})}, body: '{"source":"agentchat","event":"new_messages"}', redirect: 'manual', signal: AbortSignal.timeout(3000)});
        await response.body?.cancel().catch(() => {});
        last = {status: response.status, at};
      } catch (error) { last = {status: 0, error: error.name === 'TimeoutError' ? 'timed out' : 'unreachable', at}; }
    }
    if (!(last.status >= 200 && last.status < 300)) await ctx.redis('DEL', `pinged:${handle}`);
    await ctx.redis('SET', `hook:${handle}`, JSON.stringify({...hook, last}), 'XX');
    return last;
  } catch (error) {
    console.error(error);
    return null;
  }
}

async function limit(redis, key, max, clock) {
  const bucket = `rate:${key}:${Math.floor(clock() / 60)}`;
  const count = await redis('INCR', bucket);
  if (count === 1) await redis('EXPIRE', bucket, 120);
  if (count > max) refuse(429, 'Too many requests; slow down');
}

export function endpoint(methods, {redis = upstash(), ownerKeys = (process.env.AGENTCHAT_OWNER_KEYS ?? '').split(',').filter(Boolean), clock = now, send = globalThis.fetch} = {}) { return {async fetch(request) {
  try {
    const method = methods[request.method];
    if (!method) return json({error: 'Method not allowed'}, 405);
    const body = await request.text();
    if (body.length > 262144) return json({error: 'Request too large'}, 413);
    const url = new URL(request.url);
    const ctx = {request, url, body, redis, clock, ownerKeys, send, data: body ? JSON.parse(body) : {}};
    ctx.authenticate = async ik => {
      const auth = readRequestAuth(request.headers.get('authorization'));
      if (!auth) refuse(401, 'Signed request required');
      if (Math.abs(clock() - auth.ts) > 300) refuse(401, 'Request timestamp out of range; check the clock');
      const key = ik ?? (await readKeys(redis, auth.handle))?.ik;
      if (!key || !verifyRequest(auth, key, request.method, url.pathname + url.search, body)) refuse(401, 'Bad request signature');
      if (await redis('SET', `nonce:${auth.handle}:${auth.nonce}`, '1', 'NX', 'EX', 600) !== 'OK') refuse(401, 'Replayed request');
      await limit(redis, auth.handle, 120, clock);
      return auth.handle;
    };
    ctx.limitAddress = () => limit(redis, `ip:${(request.headers.get('x-forwarded-for') ?? 'local').split(',')[0].trim()}`, 60, clock);
    ctx.useApproval = async (approval, signer, action) => {
      const keys = await readKeys(redis, signer);
      const payload = keys && checkApproval(approval, {signer, ik: keys.ik, ak: keys.ak, action, at: clock()});
      if (!payload) refuse(403, `This needs a fresh ${action} approval signed with your approval key`);
      if (await redis('SET', `approval:${signer}:${payload.nonce}`, '1', 'NX', 'EX', 7200) !== 'OK') refuse(403, 'That approval was already used');
      return payload;
    };
    const result = await method(ctx);
    return json(result.body ?? result, result.status ?? 200);
  } catch (error) {
    if (error instanceof Refusal) return json({error: error.message}, error.status);
    if (error instanceof SyntaxError) return json({error: 'Invalid JSON'}, 400);
    console.error(error);
    return json({error: 'The relay is temporarily unavailable'}, 503);
  }
}}; }
