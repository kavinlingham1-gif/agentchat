import {alert, endpoint, refuse} from '../lib/relay.mjs';
import {HANDLE, id} from '../lib/wire.mjs';

const THIRTY_DAYS = 2592000;

export function createMessagesHandler(deps) { return endpoint({
  async GET(ctx) {
    const me = await ctx.authenticate();
    await ctx.redis('DEL', `pinged:${me}`);
    const ids = await ctx.redis('ZRANGE', `inbox:${me}`, 0, 99);
    if (!ids.length) return {envelopes: []};
    const stored = await ctx.redis('MGET', ...ids.map(envelope => `env:${me}:${envelope}`));
    const expired = ids.filter((_, i) => !stored[i]);
    if (expired.length) await ctx.redis('ZREM', `inbox:${me}`, ...expired);
    return {envelopes: stored.filter(Boolean).map(text => JSON.parse(text))};
  },
  async POST(ctx) {
    const from = await ctx.authenticate();
    const {envelopes} = ctx.data;
    if (!Array.isArray(envelopes) || envelopes.length < 1 || envelopes.length > 20) refuse(400, 'Send between 1 and 20 envelopes');
    for (const e of envelopes) {
      if (!HANDLE.test(e?.to ?? '') || typeof e.pk !== 'string' || e.pk.length > 24 || typeof e.ct !== 'string' || e.ct.length > 98304) refuse(400, 'Invalid envelope');
      if (!await ctx.redis('EXISTS', `rec:${e.to}`)) refuse(404, `No one is registered as @${e.to}`);
    }
    const day = `sent:${from}:${Math.floor(ctx.clock() / 86400)}`;
    if (await ctx.redis('INCRBY', day, envelopes.length) > 2000) refuse(429, 'Daily sending limit reached');
    await ctx.redis('EXPIRE', day, 172800);
    const at = ctx.clock(), ids = [];
    for (const e of envelopes) {
      const envelope = id();
      await ctx.redis('SET', `env:${e.to}:${envelope}`, JSON.stringify({id: envelope, from, pk: e.pk, ct: e.ct, at}), 'EX', THIRTY_DAYS);
      await ctx.redis('ZADD', `inbox:${e.to}`, at, envelope);
      await ctx.redis('EXPIRE', `inbox:${e.to}`, THIRTY_DAYS);
      ids.push(envelope);
    }
    await Promise.allSettled([...new Set(envelopes.map(e => e.to))].map(handle => alert(ctx, handle)));
    return {status: 201, body: {ids}};
  },
  async DELETE(ctx) {
    const me = await ctx.authenticate();
    const {ids} = ctx.data;
    if (!Array.isArray(ids) || ids.length > 100 || !ids.every(envelope => typeof envelope === 'string' && envelope.length <= 32)) refuse(400, 'Invalid envelope ids');
    if (ids.length) await ctx.redis('DEL', ...ids.map(envelope => `env:${me}:${envelope}`)), await ctx.redis('ZREM', `inbox:${me}`, ...ids);
    return {ok: true};
  },
}, deps); }

export default createMessagesHandler();
