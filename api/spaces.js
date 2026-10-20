import {endpoint, refuse} from '../lib/relay.mjs';
import {HANDLE} from '../lib/wire.mjs';

const SPACE = /^[A-Za-z0-9_-]{22}$/;

export function createSpacesHandler(deps) { return endpoint({
  async GET(ctx) {
    const me = await ctx.authenticate();
    const space = ctx.url.searchParams.get('id');
    if (!space) {
      const spaces = await ctx.redis('SMEMBERS', `spaces:${me}`);
      return {spaces: await Promise.all(spaces.map(async s => ({space: s, version: Number(await ctx.redis('GET', `space:${s}:version`) ?? 0)})))};
    }
    if (!SPACE.test(space) || !await ctx.redis('SISMEMBER', `space:${space}:members`, me)) refuse(403, 'Not a member of that space');
    const after = Math.max(0, Number.parseInt(ctx.url.searchParams.get('after') ?? '0', 10) || 0);
    const entries = await ctx.redis('LRANGE', `space:${space}:log`, after, after + 199);
    return {acl: JSON.parse(await ctx.redis('GET', `space:${space}:acl`)), wrap: await ctx.redis('GET', `space:${space}:wrap:${me}`), entries: entries.map(text => JSON.parse(text)), next: after + entries.length};
  },
  async PUT(ctx) {
    const owner = await ctx.authenticate();
    const {acl, wraps} = ctx.data;
    const p = await ctx.useApproval(acl, owner, 'space.acl');
    if (!SPACE.test(p.space ?? '') || !Array.isArray(p.members) || !p.members.includes(owner) || p.members.length > 32 || new Set(p.members).size !== p.members.length || !p.members.every(m => HANDLE.test(m))) refuse(400, 'Invalid member list');
    const stored = await ctx.redis('GET', `space:${p.space}:acl`);
    const previous = stored ? JSON.parse(JSON.parse(stored).payload) : {signer: owner, version: 0, members: [], key_epoch: 1};
    if (previous.signer !== owner) refuse(403, 'Only the owner can change who is in a space');
    if (p.prev_version !== previous.version || p.version !== previous.version + 1 || JSON.stringify(p.prev_members) !== JSON.stringify(previous.members) || !Number.isInteger(p.key_epoch) || p.key_epoch < previous.key_epoch) refuse(409, 'The space changed since this approval; sync and try again');
    if (!wraps || typeof wraps !== 'object' || Object.keys(wraps).length !== p.members.length || !p.members.every(m => typeof wraps[m] === 'string' && wraps[m].length <= 8192)) refuse(400, 'Every member needs a key wrap');
    for (const member of p.members) if (!await ctx.redis('EXISTS', `rec:${member}`)) refuse(404, `No one is registered as @${member}`);
    await ctx.redis('SET', `space:${p.space}:acl`, JSON.stringify({payload: acl.payload, sig: acl.sig}));
    await ctx.redis('SET', `space:${p.space}:version`, String(p.version));
    for (const member of previous.members.filter(m => !p.members.includes(m))) {
      await ctx.redis('SREM', `space:${p.space}:members`, member), await ctx.redis('SREM', `spaces:${member}`, p.space), await ctx.redis('DEL', `space:${p.space}:wrap:${member}`);
    }
    for (const member of p.members) {
      await ctx.redis('SADD', `space:${p.space}:members`, member), await ctx.redis('SADD', `spaces:${member}`, p.space), await ctx.redis('SET', `space:${p.space}:wrap:${member}`, wraps[member]);
    }
    return {version: p.version};
  },
  async POST(ctx) {
    const author = await ctx.authenticate();
    const {space, entry} = ctx.data;
    if (!SPACE.test(space ?? '') || !await ctx.redis('SISMEMBER', `space:${space}:members`, author)) refuse(403, 'Not a member of that space');
    if (typeof entry?.id !== 'string' || entry.id.length > 32 || !Number.isInteger(entry.epoch) || typeof entry.nonce !== 'string' || entry.nonce.length > 40 || typeof entry.ct !== 'string' || entry.ct.length > 32768) refuse(400, 'Invalid entry');
    if (await ctx.redis('LLEN', `space:${space}:log`) >= 5000) refuse(429, 'This space is full');
    await ctx.redis('RPUSH', `space:${space}:log`, JSON.stringify({id: entry.id, epoch: entry.epoch, nonce: entry.nonce, ct: entry.ct, author, at: ctx.clock()}));
    return {status: 201, body: {ok: true}};
  },
}, deps); }

export default createSpacesHandler();
