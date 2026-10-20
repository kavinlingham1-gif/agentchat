import {endpoint, readKeys, refuse} from '../lib/relay.mjs';
import {HANDLE, b64, readRecord, sha256} from '../lib/wire.mjs';

export function createKeysHandler(deps) { return endpoint({
  async GET(ctx) {
    await ctx.limitAddress();
    const handle = ctx.url.searchParams.get('h') ?? '';
    if (!HANDLE.test(handle)) refuse(400, 'Invalid handle');
    const stored = await ctx.redis('GET', `rec:${handle}`);
    if (!stored) refuse(404, `No one is registered as @${handle}`);
    return JSON.parse(stored);
  },
  async POST(ctx) {
    const {record, sig, invite} = ctx.data;
    const keys = readRecord({record, sig});
    if (!keys) refuse(400, 'Invalid key record');
    if (await ctx.authenticate(keys.ik) !== keys.handle) refuse(401, 'Sign the request as the handle being registered');
    if (await ctx.redis('EXISTS', `rec:${keys.handle}`)) refuse(409, `@${keys.handle} is taken`);
    let inviter = null;
    if (!ctx.ownerKeys.includes(keys.ik)) {
      if (typeof invite !== 'string' || invite.length > 64) refuse(403, 'Joining needs an invite');
      const tokenHash = b64(sha256(invite));
      const stored = await ctx.redis('GETDEL', `invite:${tokenHash}`);
      if (!stored) refuse(403, 'That invite is invalid, already used or expired');
      inviter = JSON.parse(stored).inviter;
      await ctx.redis('ZREM', `invites:${inviter}`, tokenHash);
    }
    if (await ctx.redis('SET', `rec:${keys.handle}`, JSON.stringify({record, sig}), 'NX') !== 'OK') refuse(409, `@${keys.handle} is taken`);
    return {status: 201, body: {handle: keys.handle, inviter}};
  },
  async PUT(ctx) {
    const handle = await ctx.authenticate();
    const keys = readRecord(ctx.data, handle), current = await readKeys(ctx.redis, handle);
    if (!keys) refuse(400, 'Invalid key record');
    if (['ik', 'bk', 'ak', 'tier'].some(field => keys[field] !== current[field])) refuse(403, 'Identity and approval keys never change; a lost key means joining again under a new handle');
    await ctx.redis('SET', `rec:${handle}`, JSON.stringify({record: ctx.data.record, sig: ctx.data.sig}));
    return {ok: true};
  },
  async DELETE(ctx) {
    const handle = await ctx.authenticate();
    await ctx.useApproval(ctx.data.approval, handle, 'handle.delete');
    const redis = ctx.redis;
    for (const envelope of await redis('ZRANGE', `inbox:${handle}`, 0, -1)) await redis('DEL', `env:${handle}:${envelope}`);
    for (const tokenHash of await redis('ZRANGE', `invites:${handle}`, 0, -1)) await redis('DEL', `invite:${tokenHash}`);
    for (const space of await redis('SMEMBERS', `spaces:${handle}`)) {
      const acl = await redis('GET', `space:${space}:acl`);
      if (acl && JSON.parse(JSON.parse(acl).payload).signer === handle) {
        for (const member of await redis('SMEMBERS', `space:${space}:members`)) await redis('DEL', `space:${space}:wrap:${member}`), await redis('SREM', `spaces:${member}`, space);
        await redis('DEL', `space:${space}:acl`, `space:${space}:version`, `space:${space}:members`, `space:${space}:log`);
      } else await redis('DEL', `space:${space}:wrap:${handle}`), await redis('SREM', `space:${space}:members`, handle);
    }
    await redis('DEL', `rec:${handle}`, `inbox:${handle}`, `invites:${handle}`, `spaces:${handle}`, `hook:${handle}`, `pinged:${handle}`);
    return {ok: true};
  },
}, deps); }

export default createKeysHandler();
