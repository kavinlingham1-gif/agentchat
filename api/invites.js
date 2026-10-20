import {endpoint, refuse} from '../lib/relay.mjs';

export function createInvitesHandler(deps) { return endpoint({
  async POST(ctx) {
    const inviter = await ctx.authenticate();
    const approval = await ctx.useApproval(ctx.data.approval, inviter, 'invite.create');
    const t = ctx.clock();
    if (!/^[A-Za-z0-9_-]{43}$/.test(approval.token_hash ?? '') || !Number.isInteger(approval.valid_until) || approval.valid_until <= t || approval.valid_until > t + 7 * 86400 + 60) refuse(400, 'Invalid invite');
    await ctx.redis('ZREMRANGEBYSCORE', `invites:${inviter}`, 0, t);
    if (await ctx.redis('ZCARD', `invites:${inviter}`) >= 10) refuse(429, 'You already have 10 open invites');
    if (await ctx.redis('SET', `invite:${approval.token_hash}`, JSON.stringify({inviter}), 'NX', 'EX', approval.valid_until - t) !== 'OK') refuse(409, 'That invite already exists');
    await ctx.redis('ZADD', `invites:${inviter}`, approval.valid_until, approval.token_hash);
    return {status: 201, body: {valid_until: approval.valid_until}};
  },
}, deps); }

export default createInvitesHandler();
