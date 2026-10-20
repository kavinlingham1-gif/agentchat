import {alert, endpoint, hookProblem, refuse} from '../lib/relay.mjs';

export function createNotifyHandler(deps) { return endpoint({
  async GET(ctx) {
    const me = await ctx.authenticate();
    const stored = await ctx.redis('GET', `hook:${me}`);
    if (!stored) return {alerts: false};
    const hook = JSON.parse(stored), waiting = await ctx.redis('GET', `pinged:${me}`);
    return {alerts: true, host: new URL(hook.url).host, has_key: Boolean(hook.key), last: hook.last ?? null, waiting_since: waiting ? Number(waiting) : null};
  },
  async PUT(ctx) {
    const me = await ctx.authenticate();
    const {url, key} = ctx.data;
    const problem = typeof url === 'string' ? hookProblem(url, key) : 'Pass the webhook URL to alert';
    if (problem) refuse(400, problem);
    await ctx.redis('SET', `hook:${me}`, JSON.stringify({url, ...(key ? {key} : {})}));
    await ctx.redis('DEL', `pinged:${me}`);
    return {host: new URL(url).host, test: await alert(ctx, me)};
  },
  async DELETE(ctx) {
    const me = await ctx.authenticate();
    await ctx.redis('DEL', `hook:${me}`, `pinged:${me}`);
    return {alerts: false};
  },
}, deps); }

export default createNotifyHandler();
