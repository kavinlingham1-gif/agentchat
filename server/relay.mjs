import {createServer} from 'node:http';
import {createInvitesHandler} from '../api/invites.js';
import {createKeysHandler} from '../api/keys.js';
import {createMessagesHandler} from '../api/messages.js';
import {createNotifyHandler} from '../api/notify.js';
import {createSpacesHandler} from '../api/spaces.js';

const MAX_BODY = 262144;
const HEADERS = {'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-robots-tag': 'noindex, nofollow', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'", 'cache-control': 'no-store'};

// The same relay handlers Vercel runs, served by plain Node for a self-hosted origin. Vercel capped bodies and set the client address; here both are done before a handler runs.
export function relayServer(deps, {base = 'http://relay.invalid', trustedProxyHops = 1} = {}) {
  const routes = {'/api/keys': createKeysHandler(deps), '/api/messages': createMessagesHandler(deps), '/api/spaces': createSpacesHandler(deps), '/api/invites': createInvitesHandler(deps), '/api/notify': createNotifyHandler(deps)};
  const server = createServer(async (req, res) => {
    const send = (status, body, headers = {}) => { res.writeHead(status, {...HEADERS, ...headers}); res.end(body); };
    try {
      const url = new URL(req.url, base);
      if (req.method === 'GET' && url.pathname === '/healthz') return send(200, 'ok', {'content-type': 'text/plain'});
      const route = routes[url.pathname];
      if (!route) return send(404, '{"error":"Not found"}', {'content-type': 'application/json'});
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY) return send(413, '{"error":"Request too large"}', {'content-type': 'application/json', connection: 'close'});
        chunks.push(chunk);
      }
      // Only addresses appended by the trusted proxies count; earlier X-Forwarded-For entries are whatever the client sent.
      const hops = String(req.headers['x-forwarded-for'] ?? '').split(',').map(s => s.trim()).filter(Boolean);
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) if (name !== 'x-forwarded-for' && typeof value === 'string') headers.set(name, value);
      headers.set('x-forwarded-for', hops.at(-trustedProxyHops) ?? req.socket.remoteAddress ?? 'local');
      const response = await route.fetch(new Request(url, {method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks)}));
      send(response.status, Buffer.from(await response.arrayBuffer()), Object.fromEntries(response.headers));
    } catch (error) {
      console.error(error);
      if (!res.headersSent) send(503, '{"error":"The relay is temporarily unavailable"}', {'content-type': 'application/json'});
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}
