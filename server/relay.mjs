import {lookup} from 'node:dns';
import {createServer} from 'node:http';
import {request} from 'node:https';
import {BlockList, isIP} from 'node:net';
import {createInvitesHandler} from '../api/invites.js';
import {createKeysHandler} from '../api/keys.js';
import {createMessagesHandler} from '../api/messages.js';
import {createNotifyHandler} from '../api/notify.js';
import {createSpacesHandler} from '../api/spaces.js';
import {upstash} from '../lib/relay.mjs';

const MAX_BODY = 262144;
const HEADERS = {'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-robots-tag': 'noindex, nofollow', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'", 'cache-control': 'no-store'};

// The same relay handlers Vercel runs, served by plain Node for a self-hosted origin. Vercel capped bodies and set the client address; here both are done before a handler runs.
export function relayServer(deps, {base = 'http://relay.invalid', trustedProxyHops = 1} = {}) {
  const redis = deps.redis ?? upstash(), shared = {...deps, redis};
  const routes = {'/api/keys': createKeysHandler(shared), '/api/messages': createMessagesHandler(shared), '/api/spaces': createSpacesHandler(shared), '/api/invites': createInvitesHandler(shared), '/api/notify': createNotifyHandler(shared)};
  const server = createServer(async (req, res) => {
    const send = (status, body, headers = {}) => { res.writeHead(status, {...HEADERS, ...headers}); res.end(body); };
    try {
      const url = new URL(req.url, base);
      if (req.method === 'GET' && url.pathname === '/healthz') {
        const up = await redis('PING').then(() => true, () => false);
        return send(up ? 200 : 503, up ? 'ok' : 'storage unavailable', {'content-type': 'text/plain'});
      }
      const route = routes[url.pathname];
      if (!route) return send(404, '{"error":"Not found"}', {'content-type': 'application/json'});
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY) return send(413, '{"error":"Request too large"}', {'content-type': 'application/json', connection: 'close'});
        chunks.push(chunk);
      }
      // Only addresses appended by trusted proxies count, so with none the header is ignored; earlier X-Forwarded-For entries are whatever the client sent.
      const hops = String(req.headers['x-forwarded-for'] ?? '').split(',').map(s => s.trim()).filter(Boolean);
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) if (name !== 'x-forwarded-for' && typeof value === 'string') headers.set(name, value);
      headers.set('x-forwarded-for', (trustedProxyHops > 0 ? hops.at(-trustedProxyHops) : undefined) ?? req.socket.remoteAddress ?? 'local');
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

const PRIVATE = new BlockList();
for (const [address, bits] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]]) PRIVATE.addSubnet(address, bits, 'ipv4');
for (const [address, bits] of [['::', 127], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]]) PRIVATE.addSubnet(address, bits, 'ipv6');
const isPrivate = address => PRIVATE.check(address, isIP(address) === 6 ? 'ipv6' : 'ipv4');

// Alert URLs are checked by name when they're saved; this checks what a name resolves to each time an alert goes out, so a public
// name can't aim a self-hosted relay at the network it runs in (100.64.0.0/10 covers a tailnet). Answers like fetch with redirect: 'manual'.
export function publicSend(url, {method, headers, body, signal} = {}, resolve = lookup) {
  return new Promise((done, fail) => {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
    if (isIP(host) && isPrivate(host)) return fail(new Error(`${host} is a private address`));
    const publicOnly = (name, options, callback) => resolve(name, {...options, all: true}, (error, found) => {
      const usable = error ? [] : found.filter(a => !isPrivate(a.address));
      if (!usable.length) return callback(error ?? Object.assign(new Error(`${name} resolves only to private addresses`), {code: 'ENOTFOUND'}));
      if (options.all) callback(null, usable); else callback(null, usable[0].address, usable[0].family);
    });
    const req = request(url, {method, headers, signal, lookup: publicOnly}, res => { res.resume(); done({status: res.statusCode, body: null}); });
    req.on('error', error => fail(signal?.aborted ? signal.reason : error));
    req.end(body);
  });
}
