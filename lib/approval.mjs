import {generateKeyPairSync, randomUUID, sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {b64, unb64} from './wire.mjs';

export const HELPER = fileURLToPath(new URL('../bin/agentchat-approve', import.meta.url));
export const HERE = process.platform === 'darwin' ? 'Mac' : 'computer';
export const LOST_KEY = `This ${HERE}'s approval key is missing or unusable. Ask a contact for a fresh invite and join again under a new handle; your contacts will see you as a new, verified person.`;
const ACTIONS = new Set(['contact.connect', 'contact.verify', 'invite.create', 'space.acl', 'plan.confirm', 'handle.delete']);

// For a computer with no one to ask (a server, Windows, Linux, or a Mac set up with --agent): a P-256 key in a 0600 file signs at once, and contacts see "software key".
export function softwareKey(keyFile) {
  return {
    create() {
      const {privateKey, publicKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
      const jwk = publicKey.export({format: 'jwk'});
      return {tier: 'software', public_key: b64(Buffer.concat([Buffer.from([4]), unb64(jwk.x), unb64(jwk.y)])), private_key: privateKey.export({format: 'pem', type: 'pkcs8'})};
    },
    async sign(payload) {
      let p;
      try { p = JSON.parse(payload); } catch {}
      if (p?.ctx !== 'agentchat/v1/approval' || !ACTIONS.has(p.action)) throw new ApprovalError('failed', 'not an Agentchat approval');
      return b64(sign('sha256', Buffer.from(payload), {key: JSON.parse(readFileSync(keyFile, 'utf8')).private_key, dsaEncoding: 'ieee-p1363'}));
    },
  };
}

export class ApprovalError extends Error { constructor(code, message) { super(message); this.code = code; } }

const outcomes = {
  2: ['canceled', 'Touch ID was cancelled'],
  5: ['lost-key', LOST_KEY],
  6: ['no-interaction', 'Touch ID cannot be shown from this process. Run the same request with the agentchat command in Terminal'],
};

export function runHelper(args, input = '', timeout = 30000, helper = HELPER) {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, args, {stdio: ['pipe', 'pipe', 'ignore']});
    let out = '';
    const timer = setTimeout(() => child.kill('SIGTERM'), timeout);
    child.stdout.on('data', chunk => { out += chunk; });
    child.on('error', error => { clearTimeout(timer); reject(new ApprovalError('unavailable', `The Touch ID helper could not start: ${error.message}`)); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      let result = {};
      try { result = JSON.parse(out); } catch {}
      if (code === 0) return resolve(result);
      if (signal) return reject(new ApprovalError('timeout', 'Touch ID was not confirmed in time'));
      const [kind, message] = outcomes[code] ?? ['failed', result.error ?? 'The approval failed'];
      reject(new ApprovalError(kind, message));
    });
    child.stdin.end(input);
  });
}

// The real approver: a Secure Enclave key; the helper writes the Touch ID prompt from the payload, never from the caller.
export function enclave(keyFile) {
  return {
    create: () => runHelper(['create']),
    sign: async (payload, labels = {}) => (await runHelper(['sign', keyFile], JSON.stringify({payload, ...labels}), 120000)).signature,
  };
}

// One prompt at a time across every agent on this Mac, and a pause after a cancel so a looping agent can't wear the owner down.
export function gate(store, approver, clock = Date.now) {
  return async (payload, labels) => {
    const coolUntil = Number(store.meta('prompt.cooldown') ?? 0);
    if (clock() < coolUntil) throw new ApprovalError('cooldown', `Touch ID was just cancelled; wait ${Math.ceil((coolUntil - clock()) / 1000)} seconds and ask your owner again`);
    const owner = randomUUID();
    if (!store.lease('prompt', owner, 130000)) throw new ApprovalError('busy', `Another approval is already waiting on this ${HERE}`);
    try { return await approver.sign(payload, labels); }
    catch (error) {
      if (error.code === 'canceled' || error.code === 'timeout') store.meta('prompt.cooldown', String(clock() + 20000));
      throw error;
    } finally { store.release('prompt', owner); }
  };
}
