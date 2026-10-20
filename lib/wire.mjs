import {createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, sign, timingSafeEqual, verify} from 'node:crypto';

// Signed bytes are always "agentchat/v1/<context>\n" + the exact transmitted text, so a signature made for one purpose never verifies for another.

let sodiumLoad;
const sodium = () => (sodiumLoad ??= import('libsodium-wrappers').then(async ({default: s}) => { await s.ready; return s; }));

export const HANDLE = /^[a-z0-9][a-z0-9_]{1,23}$/;
export const b64 = bytes => Buffer.from(bytes).toString('base64url');
export const unb64 = text => Buffer.from(text, 'base64url');
export const id = (bytes = 16) => b64(randomBytes(bytes));
export const sha256 = data => createHash('sha256').update(data).digest();
export const now = () => Math.floor(Date.now() / 1000);
export const cleanHandle = value => typeof value === 'string' && HANDLE.test(value.replace(/^@/, '').toLowerCase()) ? value.replace(/^@/, '').toLowerCase() : null;

const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const P256_SPKI = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
const isKey = (text, length) => typeof text === 'string' && text.length < 100 && /^[A-Za-z0-9_-]+$/.test(text) && unb64(text).length === length && (length !== 65 || unb64(text)[0] === 4);

export function identityFromSeed(seed) {
  const privateKey = createPrivateKey({key: Buffer.concat([ED_PKCS8, seed]), format: 'der', type: 'pkcs8'});
  return {privateKey, ik: b64(createPublicKey(privateKey).export({format: 'der', type: 'spki'}).subarray(ED_SPKI.length))};
}

export const signAs = (identity, context, text) => b64(sign(null, Buffer.from(`agentchat/v1/${context}\n${text}`), identity.privateKey));

export function verifyAs(ik, context, text, signature) {
  if (!isKey(ik, 32) || typeof signature !== 'string' || typeof text !== 'string') return false;
  try { return verify(null, Buffer.from(`agentchat/v1/${context}\n${text}`), createPublicKey({key: Buffer.concat([ED_SPKI, unb64(ik)]), format: 'der', type: 'spki'}), unb64(signature)); } catch { return false; }
}

export function fingerprint(ik, ak) {
  const digest = createHash('sha512').update(`agentchat/v1/fingerprint\n${ik}\n${ak}`).digest();
  return Array.from({length: 6}, (_, i) => String(digest.readUIntBE(i * 5, 5) % 100000).padStart(5, '0')).join(' ');
}

export const safetyNumber = (a, b) => [a, b].sort((x, y) => (x.handle < y.handle ? -1 : 1)).map(p => fingerprint(p.ik, p.ak)).join(' ');

export const tierLabel = tier => ({'se-biometry': 'Touch ID', 'se-passcode': 'device passcode', la: 'password with a software key', software: 'software key'})[tier] ?? 'unknown key';

export function makeRecord(identity, fields) {
  const record = JSON.stringify({v: 1, handle: fields.handle, ik: identity.ik, bk: fields.bk, ak: fields.ak, tier: fields.tier, prekeys: fields.prekeys, updated: now()});
  return {record, sig: signAs(identity, 'record', record)};
}

// A key record is accepted only when well-formed and signed by its own identity key; callers compare that key against what they pinned.
export function readRecord(signed, handle) {
  if (!signed || typeof signed.record !== 'string' || signed.record.length > 4096) return null;
  let r;
  try { r = JSON.parse(signed.record); } catch { return null; }
  if (r?.v !== 1 || !HANDLE.test(r.handle) || (handle && r.handle !== handle) || !isKey(r.ik, 32) || !isKey(r.bk, 32) || !isKey(r.ak, 65) || typeof r.tier !== 'string' || r.tier.length > 20) return null;
  if (!Array.isArray(r.prekeys) || r.prekeys.length < 1 || r.prekeys.length > 4 || !r.prekeys.every(p => typeof p.id === 'string' && p.id.length <= 24 && isKey(p.pk, 32) && Number.isInteger(p.exp))) return null;
  return verifyAs(r.ik, 'record', signed.record, signed.sig) ? r : null;
}

export function signRequest(identity, handle, method, path, body) {
  const ts = now(), nonce = id(12);
  return `Agentchat h=${handle},t=${ts},n=${nonce},s=${signAs(identity, 'request', [method, path, ts, nonce, sha256(body).toString('hex')].join('\n'))}`;
}

export function readRequestAuth(header) {
  const m = /^Agentchat h=([a-z0-9_]{2,24}),t=(\d{1,12}),n=([A-Za-z0-9_-]{16}),s=([A-Za-z0-9_-]{86})$/.exec(header ?? '');
  return m && {handle: m[1], ts: Number(m[2]), nonce: m[3], sig: m[4]};
}

export const verifyRequest = (auth, ik, method, path, body) => verifyAs(ik, 'request', [method, path, auth.ts, auth.nonce, sha256(body).toString('hex')].join('\n'), auth.sig);

export function approvalPayload(signer, ik, action, fields) {
  const t = now();
  return JSON.stringify({ctx: 'agentchat/v1/approval', signer, signer_ik: ik, action, ...fields, nonce: id(), iat: t, exp: t + 600});
}

export function verifyApprovalSignature(ak, payload, signature) {
  if (!isKey(ak, 65) || typeof signature !== 'string') return false;
  try { return verify('sha256', Buffer.from(payload), {key: createPublicKey({key: Buffer.concat([P256_SPKI, unb64(ak)]), format: 'der', type: 'spki'}), dsaEncoding: 'ieee-p1363'}, unb64(signature)); } catch { return false; }
}

// Returns the payload only when it is a valid approval-key signature by exactly this signer, for exactly this action, current at `at`.
export function checkApproval(approval, {signer, ik, ak, action, at = now(), current = true}) {
  if (!approval || typeof approval.payload !== 'string' || approval.payload.length > 8192) return null;
  let p;
  try { p = JSON.parse(approval.payload); } catch { return null; }
  if (p?.ctx !== 'agentchat/v1/approval' || p.signer !== signer || p.signer_ik !== ik || p.action !== action || typeof p.nonce !== 'string' || !Number.isInteger(p.iat) || !Number.isInteger(p.exp)) return null;
  if (p.exp - p.iat > 3600 || (current && !(p.iat <= at + 60 && at <= p.exp))) return null;
  return verifyApprovalSignature(ak, approval.payload, approval.sig) ? p : null;
}

export async function boxKeypair() {
  const s = await sodium(), k = s.crypto_box_keypair();
  return {pk: b64(k.publicKey), sk: b64(k.privateKey)};
}

export async function seal(identity, inner, prekeyPk) {
  const s = await sodium(), m = JSON.stringify(inner);
  return b64(s.crypto_box_seal(s.pad(Buffer.from(JSON.stringify({m, s: signAs(identity, 'message', m)})), 1024), unb64(prekeyPk)));
}

// Recipient-side: decrypts, then requires the sender's signature, the recipient bound inside it, and the relay-reported sender to agree.
export async function open(ciphertext, prekey, {me, from, ik}) {
  const s = await sodium();
  try {
    const {m, s: signature} = JSON.parse(Buffer.from(s.unpad(s.crypto_box_seal_open(unb64(ciphertext), unb64(prekey.pk), unb64(prekey.sk)), 1024)).toString());
    const inner = JSON.parse(m);
    if (inner?.v !== 1 || inner.to !== me || inner.from !== from || typeof inner.type !== 'string' || typeof inner.id !== 'string' || !Number.isInteger(inner.seq) || !Number.isInteger(inner.sent)) return null;
    return {inner, verified: verifyAs(ik, 'message', m, signature), m, signature};
  } catch { return null; }
}

export async function wrapFor(identity, data, bk) {
  const s = await sodium(), w = JSON.stringify(data);
  return b64(s.crypto_box_seal(s.pad(Buffer.from(JSON.stringify({w, s: signAs(identity, 'wrap', w)})), 256), unb64(bk)));
}

export async function unwrap(ciphertext, box, ownerIk) {
  const s = await sodium();
  try {
    const {w, s: signature} = JSON.parse(Buffer.from(s.unpad(s.crypto_box_seal_open(unb64(ciphertext), unb64(box.pk), unb64(box.sk)), 256)).toString());
    return verifyAs(ownerIk, 'wrap', w, signature) ? JSON.parse(w) : null;
  } catch { return null; }
}

export const spaceKey = async () => b64((await sodium()).crypto_aead_xchacha20poly1305_ietf_keygen());
export const nameHash = (space, salt, name) => b64(sha256(`agentchat/v1/space-name\n${space}\n${salt}\n${name}`));
const entryAd = (space, epoch, entryId) => Buffer.from(`agentchat/v1/entry\n${space}\n${epoch}\n${entryId}`);

export async function sealEntry(identity, key, entry) {
  const s = await sodium(), e = JSON.stringify(entry), nonce = s.randombytes_buf(24);
  const plain = s.pad(Buffer.from(JSON.stringify({e, s: signAs(identity, 'entry', e)})), 1024);
  return {id: entry.id, epoch: entry.epoch, nonce: b64(nonce), ct: b64(s.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, entryAd(entry.space, entry.epoch, entry.id), null, nonce, unb64(key)))};
}

export async function openEntry(sealed, space, key) {
  const s = await sodium();
  try {
    const plain = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, unb64(sealed.ct), entryAd(space, sealed.epoch, sealed.id), unb64(sealed.nonce), unb64(key));
    const {e, s: signature} = JSON.parse(Buffer.from(s.unpad(plain, 1024)).toString());
    const entry = JSON.parse(e);
    return entry.id === sealed.id && entry.space === space && entry.epoch === sealed.epoch ? {entry, e, signature} : null;
  } catch { return null; }
}

export function inviteKeys(secret) {
  const derive = label => createHmac('sha256', secret).update(`agentchat/v1/invite/${label}`).digest();
  const gate = b64(derive('relay-gate'));
  return {gate, tokenHash: b64(sha256(gate)), mutual: derive('mutual-auth')};
}

export const helloMac = (mutual, inviter, invitee, ik, ak) => b64(createHmac('sha256', mutual).update(`agentchat/v1/hello\n${inviter}\n${invitee}\n${ik}\n${ak}`).digest());
export const sameMac = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export const encodeInvite = invite => `agentchat1-${b64(JSON.stringify(invite))}`;

export function decodeInvite(code) {
  const m = /^agentchat1-([A-Za-z0-9_-]{40,2000})$/.exec(String(code ?? '').trim());
  if (!m) return null;
  try {
    const i = JSON.parse(unb64(m[1]).toString());
    if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/.test(i.r) || !HANDLE.test(i.i) || unb64(i.s ?? '').length !== 32 || !/^(\d{5} ){5}\d{5}$/.test(i.f)) return null;
    // The package line ends up in shell commands the joiner later sends to others, so only an exact hash and a tarball on the same relay pass.
    const packaged = i.p === undefined && i.u === undefined
      || (/^[0-9a-f]{64}$/.test(i.p ?? '') && typeof i.u === 'string' && i.u.startsWith(`${i.r}/dl/`) && /^agentchat-\d+\.\d+\.\d+\.tgz$/.test(i.u.slice(i.r.length + 4)));
    return packaged ? i : null;
  } catch { return null; }
}

export function isoTime(value) {
  if (typeof value !== 'string' || value.length > 40 || !/(Z|[+-]\d{2}:?\d{2})$/.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

const merged = slots => slots.map(s => [Date.parse(s.start), Date.parse(s.end)]).filter(([a, b]) => b > a).sort((x, y) => x[0] - y[0])
  .reduce((out, [a, b]) => (out.length && a <= out.at(-1)[1] ? (out.at(-1)[1] = Math.max(out.at(-1)[1], b), out) : [...out, [a, b]]), []);

export function commonSlots(window, minutes, lists) {
  let free = [[Date.parse(window.start), Date.parse(window.end)]];
  for (const list of lists) free = free.flatMap(([a, b]) => merged(list).map(([c, d]) => [Math.max(a, c), Math.min(b, d)]).filter(([x, y]) => y > x));
  return free.filter(([a, b]) => b - a >= minutes * 60000).map(([a, b]) => ({start: new Date(a).toISOString(), end: new Date(b).toISOString()}));
}
