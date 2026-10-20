import {chmodSync, mkdirSync} from 'node:fs';
import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';
import {homedir} from 'node:os';
import {join, posix, win32} from 'node:path';

// Keys and messages; never the app itself, because `leave` deletes this whole folder. Fixed per OS so an agent runner with a different environment still finds it.
export function defaultHome({platform = process.platform, env = process.env, home = homedir()} = {}) {
  if (platform === 'darwin') return posix.join(home, 'Library', 'Application Support', 'agentchat');
  if (platform === 'win32') return win32.join(env.LOCALAPPDATA || win32.join(home, 'AppData', 'Local'), 'agentchat');
  return posix.join(home, '.local', 'share', 'agentchat');
}

const SCHEMA = `
create table if not exists meta (k text primary key, v text);
create table if not exists contacts (handle text primary key, ik text, ak text, bk text, tier text, verified integer default 0, status text, pending text, note text, added integer);
create table if not exists prekeys (id text primary key, pk text, sk blob, created integer, exp integer);
create table if not exists seen (id text primary key, at integer);
create table if not exists seqs (peer text primary key, sent integer default 0, received integer default 0);
create table if not exists threads (id text primary key, parts text, created integer, updated integer);
create table if not exists messages (id text primary key, thread text, sender text, type text, sent integer, body blob, unread integer, held integer default 0, flag text);
create table if not exists approvals (id text primary key, kind text, peer text, created integer, status text);
create table if not exists invites (token_hash text primary key, secret blob, created integer, valid_until integer, used_by text);
create table if not exists spaces (id text primary key, owner text, name blob, salt text, version integer, key_epoch integer, members text, member_keys text, cursor integer default 0, removed integer default 0);
create table if not exists space_keys (space text, epoch integer, key blob, primary key (space, epoch));
create table if not exists entries (id text primary key, space text, epoch integer, author text, at integer, body blob, unread integer);
create table if not exists approval_nonces (signer text, nonce text, primary key (signer, nonce));
`;

async function loadSqlite() {
  const emit = process.emitWarning;
  process.emitWarning = (warning, ...rest) => (String(warning?.message ?? warning).includes('SQLite') ? undefined : emit.call(process, warning, ...rest));
  try { return await import('node:sqlite'); } finally { process.emitWarning = emit; }
}

export async function openStore(home, key) {
  mkdirSync(home, {recursive: true, mode: 0o700});
  chmodSync(home, 0o700);
  const {DatabaseSync} = await loadSqlite();
  const db = new DatabaseSync(join(home, 'node.db'));
  db.exec('pragma journal_mode = wal; pragma busy_timeout = 10000;');
  db.exec(SCHEMA);
  for (const file of ['node.db', 'node.db-wal', 'node.db-shm']) try { chmodSync(join(home, file), 0o600); } catch {}
  const statement = sql => db.prepare(sql);
  return {
    home,
    all: (sql, ...params) => statement(sql).all(...params),
    get: (sql, ...params) => statement(sql).get(...params),
    run: (sql, ...params) => statement(sql).run(...params),
    // Bodies and secrets are encrypted at rest; the row identity is bound as associated data so ciphertexts can't be swapped between rows.
    seal(text, context) {
      const iv = randomBytes(12), cipher = createCipheriv('chacha20-poly1305', key, iv, {authTagLength: 16});
      cipher.setAAD(Buffer.from(context), {plaintextLength: Buffer.byteLength(text)});
      const body = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), body]);
    },
    open(blob, context) {
      const data = Buffer.from(blob), decipher = createDecipheriv('chacha20-poly1305', key, data.subarray(0, 12), {authTagLength: 16});
      decipher.setAAD(Buffer.from(context), {plaintextLength: data.length - 28});
      decipher.setAuthTag(data.subarray(12, 28));
      return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8');
    },
    meta(k, v) {
      if (v === undefined) return statement('select v from meta where k = ?').get(k)?.v ?? null;
      statement('insert into meta (k, v) values (?, ?) on conflict(k) do update set v = excluded.v').run(k, v);
    },
    transaction(fn) {
      db.exec('begin immediate');
      try { const result = fn(); db.exec('commit'); return result; } catch (error) { db.exec('rollback'); throw error; }
    },
    // Cross-process lease: several agents on one Mac share this store, so only one syncs or prompts at a time.
    lease(name, owner, ms) {
      const t = Date.now();
      return statement("insert into meta (k, v) values (?, ?) on conflict(k) do update set v = excluded.v where json_extract(meta.v, '$.until') < ?").run(`lock:${name}`, JSON.stringify({owner, until: t + ms}), t).changes === 1;
    },
    release: (name, owner) => statement("delete from meta where k = ? and json_extract(v, '$.owner') = ?").run(`lock:${name}`, owner),
    close: () => db.close(),
  };
}
