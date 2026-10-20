import {execFile, spawn} from 'node:child_process';
import {mkdirSync, readFileSync, renameSync, writeFileSync} from 'node:fs';
import {dirname} from 'node:path';

const SECURITY = '/usr/bin/security';

// Computers without Touch ID keep their keys in one 0600 file. A stored key is never replaced: the relay refuses changed keys, so a lost one can't come back.
export function fileKeystore(file) {
  const read = () => {
    try { return JSON.parse(readFileSync(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return {}; throw new Error(`Can't read ${file}: ${error.message}`); }
  };
  const write = values => {
    mkdirSync(dirname(file), {recursive: true, mode: 0o700});
    const temp = `${file}.${process.pid}.tmp`;
    writeFileSync(temp, JSON.stringify(values), {mode: 0o600});
    renameSync(temp, file);
  };
  return {
    get: async account => read()[account] ?? null,
    async set(account, secret) {
      const values = read();
      if (values[account] !== undefined && values[account] !== secret) throw new Error(`Refusing to replace the ${account} key in ${file}`);
      write({...values, [account]: secret});
    },
    async remove(account) {
      const values = read();
      if (account in values) { delete values[account]; write(values); }
    },
  };
}

export function keychain(service = 'agentchat') {
  const get = account => new Promise(resolve => execFile(SECURITY, ['find-generic-password', '-s', service, '-a', account, '-w'], (error, stdout) => resolve(error ? null : stdout.trim())));
  return {
    get,
    // `security -i` reads the command from stdin, so the secret never appears in any process's arguments.
    async set(account, secret) {
      if (!/^[a-z]+$/.test(account) || !/^[A-Za-z0-9_.-]+$/.test(secret)) throw new Error('Unexpected Keychain value');
      await new Promise((resolve, reject) => {
        const child = spawn(SECURITY, ['-i'], {stdio: ['pipe', 'ignore', 'ignore']});
        child.on('error', reject);
        child.on('close', resolve);
        child.stdin.end(`add-generic-password -U -s ${service} -a ${account} -w ${secret}\n`);
      });
      if (await get(account) !== secret) throw new Error(`Could not save the ${account} key to the Keychain`);
    },
    remove: account => new Promise(resolve => execFile(SECURITY, ['delete-generic-password', '-s', service, '-a', account], () => resolve())),
  };
}
