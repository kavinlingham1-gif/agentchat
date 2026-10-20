import {createConnection} from 'node:net';

// The relay's storage calls (the same redis(command, ...args) as upstash()) spoken to Valkey or Redis directly. Replies come back
// in the order commands were sent, so one connection carries everything. A lost or stalled connection fails what was in flight
// instead of resending it, because INCR and RPUSH aren't safe to repeat; the next command reconnects.
export function valkey(address, {user, password, timeout = 5000} = {}) {
  const at = address.lastIndexOf(':');
  const target = address.includes('/') ? {path: address} : {host: address.slice(0, at).replace(/^\[|\]$/g, ''), port: Number(address.slice(at + 1))};
  let socket = null, buffer = Buffer.alloc(0), pending = [];

  const fail = error => {
    const lost = pending;
    socket?.destroy();
    [socket, buffer, pending] = [null, Buffer.alloc(0), []];
    for (const p of lost) { clearTimeout(p.timer); p.reject(error); }
  };
  const write = (args, settle) => {
    const timer = setTimeout(() => fail(new Error(`redis ${args[0]}: timed out`)), timeout);
    pending.push({command: args[0], timer, ...settle});
    const parts = [Buffer.from(`*${args.length}\r\n`)];
    for (const arg of args) { const bytes = Buffer.from(String(arg)); parts.push(Buffer.from(`$${bytes.length}\r\n`), bytes, Buffer.from('\r\n')); }
    socket.write(Buffer.concat(parts));
  };
  const connect = () => {
    const current = socket = createConnection(target).unref();
    const lose = message => { if (socket === current) fail(new Error(`redis: ${message}`)); };
    current.on('error', error => lose(error.message));
    current.on('close', () => lose('connection closed'));
    current.on('data', chunk => {
      if (socket !== current) return;
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
      try {
        for (let reply; (reply = parse(buffer, 0));) {
          buffer = buffer.subarray(reply.end);
          const p = pending.shift();
          if (!p) throw new Error('reply without a command');
          clearTimeout(p.timer);
          if (reply.value instanceof Error) p.reject(new Error(`redis ${p.command}: ${reply.value.message}`)); else p.resolve(reply.value);
        }
      } catch (error) { lose(error.message); }
    });
    if (password) write(['AUTH', ...(user ? [user] : []), password], {resolve() {}, reject: error => fail(error)});
  };

  return (...args) => new Promise((resolve, reject) => {
    if (!socket) connect();
    write(args, {resolve, reject});
  });
}

// One RESP2 reply starting at `at`, or null until all of it has arrived.
function parse(buffer, at) {
  const eol = buffer.indexOf('\r\n', at);
  if (eol < 0) return null;
  const line = buffer.toString('utf8', at + 1, eol), next = eol + 2;
  switch (String.fromCharCode(buffer[at])) {
    case '+': return {value: line, end: next};
    case '-': return {value: new Error(line), end: next};
    case ':': return {value: Number(line), end: next};
    case '$': {
      const length = Number(line);
      if (length < 0) return {value: null, end: next};
      return buffer.length < next + length + 2 ? null : {value: buffer.toString('utf8', next, next + length), end: next + length + 2};
    }
    case '*': {
      const count = Number(line), items = [];
      if (count < 0) return {value: null, end: next};
      let end = next;
      for (let i = 0; i < count; i++) {
        const item = parse(buffer, end);
        if (!item) return null;
        items.push(item.value);
        end = item.end;
      }
      return {value: items, end};
    }
    default: throw new Error(`unexpected reply type ${JSON.stringify(String.fromCharCode(buffer[at]))}`);
  }
}
