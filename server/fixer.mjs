// No website credential is distributed. Clients sign with independent local keys.
// Signatures authenticate an installation, not the truth of its reports.
export const FIXER_POLICY = '2026-10-03.1';
const utf8 = new TextEncoder();
const RETENTION = 30 * 86400;
const json = (value, status = 200) => new Response(JSON.stringify(value), {status,
  headers: {'content-type': 'application/json', 'cache-control': 'no-store'}});
const fail = (error, status = 400) => json({ok: false, error}, status);
const digest = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(value)));
const hex = value => Buffer.from(value).toString('hex');
export async function fixerId(key) { return hex(await digest(`RSA\n${key.n}\n${key.e}`)); }
export async function fixerMessage(req, raw) {
  return `fixer-report-v1\n${req.method}\n${new URL(req.url).origin}${new URL(req.url).pathname}\n${req.headers.get('x-fixer-id')}\n${req.headers.get('x-fixer-time')}\n${req.headers.get('x-fixer-nonce')}\n${Buffer.from(await digest(raw)).toString('base64')}`;
}
function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && Object.keys(value).every(k => keys.includes(k));
}
function validKey(key) {
  return exactKeys(key, ['kty','n','e']) && key.kty === 'RSA' && key.e === 'AQAB' &&
    typeof key.n === 'string' && /^[A-Za-z0-9_-]{342}$/.test(key.n) &&
    Buffer.from(key.n, 'base64url').length === 256 && (Buffer.from(key.n, 'base64url')[0] & 128) !== 0;
}
const enums = {
  os: ['windows','windows-10','windows-11'],
  status: ['started','checking','login','updating','ready','launched','failed','closed'],
  mode: ['none','kernel','usermode'], update: ['none','updating','completed','already-current'],
  tunnel: ['off','needed','connected','failed','disconnected'],
  error: ['none','connection','loader','launch','tunnel','unavailable'],
};
export function validReport(b) {
  return exactKeys(b, ['run','seq','version','os','status','mode','update','tunnel','error','duration','ended']) &&
    /^[a-f0-9]{32}$/.test(b.run) && Number.isSafeInteger(b.seq) && b.seq > 0 && b.seq <= 10000 &&
    typeof b.version === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(b.version) &&
    Object.entries(enums).every(([k, values]) => values.includes(b[k])) &&
    Number.isSafeInteger(b.duration) && b.duration >= 0 && b.duration <= 7 * 86400 && typeof b.ended === 'boolean';
}
async function rawBody(req) {
  if (!req.headers.get('content-type')?.startsWith('application/json')) throw new Error('json required');
  const reader = req.body?.getReader(); if (!reader) throw new Error('body required');
  let count = 0; const chunks = [];
  for (;;) { const {value, done} = await reader.read(); if (done) break;
    count += value.length; if (count > 4096) { await reader.cancel(); throw new Error('body too large'); } chunks.push(value); }
  const bytes = new Uint8Array(count); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
}
export function createFixer(env) {
  const db = env.DB;
  const one = (sql, ...args) => db.prepare(sql).bind(...args).first();
  const all = async (sql, ...args) => (await db.prepare(sql).bind(...args).all()).results;
  const run = (sql, ...args) => db.prepare(sql).bind(...args).run();
  async function client(req) {
    const url = new URL(req.url), path = url.pathname;
    if (url.protocol !== 'https:' || (env.ORIGIN && url.origin !== env.ORIGIN) || url.search) return fail('secure origin required', 403);
    if (!['/api/fixer/register','/api/fixer/report','/api/fixer/delete'].includes(path)) return fail('not found', 404);
    if (req.method !== 'POST') return fail('post required', 405);
    const peer = req.headers.get('cf-connecting-ip') || env.LOCAL_IP || 'local';
    if (!(await env.API_LIMIT.limit({key: 'fixer-ip:' + hex(await digest(peer))})).success) return fail('please slow down', 429);
    if (path.endsWith('/register') && !(await env.REGISTER_LIMIT.limit({key: 'fixer-register:' + hex(await digest(peer))})).success) return fail('please slow down', 429);
    let raw, b; try { raw = await rawBody(req); b = JSON.parse(raw); } catch { return fail('invalid report'); }
    const now = Math.floor(Date.now() / 1000), id = req.headers.get('x-fixer-id'), nonce = req.headers.get('x-fixer-nonce');
    const stamp = req.headers.get('x-fixer-time'), signature = req.headers.get('x-fixer-signature');
    if (!/^[0-9]{10}$/.test(stamp || '') || Math.abs(Number(stamp) - now) > 300 || !/^[a-f0-9]{32}$/.test(nonce || '') ||
        !/^[A-Za-z0-9+/]{342}==$/.test(signature || '')) return fail('invalid signature', 401);
    let key, installation;
    if (path.endsWith('/register')) {
      if (id !== '-' || !exactKeys(b, ['policy','publicKey']) || b.policy !== FIXER_POLICY || !validKey(b.publicKey)) return fail('invalid registration');
      key = b.publicKey; installation = await fixerId(key);
    } else {
      if (!/^[a-f0-9]{64}$/.test(id || '')) return fail('installation required', 401);
      const row = await one('SELECT public_key,policy FROM fixer_installations WHERE id=?', id);
      if (!row || row.policy !== FIXER_POLICY) return fail('registration required', 401);
      key = JSON.parse(row.public_key); installation = id;
    }
    try {
      const publicKey = await crypto.subtle.importKey('jwk', {...key, ext: true}, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
      if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, Buffer.from(signature, 'base64'), utf8.encode(await fixerMessage(req, raw)))) return fail('invalid signature', 401);
    } catch { return fail('invalid signature', 401); }
    if (!(await env.API_LIMIT.limit({key: 'fixer-key:' + installation})).success) return fail('please slow down', 429);
    // Validate before allocating any database state. Never retain arbitrary client text.
    if (path.endsWith('/report') && !validReport(b)) return fail('invalid report');
    if (path.endsWith('/delete') && !exactKeys(b, [])) return fail('invalid request');
    const claimed = await run('INSERT OR IGNORE INTO fixer_nonces(installation,nonce,created) VALUES(?,?,?)', installation, nonce, now);
    if (!claimed.meta.changes) return fail('request already used', 409);
    if (path.endsWith('/register')) {
      const inserted = await run('INSERT OR IGNORE INTO fixer_installations(id,public_key,policy,created,last_seen) SELECT ?,?,?,?,? WHERE (SELECT COUNT(*) FROM fixer_installations WHERE created>=?)<200', installation, JSON.stringify(key), FIXER_POLICY, now, now, now - 86400);
      if (!inserted.meta.changes && !await one('SELECT id FROM fixer_installations WHERE id=?', installation)) return fail('registration busy; try later', 429);
    }
    if (path.endsWith('/register')) return json({ok: true, installation, policy: FIXER_POLICY});
    if (path.endsWith('/delete')) {
      await db.batch([
        db.prepare('DELETE FROM fixer_runs WHERE installation=?').bind(installation),
        // Keep replay fingerprints for ten minutes so captured enrollment cannot undo deletion.
        db.prepare('DELETE FROM fixer_installations WHERE id=?').bind(installation),
      ]); return json({ok: true});
    }
    const prior = await one('SELECT seq,ended FROM fixer_runs WHERE installation=? AND run_id=?', installation, b.run);
    if (prior && (prior.seq >= b.seq || prior.ended)) return fail('run already updated or ended', 409);
    // Atomic quota and ordering checks also cover simultaneous submissions.
    const saved = await run(`INSERT INTO fixer_runs(installation,run_id,seq,started,updated,version,os,status,mode,update_result,tunnel,error,duration,ended)
      SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM fixer_installations WHERE id=?) AND
      (EXISTS(SELECT 1 FROM fixer_runs WHERE installation=? AND run_id=?) OR (SELECT COUNT(*) FROM fixer_runs WHERE installation=? AND started>=?)<50)
      ON CONFLICT(installation,run_id) DO UPDATE SET seq=excluded.seq,updated=excluded.updated,status=excluded.status,mode=excluded.mode,
      update_result=excluded.update_result,tunnel=excluded.tunnel,error=excluded.error,duration=excluded.duration,ended=excluded.ended
      WHERE excluded.seq>fixer_runs.seq AND fixer_runs.ended=0`, installation, b.run, b.seq, now, now, b.version, b.os, b.status, b.mode, b.update, b.tunnel, b.error, b.duration, +b.ended,
      installation, installation, b.run, installation, now - 86400);
    if (!saved.meta.changes) return fail('run limit or stale report', 409);
    await run('UPDATE fixer_installations SET last_seen=? WHERE id=?', now, installation);
    return json({ok: true});
  }
  async function admin() {
    const now = Math.floor(Date.now() / 1000), since = now - RETENTION;
    const summary = await one(`SELECT COUNT(*) runs,COUNT(DISTINCT installation) installations,
      COALESCE(SUM(updated>? AND ended=0),0) active,COALESCE(SUM(error<>'none'),0) problems,
      COALESCE(SUM(update_result='completed'),0) updates FROM fixer_runs WHERE updated>?`, now - 120, since);
    const runs = await all(`SELECT substr(installation,1,8) installation,substr(run_id,1,8) run,started,updated,version,os,status,mode,
      update_result AS updateResult,tunnel,error,duration,ended FROM fixer_runs WHERE updated>? ORDER BY updated DESC LIMIT 200`, since);
    return json({ok: true, now, summary, runs, notice: 'optional client-reported diagnostics · last 30 days · signatures identify an installation, not verified people or trustworthy usage counts'});
  }
  async function cleanup() {
    const now = Math.floor(Date.now() / 1000);
    await db.batch([
      db.prepare('DELETE FROM fixer_runs WHERE updated<?').bind(now - RETENTION),
      db.prepare('DELETE FROM fixer_nonces WHERE created<?').bind(now - 600),
      db.prepare('DELETE FROM fixer_installations WHERE last_seen<?').bind(now - RETENTION),
    ]);
  }
  return {client, admin, cleanup};
}
