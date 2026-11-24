// Netlify Function: accounts, permissions and guide data for ڕێبەری پەروەردەی شارباژێڕ.
// Storage: Netlify Blobs (store "rebari"). Auth: PBKDF2 passwords + HMAC-signed tokens.
// Roles: هۆبەی پلان (plan) edits everything; every other unit edits only its own unit.
import { getStore } from '@netlify/blobs';
import { pbkdf2Sync, randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import UNITS from './units.json';

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const TOKEN_HOURS = 12;
const norm = s => String(s || '').replace(/[\u200c\u200d]/g, '').replace(/ي/g, 'ی').replace(/ى/g, 'ی').replace(/ك/g, 'ک').replace(/\s+/g, ' ').trim();
const isPlanUnit = name => norm(name).includes(norm('پلان'));
const PLAN_UNIT = UNITS.find(isPlanUnit) || 'هۆبەی پلان';
const store = () => getStore('rebari');

const send = (status, body) => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
const fail = (status, msg) => send(status, { error: msg });

// ---------- passwords & tokens ----------
function hashPassword(password, salt = randomBytes(16).toString('base64')) {
  const hash = pbkdf2Sync(password, salt, 210000, 32, 'sha256').toString('base64');
  return { salt, hash };
}
function checkPassword(password, user) {
  const h = pbkdf2Sync(password, user.salt, 210000, 32, 'sha256');
  const expected = Buffer.from(user.hash, 'base64');
  return h.length === expected.length && timingSafeEqual(h, expected);
}
function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) throw new Error('AUTH_SECRET must be set (at least 32 characters)');
  return s;
}
function makeToken(user) {
  const payload = Buffer.from(JSON.stringify({ u: user.username, unit: user.unit, exp: Date.now() + TOKEN_HOURS * 3600e3 })).toString('base64url');
  const sig = createHmac('sha256', secret()).update(payload).digest('base64url');
  return payload + '.' + sig;
}
async function currentUser(req) {
  const auth = req.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const good = createHmac('sha256', secret()).update(payload).digest('base64url');
  if (good.length !== sig.length || !timingSafeEqual(Buffer.from(good), Buffer.from(sig))) return null;
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  if (!data.exp || data.exp < Date.now()) return null;
  const users = (await store().get('users', { type: 'json' })) || [];
  const user = users.find(x => x.username === data.u);
  if (!user) return null;
  return { ...user, role: isPlanUnit(user.unit) ? 'plan' : 'unit' };
}

// ---------- data helpers ----------
async function getUsers() { return (await store().get('users', { type: 'json' })) || []; }
async function saveUsers(users) { await store().setJSON('users', users); }
async function getGuide() {
  return (await store().get('guide', { type: 'json' })) || { units: {}, faq: [], transactions: [], log: [] };
}
async function saveGuide(g) { await store().setJSON('guide', g); }
const pick = (obj, keys) => Object.fromEntries(keys.filter(k => obj[k] !== undefined).map(k => [k, String(obj[k]).slice(0, 500)]));


// ---------- records (staff & schools) ----------
const STAFF_KEYS = ['place', 'placeType', 'name', 'role', 'gender', 'ty', 'deg', 'sp', 'tel', 'lv', 'lt'];
const SCHOOL_KEYS = ['name', 'stage', 'subdistrict', 'principal', 'lat', 'lng'];
const COLS = { staff: STAFF_KEYS, schools: SCHOOL_KEYS };
async function getRecords() { return (await store().get('records', { type: 'json' })) || { staff: [], schools: [], version: 0 }; }
async function saveRecords(r) { r.version = (r.version || 0) + 1; r.updated = new Date().toISOString(); await store().setJSON('records', r); }
const newId = () => randomBytes(8).toString('hex');
function cleanRecord(o, keys) {
  const out = {};
  for (const k of keys) {
    if (o[k] === undefined) continue;
    out[k] = typeof o[k] === 'boolean' ? o[k] : String(o[k]).slice(0, 300);
  }
  if ('lv' in out) out.lv = !!out.lv;
  for (const k of ['lat', 'lng']) if (k in out) { const n = parseFloat(out[k]); out[k] = Number.isFinite(n) ? n : ''; }
  return out;
}
function importFromData(d) {
  if (!d || !Array.isArray(d.diwan) || !d.schools) throw new Error('فایلی داتا هەڵەیە (پێویستە data.json بێت)');
  const gi = (d.fields || []).findIndex(f => f[0] === 'ڕەگەز');
  const staff = [], schools = [];
  const mk = (place, type, m) => ({
    id: newId(), place, placeType: type, name: m.name || '', role: m.role || '',
    gender: gi >= 0 && Array.isArray(m.d) ? (m.d[gi] || '') : '',
    ty: m.ty || '', deg: m.deg || '', sp: m.sp || '', tel: m.tel || '', lv: !!m.lv, lt: m.lt || ''
  });
  d.diwan.forEach(u => (u.members || []).forEach(m => staff.push(mk(u.name, 'unit', m))));
  for (const stage of ['basic', 'prep', 'mid', 'kg']) {
    (d.schools[stage] || []).forEach(sc => {
      const principal = (sc.members || []).filter(x => x.role === 'بەڕێوەبەر').map(x => x.name).join('، ');
      schools.push({ id: newId(), name: sc.name, stage, subdistrict: '', principal });
      (sc.members || []).forEach(m => staff.push(mk(sc.name, 'school', m)));
    });
  }
  return { staff, schools, version: 0 };
}

// ---------- router ----------
export default async (req, context) => {
  try {
    const url = new URL(req.url);
    const parts = url.pathname.split('/').filter(Boolean);
    const i = parts.indexOf('api');
    const route = parts.slice(i + 1);           // e.g. ['login'] or ['unit', 'هۆبەی ...']
    const method = req.method;

    if (method === 'GET' && route[0] === 'guide') {
      return send(200, await getGuide());
    }
    if (method === 'GET' && route[0] === 'setup-status') {
      return send(200, { needsSetup: (await getUsers()).length === 0 });
    }
    if (method === 'GET' && route[0] === 'units') {
      return send(200, { units: UNITS, planUnit: PLAN_UNIT });
    }

    if (method === 'POST' && route[0] === 'setup') {
      const body = await req.json();
      if (!process.env.SETUP_KEY || body.setupKey !== process.env.SETUP_KEY) return fail(403, 'کلیلی دامەزراندن هەڵەیە');
      const users = await getUsers();
      if (users.length) return fail(409, 'ئەکاونت پێشتر دروست کراوە');
      if (!body.username || !body.password || body.password.length < 8) return fail(400, 'ناو و وشەی نهێنی (لانیکەم ٨ پیت) پێویستە');
      const { salt, hash } = hashPassword(body.password);
      await saveUsers([{ username: body.username.trim(), unit: PLAN_UNIT, salt, hash }]);
      return send(201, { ok: true });
    }

    if (method === 'POST' && route[0] === 'login') {
      const body = await req.json();
      const users = await getUsers();
      const user = users.find(x => x.username === (body.username || '').trim());
      if (!user || !checkPassword(body.password || '', user)) return fail(401, 'ناو یان وشەی نهێنی هەڵەیە');
      return send(200, { token: makeToken(user), username: user.username, unit: user.unit, role: isPlanUnit(user.unit) ? 'plan' : 'unit' });
    }

    if (method === 'GET' && route[0] === 'me') {
      const me = await currentUser(req);
      if (!me) return fail(401, 'پێویستە بچیتە ژوورەوە');
      return send(200, { username: me.username, unit: me.unit, role: me.role });
    }

    // everything below needs a signed-in user
    const me = await currentUser(req);
    if (!me) return fail(401, 'پێویستە بچیتە ژوورەوە');

    if (method === 'PUT' && route[0] === 'unit') {
      const name = decodeURIComponent(route[1] || '');
      if (!UNITS.includes(name)) return fail(404, 'هۆبە نەدۆزرایەوە');
      if (me.role !== 'plan' && name !== me.unit) return fail(403, 'تەنها دەتوانیت هۆبەی خۆت دەستکاری بکەیت');
      const body = await req.json();
      const g = await getGuide();
      g.units[name] = { ...(g.units[name] || {}), ...pick(body, ['duties', 'room', 'hours', 'phone', 'email']) };
      g.log = [{ by: me.username, unit: name, at: new Date().toISOString() }, ...(g.log || [])].slice(0, 200);
      await saveGuide(g);
      return send(200, { ok: true, unit: g.units[name] });
    }

    if (method === 'PUT' && route[0] === 'faq') {
      if (me.role !== 'plan') return fail(403, 'تەنها هۆبەی پلان');
      const body = await req.json();
      const g = await getGuide();
      g.faq = (Array.isArray(body.faq) ? body.faq : []).slice(0, 100).map(f => ({ q: String(f.q || '').slice(0, 300), a: String(f.a || '').slice(0, 2000) }));
      await saveGuide(g);
      return send(200, { ok: true });
    }

    if (method === 'PUT' && route[0] === 'transactions') {
      if (me.role !== 'plan') return fail(403, 'تەنها هۆبەی پلان');
      const body = await req.json();
      const g = await getGuide();
      g.transactions = (Array.isArray(body.transactions) ? body.transactions : []).slice(0, 200);
      await saveGuide(g);
      return send(200, { ok: true });
    }


    if (route[0] === 'records') {
      if (me.role !== 'plan') return fail(403, 'تەنها هۆبەی پلان');
      if (method === 'GET' && route.length === 1) return send(200, await getRecords());
      if (method === 'POST' && route[1] === 'import') {
        const body = await req.json();
        const r = importFromData(body.data);
        await saveRecords(r);
        return send(201, { ok: true, staff: r.staff.length, schools: r.schools.length });
      }
      const col = route[1];
      if (!COLS[col]) return fail(404, 'جۆری داتا نەدۆزرایەوە');
      const r = await getRecords();
      if (method === 'POST' && route.length === 2) {
        const item = { id: newId(), ...cleanRecord(await req.json(), COLS[col]) };
        r[col].push(item); await saveRecords(r);
        return send(201, { ok: true, item });
      }
      const id = route[2];
      const idx = r[col].findIndex(x => x.id === id);
      if (idx < 0) return fail(404, 'تۆمار نەدۆزرایەوە');
      if (method === 'PUT') {
        r[col][idx] = { id, ...cleanRecord({ ...r[col][idx], ...(await req.json()) }, COLS[col]) };
        await saveRecords(r);
        return send(200, { ok: true, item: r[col][idx] });
      }
      if (method === 'DELETE') {
        r[col].splice(idx, 1); await saveRecords(r);
        return send(200, { ok: true });
      }
    }

    if (route[0] === 'users') {
      if (me.role !== 'plan') return fail(403, 'تەنها هۆبەی پلان');
      const users = await getUsers();
      if (method === 'GET') return send(200, { users: users.map(u => ({ username: u.username, unit: u.unit })) });
      if (method === 'POST') {
        const body = await req.json();
        const username = (body.username || '').trim(), unit = body.unit;
        if (!username || !/^[A-Za-z0-9_.-]{3,30}$/.test(username)) return fail(400, 'ناوی بەکارهێنەر: ٣–٣٠ پیت (ئینگلیزی، ژمارە، _ . -)');
        if (!UNITS.includes(unit)) return fail(400, 'هۆبە هەڵەیە');
        if (!body.password || body.password.length < 8) return fail(400, 'وشەی نهێنی لانیکەم ٨ پیت');
        if (users.some(u => u.username === username)) return fail(409, 'ئەم ناوە پێشتر هەیە');
        if (users.some(u => u.unit === unit)) return fail(409, 'ئەم هۆبەیە پێشتر ئەکاونتی هەیە');
        const { salt, hash } = hashPassword(body.password);
        users.push({ username, unit, salt, hash });
        await saveUsers(users);
        return send(201, { ok: true });
      }
      if (method === 'DELETE') {
        const username = decodeURIComponent(route[1] || '');
        const target = users.find(u => u.username === username);
        if (!target) return fail(404, 'بەکارهێنەر نەدۆزرایەوە');
        if (isPlanUnit(target.unit)) return fail(400, 'ئەکاونتی هۆبەی پلان ناسڕێتەوە');
        await saveUsers(users.filter(u => u.username !== username));
        return send(200, { ok: true });
      }
    }

    return fail(404, 'ڕێگە نەدۆزرایەوە');
  } catch (err) {
    return fail(500, 'هەڵەیەک ڕوویدا: ' + (err && err.message ? err.message : 'unknown'));
  }
};
