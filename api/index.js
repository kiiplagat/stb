const express = require('express'), { Pool } = require('pg');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), path = require('path');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const pool = new Pool({ connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URL, ssl: { rejectUnauthorized: false }, max: 1, connectionTimeoutMillis: 15000, keepAlive: true });
pool.on('error', () => {});
const RETRY = /TLS|ECONNRESET|socket disconnected|connection timeout|terminated unexpectedly/i;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const Q = async (sql, p = []) => {
  try { return (await pool.query(sql, p)).rows; }
  catch (e) { if (!RETRY.test(e.message)) throw e; await sleep(1000); return (await pool.query(sql, p)).rows; }
};
const one = async (sql, p) => (await Q(sql, p))[0];
const TODAY = "to_char(now() at time zone 'Africa/Nairobi','YYYY-MM-DD')";
const STAMP = "to_char(now() at time zone 'Africa/Nairobi','YYYY-MM-DD HH24:MI:SS')";
const SCHEMA = `
create table if not exists users(id serial primary key, name text, username text unique, hash text, role text, property_id int);
create table if not exists properties(id serial primary key, name text, location text);
create table if not exists units(id serial primary key, property_id int, number text, rent double precision);
create table if not exists tenants(id serial primary key, user_id int, name text, phone text, id_number text, unit_id int, move_in text, deposit double precision default 0, status text default 'active');
create table if not exists payments(id serial primary key, tenant_id int, amount double precision, method text, note text, date text default ${TODAY}, recorded_by int);
create table if not exists complaints(id serial primary key, tenant_id int, title text, description text, status text default 'open', comment text, created_at text default ${STAMP});
`;
let ready = null; // retried on the next request if the database was asleep or unreachable
const init = async () => { for (let i = 0; i < 3; i++) { try { await Q(SCHEMA); return; } catch (e) { if (i === 2) throw e; await sleep(1500); } } };

const app = express();
app.use(express.json());
// Serve the web app itself from this function (so / and /manager work on Vercel); no database needed for these
const PUB = path.join(__dirname, '..', 'public');
app.use(express.static(PUB));
app.get(['/', '/manager'], (req, res) => res.sendFile(path.join(PUB, 'index.html')));
app.use((req, res, next) => {
  ready = ready || init().catch(e => { ready = null; throw e; });
  ready.then(() => next(), e => res.status(500).json({ error: 'Database error: ' + e.message }));
});
const wrap = f => (req, res) => f(req, res).catch(e => res.status(400).json({ error: e.message }));
const auth = (...roles) => (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').slice(7), SECRET); }
  catch { return res.status(401).json({ error: 'Please log in' }); }
  if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed for your role' });
  next();
};
const need = (o, ...k) => k.forEach(x => { if (!o[x]) throw new Error(x + ' is required'); });
const mkUser = async (name, username, password, role, property_id = null) => {
  need({ name, username, password }, 'name', 'username', 'password');
  if (await one('select 1 from users where username=$1', [username])) throw new Error('Username already taken');
  return (await one('insert into users(name,username,hash,role,property_id) values($1,$2,$3,$4,$5) returning id',
    [name, username, bcrypt.hashSync(password, 10), role, property_id])).id;
};

// ---- Auth ----
app.get('/api/setup', wrap(async (req, res) => res.json({ needed: !(await one("select 1 from users where role='landlord'")) })));
app.post('/api/register', wrap(async (req, res) => {
  if (await one("select 1 from users where role='landlord'")) throw new Error('Landlord account already exists');
  await mkUser(req.body.name, req.body.username, req.body.password, 'landlord'); res.json({ ok: true });
}));
app.post('/api/login', wrap(async (req, res) => {
  const u = await one('select * from users where username=$1', [req.body.username]);
  if (!u || !bcrypt.compareSync(req.body.password || '', u.hash)) throw new Error('Wrong username or password');
  if (u.role === 'tenant') {
    const t = await one('select status from tenants where user_id=$1', [u.id]);
    if (t && t.status === 'moved_out') throw new Error('This account has been closed');
    if (!t || t.status !== 'active') throw new Error('Your account is awaiting approval by the landlord or caretaker');
  }
  const user = { id: u.id, name: u.name, role: u.role, property_id: u.property_id };
  res.json({ token: jwt.sign(user, SECRET, { expiresIn: '7d' }), user });
}));

// ---- Helpers ----
const TQ = `select t.*, u.number unit, u.rent, u.property_id,
  (select coalesce(sum(p.amount),0)::float8 from payments p where p.tenant_id=t.id) paid
  from tenants t left join units u on u.id=t.unit_id`;
const balance = t => {
  if (!t.unit_id || !t.move_in) return 0;
  const a = new Date(t.move_in), n = new Date();
  // Move-in month is charged at move-in; each later month is charged once its 5th has arrived
  let diff = (n.getFullYear() - a.getFullYear()) * 12 + n.getMonth() - a.getMonth();
  if (n.getDate() < 5) diff -= 1;
  return (1 + Math.max(0, diff)) * (t.rent || 0) - t.paid; // positive = owes
};
const scope = (user, rows) => user.role === 'caretaker' ? rows.filter(r => r.property_id === user.property_id) : rows;
const myTenant = user => one(TQ + ' where t.user_id=$1', [user.id]);

// ---- Tenant self sign-up ----
app.get('/api/vacant-units', wrap(async (req, res) => res.json(await Q(
  'select u.id,u.number,u.rent,u.property_id,p.name property from units u join properties p on p.id=u.property_id where u.id not in (select unit_id from tenants where unit_id is not null)'))));
app.post('/api/signup', wrap(async (req, res) => {
  const b = req.body; need(b, 'name', 'phone', 'unit_id', 'username', 'password');
  if (await one('select 1 from tenants where unit_id=$1', [b.unit_id])) throw new Error('That unit is no longer available');
  const uid = await mkUser(b.name, b.username, b.password, 'tenant');
  await Q("insert into tenants(user_id,name,phone,id_number,unit_id,status) values($1,$2,$3,$4,$5,'pending')", [uid, b.name, b.phone, b.id_number || '', b.unit_id]);
  res.json({ ok: true });
}));

// ---- Approvals ----
const findPending = async req => scope(req.user, await Q(TQ + " where t.status='pending' and t.id=$1", [req.params.id]))[0];
app.get('/api/pending', auth('landlord', 'caretaker'), wrap(async (req, res) =>
  res.json(scope(req.user, await Q(TQ + " where t.status='pending'")))));
app.post('/api/pending/:id/approve', auth('landlord', 'caretaker'), wrap(async (req, res) => {
  need(req.body, 'move_in');
  const t = await findPending(req); if (!t) throw new Error('Request not found');
  await Q("update tenants set status='active', move_in=$1, deposit=$2 where id=$3", [req.body.move_in, +req.body.deposit || 0, t.id]);
  res.json({ ok: true });
}));
app.delete('/api/pending/:id', auth('landlord', 'caretaker'), wrap(async (req, res) => {
  const t = await findPending(req); if (!t) throw new Error('Request not found');
  await Q('delete from tenants where id=$1', [t.id]); await Q('delete from users where id=$1', [t.user_id]);
  res.json({ ok: true });
}));

// ---- Properties & units ----
app.get('/api/properties', auth('landlord', 'caretaker'), wrap(async (req, res) => {
  const r = await Q('select * from properties order by id');
  res.json(req.user.role === 'caretaker' ? r.filter(p => p.id === req.user.property_id) : r);
}));
app.post('/api/properties', auth('landlord'), wrap(async (req, res) => {
  need(req.body, 'name'); await Q('insert into properties(name,location) values($1,$2)', [req.body.name, req.body.location || '']); res.json({ ok: true });
}));
app.get('/api/units', auth('landlord', 'caretaker'), wrap(async (req, res) => res.json(scope(req.user, await Q(
  "select u.*, p.name property, t.name tenant from units u join properties p on p.id=u.property_id left join tenants t on t.unit_id=u.id and t.status='active' order by u.id")))));
app.post('/api/units', auth('landlord'), wrap(async (req, res) => {
  need(req.body, 'property_id', 'number', 'rent');
  await Q('insert into units(property_id,number,rent) values($1,$2,$3)', [+req.body.property_id, req.body.number, +req.body.rent]); res.json({ ok: true });
}));

// ---- Tenants ----
app.get('/api/tenants', auth('landlord', 'caretaker'), wrap(async (req, res) =>
  res.json(scope(req.user, await Q(TQ + " where t.status='active' order by t.id")).map(t => ({ ...t, balance: balance(t) })))));
app.post('/api/tenants', auth('landlord', 'caretaker'), wrap(async (req, res) => {
  const b = req.body; need(b, 'name', 'phone', 'unit_id', 'move_in', 'username', 'password');
  const unit = await one('select * from units where id=$1', [b.unit_id]);
  if (!unit || (req.user.role === 'caretaker' && unit.property_id !== req.user.property_id)) throw new Error('Unit not in your property');
  if (await one('select 1 from tenants where unit_id=$1', [b.unit_id])) throw new Error('That unit is taken or has a pending request');
  const uid = await mkUser(b.name, b.username, b.password, 'tenant');
  await Q("insert into tenants(user_id,name,phone,id_number,unit_id,move_in,deposit,status) values($1,$2,$3,$4,$5,$6,$7,'active')",
    [uid, b.name, b.phone, b.id_number || '', b.unit_id, b.move_in, +b.deposit || 0]);
  res.json({ ok: true });
}));
app.post('/api/tenants/:id/moveout', auth('landlord'), wrap(async (req, res) => {
  const t = await one(TQ + " where t.id=$1 and t.status='active'", [req.params.id]); if (!t) throw new Error('Not found');
  const owed = Math.max(0, balance(t)), dep = t.deposit || 0, applied = Math.min(owed, dep);
  if (applied > 0) await Q("insert into payments(tenant_id,amount,method,note,recorded_by) values($1,$2,'deposit','Deposit applied at move-out',$3)", [t.id, applied, req.user.id]);
  await Q("update tenants set status='moved_out', unit_id=null where id=$1", [t.id]);
  res.json({ deposit: dep, applied, refund: dep - applied, stillOwed: owed - applied });
}));
app.delete('/api/tenants/:id', auth('landlord'), wrap(async (req, res) => {
  const t = await one('select * from tenants where id=$1', [req.params.id]); if (!t) throw new Error('Not found');
  await Q('delete from tenants where id=$1', [t.id]); await Q('delete from users where id=$1', [t.user_id]); res.json({ ok: true });
}));

// ---- Caretakers ----
app.get('/api/caretakers', auth('landlord'), wrap(async (req, res) => res.json(await Q(
  "select u.id,u.name,u.username,p.name property from users u left join properties p on p.id=u.property_id where u.role='caretaker' order by u.id"))));
app.post('/api/caretakers', auth('landlord'), wrap(async (req, res) => {
  need(req.body, 'property_id'); await mkUser(req.body.name, req.body.username, req.body.password, 'caretaker', +req.body.property_id); res.json({ ok: true });
}));
app.delete('/api/caretakers/:id', auth('landlord'), wrap(async (req, res) => {
  await Q("delete from users where id=$1 and role='caretaker'", [req.params.id]); res.json({ ok: true });
}));

// ---- Payments ----
app.get('/api/payments', auth('landlord', 'caretaker'), wrap(async (req, res) => res.json(scope(req.user, await Q(
  'select p.*, t.name tenant, u.number unit, u.property_id from payments p join tenants t on t.id=p.tenant_id left join units u on u.id=t.unit_id order by p.id desc')))));
app.post('/api/payments', auth('landlord', 'caretaker'), wrap(async (req, res) => {
  need(req.body, 'tenant_id', 'amount');
  const t = await one(TQ + " where t.id=$1 and t.status='active'", [req.body.tenant_id]);
  if (!t || (req.user.role === 'caretaker' && t.property_id !== req.user.property_id)) throw new Error('Tenant not in your property');
  await Q('insert into payments(tenant_id,amount,method,note,recorded_by) values($1,$2,$3,$4,$5)', [t.id, +req.body.amount, req.body.method || 'cash', req.body.note || '', req.user.id]);
  res.json({ ok: true });
}));
app.delete('/api/payments/:id', auth('landlord'), wrap(async (req, res) => { await Q('delete from payments where id=$1', [req.params.id]); res.json({ ok: true }); }));

// ---- Complaints ----
const CQ = 'select c.*, t.name tenant, u.number unit, u.property_id from complaints c join tenants t on t.id=c.tenant_id left join units u on u.id=t.unit_id order by c.id desc';
app.get('/api/complaints', auth(), wrap(async (req, res) => {
  if (req.user.role === 'tenant') { const t = await myTenant(req.user); return res.json(await Q('select * from complaints where tenant_id=$1 order by id desc', [t.id])); }
  res.json(scope(req.user, await Q(CQ)));
}));
app.post('/api/complaints', auth('tenant'), wrap(async (req, res) => {
  need(req.body, 'title'); const t = await myTenant(req.user);
  await Q('insert into complaints(tenant_id,title,description) values($1,$2,$3)', [t.id, req.body.title, req.body.description || '']); res.json({ ok: true });
}));
app.patch('/api/complaints/:id', auth('landlord', 'caretaker'), wrap(async (req, res) => {
  const c = scope(req.user, await Q(CQ)).find(x => x.id == req.params.id); if (!c) throw new Error('Complaint not found');
  await Q('update complaints set status=$1, comment=$2 where id=$3', [req.body.status || c.status, req.body.comment ?? c.comment, c.id]); res.json({ ok: true });
}));

// ---- Tenant self view & landlord summary ----
app.get('/api/me', auth('tenant'), wrap(async (req, res) => {
  const t = await myTenant(req.user);
  res.json({ ...t, balance: balance(t), payments: await Q('select * from payments where tenant_id=$1 order by id desc', [t.id]) });
}));
app.get('/api/summary', auth('landlord'), wrap(async (req, res) => {
  const ts = await Q(TQ + " where t.status='active'");
  res.json({
    units: (await one('select count(*)::int n from units')).n, tenants: ts.length,
    collected: (await one("select coalesce(sum(amount),0)::float8 s from payments where method!='deposit' and substr(date,1,7)=to_char(now() at time zone 'Africa/Nairobi','YYYY-MM')")).s,
    arrears: ts.reduce((a, t) => a + Math.max(0, balance(t)), 0),
    openComplaints: (await one("select count(*)::int n from complaints where status!='resolved'")).n,
    pending: (await one("select count(*)::int n from tenants where status='pending'")).n
  });
}));

// ---- Passwords ----
const checkNew = v => { if (String(v || '').length < 6) throw new Error('Password must be at least 6 characters'); };
app.post('/api/password', auth(), wrap(async (req, res) => { // anyone changes their own password
  need(req.body, 'current', 'new'); checkNew(req.body.new);
  const u = await one('select * from users where id=$1', [req.user.id]);
  if (!u || !bcrypt.compareSync(req.body.current, u.hash)) throw new Error('Current password is wrong');
  await Q('update users set hash=$1 where id=$2', [bcrypt.hashSync(req.body.new, 10), u.id]); res.json({ ok: true });
}));
app.post('/api/users/:id/reset', auth('landlord', 'caretaker'), wrap(async (req, res) => { // landlord: caretakers+tenants; caretaker: own tenants
  checkNew(req.body.password);
  const u = await one('select * from users where id=$1', [req.params.id]);
  if (!u || u.role === 'landlord') throw new Error('Not allowed');
  if (req.user.role === 'caretaker') {
    const t = await one(TQ + ' where t.user_id=$1', [u.id]);
    if (u.role !== 'tenant' || !t || t.property_id !== req.user.property_id) throw new Error('Not allowed');
  }
  await Q('update users set hash=$1 where id=$2', [bcrypt.hashSync(req.body.password, 10), u.id]); res.json({ ok: true });
}));

module.exports = app;
if (require.main === module) { // local testing: npm start
  app.listen(process.env.PORT || 3000, () => console.log('STB running on http://localhost:3000'));
}
