// Use only if the landlord forgets their own password.
// PowerShell:  $env:DATABASE_URL = "your Neon connection string"
//              node reset-landlord.js <landlord-username> <new-password>
const { Pool } = require('pg'), bcrypt = require('bcryptjs');
const [, , username, password] = process.argv;
if (!process.env.DATABASE_URL || !username || !password || password.length < 6) {
  console.log('Usage: set DATABASE_URL first, then: node reset-landlord.js <username> <new-password (6+ chars)>');
  process.exit(1);
}
(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  const r = await pool.query("update users set hash=$1 where username=$2 and role='landlord'", [bcrypt.hashSync(password, 10), username]);
  console.log(r.rowCount ? 'Landlord password updated.' : 'No landlord found with that username.');
  await pool.end();
})().catch(e => { console.log('Failed:', e.message); process.exit(1); });
