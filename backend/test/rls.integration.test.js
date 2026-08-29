const test = require('node:test');
const assert = require('node:assert/strict');
const { getPool, migrate, withTenant } = require('../src/db');

test('PostgreSQL RLS prevents cross-tenant reads and writes', { skip: !process.env.DATABASE_URL }, async () => {
  await migrate();
  const suffix = Date.now().toString(36);
  const orgs = await getPool().query("INSERT INTO organizations(name,slug) VALUES ($1,$2),($3,$4) RETURNING id", [`Tenant A ${suffix}`,`tenant-a-${suffix}`,`Tenant B ${suffix}`,`tenant-b-${suffix}`]);
  const users = [];
  for (let i=0;i<2;i++) {
    const result = await getPool().query("INSERT INTO users(organization_id,email,password_hash,full_name,role) VALUES($1,$2,'test','CI User','admin') RETURNING id", [orgs.rows[i].id,`ci-${suffix}-${i}@example.test`]);
    users.push(result.rows[0].id);
  }
  await withTenant(orgs.rows[0].id, client => client.query("INSERT INTO cases(organization_id,case_number,title,case_type,priority,created_by) VALUES($1,'CASE-9001','A only','DFIR','High',$2)", [orgs.rows[0].id,users[0]]));
  await withTenant(orgs.rows[1].id, client => client.query("INSERT INTO cases(organization_id,case_number,title,case_type,priority,created_by) VALUES($1,'CASE-9001','B only','DFIR','High',$2)", [orgs.rows[1].id,users[1]]));
  const visible = await withTenant(orgs.rows[0].id, client => client.query('SELECT organization_id,title FROM cases ORDER BY title'));
  assert.equal(visible.rows.length,1);
  assert.equal(visible.rows[0].title,'A only');
  await assert.rejects(() => withTenant(orgs.rows[0].id, client => client.query("INSERT INTO cases(organization_id,case_number,title,case_type,priority,created_by) VALUES($1,'CASE-9002','Forbidden','DFIR','High',$2)", [orgs.rows[1].id,users[0]])));
});
