const test = require('node:test');
const assert = require('node:assert/strict');
const { getPool, migrate, withTenant } = require('../src/db');

test('PostgreSQL RLS prevents cross-tenant reads and writes', { skip: !process.env.DATABASE_URL }, async () => {
  await migrate();
  await getPool().query(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='centinell_app_test') THEN
      CREATE ROLE centinell_app_test NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
  END $$`);
  await getPool().query('GRANT USAGE ON SCHEMA public TO centinell_app_test');
  await getPool().query('GRANT SELECT,INSERT,UPDATE,DELETE ON cases TO centinell_app_test');
  const suffix = Date.now().toString(36);
  const orgs = await getPool().query("INSERT INTO organizations(name,slug) VALUES ($1,$2),($3,$4) RETURNING id", [`Tenant A ${suffix}`,`tenant-a-${suffix}`,`Tenant B ${suffix}`,`tenant-b-${suffix}`]);
  const users = [];
  for (let i=0;i<2;i++) {
    const result = await getPool().query("INSERT INTO users(organization_id,email,password_hash,full_name,role) VALUES($1,$2,'test','CI User','admin') RETURNING id", [orgs.rows[i].id,`ci-${suffix}-${i}@example.test`]);
    users.push(result.rows[0].id);
  }
  const asApplicationTenant = (organizationId, work) => withTenant(organizationId, async client => {
    await client.query('SET LOCAL ROLE centinell_app_test');
    return work(client);
  });
  await asApplicationTenant(orgs.rows[0].id, client => client.query("INSERT INTO cases(organization_id,case_number,title,case_type,priority,created_by) VALUES($1,'CASE-9001','A only','DFIR','High',$2)", [orgs.rows[0].id,users[0]]));
  await asApplicationTenant(orgs.rows[1].id, client => client.query("INSERT INTO cases(organization_id,case_number,title,case_type,priority,created_by) VALUES($1,'CASE-9001','B only','DFIR','High',$2)", [orgs.rows[1].id,users[1]]));
  const visible = await asApplicationTenant(orgs.rows[0].id, client => client.query('SELECT organization_id,title FROM cases ORDER BY title'));
  assert.equal(visible.rows.length,1);
  assert.equal(visible.rows[0].title,'A only');
  await assert.rejects(() => asApplicationTenant(orgs.rows[0].id, client => client.query("INSERT INTO cases(organization_id,case_number,title,case_type,priority,created_by) VALUES($1,'CASE-9002','Forbidden','DFIR','High',$2)", [orgs.rows[1].id,users[0]])));
});
