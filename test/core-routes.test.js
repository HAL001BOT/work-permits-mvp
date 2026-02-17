const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const request = require('supertest');
const bcrypt = require('bcryptjs');

function buildRequiredFields() {
  return {
    permit_date: '2026-02-20',
    pf__start_time: '08:00',
    pf__start_date: '2026-02-12',
    pf__building_location: 'Manufacturing building',
    pf__contractor_company_enabled: '1',
    pf__contractor_company: 'Acme',
    pf__shift: 'A',
    pf__equipment: 'Pump 1',
    pf__contractor_lead: 'Lead A',
    pf__shift_supervisor: 'supervisor1',
    pf__work_order_number: 'WO-1',
    pf__project_number_needed: '1',
    pf__project_number: 'PR-1',
    pf__confirm_no_other_permits: '1',
    pf__scope_of_work: 'Routine maintenance',
    pf__personnel_trained_protocols: 'Yes',
    pf__personnel_briefed_hazards: 'Yes',
    pf__needs_shutdown: 'No',
    pf__chemicals_cleared: 'Yes',
    pf__team_member_signoffs: JSON.stringify([{ name: 'Admin User', date: '2026-02-12' }]),
    pf__team_leader_sign: 'Leader',
    pf__closeout_completed: '1',
    pf__closeout_not_completed: '1',
    pf__closeout_comments: 'Done',
    pf__area_owner_sign: 'supervisor1',
    pf__area_owner_sign_date: '2026-02-12',
    pf__haz_low_visibility: '1',
  };
}

function freshApp() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'permits-test-'));
  process.env.NODE_ENV = 'test';
  process.env.DB_PATH = path.join(tmpDir, 'app.db');
  delete require.cache[require.resolve('../db')];
  delete require.cache[require.resolve('../server')];
  const { app, db } = require('../server');

  const adminHash = bcrypt.hashSync('Admin!Pass123', 10);
  db.prepare(`INSERT INTO users (username, password_hash, role, full_name, position) VALUES (?, ?, 'admin', 'Admin User', 'Manager')`).run('admin', adminHash);
  const staffSeeds = [
    { username: 'supervisor1', role: 'supervisor', group_name: 'supervisors' },
    { username: 'supervisor2', role: 'supervisor', group_name: 'supervisors' },
    { username: 'supervisor3', role: 'supervisor', group_name: 'supervisors' },
  ];
  const staffHash = bcrypt.hashSync('permit123!', 10);
  for (const staff of staffSeeds) {
    db.prepare(`INSERT OR IGNORE INTO users (username, password_hash, role, group_name) VALUES (?, ?, ?, ?)`)
      .run(staff.username, staffHash, staff.role, staff.group_name);
  }

  return { app, db, cleanup: () => fs.rmSync(tmpDir, { recursive: true, force: true }) };
}

async function login(agent) {
  const res = await agent.post('/login').type('form').send({ username: 'admin', password: 'Admin!Pass123' });
  assert.equal(res.status, 302);
}

test('auth + create permit + workflow transition', async () => {
  const { app, db, cleanup } = freshApp();
  const agent = request.agent(app);

  try {
    const redirect = await agent.get('/permits');
    assert.equal(redirect.status, 302);

    await login(agent);

    const created = await agent.post('/permits').type('form').send(buildRequiredFields());
    assert.equal(created.status, 302);
    const permitId = Number(created.headers.location.split('/').pop());
    assert.ok(permitId > 0);

    const permit = db.prepare('SELECT status, permit_number FROM permits WHERE id = ?').get(permitId);
    assert.equal(permit.status, 'draft');
    assert.match(permit.permit_number, /^GSWP-\d{5}$/);

    const submit = await agent.post(`/permits/${permitId}/transition`).type('form').send({ action: 'submit' });
    assert.equal(submit.status, 302);

    const approve = await agent.post(`/permits/${permitId}/transition`).type('form').send({ action: 'approve', signature_text: 'Admin User' });
    assert.equal(approve.status, 302);

    const approved = db.prepare('SELECT status, is_locked, approver_name FROM permits WHERE id = ?').get(permitId);
    assert.equal(approved.status, 'approved');
    assert.equal(approved.is_locked, 1);
    assert.ok(approved.approver_name.includes('Admin User'));
  } finally {
    cleanup();
  }
});

test('enforces unique active permit_number and lockout after repeated failed logins', async () => {
  const { app, db, cleanup } = freshApp();
  const agent = request.agent(app);

  try {
    await login(agent);
    const one = await agent.post('/permits').type('form').send(buildRequiredFields());
    const two = await agent.post('/permits').type('form').send(buildRequiredFields());
    assert.equal(one.status, 302);
    assert.equal(two.status, 302);

    const nums = db.prepare(`SELECT permit_number FROM permits WHERE deleted_at IS NULL ORDER BY id ASC`).all().map((r) => r.permit_number);
    assert.equal(new Set(nums).size, nums.length);

    const failedAgent = request.agent(app);
    for (let i = 0; i < 5; i += 1) {
      const fail = await failedAgent.post('/login').type('form').send({ username: 'admin', password: 'wrong-password' });
      assert.equal(fail.status, 401);
    }
    const blocked = await failedAgent.post('/login').type('form').send({ username: 'admin', password: 'wrong-password' });
    assert.equal(blocked.status, 429);
  } finally {
    cleanup();
  }
});
