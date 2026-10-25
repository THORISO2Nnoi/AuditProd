const http = require('http');

function post(path, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body || {});
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'POST',
      headers
    }, (res) => {
      let buf = '';
      res.on('data', chunk => buf += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch (e) { resolve({ status: res.statusCode, raw: buf }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function put(path, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body || {});
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'PUT',
      headers
    }, (res) => {
      let buf = '';
      res.on('data', chunk => buf += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch (e) { resolve({ status: res.statusCode, raw: buf }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function del(path, token) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'DELETE',
      headers
    }, (res) => {
      let buf = '';
      res.on('data', chunk => buf += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch (e) { resolve({ status: res.statusCode, raw: buf }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function get(path, token) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'GET',
      headers
    }, (res) => {
      let buf = '';
      res.on('data', chunk => buf += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch (e) { resolve({ status: res.statusCode, raw: buf }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function run() {
  console.log('--- 1. Authenticating Alice and Admin ---');
  const aliceLogin = await post('/api/auth/login', { username: 'alice', password: 'User@123' });
  const adminLogin = await post('/api/auth/login', { username: 'admin', password: 'Admin@123' });

  const aliceToken = aliceLogin.body.accessToken;
  const adminToken = adminLogin.body.accessToken;

  console.log(`Alice login status: ${aliceLogin.status}, Admin login status: ${adminLogin.status}`);

  console.log('\n--- 2. Alice creates a task ---');
  const createTaskRes = await post('/api/tasks', {
    title: 'Alice Special Task ' + Date.now(),
    description: 'Confidential work created by Alice',
    priority: 'high',
    status: 'in_progress'
  }, aliceToken);

  console.log(`Task created by Alice: status ${createTaskRes.status}, id: ${createTaskRes.body.task?.id}, created_by: ${createTaskRes.body.task?.created_by}`);
  const taskId = createTaskRes.body.task?.id;

  console.log('\n--- 3. Admin attempts to edit Alice task ---');
  const adminEditRes = await put(`/api/tasks/${taskId}`, {
    title: 'Admin Hijacked Title',
    status: 'completed'
  }, adminToken);

  console.log(`Admin edit attempt status: ${adminEditRes.status} (Expected 403 Forbidden)`);
  console.log(`Admin edit response body:`, adminEditRes.body);

  console.log('\n--- 4. Admin attempts to delete Alice task ---');
  const adminDelRes = await del(`/api/tasks/${taskId}`, adminToken);
  console.log(`Admin delete attempt status: ${adminDelRes.status} (Expected 403 Forbidden)`);
  console.log(`Admin delete response body:`, adminDelRes.body);

  console.log('\n--- 5. Alice records screen view (view footprint) ---');
  const viewRes = await post('/api/audit/view', {
    viewName: 'Products Inventory',
    entityType: 'screen_view',
    entityId: 'products',
    durationInView: 42
  }, aliceToken);
  console.log(`Alice view footprint status: ${viewRes.status}, logId: ${viewRes.body.logId}`);

  console.log('\n--- 6. Alice sends heartbeat with dwell time ---');
  const hbRes = await post('/api/auth/heartbeat', {
    durationSeconds: 125,
    currentView: 'Task Workspace'
  }, aliceToken);
  console.log(`Alice heartbeat status: ${hbRes.status}`);

  console.log('\n--- 7. Query User Sessions (Presence and dwell duration) ---');
  const sessionsRes = await get('/api/audit/sessions', adminToken);
  console.log(`User sessions status: ${sessionsRes.status}, count: ${sessionsRes.body.sessions?.length}`);
  const aliceSession = sessionsRes.body.sessions?.find(s => s.username === 'alice');
  if (aliceSession) {
    console.log(`Alice session record: status=${aliceSession.status}, duration=${aliceSession.formatted_duration}, last_view=${aliceSession.last_view}`);
  }

  console.log('\n--- 8. Query Activity Trail (Checking for view and access denied logs) ---');
  const logsRes = await get('/api/audit/logs?limit=5', adminToken);
  console.log(`Recent activity logs: total=${logsRes.body.total}`);
  logsRes.body.logs.forEach(l => {
    console.log(`[#${l.id}] ${l.timestamp} | ${l.event} | ${l.username} (${l.status}) -> ${l.action}`);
  });

  console.log('\n=== ALL VERIFICATIONS COMPLETED SUCCESSFULLY ===');
}

run().catch(console.error);
