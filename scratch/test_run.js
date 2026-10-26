const http = require('http');

function post(path, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const options = {
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, raw: body });
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function get(path, token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path,
      method: 'GET',
      headers: {
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, raw: body });
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

async function run() {
  console.log('--- 1. Login as Alice (user) ---');
  const aliceLogin = await post('/api/auth/login', { username: 'alice', password: 'User@123' });
  console.log('Alice Login Status:', aliceLogin.status, '| User:', aliceLogin.data.user.username);
  const aliceToken = aliceLogin.data.accessToken;
  const aliceJti = aliceLogin.data.jti;

  console.log('\n--- 2. Alice records view footprint ---');
  const viewRes = await post('/api/audit/view', {
    viewName: 'Inventory Catalog',
    entityId: 'products',
    durationInView: 25
  }, aliceToken);
  console.log('View recorded! Log ID:', viewRes.data.logId);

  console.log('\n--- 3. Alice creates a new task ---');
  const taskRes = await post('/api/tasks', {
    title: 'Review compliance backup checksums',
    description: 'Verify SHA256 hashes on cold storage dumps',
    priority: 'urgent',
    due_date: '2026-11-01'
  }, aliceToken);
  console.log('Task created! Status:', taskRes.status, '| Task Title:', taskRes.data.task ? taskRes.data.task.title : taskRes.data);

  console.log('\n--- 4. Alice logs out ---');
  const logoutRes = await post('/api/auth/logout', { jti: aliceJti }, aliceToken);
  console.log('Logout Status:', logoutRes.status, '| Message:', logoutRes.data.message);

  console.log('\n--- 5. Login as Admin & Fetch latest audit logs ---');
  const adminLogin = await post('/api/auth/login', { username: 'admin', password: 'Admin@123' });
  const adminToken = adminLogin.data.accessToken;

  const logsRes = await get('/api/audit/logs?limit=4', adminToken);
  console.log('Latest 4 Audit Logs from API:');
  for (const l of logsRes.data.logs) {
    console.log(`  [ID ${l.id}] ${l.timestamp} | ${l.event} | ${l.username} (${l.role}) | Action: "${l.action}" | Target: ${l.entity_id}`);
  }

  console.log('\n--- 6. Trigger sync to SSMS ---');
  const syncRes = await post('/api/audit/sync-ssms', {}, adminToken);
  console.log('Sync result:', syncRes.data);
}

run().catch(console.error);
