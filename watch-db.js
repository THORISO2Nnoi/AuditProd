const Database = require('better-sqlite3');
const path = require('path');

const auditDbPath = path.join(__dirname, 'db', 'audit.db');
const businessDbPath = path.join(__dirname, 'db', 'business.db');

const auditDb = new Database(auditDbPath, { readonly: true });
const businessDb = new Database(businessDbPath, { readonly: true });

console.log('===============================================================');
console.log('👀 AUDITPRO LIVE DATABASE MONITOR');
console.log('===============================================================');
console.log(`📁 Audit DB:    ${auditDbPath}`);
console.log(`📁 Business DB: ${businessDbPath}`);
console.log('');
console.log('👉 Open your browser at http://localhost:3000');
console.log('👉 Watch this console to see database changes in real-time!');
console.log('===============================================================\n');

let lastLogId = auditDb.prepare('SELECT MAX(id) as maxId FROM audit_logs').get().maxId || 0;
let lastProductCount = businessDb.prepare('SELECT COUNT(*) as c FROM products').get().c || 0;
let lastTaskCount = businessDb.prepare('SELECT COUNT(*) as c FROM tasks').get().c || 0;

console.log(`📊 Baseline State:`);
console.log(`   - Audit Logs: ${lastLogId} records`);
console.log(`   - Business Products: ${lastProductCount} items`);
console.log(`   - Business Tasks: ${lastTaskCount} tasks\n`);
console.log('⏳ Waiting for events... (Passive clicks like switching tabs will NOT log anything)');

setInterval(() => {
  try {
    // Check for new audit logs
    const newLogs = auditDb.prepare('SELECT id, timestamp, event, username, role, action, status FROM audit_logs WHERE id > ? ORDER BY id ASC').all(lastLogId);
    
    if (newLogs.length > 0) {
      newLogs.forEach(log => {
        lastLogId = log.id;
        console.log(`\n🔔 [AUDIT LOG INSERTED] -> audit.db (Row #${log.id})`);
        console.log(`   ⏱️  Timestamp : ${log.timestamp}`);
        console.log(`   🎯 Event     : ${log.event}`);
        console.log(`   👤 User      : ${log.username} (${log.role})`);
        console.log(`   📝 Action    : ${log.action}`);
        console.log(`   🔒 Status    : ${log.status}`);
      });
    }

    // Check for business database changes
    const currentProductCount = businessDb.prepare('SELECT COUNT(*) as c FROM products').get().c;
    if (currentProductCount !== lastProductCount) {
      console.log(`\n📦 [BUSINESS DB CHANGED] -> products table count: ${lastProductCount} -> ${currentProductCount}`);
      lastProductCount = currentProductCount;
    }

    const currentTaskCount = businessDb.prepare('SELECT COUNT(*) as c FROM tasks').get().c;
    if (currentTaskCount !== lastTaskCount) {
      console.log(`\n📋 [BUSINESS DB CHANGED] -> tasks table count: ${lastTaskCount} -> ${currentTaskCount}`);
      lastTaskCount = currentTaskCount;
    }
  } catch (err) {
    // ignore busy/read lock hiccups
  }
}, 500);
