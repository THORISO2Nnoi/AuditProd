require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

// Database connections (initializes schemas and triggers)
const authDb = require('./db/auth');
const businessDb = require('./db/business');
const auditDb = require('./db/audit');

// Route handlers
const authRoutes = require('./routes/auth.routes');
const usersRoutes = require('./routes/users.routes');
const productsRoutes = require('./routes/products.routes');
const tasksRoutes = require('./routes/tasks.routes');
const auditRoutes = require('./routes/audit.routes');
const reportsRoutes = require('./routes/reports.routes');

const app = express();
const PORT = process.env.PORT || 3000;

// Core Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static assets
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint verifying 3-database readiness
app.get('/api/health', (req, res) => {
  try {
    const authOk = authDb.db.prepare('SELECT 1').get() !== undefined;
    const businessOk = businessDb.db.prepare('SELECT 1').get() !== undefined;
    const auditOk = auditDb.db.prepare('SELECT 1').get() !== undefined;

    return res.json({
      status: 'UP',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      architecture: {
        pattern: '3-Database Compliant Isolation',
        databases: {
          auth_db: { file: 'db/auth.db', status: authOk ? 'HEALTHY' : 'DOWN', purpose: 'Identity & Tokens' },
          business_db: { file: 'db/business.db', status: businessOk ? 'HEALTHY' : 'DOWN', purpose: 'Products & Tasks' },
          audit_db: { file: 'db/audit.db', status: auditOk ? 'HEALTHY (TRIGGERS_ACTIVE)' : 'DOWN', purpose: 'Immutable Forensics' }
        }
      }
    });
  } catch (err) {
    return res.status(500).json({ status: 'DEGRADED', error: err.message });
  }
});

// Mount API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/products', productsRoutes);
app.use('/api/tasks', tasksRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/reports', reportsRoutes);

// SPA fallback handler
app.use((req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Endpoint not found', path: req.path });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error('[AuditPro Server Error]', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    code: err.code || 'SERVER_ERROR'
  });
});

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  AUDITPRO SECURE COMPLIANCE ENGINE RUNNING`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`🗄️  Auth DB:     db/auth.db (users, refresh_tokens)`);
  console.log(`🗄️  Business DB: db/business.db (products, tasks)`);
  console.log(`🗄️  Audit DB:    db/audit.db (immutable triggers active)`);
  console.log(`🗄️  SSMS Sync:   AuditPro_Audit / AuditProDB (Live Replication)`);
  console.log(`👥 Demo Logins:`);
  console.log(`   Admin:   admin / Admin@123   (Control Center)`);
  console.log(`   Auditor: auditor / Audit@123 (Compliance Center)`);
  console.log(`   User:    alice / User@123    (My Workspace)`);
  console.log(`=======================================================`);

  // Sync databases to SSMS immediately on startup
  try {
    const { syncToSsms } = require('./utils/ssmsSync');
    syncToSsms();
  } catch (e) {
    console.warn('[Startup Sync Notice]', e.message);
  }
});
