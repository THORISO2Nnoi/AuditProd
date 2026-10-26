const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'business.db');
const db = new Database(dbPath);

let triggerSyncDebounced;
try {
  const ssms = require('../utils/ssmsSync');
  triggerSyncDebounced = ssms.triggerSyncDebounced;
} catch (e) {
  triggerSyncDebounced = () => {};
}

db.pragma('journal_mode = WAL');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sku TEXT UNIQUE NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL,
    description TEXT,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    priority TEXT NOT NULL CHECK(priority IN ('low', 'medium', 'high', 'urgent')),
    status TEXT NOT NULL CHECK(status IN ('pending', 'in_progress', 'completed', 'archived')),
    assigned_to TEXT NOT NULL,
    created_by TEXT NOT NULL,
    due_date TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to);
  CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);
`);

function seedBusinessData() {
  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
  if (productCount === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (id, name, sku, category, price, stock, description, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertProduct.run(crypto.randomUUID(), 'Enterprise Firewall Appliance X9', 'NET-FW-01', 'Security Hardware', 2499.00, 12, 'Layer-7 stateful inspection firewall with IPSec VPN hardware acceleration', 'admin');
    insertProduct.run(crypto.randomUUID(), 'HSM Cryptographic Key Accelerator', 'CRYPTO-HSM-9', 'Security Hardware', 899.50, 45, 'FIPS 140-2 Level 3 certified hardware security module for RSA/ECC key storage', 'admin');
    insertProduct.run(crypto.randomUUID(), 'Audit Vault Immutable Storage Array', 'STRG-VLT-04', 'Infrastructure', 4200.00, 8, 'WORM compliant high-density NVMe storage array for audit logs retention', 'admin');
    insertProduct.run(crypto.randomUUID(), 'Zero-Trust Secure Access License (100 Seat)', 'LIC-ZTG-100', 'Software Licenses', 350.00, 250, 'Continuous identity verification client licence with telemetry auditing', 'admin');
    insertProduct.run(crypto.randomUUID(), 'Managed Bastion Host Gateway', 'CLOUD-BST-22', 'Cloud Infrastructure', 680.00, 20, 'Audited SSH/RDP jump server with keystroke session recording', 'admin');

    console.log('[Business DB] Seeded initial products catalog.');
  }

  const taskCount = db.prepare('SELECT COUNT(*) as count FROM tasks').get().count;
  if (taskCount === 0) {
    const insertTask = db.prepare(`
      INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertTask.run(
      crypto.randomUUID(),
      'Review Q3 PCI-DSS compliance requirements',
      'Audit requirement 10.2: verify automated audit trails are enabled and reviewed for all system components.',
      'high',
      'in_progress',
      'alice',
      'admin',
      '2026-11-15'
    );

    insertTask.run(
      crypto.randomUUID(),
      'Conduct quarterly cryptographic key rotation',
      'Rotate HSM master encryption keys and record JTI authorization trace in audit vault.',
      'urgent',
      'pending',
      'alice',
      'admin',
      '2026-10-30'
    );

    insertTask.run(
      crypto.randomUUID(),
      'Update customer disaster recovery runbooks',
      'Document DB backup restoration procedure from cold storage and test hash validation.',
      'medium',
      'completed',
      'bob',
      'admin',
      '2026-10-20'
    );

    insertTask.run(
      crypto.randomUUID(),
      'Inspect SIEM forwarding rules for audit.db',
      'Ensure syslog daemon mirrors all SQL trigger alerts to central security operations center.',
      'high',
      'completed',
      'admin',
      'admin',
      '2026-10-22'
    );

    console.log('[Business DB] Seeded initial business tasks.');
  }
}

seedBusinessData();

// Products API Helpers
const getProducts = () => {
  return db.prepare('SELECT * FROM products ORDER BY created_at DESC').all();
};

const getProductById = (id) => {
  return db.prepare('SELECT * FROM products WHERE id = ?').get(id);
};

const createProduct = ({ name, sku, category, price, stock, description, created_by }) => {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, sku, category, Number(price), Number(stock), description || '', created_by, now, now);

  if (triggerSyncDebounced) triggerSyncDebounced();
  return getProductById(id);
};

const updateProduct = (id, data) => {
  const current = getProductById(id);
  if (!current) return null;

  const now = new Date().toISOString();
  const updated = {
    name: data.name !== undefined ? data.name : current.name,
    sku: data.sku !== undefined ? data.sku : current.sku,
    category: data.category !== undefined ? data.category : current.category,
    price: data.price !== undefined ? Number(data.price) : current.price,
    stock: data.stock !== undefined ? Number(data.stock) : current.stock,
    description: data.description !== undefined ? data.description : current.description,
    updated_at: now
  };

  db.prepare(`
    UPDATE products 
    SET name = ?, sku = ?, category = ?, price = ?, stock = ?, description = ?, updated_at = ?
    WHERE id = ?
  `).run(updated.name, updated.sku, updated.category, updated.price, updated.stock, updated.description, updated.updated_at, id);

  if (triggerSyncDebounced) triggerSyncDebounced();
  return getProductById(id);
};

const deleteProduct = (id) => {
  const current = getProductById(id);
  if (!current) return null;

  db.prepare('DELETE FROM products WHERE id = ?').run(id);
  if (triggerSyncDebounced) triggerSyncDebounced();
  return current;
};

// Tasks API Helpers
const getTasks = (filter = {}) => {
  if (filter.username) {
    return db.prepare(`
      SELECT * FROM tasks 
      WHERE assigned_to = ? OR created_by = ? 
      ORDER BY 
        CASE priority 
          WHEN 'urgent' THEN 1 
          WHEN 'high' THEN 2 
          WHEN 'medium' THEN 3 
          WHEN 'low' THEN 4 
          ELSE 5 
        END,
        created_at DESC
    `).all(filter.username, filter.username);
  }

  return db.prepare(`
    SELECT * FROM tasks 
    ORDER BY 
      CASE priority 
        WHEN 'urgent' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        WHEN 'low' THEN 4 
        ELSE 5 
      END,
      created_at DESC
  `).all();
};

const getTaskById = (id) => {
  return db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
};

const createTask = ({ title, description, priority, status, assigned_to, created_by, due_date }) => {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    title,
    description || '',
    priority || 'medium',
    status || 'pending',
    assigned_to || created_by,
    created_by,
    due_date || null,
    now,
    now
  );

  if (triggerSyncDebounced) triggerSyncDebounced();
  return getTaskById(id);
};

const updateTask = (id, data) => {
  const current = getTaskById(id);
  if (!current) return null;

  const now = new Date().toISOString();
  const updated = {
    title: data.title !== undefined ? data.title : current.title,
    description: data.description !== undefined ? data.description : current.description,
    priority: data.priority !== undefined ? data.priority : current.priority,
    status: data.status !== undefined ? data.status : current.status,
    assigned_to: data.assigned_to !== undefined ? data.assigned_to : current.assigned_to,
    due_date: data.due_date !== undefined ? data.due_date : current.due_date,
    updated_at: now
  };

  db.prepare(`
    UPDATE tasks
    SET title = ?, description = ?, priority = ?, status = ?, assigned_to = ?, due_date = ?, updated_at = ?
    WHERE id = ?
  `).run(
    updated.title,
    updated.description,
    updated.priority,
    updated.status,
    updated.assigned_to,
    updated.due_date,
    updated.updated_at,
    id
  );

  if (triggerSyncDebounced) triggerSyncDebounced();
  return getTaskById(id);
};

const deleteTask = (id) => {
  const current = getTaskById(id);
  if (!current) return null;

  db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
  if (triggerSyncDebounced) triggerSyncDebounced();
  return current;
};

module.exports = {
  db,
  getProducts,
  getProductById,
  createProduct,
  updateProduct,
  deleteProduct,
  getTasks,
  getTaskById,
  createTask,
  updateTask,
  deleteTask
};
