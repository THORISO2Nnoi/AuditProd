const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'auth.db');
const db = new Database(dbPath);

// Enable WAL mode for high concurrency and resilience
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'auditor', 'user')),
    full_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0,
    replaced_by_token TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);
`);

// Seed default users if table is empty
function seedUsers() {
  const count = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (count === 0) {
    const saltRounds = 10;
    const adminHash = bcrypt.hashSync('Admin@123', saltRounds);
    const auditorHash = bcrypt.hashSync('Audit@123', saltRounds);
    const aliceHash = bcrypt.hashSync('User@123', saltRounds);
    const bobHash = bcrypt.hashSync('User@123', saltRounds);

    const insert = db.prepare(`
      INSERT INTO users (id, username, password_hash, role, full_name)
      VALUES (?, ?, ?, ?, ?)
    `);

    insert.run(crypto.randomUUID(), 'admin', adminHash, 'admin', 'System Administrator');
    insert.run(crypto.randomUUID(), 'auditor', auditorHash, 'auditor', 'Lead Compliance Officer');
    insert.run(crypto.randomUUID(), 'alice', aliceHash, 'user', 'Alice Johnson (Developer)');
    insert.run(crypto.randomUUID(), 'bob', bobHash, 'user', 'Bob Smith (Support)');

    console.log('[Auth DB] Seeded 4 default users (admin, auditor, alice, bob).');
  }
}

seedUsers();

// Query Helpers
const getUserByUsername = (username) => {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
};

const getUserById = (id) => {
  return db.prepare('SELECT id, username, role, full_name, created_at, updated_at FROM users WHERE id = ?').get(id);
};

const getAllUsers = () => {
  return db.prepare('SELECT id, username, role, full_name, created_at, updated_at FROM users ORDER BY created_at ASC').all();
};

const createUser = ({ username, password, role, full_name }) => {
  const id = crypto.randomUUID();
  const password_hash = bcrypt.hashSync(password, 10);
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO users (id, username, password_hash, role, full_name, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, username, password_hash, role, full_name, now, now);

  return getUserById(id);
};

const updateUser = (id, { role, full_name, password }) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return null;

  const now = new Date().toISOString();
  let query = 'UPDATE users SET full_name = ?, role = ?, updated_at = ?';
  const params = [full_name || user.full_name, role || user.role, now];

  if (password && password.trim().length > 0) {
    query += ', password_hash = ?';
    params.push(bcrypt.hashSync(password, 10));
  }

  query += ' WHERE id = ?';
  params.push(id);

  db.prepare(query).run(...params);
  return getUserById(id);
};

const deleteUser = (id) => {
  const user = getUserById(id);
  if (!user) return null;

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  return user;
};

// Refresh token helpers
const storeRefreshToken = ({ id, userId, tokenHash, jti, expiresAt }) => {
  db.prepare(`
    INSERT INTO refresh_tokens (id, user_id, token_hash, jti, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, userId, tokenHash, jti, expiresAt);
};

const findRefreshToken = (tokenHash) => {
  return db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash);
};

const revokeRefreshToken = (tokenHash, replacedByToken = null) => {
  db.prepare(`
    UPDATE refresh_tokens 
    SET revoked = 1, replaced_by_token = ? 
    WHERE token_hash = ?
  `).run(replacedByToken, tokenHash);
};

const revokeAllUserTokens = (userId) => {
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(userId);
};

module.exports = {
  db,
  getUserByUsername,
  getUserById,
  getAllUsers,
  createUser,
  updateUser,
  deleteUser,
  storeRefreshToken,
  findRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens
};
