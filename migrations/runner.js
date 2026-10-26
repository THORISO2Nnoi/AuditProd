/**
 * ============================================================================
 * AuditPro Database Migration Engine (migrations/runner.js)
 * ============================================================================
 * 
 * Provides an enterprise-grade migration lifecycle manager for AuditPro's
 * 3-Database isolated architecture (auth.db, business.db, audit.db).
 * 
 * Capabilities:
 *   - Automated target database resolution via file header or naming conventions
 *   - Idempotent schema tracking via `_schema_migrations` table per database
 *   - SHA-256 checksum validation to detect unauthorized migration tampering
 *   - Transactional execution with automatic rollback on syntax or constraint errors
 *   - Forward migration (`up`), rollback (`down`), status reporting (`status`),
 *     and fresh database re-creation (`reset`).
 * 
 * Usage:
 *   node migrations/runner.js up        # Run all pending migrations
 *   node migrations/runner.js down      # Roll back the most recent migration batch
 *   node migrations/runner.js status    # Display status of all migrations
 *   node migrations/runner.js reset     # Roll back all migrations and re-apply fresh
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

// Directory paths
const BASE_DIR = path.join(__dirname, '..');
const DB_DIR = path.join(BASE_DIR, 'db');
const SQLITE_MIGRATIONS_DIR = path.join(__dirname, 'sqlite');

// Database connections cache
const databases = {
  auth: {
    name: 'auth.db',
    path: path.join(DB_DIR, 'auth.db'),
    instance: null
  },
  business: {
    name: 'business.db',
    path: path.join(DB_DIR, 'business.db'),
    instance: null
  },
  audit: {
    name: 'audit.db',
    path: path.join(DB_DIR, 'audit.db'),
    instance: null
  }
};

/**
 * Get or initialize a database connection with WAL mode enabled
 * @param {'auth' | 'business' | 'audit'} dbKey 
 * @returns {Database.Database}
 */
function getDb(dbKey) {
  if (!databases[dbKey]) {
    throw new Error(`[Migration Runner] Unknown database target: ${dbKey}`);
  }

  if (!databases[dbKey].instance) {
    if (!fs.existsSync(DB_DIR)) {
      fs.mkdirSync(DB_DIR, { recursive: true });
    }
    const db = new Database(databases[dbKey].path);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    // Ensure migration tracking table exists in each database
    db.exec(`
      CREATE TABLE IF NOT EXISTS _schema_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        migration_name TEXT NOT NULL UNIQUE,
        batch INTEGER NOT NULL,
        checksum TEXT NOT NULL,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    databases[dbKey].instance = db;
  }

  return databases[dbKey].instance;
}

/**
 * Close all active database connections
 */
function closeAllDbs() {
  for (const key of Object.keys(databases)) {
    if (databases[key].instance) {
      try {
        databases[key].instance.close();
      } catch (e) {
        // ignore
      }
      databases[key].instance = null;
    }
  }
}

/**
 * Detects which database a migration file belongs to based on header comments or filename
 * @param {string} filePath 
 * @param {string} content 
 * @returns {'auth' | 'business' | 'audit'}
 */
function resolveTargetDb(filePath, content) {
  const baseName = path.basename(filePath).toLowerCase();

  // Check header comments for target declaration
  const headerMatch = content.match(/--\s*Target Database:\s*([a-zA-Z0-9_\.]+)/i);
  if (headerMatch) {
    const rawTarget = headerMatch[1].toLowerCase().replace('.db', '').trim();
    if (databases[rawTarget]) return rawTarget;
  }

  // Fallback to filename pattern matching
  if (baseName.includes('auth')) return 'auth';
  if (baseName.includes('biz') || baseName.includes('business')) return 'business';
  if (baseName.includes('audit')) return 'audit';

  throw new Error(`[Migration Runner] Unable to determine target database for: ${baseName}`);
}

/**
 * Calculates SHA-256 hash of file content for integrity tracking
 * @param {string} content 
 * @returns {string}
 */
function computeChecksum(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Discovers and parses all forward (.sql) migrations
 * @returns {Array<{ filename: string, filePath: string, targetDb: string, checksum: string, downFile: string|null }>}
 */
function loadMigrations() {
  if (!fs.existsSync(SQLITE_MIGRATIONS_DIR)) {
    return [];
  }

  const files = fs.readdirSync(SQLITE_MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql') && !f.endsWith('.down.sql'))
    .sort();

  return files.map(filename => {
    const filePath = path.join(SQLITE_MIGRATIONS_DIR, filename);
    const content = fs.readFileSync(filePath, 'utf8');
    const targetDb = resolveTargetDb(filePath, content);
    const checksum = computeChecksum(content);

    const downFilename = filename.replace(/\.sql$/, '.down.sql');
    const downPath = path.join(SQLITE_MIGRATIONS_DIR, downFilename);
    const downFile = fs.existsSync(downPath) ? downPath : null;

    return {
      filename,
      filePath,
      content,
      targetDb,
      checksum,
      downFile
    };
  });
}

/**
 * Retrieve current max batch number across all databases
 * @returns {number}
 */
function getNextBatchNumber() {
  let maxBatch = 0;
  for (const key of Object.keys(databases)) {
    const db = getDb(key);
    const row = db.prepare('SELECT MAX(batch) as max_batch FROM _schema_migrations').get();
    if (row && row.max_batch && row.max_batch > maxBatch) {
      maxBatch = row.max_batch;
    }
  }
  return maxBatch + 1;
}

/**
 * Executes all pending migrations
 */
async function migrateUp() {
  console.log('================================================================');
  console.log('🚀 AUDITPRO MIGRATION ENGINE: APPLYING PENDING MIGRATIONS');
  console.log('================================================================\n');

  const migrations = loadMigrations();
  const nextBatch = getNextBatchNumber();
  let appliedCount = 0;

  for (const m of migrations) {
    const db = getDb(m.targetDb);
    const existing = db.prepare('SELECT * FROM _schema_migrations WHERE migration_name = ?').get(m.filename);

    if (existing) {
      // Check for checksum tampering
      if (existing.checksum !== m.checksum) {
        console.warn(`⚠️  WARNING: Checksum mismatch for already applied migration: ${m.filename}`);
        console.warn(`   Recorded: ${existing.checksum.substring(0, 16)}...`);
        console.warn(`   Current:  ${m.checksum.substring(0, 16)}...`);
      }
      continue;
    }

    console.log(`▶️ Applying [${m.targetDb}.db] -> ${m.filename}...`);

    // Execute within a transaction
    const runTransaction = db.transaction(() => {
      db.exec(m.content);
      db.prepare(`
        INSERT INTO _schema_migrations (migration_name, batch, checksum)
        VALUES (?, ?, ?)
      `).run(m.filename, nextBatch, m.checksum);
    });

    try {
      runTransaction();
      console.log(`   ✅ Success! (Batch ${nextBatch})`);
      appliedCount++;
    } catch (err) {
      console.error(`   ❌ Failed migrating ${m.filename}: ${err.message}`);
      throw err;
    }
  }

  if (appliedCount === 0) {
    console.log('✨ All databases are already up to date. No pending migrations.\n');
  } else {
    console.log(`\n🎉 Successfully applied ${appliedCount} migration(s) in Batch #${nextBatch}.\n`);
  }
}

/**
 * Rolls back the latest migration batch
 */
async function migrateDown() {
  console.log('================================================================');
  console.log('⏪ AUDITPRO MIGRATION ENGINE: ROLLING BACK LATEST BATCH');
  console.log('================================================================\n');

  // Find the highest batch across all databases
  let latestBatch = 0;
  for (const key of Object.keys(databases)) {
    const db = getDb(key);
    const row = db.prepare('SELECT MAX(batch) as max_batch FROM _schema_migrations').get();
    if (row && row.max_batch && row.max_batch > latestBatch) {
      latestBatch = row.max_batch;
    }
  }

  if (latestBatch === 0) {
    console.log('ℹ️  No migrations found to rollback.\n');
    return;
  }

  console.log(`🔍 Rolling back Batch #${latestBatch} across all databases...\n`);
  let rollbackCount = 0;

  // Process in reverse chronological order
  const allMigrations = loadMigrations().reverse();

  for (const m of allMigrations) {
    const db = getDb(m.targetDb);
    const record = db.prepare('SELECT * FROM _schema_migrations WHERE migration_name = ? AND batch = ?').get(m.filename, latestBatch);

    if (!record) continue;

    if (!m.downFile || !fs.existsSync(m.downFile)) {
      throw new Error(`[Migration Rollback Error] Missing down file for: ${m.filename}`);
    }

    const downSql = fs.readFileSync(m.downFile, 'utf8');
    console.log(`◀️ Rolling back [${m.targetDb}.db] -> ${path.basename(m.downFile)}...`);

    const rollbackTransaction = db.transaction(() => {
      db.exec(downSql);
      db.prepare('DELETE FROM _schema_migrations WHERE migration_name = ?').run(m.filename);
    });

    try {
      rollbackTransaction();
      console.log(`   ✅ Rolled back successfully!`);
      rollbackCount++;
    } catch (err) {
      console.error(`   ❌ Failed rolling back ${m.filename}: ${err.message}`);
      throw err;
    }
  }

  console.log(`\n🎉 Successfully rolled back ${rollbackCount} migration(s) from Batch #${latestBatch}.\n`);
}

/**
 * Prints the status of all migrations across all databases
 */
async function migrateStatus() {
  console.log('================================================================');
  console.log('📊 AUDITPRO DATABASE MIGRATION STATUS');
  console.log('================================================================\n');

  const migrations = loadMigrations();
  const statusTable = [];

  for (const m of migrations) {
    const db = getDb(m.targetDb);
    const record = db.prepare('SELECT * FROM _schema_migrations WHERE migration_name = ?').get(m.filename);

    statusTable.push({
      Migration: m.filename,
      Target: `${m.targetDb}.db`,
      Status: record ? 'APPLIED' : 'PENDING',
      Batch: record ? record.batch : '-',
      AppliedAt: record ? record.applied_at : '-'
    });
  }

  console.table(statusTable);
  console.log('');
}

/**
 * Resets the databases by rolling back all batches, then applying forward migrations
 */
async function migrateReset() {
  console.log('================================================================');
  console.log('🔄 AUDITPRO MIGRATION ENGINE: RESETTING ALL DATABASES');
  console.log('================================================================\n');

  while (true) {
    let hasApplied = false;
    for (const key of Object.keys(databases)) {
      const db = getDb(key);
      const count = db.prepare('SELECT COUNT(*) as c FROM _schema_migrations').get().c;
      if (count > 0) hasApplied = true;
    }

    if (!hasApplied) break;
    await migrateDown();
  }

  console.log('✨ All migrations rolled back. Re-running all forward migrations...\n');
  await migrateUp();
}

// ----------------------------------------------------------------------------
// CLI Entry Point
// ----------------------------------------------------------------------------
async function main() {
  const command = (process.argv[2] || 'up').toLowerCase();

  try {
    switch (command) {
      case 'up':
      case 'migrate':
        await migrateUp();
        break;
      case 'down':
      case 'rollback':
        await migrateDown();
        break;
      case 'status':
        await migrateStatus();
        break;
      case 'reset':
        await migrateReset();
        break;
      default:
        console.log(`Unknown command: ${command}`);
        console.log('Available commands: up, down, status, reset');
        process.exit(1);
    }
  } catch (err) {
    console.error('\n💥 Migration execution terminated with error:\n', err);
    process.exit(1);
  } finally {
    closeAllDbs();
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  migrateUp,
  migrateDown,
  migrateStatus,
  migrateReset,
  loadMigrations
};
