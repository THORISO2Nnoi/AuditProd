import sqlite3
import subprocess
import os

def esc(val):
    if val is None:
        return "NULL"
    s = str(val).replace("'", "''")
    return f"N'{s}'"

def sync():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    audit_sqlite = os.path.join(base_dir, "db", "audit.db")
    business_sqlite = os.path.join(base_dir, "db", "business.db")
    auth_sqlite = os.path.join(base_dir, "db", "auth.db")
    sync_sql = os.path.join(base_dir, "sync.sql")

    c_audit = sqlite3.connect(audit_sqlite)
    c_audit.row_factory = sqlite3.Row
    c_biz = sqlite3.connect(business_sqlite)
    c_biz.row_factory = sqlite3.Row
    c_auth = sqlite3.connect(auth_sqlite)
    c_auth.row_factory = sqlite3.Row

    sql_statements = [
        "-- AuditPro Full SSMS Synchronization",
        "USE AuditPro_Audit;",
        "IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_sessions')",
        "BEGIN",
        "  CREATE TABLE user_sessions (",
        "    id INT IDENTITY(1,1) PRIMARY KEY,",
        "    jti NVARCHAR(100) NOT NULL,",
        "    user_id NVARCHAR(100) NULL,",
        "    username NVARCHAR(100) NOT NULL,",
        "    role NVARCHAR(50) NULL,",
        "    ip_address NVARCHAR(50) NULL,",
        "    user_agent NVARCHAR(MAX) NULL,",
        "    login_time DATETIME2 DEFAULT GETDATE(),",
        "    last_active DATETIME2 DEFAULT GETDATE(),",
        "    logout_time DATETIME2 NULL,",
        "    duration_seconds INT DEFAULT 0,",
        "    formatted_duration NVARCHAR(50) DEFAULT '0s',",
        "    status NVARCHAR(50) DEFAULT 'ACTIVE',",
        "    last_view NVARCHAR(200) DEFAULT 'Dashboard',",
        "    total_actions INT DEFAULT 0,",
        "    created_at DATETIME2 DEFAULT GETDATE()",
        "  );",
        "END",
        "GO",
        "USE AuditProDB;",
        "IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_sessions')",
        "BEGIN",
        "  CREATE TABLE user_sessions (",
        "    id INT IDENTITY(1,1) PRIMARY KEY,",
        "    jti NVARCHAR(100) NOT NULL,",
        "    user_id NVARCHAR(100) NULL,",
        "    username NVARCHAR(100) NOT NULL,",
        "    role NVARCHAR(50) NULL,",
        "    ip_address NVARCHAR(50) NULL,",
        "    user_agent NVARCHAR(MAX) NULL,",
        "    login_time DATETIME2 DEFAULT GETDATE(),",
        "    last_active DATETIME2 DEFAULT GETDATE(),",
        "    logout_time DATETIME2 NULL,",
        "    duration_seconds INT DEFAULT 0,",
        "    formatted_duration NVARCHAR(50) DEFAULT '0s',",
        "    status NVARCHAR(50) DEFAULT 'ACTIVE',",
        "    last_view NVARCHAR(200) DEFAULT 'Dashboard',",
        "    total_actions INT DEFAULT 0,",
        "    created_at DATETIME2 DEFAULT GETDATE()",
        "  );",
        "END",
        "GO"
    ]

    # 1. Audit Logs
    logs = c_audit.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
    sql_statements.append("USE AuditPro_Audit;")
    sql_statements.append("TRUNCATE TABLE audit_logs;")
    sql_statements.append("SET IDENTITY_INSERT audit_logs ON;")
    for r in logs:
        cols = [
            str(r['id']), esc(r['timestamp']), esc(r['event']), esc(r['user_id']),
            esc(r['username']), esc(r['role']), esc(r['ip_address']),
            esc(r['action']), esc(r['entity_id']), esc(r['status'])
        ]
        sql_statements.append(f"INSERT INTO audit_logs (id, timestamp, event, user_id, username, role, ip_address, action, entity_id, status) VALUES ({', '.join(cols)});")
    sql_statements.append("SET IDENTITY_INSERT audit_logs OFF;")
    sql_statements.append("GO")

    # 2. User Sessions (Logins, logouts, time spent, actions taken)
    sessions = c_audit.execute("SELECT * FROM user_sessions ORDER BY id ASC").fetchall()
    sql_statements.append("USE AuditPro_Audit;")
    sql_statements.append("TRUNCATE TABLE user_sessions;")
    sql_statements.append("SET IDENTITY_INSERT user_sessions ON;")
    for s in sessions:
        dur = s['duration_seconds'] or 0
        mins = dur // 60
        secs = dur % 60
        formatted = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
        logout_time_val = s['logout_time'] if 'logout_time' in s.keys() else None
        total_actions_val = s['total_actions'] if 'total_actions' in s.keys() else 0
        cols = [
            str(s['id']), esc(s['jti']), esc(s['user_id']), esc(s['username']),
            esc(s['role']), esc(s['ip_address']), esc(s['user_agent']),
            esc(s['login_time']), esc(s['last_active']), esc(logout_time_val),
            str(dur), esc(formatted), esc(s['status'] or 'ACTIVE'),
            esc(s['last_view'] or 'Dashboard'), str(total_actions_val or 0), esc(s['created_at'])
        ]
        sql_statements.append(f"INSERT INTO user_sessions (id, jti, user_id, username, role, ip_address, user_agent, login_time, last_active, logout_time, duration_seconds, formatted_duration, status, last_view, total_actions, created_at) VALUES ({', '.join(cols)});")
    sql_statements.append("SET IDENTITY_INSERT user_sessions OFF;")
    sql_statements.append("GO")

    # 3. Business Tasks
    tasks = c_biz.execute("SELECT * FROM tasks ORDER BY created_at ASC").fetchall()
    sql_statements.append("USE AuditPro_Business;")
    sql_statements.append("TRUNCATE TABLE tasks;")
    for t in tasks:
        sql_statements.append(f"INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at) VALUES ({esc(t['id'])}, {esc(t['title'])}, {esc(t['description'])}, {esc(t['priority'])}, {esc(t['status'])}, {esc(t['assigned_to'])}, {esc(t['created_by'])}, {esc(t['due_date'])}, {esc(t['created_at'])}, {esc(t['updated_at'])});")
    sql_statements.append("GO")

    # 4. Products Catalog
    products = c_biz.execute("SELECT * FROM products ORDER BY created_at ASC").fetchall()
    sql_statements.append("USE AuditPro_Business;")
    sql_statements.append("TRUNCATE TABLE products;")
    for p in products:
        sql_statements.append(f"INSERT INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at) VALUES ({esc(p['id'])}, {esc(p['name'])}, {esc(p['sku'])}, {esc(p['category'])}, {p['price']}, {p['stock']}, {esc(p['description'])}, {esc(p['created_by'])}, {esc(p['created_at'])}, {esc(p['updated_at'])});")
    sql_statements.append("GO")

    # 5. Users
    users = c_auth.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
    sql_statements.append("USE AuditPro_Auth;")
    sql_statements.append("TRUNCATE TABLE users;")
    for u in users:
        sql_statements.append(f"INSERT INTO users (id, username, password_hash, role, full_name, created_at, updated_at) VALUES ({esc(u['id'])}, {esc(u['username'])}, {esc(u['password_hash'])}, {esc(u['role'])}, {esc(u['full_name'])}, {esc(u['created_at'])}, {esc(u['updated_at'])});")
    sql_statements.append("GO")

    # 6. Mirror to unified AuditProDB
    sql_statements.append("USE AuditProDB;")
    sql_statements.append("TRUNCATE TABLE audit_logs;")
    sql_statements.append("SET IDENTITY_INSERT audit_logs ON;")
    for r in logs:
        cols = [
            str(r['id']), esc(r['timestamp']), esc(r['event']), esc(r['user_id']),
            esc(r['username']), esc(r['role']), esc(r['ip_address']),
            esc(r['action']), esc(r['entity_id']), esc(r['status'])
        ]
        sql_statements.append(f"INSERT INTO audit_logs (id, timestamp, event, user_id, username, role, ip_address, action, entity_id, status) VALUES ({', '.join(cols)});")
    sql_statements.append("SET IDENTITY_INSERT audit_logs OFF;")
    sql_statements.append("GO")

    sql_statements.append("USE AuditProDB;")
    sql_statements.append("TRUNCATE TABLE user_sessions;")
    sql_statements.append("SET IDENTITY_INSERT user_sessions ON;")
    for s in sessions:
        dur = s['duration_seconds'] or 0
        mins = dur // 60
        secs = dur % 60
        formatted = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
        logout_time_val = s['logout_time'] if 'logout_time' in s.keys() else None
        total_actions_val = s['total_actions'] if 'total_actions' in s.keys() else 0
        cols = [
            str(s['id']), esc(s['jti']), esc(s['user_id']), esc(s['username']),
            esc(s['role']), esc(s['ip_address']), esc(s['user_agent']),
            esc(s['login_time']), esc(s['last_active']), esc(logout_time_val),
            str(dur), esc(formatted), esc(s['status'] or 'ACTIVE'),
            esc(s['last_view'] or 'Dashboard'), str(total_actions_val or 0), esc(s['created_at'])
        ]
        sql_statements.append(f"INSERT INTO user_sessions (id, jti, user_id, username, role, ip_address, user_agent, login_time, last_active, logout_time, duration_seconds, formatted_duration, status, last_view, total_actions, created_at) VALUES ({', '.join(cols)});")
    sql_statements.append("SET IDENTITY_INSERT user_sessions OFF;")
    sql_statements.append("GO")

    sql_statements.append("USE AuditProDB;")
    sql_statements.append("TRUNCATE TABLE tasks;")
    for t in tasks:
        sql_statements.append(f"INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at) VALUES ({esc(t['id'])}, {esc(t['title'])}, {esc(t['description'])}, {esc(t['priority'])}, {esc(t['status'])}, {esc(t['assigned_to'])}, {esc(t['created_by'])}, {esc(t['due_date'])}, {esc(t['created_at'])}, {esc(t['updated_at'])});")
    sql_statements.append("GO")

    sql_statements.append("USE AuditProDB;")
    sql_statements.append("TRUNCATE TABLE products;")
    for p in products:
        sql_statements.append(f"INSERT INTO products (id, name, sku, category, price, stock, description, created_by, created_at, updated_at) VALUES ({esc(p['id'])}, {esc(p['name'])}, {esc(p['sku'])}, {esc(p['category'])}, {p['price']}, {p['stock']}, {esc(p['description'])}, {esc(p['created_by'])}, {esc(p['created_at'])}, {esc(p['updated_at'])});")
    sql_statements.append("GO")

    sql_statements.append("USE AuditProDB;")
    sql_statements.append("TRUNCATE TABLE users;")
    for u in users:
        sql_statements.append(f"INSERT INTO users (id, username, password_hash, role, full_name, created_at, updated_at) VALUES ({esc(u['id'])}, {esc(u['username'])}, {esc(u['password_hash'])}, {esc(u['role'])}, {esc(u['full_name'])}, {esc(u['created_at'])}, {esc(u['updated_at'])});")
    sql_statements.append("GO")

    full_sql = "\n".join(sql_statements)
    with open(sync_sql, "w", encoding="utf-8") as f:
        f.write(full_sql)

    print(f"Generated complete SSMS sync script: {len(logs)} logs, {len(sessions)} sessions, {len(tasks)} tasks, {len(products)} products, {len(users)} users.")
    res = subprocess.run(["sqlcmd", "-S", "localhost", "-i", sync_sql, "-E"], capture_output=True, text=True)
    if res.returncode == 0:
        print("SQLCMD Sync Success! All tables synchronized with SQL Server.")
    else:
        print("SQLCMD Error:", res.stderr or res.stdout)

if __name__ == "__main__":
    sync()
