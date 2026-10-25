import sqlite3
import subprocess

def esc(val):
    if val is None:
        return "NULL"
    s = str(val).replace("'", "''")
    return f"N'{s}'"

def sync():
    audit_sqlite = r"C:\Users\lenah\Desktop\WORK\AuditProd\db\audit.db"
    business_sqlite = r"C:\Users\lenah\Desktop\WORK\AuditProd\db\business.db"

    c_audit = sqlite3.connect(audit_sqlite)
    c_audit.row_factory = sqlite3.Row
    c_biz = sqlite3.connect(business_sqlite)
    c_biz.row_factory = sqlite3.Row

    sql_statements = [
        "USE AuditPro_Audit;",
        "TRUNCATE TABLE audit_logs;",
        "SET IDENTITY_INSERT audit_logs ON;"
    ]

    logs = c_audit.execute("SELECT * FROM audit_logs").fetchall()
    for row in logs:
        cols = [
            str(row['id']),
            esc(row['timestamp']),
            esc(row['event']),
            esc(row['user_id']),
            esc(row['username']),
            esc(row['role']),
            esc(row['ip_address']),
            esc(row['user_agent']),
            esc(row['action']),
            esc(row['entity_type']),
            esc(row['entity_id']),
            esc(row['before_snapshot']),
            esc(row['after_snapshot']),
            esc(row['diff']),
            esc(row['jti']),
            esc(row['status']),
            esc(row['metadata'])
        ]
        sql_statements.append(f"INSERT INTO audit_logs (id, timestamp, event, user_id, username, role, ip_address, user_agent, action, entity_type, entity_id, before_snapshot, after_snapshot, diff, jti, status, metadata) VALUES ({', '.join(cols)});")

    sql_statements.append("SET IDENTITY_INSERT audit_logs OFF;")
    sql_statements.append("GO")

    # Business Tasks
    sql_statements.append("USE AuditPro_Business;")
    sql_statements.append("TRUNCATE TABLE tasks;")
    tasks = c_biz.execute("SELECT * FROM tasks").fetchall()
    for t in tasks:
        sql_statements.append(f"INSERT INTO tasks (id, title, description, priority, status, assigned_to, created_by, due_date, created_at, updated_at) VALUES ({esc(t['id'])}, {esc(t['title'])}, {esc(t['description'])}, {esc(t['priority'])}, {esc(t['status'])}, {esc(t['assigned_to'])}, {esc(t['created_by'])}, {esc(t['due_date'])}, {esc(t['created_at'])}, {esc(t['updated_at'])});")

    sql_statements.append("GO")

    full_sql = "\n".join(sql_statements)
    with open(r"C:\Users\lenah\Desktop\WORK\AuditProd\sync.sql", "w", encoding="utf-8") as f:
        f.write(full_sql)

    print(f"Generated sync script with {len(logs)} audit logs and {len(tasks)} tasks.")
    res = subprocess.run(["sqlcmd", "-S", "localhost", "-i", r"C:\Users\lenah\Desktop\WORK\AuditProd\sync.sql", "-E"], capture_output=True, text=True)
    print("SQLCMD result:", res.stdout or res.stderr)

if __name__ == "__main__":
    sync()
