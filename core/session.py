# core/session.py
# BlackHunter Pro - Session Manager
# Handles scan sessions, state management, and data persistence

import os
import sys
import json
import uuid
import time
from datetime import datetime

# Import utils
try:
    from .utils import (
        Colors as C,
        ensure_dir, timestamp, timestamp_readable,
        random_token, format_time,
        log_info, log_ok, log_warn, log_error,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from utils import (
        Colors as C,
        ensure_dir, timestamp, timestamp_readable,
        random_token, format_time,
        log_info, log_ok, log_warn, log_error,
    )


# =============================================
# SESSION CLASS
# =============================================

class Session:
    """
    Represents a single scan session
    - Stores target, module, state
    - Aggregates results
    - Saves/loads state
    """

    def __init__(self, target, module="full", session_id=None):
        """Initialize session"""
        self.id = session_id or self._generate_id()
        self.target = target.rstrip('/')
        self.module = module

        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.finished_at = None

        self.state = "active"  # active, paused, completed, failed
        self.progress = 0
        self.total_phases = self._get_total_phases(module)
        self.current_phase = 0

        self.results = {
            'recon': {},
            'port': {},
            'web': {},
            'cms': {},
            'subdomain': {},
            'vulnerabilities': [],
            'exploits': [],
            'shells': [],
        }

        self.errors = []
        self.start_time = time.time()
        self.end_time = None

    def _generate_id(self):
        """Generate unique session ID"""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        token = random_token(6)
        return f"{ts}_{token}"

    def _get_total_phases(self, module):
        """Get total phases for module"""
        if module == "full":
            return 10
        elif module in ["recon", "port", "web", "cms", "subdomain"]:
            return 1
        else:
            return 1

    # =============================================
    # STATE MANAGEMENT
    # =============================================

    def update(self):
        """Update session timestamp"""
        self.updated_at = datetime.now().isoformat()

    def advance_phase(self, phase_name=""):
        """Advance to next phase"""
        self.current_phase += 1
        self.progress = (self.current_phase / self.total_phases) * 100
        self.update()

    def set_state(self, state):
        """Set session state"""
        self.state = state
        self.update()

    def complete(self):
        """Mark session as completed"""
        self.state = "completed"
        self.finished_at = datetime.now().isoformat()
        self.end_time = time.time()
        self.update()

    def fail(self, reason=""):
        """Mark session as failed"""
        self.state = "failed"
        self.finished_at = datetime.now().isoformat()
        self.end_time = time.time()
        if reason:
            self.errors.append(reason)
        self.update()

    def pause(self):
        """Pause session"""
        self.state = "paused"
        self.update()

    def resume(self):
        """Resume session"""
        self.state = "active"
        self.update()

    # =============================================
    # RESULTS MANAGEMENT
    # =============================================

    def add_recon(self, data):
        """Add reconnaissance data"""
        self.results['recon'] = data
        self.update()

    def add_port(self, data):
        """Add port scan data"""
        self.results['port'] = data
        self.update()

    def add_web(self, data):
        """Add web scan data"""
        self.results['web'] = data
        self.update()

    def add_cms(self, data):
        """Add CMS detection data"""
        self.results['cms'] = data
        self.update()

    def add_vulnerability(self, vuln):
        """Add a vulnerability"""
        self.results['vulnerabilities'].append(vuln)
        self.update()

    def add_vulnerabilities(self, vulns):
        """Add multiple vulnerabilities"""
        self.results['vulnerabilities'].extend(vulns)
        self.update()

    def add_exploit(self, exploit):
        """Add an exploit result"""
        self.results['exploits'].append(exploit)
        self.update()

    def add_shell(self, shell):
        """Add a shell"""
        self.results['shells'].append(shell)
        self.update()

    def add_error(self, error):
        """Add an error"""
        self.errors.append(error)
        self.update()

    # =============================================
    # STATISTICS
    # =============================================

    def get_duration(self):
        """Get session duration in seconds"""
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time

    def get_duration_str(self):
        """Get duration as string"""
        return format_time(self.get_duration())

    def get_vuln_count(self):
        """Get total vulnerability count"""
        return len(self.results['vulnerabilities'])

    def get_severity_counts(self):
        """Get severity distribution"""
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
        }
        for v in self.results['vulnerabilities']:
            sev = v.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    def get_summary(self):
        """Get session summary"""
        return {
            'id': self.id,
            'target': self.target,
            'module': self.module,
            'state': self.state,
            'duration': self.get_duration_str(),
            'vulnerabilities': self.get_vuln_count(),
            'severity': self.get_severity_counts(),
            'exploits': len(self.results['exploits']),
            'shells': len(self.results['shells']),
            'errors': len(self.errors),
        }

    # =============================================
    # SERIALIZATION
    # =============================================

    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'id': self.id,
            'target': self.target,
            'module': self.module,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'finished_at': self.finished_at,
            'state': self.state,
            'progress': self.progress,
            'current_phase': self.current_phase,
            'total_phases': self.total_phases,
            'results': self.results,
            'errors': self.errors,
            'duration': self.get_duration(),
        }

    def to_json(self, indent=4):
        """Convert session to JSON"""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data):
        """Create session from dictionary"""
        session = cls(
            target=data.get('target', ''),
            module=data.get('module', 'full'),
            session_id=data.get('id')
        )
        session.created_at = data.get('created_at', session.created_at)
        session.updated_at = data.get('updated_at', session.updated_at)
        session.finished_at = data.get('finished_at')
        session.state = data.get('state', 'active')
        session.progress = data.get('progress', 0)
        session.current_phase = data.get('current_phase', 0)
        session.results = data.get('results', session.results)
        session.errors = data.get('errors', [])
        return session

    @classmethod
    def from_json(cls, json_str):
        """Create session from JSON string"""
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except Exception:
            return None

    # =============================================
    # DISPLAY
    # =============================================

    def show_summary(self):
        """Display session summary"""
        summary = self.get_summary()
        sev = summary['severity']

        print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
{C.CYAN}║{C.WHITE}                 SESSION SUMMARY                      {C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  Session ID:   {C.WHITE}{summary['id'][:35]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Target:       {C.WHITE}{summary['target'][:35]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Module:       {C.WHITE}{summary['module']:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  State:        {C.WHITE}{summary['state']:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Duration:     {C.WHITE}{summary['duration']:<35}{C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  Vulnerabilities: {C.WHITE}{summary['vulnerabilities']:<31}{C.CYAN}║
{C.CYAN}║{C.RED}    CRITICAL:   {sev['CRITICAL']:<35}{C.CYAN}║
{C.CYAN}║{C.YELLOW}    HIGH:       {sev['HIGH']:<35}{C.CYAN}║
{C.CYAN}║{C.CYAN}    MEDIUM:     {sev['MEDIUM']:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}    LOW:        {sev['LOW']:<35}{C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  Exploits:     {summary['exploits']:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Shells:       {summary['shells']:<35}{C.CYAN}║
{C.CYAN}║{C.YELLOW}  Errors:       {summary['errors']:<35}{C.CYAN}║
{C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}
""")


# =============================================
# SESSION MANAGER
# =============================================

class SessionManager:
    """
    Manages multiple sessions
    - Create/load/save sessions
    - List all sessions
    - Clean old sessions
    """

    def __init__(self, sessions_dir=None):
        """Initialize session manager"""
        if sessions_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sessions_dir = os.path.join(base_dir, "reports", "sessions")

        self.sessions_dir = sessions_dir
        ensure_dir(self.sessions_dir)

        self.active_sessions = {}
        self.loaded_sessions = {}

    # =============================================
    # SESSION MANAGEMENT
    # =============================================

    def create_session(self, target, module="full"):
        """Create a new session"""
        session = Session(target, module)
        self.active_sessions[session.id] = session

        # Save initial state
        self.save_session(session)

        log_ok(f"Session created: {session.id}")
        return session

    def get_session(self, session_id):
        """Get session by ID"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]

        if session_id in self.loaded_sessions:
            return self.loaded_sessions[session_id]

        # Try to load from disk
        return self.load_session(session_id)

    def close_session(self, session_id):
        """Close and save a session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.complete()
            self.save_session(session)
            del self.active_sessions[session_id]
            log_ok(f"Session closed: {session_id}")

    def save_session(self, session):
        """Save session to disk"""
        try:
            path = self._get_session_path(session.id)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(session.to_json())
            return True
        except Exception as e:
            log_error(f"Failed to save session: {e}")
            return False

    def load_session(self, session_id):
        """Load session from disk"""
        try:
            path = self._get_session_path(session_id)
            if not os.path.exists(path):
                return None

            with open(path, 'r', encoding='utf-8') as f:
                json_str = f.read()

            session = Session.from_json(json_str)
            if session:
                self.loaded_sessions[session_id] = session

            return session
        except Exception as e:
            log_error(f"Failed to load session: {e}")
            return None

    def delete_session(self, session_id):
        """Delete a session"""
        try:
            path = self._get_session_path(session_id)
            if os.path.exists(path):
                os.remove(path)

            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            if session_id in self.loaded_sessions:
                del self.loaded_sessions[session_id]

            return True
        except Exception as e:
            log_error(f"Failed to delete session: {e}")
            return False

    # =============================================
    # PATHS
    # =============================================

    def _get_session_path(self, session_id):
        """Get file path for session"""
        return os.path.join(self.sessions_dir, f"{session_id}.json")

    # =============================================
    # LISTING
    # =============================================

    def list_sessions(self):
        """List all sessions"""
        sessions = []

        if not os.path.exists(self.sessions_dir):
            return sessions

        for filename in os.listdir(self.sessions_dir):
            if filename.endswith('.json'):
                session_id = filename[:-5]
                session = self.load_session(session_id)
                if session:
                    sessions.append(session.get_summary())

        # Sort by creation date (newest first)
        sessions.sort(key=lambda x: x.get('id', ''), reverse=True)
        return sessions

    def list_active(self):
        """List active sessions"""
        return [s.get_summary() for s in self.active_sessions.values()]

    def show_sessions(self):
        """Display all sessions"""
        sessions = self.list_sessions()

        if not sessions:
            log_warn("No sessions found")
            return

        print(f"\n{C.CYAN}{'═'*80}")
        print(f"{C.WHITE}  Sessions ({len(sessions)})")
        print(f"{C.CYAN}{'═'*80}{C.RESET}")

        for s in sessions[:20]:  # Show max 20
            state_color = {
                'completed': C.GREEN,
                'active': C.CYAN,
                'failed': C.RED,
                'paused': C.YELLOW,
            }.get(s['state'], C.WHITE)

            print(f"  {state_color}[{s['state']}]{C.RESET} {s['id']}")
            print(f"    Target: {s['target']}")
            print(f"    Vulns:  {s['vulnerabilities']} | Duration: {s['duration']}")
            print()

    # =============================================
    # CLEANUP
    # =============================================

    def clean_old_sessions(self, days=30):
        """Delete sessions older than N days"""
        import time as t

        cutoff = t.time() - (days * 86400)
        deleted = 0

        if not os.path.exists(self.sessions_dir):
            return 0

        for filename in os.listdir(self.sessions_dir):
            if not filename.endswith('.json'):
                continue

            path = os.path.join(self.sessions_dir, filename)
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    deleted += 1
            except Exception:
                pass

        if deleted:
            log_ok(f"Deleted {deleted} old sessions")

        return deleted

    def clear_all_sessions(self):
        """Delete all sessions"""
        deleted = 0

        if not os.path.exists(self.sessions_dir):
            return 0

        for filename in os.listdir(self.sessions_dir):
            if filename.endswith('.json'):
                path = os.path.join(self.sessions_dir, filename)
                try:
                    os.remove(path)
                    deleted += 1
                except Exception:
                    pass

        self.active_sessions.clear()
        self.loaded_sessions.clear()

        log_ok(f"Cleared {deleted} sessions")
        return deleted


# =============================================
# GLOBAL SESSION MANAGER
# =============================================

_global_manager = None


def get_session_manager():
    """Get global session manager"""
    global _global_manager
    if _global_manager is None:
        _global_manager = SessionManager()
    return _global_manager


# =============================================
# CONVENIENCE FUNCTIONS
# =============================================

def create_session(target, module="full"):
    """Create a new session"""
    return get_session_manager().create_session(target, module)


def close_session(session_id):
    """Close a session"""
    return get_session_manager().close_session(session_id)


def get_session(session_id):
    """Get a session"""
    return get_session_manager().get_session(session_id)


def list_sessions():
    """List all sessions"""
    return get_session_manager().list_sessions()


# =============================================
# EXPORTS
# =============================================

__all__ = [
    "Session",
    "SessionManager",
    "get_session_manager",
    "create_session",
    "close_session",
    "get_session",
    "list_sessions",
]