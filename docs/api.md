# 🔌 BlackHunter Pro - API Documentation

**Academic Penetration Testing Tool - Isolated Lab Environment Only**

---

## 📖 Table of Contents

1. [Overview](#overview)
2. [Base URL](#base-url)
3. [Authentication](#authentication)
4. [Response Format](#response-format)
5. [Error Handling](#error-handling)
6. [Endpoints](#endpoints)
   - [Server](#server)
   - [Clients](#clients)
   - [Commands](#commands)
   - [Files](#files)
   - [Credentials](#credentials)
   - [Loot](#loot)
   - [Screenshots](#screenshots)
   - [Keylogs](#keylogs)
   - [Reports](#reports)
   - [Settings](#settings)
7. [WebSocket API](#websocket-api)
8. [Rate Limiting](#rate-limiting)
9. [Examples](#examples)

---

## 📌 Overview

The **BlackHunter Pro API** is a RESTful API that provides programmatic access to all C2 server functionality. It allows you to:

- Manage connected clients
- Send commands and retrieve results
- Transfer files
- Harvest credentials and loot
- Generate reports
- Monitor server status

**Base Technology**: Python Flask + Flask-SocketIO  
**Protocol**: HTTP/HTTPS + WebSocket  
**Data Format**: JSON  
**Authentication**: Session tokens + API keys

---

## 🌐 Base URL

### Default
