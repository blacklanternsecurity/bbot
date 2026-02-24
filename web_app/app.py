from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
from flask_sock import Sock
import subprocess
import threading
import os
import json
import sqlite3
import shlex
import time
import re
from datetime import datetime

app = Flask(__name__)
sock = Sock(app)

# Global sockets for broadcasting
connected_clients = set()
graph_clients = set()
running_scans = set()
running_scans_lock = threading.Lock()

# Configuration
# Path to scans. In container, this is typically /root/.bbot/scans
SCAN_DIR = os.path.expanduser("~/.bbot/scans")

# Path to preset. Uses absolute path relative to this file to locate the preset.
# The structure is assumed to be:
# /usr/src/bbot
#   web_app/app.py
#   my_bbot/all-but-intense-http.yml
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRESET_FILE = os.path.join(BASE_DIR, "my_bbot", "all-but-intense-http.yml")

# Ensure scan directory exists
os.makedirs(SCAN_DIR, exist_ok=True)
SCAN_REGISTRY = os.path.expanduser("~/.bbot/web_app_scans.json")


def load_scan_registry():
    if not os.path.exists(SCAN_REGISTRY):
        return []
    try:
        with open(SCAN_REGISTRY, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [str(x) for x in data]
    except Exception:
        pass
    return []


def save_scan_registry(scan_names):
    try:
        os.makedirs(os.path.dirname(SCAN_REGISTRY), exist_ok=True)
        with open(SCAN_REGISTRY, "w", encoding="utf-8") as f:
            json.dump(scan_names, f, indent=2)
    except Exception:
        pass


def register_scan_name(scan_name):
    names = load_scan_registry()
    if scan_name not in names:
        names.append(scan_name)
        save_scan_registry(names)

def broadcast_log(message):
    data = json.dumps({"type": "log", "data": message})
    for client in connected_clients:
        try:
            client.send(data)
        except:
            connected_clients.remove(client)

def broadcast_graph(data):
    # data is already dict
    msg = json.dumps({"type": "graph", "data": data})
    for client in connected_clients:
        try:
            client.send(msg)
        except:
            connected_clients.remove(client)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scans')
def list_scans():
    scans = []
    with running_scans_lock:
        currently_running = set(running_scans)
    for name in load_scan_registry():
        path = os.path.join(SCAN_DIR, name)
        if os.path.isdir(path):
            scans.append({"name": name, "path": path, "running": name in currently_running})
    scans.sort(key=lambda x: x["name"].lower())
    return render_template('scans.html', scans=scans)

@app.route('/scans/<scan_name>/report')
def scan_report(scan_name):
    # Generate when missing or stale so users always see latest parsed findings details.
    scan_path = os.path.join(SCAN_DIR, scan_name)
    report_path = os.path.join(scan_path, "web_report.html")
    sqlite_path = os.path.join(scan_path, "output.sqlite")

    if not os.path.exists(sqlite_path):
        return "No report or sqlite database found."

    should_generate = not os.path.exists(report_path)
    if not should_generate:
        try:
            should_generate = os.path.getmtime(sqlite_path) >= os.path.getmtime(report_path)
        except OSError:
            should_generate = True

    if should_generate:
        cmd = [
            "python3",
            os.path.join(BASE_DIR, "gen_report.py"),
            sqlite_path,
            report_path,
        ]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if result.stderr:
                app.logger.warning("Report generation stderr for %s: %s", scan_name, result.stderr)
        except subprocess.CalledProcessError as e:
            return f"Error generating report: {e.stderr or str(e)}"
        except Exception as e:
            return f"Error generating report: {e}"

        if not os.path.exists(report_path):
            return "Error generating report: output file was not created."
    
    return send_from_directory(scan_path, "web_report.html")

@app.route('/scan/start', methods=['POST'])
def start_scan():
    scan_name = str(request.form.get("scan_name", "")).strip()
    
    domains = request.form.get("domains", "")
    ips = request.form.get("ips", "")
    ranges = request.form.get("ranges", "")
    orgs = request.form.get("orgs", "")
    
    target_list = []

    def _lines(raw):
        return [line.strip() for line in raw.splitlines() if line.strip()]

    # Domains, IPs, ranges pass through as entered.
    target_list.extend(_lines(domains))
    target_list.extend(_lines(ips))
    target_list.extend(_lines(ranges))

    # Organization names must be ORG_STUB targets for BBOT: ORG:<name>
    for org in _lines(orgs):
        if not org.upper().startswith("ORG:"):
            org = f"ORG:{org}"
        target_list.append(org)

    # remove duplicates while preserving insertion order
    target_list = list(dict.fromkeys(target_list))
    
    if not target_list:
        return jsonify({"status": "error", "message": "Provide at least one domain, IP, IP range, or org name"}), 400
    if not scan_name:
        return jsonify({"status": "error", "message": "Missing scan name"}), 400

    with running_scans_lock:
        if scan_name in running_scans:
            return jsonify({"status": "error", "message": f"Scan '{scan_name}' is already running"}), 409
        running_scans.add(scan_name)

    register_scan_name(scan_name)

    # Start scan in a separate thread
    threading.Thread(target=run_scan_thread, args=(target_list, scan_name)).start()
    
    return jsonify({"status": "started", "message": f"Scan {scan_name} started with {len(target_list)} targets"})

def run_scan_thread(target_list, scan_name):
    targets_str = ", ".join(target_list[:5])
    if len(target_list) > 5:
        targets_str += f" and {len(target_list)-5} more..."
        
    broadcast_log(f"Starting scan '{scan_name}' for targets: {targets_str}")
    
    # We are already inside the container, so we invoke 'bbot' directly.
    # The websocket configuration should point to localhost (since client is also here in the same net namespace)
    # NOTE: The websocket URL in the preset needs to point to THIS app.
    
    ansi_re = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

    def strip_ansi(line):
        return ansi_re.sub("", line)

    def build_cmd():
        cmd = [
            "bbot",
            "-n",
            scan_name,
            "-p",
            PRESET_FILE,
            "--allow-deadly",
            "-y",
            "-t",
        ]
        cmd.extend(target_list)
        return cmd

    try:
        cmd = build_cmd()
        broadcast_log(f"Executing: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            env={**os.environ, "PATH": f"/root/.bbot/tools:{os.environ.get('PATH', '')}"},
        )

        for line in process.stdout:
            broadcast_log(line.strip())

        process.wait()
        broadcast_log(f"Scan finished with exit code {process.returncode}")

    except FileNotFoundError:
        broadcast_log("Error: 'bbot' command not found. Is it installed in the PATH?")
    except Exception as e:
        broadcast_log(f"Error running scan: {e}")
    finally:
        with running_scans_lock:
            running_scans.discard(scan_name)

@sock.route('/ws')
def websocket(ws):
    connected_clients.add(ws)
    try:
        while True:
            # Keep alive or handle incoming (BBOT sends graph data here too?)
            # Wait, BBOT connects to THIS endpoint? 
            # If BBOT connects here, it acts as a client.
            # If Browser connects here, it acts as a client.
            # We need to distinguish them or echo.
            
            data = ws.receive()
            if data:
                try:
                    msg = json.loads(data)
                    # If it looks like a BBOT event (has type/data or similar structure?)
                    # BBOT's websocket module sends standard BBOT event JSON.
                    # We can detect it.
                    if "type" in msg and "data" in msg:
                        # Re-broadcast to all clients (browsers)
                        # We might filter "SCAN" or "URL" etc.
                        # Vivagraph expects {id, parent}
                        
                        # Extract graph data
                        # Simplistic logic:
                        parent = msg.get("parent", None) # BBOT event usually has parent ID?
                        # Actually BBOT event structure: {type: ..., data: ..., parent: ...}
                        # Parent is an object in python, but in JSON it might be an ID or object.
                        # We need to map it for Vivagraph.
                        
                        # Let's verify BBOT output format for websocket
                        # It sends the whole event serialized.
                        
                        # We'll assume the client (browser) knows how to parse it 
                        # OR we process it here.
                        # Let's just broadcast everything received to all clients.
                        # The browser JS will filter.
                        pass
                        
                    # Broadcast to everyone else
                    for client in connected_clients:
                        if client != ws:
                            try:
                                client.send(data)
                            except:
                                pass
                except:
                    pass
    except:
        pass
    finally:
        connected_clients.remove(ws)

if __name__ == '__main__':
    # Start app
    app.run(host='0.0.0.0', port=8765)
