#!/usr/bin/env python3
import sys, os, json, time, uuid, queue, threading, re, shutil, subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["PYTHONUNBUFFERED"] = "1"

from flask import Flask, jsonify, request, render_template, Response, stream_with_context
from flask_cors import CORS

from core import HackingTool, HackingToolsCollection
from tools.anonsurf import AnonSurfTools
from tools.information_gathering import InformationGatheringTools
from tools.wordlist_generator import WordlistGeneratorTools
from tools.wireless_attack import WirelessAttackTools
from tools.sql_injection import SqlInjectionTools
from tools.phishing_attack import PhishingAttackTools
from tools.web_attack import WebAttackTools
from tools.post_exploitation import PostExploitationTools
from tools.forensics import ForensicTools
from tools.payload_creator import PayloadCreatorTools
from tools.exploit_frameworks import ExploitFrameworkTools
from tools.reverse_engineering import ReverseEngineeringTools
from tools.ddos import DDOSTools
from tools.remote_administration import RemoteAdministrationTools
from tools.xss_attack import XSSAttackTools
from tools.steganography import SteganographyTools
from tools.active_directory import ActiveDirectoryTools
from tools.cloud_security import CloudSecurityTools
from tools.mobile_security import MobileSecurityTools
from tools.other_tools import OtherTools

app = Flask(__name__, template_folder='templates')
CORS(app)

categories = [
    ("Anonymously Hiding", AnonSurfTools(), "\U0001f6e1"),
    ("Information Gathering", InformationGatheringTools(), "\U0001f50d"),
    ("Wordlist Generator", WordlistGeneratorTools(), "\U0001f4da"),
    ("Wireless Attack", WirelessAttackTools(), "\U0001f4f6"),
    ("SQL Injection", SqlInjectionTools(), "\U0001f9e9"),
    ("Phishing Attack", PhishingAttackTools(), "\U0001f3a3"),
    ("Web Attack", WebAttackTools(), "\U0001f310"),
    ("Post Exploitation", PostExploitationTools(), "\U0001f527"),
    ("Forensics", ForensicTools(), "\U0001f575"),
    ("Payload Creation", PayloadCreatorTools(), "\U0001f4e6"),
    ("Exploit Framework", ExploitFrameworkTools(), "\U0001f9f0"),
    ("Reverse Engineering", ReverseEngineeringTools(), "\U0001f501"),
    ("DDOS Attack", DDOSTools(), "\u26a1"),
    ("Remote Admin (RAT)", RemoteAdministrationTools(), "\U0001f5a5"),
    ("XSS Attack", XSSAttackTools(), "\U0001f4a5"),
    ("Steganography", SteganographyTools(), "\U0001f5bc"),
    ("Active Directory", ActiveDirectoryTools(), "\U0001f3e2"),
    ("Cloud Security", CloudSecurityTools(), "\u2601"),
    ("Mobile Security", MobileSecurityTools(), "\U0001f4f1"),
    ("Other Tools", OtherTools(), "\u2728"),
]

task_outputs = {}

def get_tools_from_collection(collection):
    tools = []
    for t in collection.TOOLS:
        if isinstance(t, HackingToolsCollection):
            tools.extend(get_tools_from_collection(t))
        elif isinstance(t, HackingTool):
            tools.append(t)
    return tools

def serialize_tool(tool, cat_idx=None, tool_idx=None):
    desc = (getattr(tool, 'DESCRIPTION', '') or '').splitlines()[0] if getattr(tool, 'DESCRIPTION', '') else ''
    return {
        'id': tool_idx if tool_idx is not None else id(tool),
        'title': getattr(tool, 'TITLE', 'Unknown'),
        'description': desc[:120],
        'description_full': getattr(tool, 'DESCRIPTION', ''),
        'project_url': getattr(tool, 'PROJECT_URL', ''),
        'is_installed': tool.is_installed if hasattr(tool, 'is_installed') else False,
        'installable': bool(getattr(tool, 'INSTALL_COMMANDS', [])),
        'runnable': bool(getattr(tool, 'RUN_COMMANDS', [])),
        'tags': list(getattr(tool, 'TAGS', [])),
        'supported_os': getattr(tool, 'SUPPORTED_OS', ['linux', 'macos']),
        'requires_root': getattr(tool, 'REQUIRES_ROOT', False),
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/categories')
def api_categories():
    result = []
    for i, (name, coll, icon) in enumerate(categories):
        tools = get_tools_from_collection(coll)
        installed = sum(1 for t in tools if hasattr(t, 'is_installed') and t.is_installed)
        result.append({
            'id': i,
            'name': name,
            'icon': icon,
            'tool_count': len(tools),
            'installed': installed,
        })
    return jsonify(result)

@app.route('/api/category/<int:cat_id>')
def api_category(cat_id):
    if cat_id < 0 or cat_id >= len(categories):
        return jsonify({'error': 'Category not found'}), 404
    name, coll, icon = categories[cat_id]
    tools = get_tools_from_collection(coll)
    result = [serialize_tool(t, cat_id, i) for i, t in enumerate(tools)]
    return jsonify({'name': name, 'icon': icon, 'tools': result})

@app.route('/api/search')
def api_search():
    q = request.args.get('q', '').lower()
    if not q:
        return jsonify([])
    results = []
    for cat_id, (name, coll, icon) in enumerate(categories):
        tools = get_tools_from_collection(coll)
        for ti, t in enumerate(tools):
            title = (getattr(t, 'TITLE', '') or '').lower()
            desc = (getattr(t, 'DESCRIPTION', '') or '').lower()
            tags = ' '.join(getattr(t, 'TAGS', []) or []).lower()
            if q in title or q in desc or q in tags:
                s = serialize_tool(t, cat_id, ti)
                s['category'] = name
                s['category_icon'] = icon
                results.append(s)
    return jsonify(results)

def run_command(cmd, task_id):
    lines = []
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
            bufsize=1, executable='/bin/bash',
        )
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            lines.append(line)
            task_outputs[task_id] = lines.copy()
        proc.wait()
        if proc.returncode != 0:
            lines.append(f"\n[ERROR] Exit code: {proc.returncode}")
            task_outputs[task_id] = lines.copy()
    except Exception as e:
        lines.append(f"\n[ERROR] {e}")
        task_outputs[task_id] = lines.copy()
    task_outputs[task_id + '_done'] = True

@app.route('/api/tool/<int:cat_id>/<int:tool_id>/<action>', methods=['POST'])
def api_tool_action(cat_id, tool_id, action):
    if cat_id < 0 or cat_id >= len(categories):
        return jsonify({'error': 'Category not found'}), 404
    _, coll, _ = categories[cat_id]
    tools = get_tools_from_collection(coll)
    if tool_id < 0 or tool_id >= len(tools):
        return jsonify({'error': 'Tool not found'}), 404
    tool = tools[tool_id]

    task_id = str(uuid.uuid4())
    task_outputs[task_id] = []
    task_outputs[task_id + '_done'] = False

    if action == 'install':
        cmds = getattr(tool, 'INSTALL_COMMANDS', [])
        if not cmds:
            return jsonify({'error': 'No install commands'}), 400
        full_cmd = ' && '.join(cmds)
        threading.Thread(target=run_command, args=(full_cmd, task_id), daemon=True).start()
        return jsonify({'task_id': task_id, 'command': full_cmd})

    elif action == 'run':
        cmds = getattr(tool, 'RUN_COMMANDS', [])
        if not cmds:
            return jsonify({'error': 'No run commands'}), 400
        full_cmd = ' && '.join(cmds)
        threading.Thread(target=run_command, args=(full_cmd, task_id), daemon=True).start()
        return jsonify({'task_id': task_id, 'command': full_cmd})

    elif action == 'update':
        cmds = []
        for ic in (getattr(tool, 'INSTALL_COMMANDS', []) or []):
            if 'git clone' in ic:
                parts = ic.split()
                repo_urls = [p for p in parts if p.startswith('http')]
                if repo_urls:
                    dirname = repo_urls[0].rstrip('/').rsplit('/', 1)[-1].replace('.git', '')
                    cmds.append(f'cd {dirname} && git pull')
            elif 'pip install' in ic:
                cmds.append(ic.replace('pip install', 'pip install --upgrade'))
            elif 'go install' in ic:
                cmds.append(ic)
        if not cmds:
            return jsonify({'error': 'No update method'}), 400
        full_cmd = ' && '.join(cmds)
        threading.Thread(target=run_command, args=(full_cmd, task_id), daemon=True).start()
        return jsonify({'task_id': task_id, 'command': full_cmd})

    elif action == 'status':
        return jsonify({'is_installed': tool.is_installed})

    return jsonify({'error': 'Unknown action'}), 400

@app.route('/api/stream/<task_id>')
def api_stream(task_id):
    def generate():
        last_len = 0
        while True:
            lines = task_outputs.get(task_id, [])
            if len(lines) > last_len:
                yield ''.join(lines[last_len:])
                last_len = len(lines)
            if task_outputs.get(task_id + '_done'):
                if len(lines) == last_len:
                    break
                yield ''
                break
            time.sleep(0.1)
    return Response(stream_with_context(generate()), mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
