#!/usr/bin/env python3
import sys, os, json, time, uuid, threading, re, shutil, subprocess, io
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["PYTHONUNBUFFERED"] = "1"

from flask import Flask, jsonify, request, render_template, Response
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

app = Flask(__name__, template_folder=str(PROJECT_ROOT / 'web' / 'templates'))
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

def get_tools(coll):
    tools = []
    for t in coll.TOOLS:
        if isinstance(t, HackingToolsCollection):
            tools.extend(get_tools(t))
        elif isinstance(t, HackingTool):
            tools.append(t)
    return tools

def serialize(tool, cat_idx=None, tool_idx=None):
    desc = ((tool.DESCRIPTION or '').splitlines()[0] if getattr(tool, 'DESCRIPTION', '') else '')[:120]
    return {
        'id': tool_idx if tool_idx is not None else id(tool),
        'title': getattr(tool, 'TITLE', 'Unknown'),
        'description': desc,
        'description_full': getattr(tool, 'DESCRIPTION', ''),
        'project_url': getattr(tool, 'PROJECT_URL', ''),
        'is_installed': tool.is_installed,
        'installable': bool(getattr(tool, 'INSTALL_COMMANDS', [])),
        'runnable': bool(getattr(tool, 'RUN_COMMANDS', [])),
        'tags': list(getattr(tool, 'TAGS', [])),
        'supported_os': getattr(tool, 'SUPPORTED_OS', ['linux', 'macos']),
        'requires_root': getattr(tool, 'REQUIRES_ROOT', False),
        'has_custom_run': tool.__class__.run is not HackingTool.run,
    }

def has_any_sudo(cmd):
    return 'sudo' in cmd or 'doas' in cmd

def can_sudo():
    r = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=5)
    return r.returncode == 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/categories')
def api_categories():
    result = []
    for i, (name, coll, icon) in enumerate(categories):
        tools = get_tools(coll)
        result.append({
            'id': i, 'name': name, 'icon': icon,
            'tool_count': len(tools),
            'installed': sum(1 for t in tools if t.is_installed),
        })
    return jsonify(result)

@app.route('/api/category/<int:cat_id>')
def api_category(cat_id):
    if cat_id < 0 or cat_id >= len(categories):
        return jsonify({'error': 'Category not found'}), 404
    name, coll, icon = categories[cat_id]
    tools = get_tools(coll)
    return jsonify({'name': name, 'icon': icon, 'tools': [serialize(t, cat_id, i) for i, t in enumerate(tools)]})

@app.route('/api/search')
def api_search():
    q = request.args.get('q', '').lower()
    if not q:
        return jsonify([])
    results = []
    for cat_id, (name, coll, icon) in enumerate(categories):
        for ti, t in enumerate(get_tools(coll)):
            title = (t.TITLE or '').lower()
            desc = (t.DESCRIPTION or '').lower()
            tags = ' '.join(getattr(t, 'TAGS', []) or []).lower()
            if q in title or q in desc or q in tags:
                s = serialize(t, cat_id, ti)
                s['category'] = name
                s['category_icon'] = icon
                results.append(s)
    return jsonify(results)

@app.route('/api/tool/<int:cat_id>/<int:tool_id>')
def api_tool_info(cat_id, tool_id):
    if cat_id < 0 or cat_id >= len(categories):
        return jsonify({'error': 'Category not found'}), 404
    _, coll, _ = categories[cat_id]
    tools = get_tools(coll)
    if tool_id < 0 or tool_id >= len(tools):
        return jsonify({'error': 'Tool not found'}), 404
    return jsonify(serialize(tools[tool_id], cat_id, tool_id))

HAS_SUDO = can_sudo()

def run_shell(full_cmd, task_id, cwd=None):
    lines = []
    try:
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        proc = subprocess.Popen(
            full_cmd, shell=True, cwd=cwd or str(PROJECT_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, executable='/bin/bash',
            env=env,
        )
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            lines.append(line)
            task_outputs[task_id] = lines.copy()
        proc.wait()
        rc = proc.returncode
        if rc != 0:
            msg = f"\n\u274c Command finished with exit code {rc}"
            lines.append(msg)
            task_outputs[task_id] = lines.copy()
        else:
            lines.append("\n\u2705 Done (exit code 0)")
            task_outputs[task_id] = lines.copy()
    except Exception as e:
        lines.append(f"\n\u274c Error: {e}")
        task_outputs[task_id] = lines.copy()
    task_outputs[task_id + '_done'] = True

def run_via_tool_method(tool, method_name, task_id):
    """Run tool.install() or tool.run() capturing os.system and console output."""
    from contextlib import redirect_stdout, redirect_stderr
    import builtins

    captured = []
    def write(s):
        captured.append(s)
        task_outputs[task_id] = [''.join(captured)]
        return len(s)

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    old_os_system = os.system
    old_subprocess_run = subprocess.run
    old_subprocess_popen = subprocess.Popen

    class FakeWriter(io.TextIOBase):
        def write(self, s): return write(s)
        def flush(self): pass
        def isatty(self): return False

    fake = FakeWriter()

    def captured_os_system(cmd):
        write(f"$ {cmd}\n")
        r = subprocess.run(cmd, shell=True, cwd=str(PROJECT_ROOT),
                          capture_output=True, text=True, timeout=600)
        if r.stdout: write(r.stdout)
        if r.stderr: write(r.stderr)
        if r.returncode != 0:
            write(f"\n\u274c Exit code: {r.returncode}\n")
        else:
            write(f"\u2705 OK\n")
        return r.returncode

    def captured_run(*a, **kw):
        kw.setdefault('cwd', str(PROJECT_ROOT))
        kw.setdefault('timeout', 600)
        result = old_subprocess_run(*a, **kw)
        if result.stdout: write(result.stdout)
        if result.stderr: write(result.stderr)
        return result

    def captured_popen(*a, **kw):
        kw.setdefault('cwd', str(PROJECT_ROOT))
        return old_subprocess_popen(*a, **kw)

    try:
        sys.stdout = fake
        sys.stderr = fake
        os.system = captured_os_system
        subprocess.run = captured_run
        subprocess.Popen = captured_popen

        getattr(tool, method_name)()
    except SystemExit:
        pass
    except Exception as e:
        write(f"\n\u274c {type(e).__name__}: {e}\n")
        import traceback
        write(traceback.format_exc())
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        os.system = old_os_system
        subprocess.run = old_subprocess_run
        subprocess.Popen = old_subprocess_popen

    task_outputs[task_id + '_done'] = True

@app.route('/api/tool/<int:cat_id>/<int:tool_id>/<action>', methods=['POST'])
def api_tool_action(cat_id, tool_id, action):
    if cat_id < 0 or cat_id >= len(categories):
        return jsonify({'error': 'Category not found'}), 404
    _, coll, _ = categories[cat_id]
    tools = get_tools(coll)
    if tool_id < 0 or tool_id >= len(tools):
        return jsonify({'error': 'Tool not found'}), 404
    tool = tools[tool_id]

    task_id = str(uuid.uuid4())
    task_outputs[task_id] = []
    task_outputs[task_id + '_done'] = False

    if action == 'install':
        cmds = getattr(tool, 'INSTALL_COMMANDS', [])
        if not cmds:
            return jsonify({'error': 'No install commands defined'}), 400
        needs_sudo = any(has_any_sudo(c) for c in cmds)
        if needs_sudo and not HAS_SUDO and os.geteuid() != 0:
            return jsonify({
                'error': 'This tool requires sudo but password-less sudo is not available. Run the web app as root or configure sudo NOPASSWD.',
                'task_id': task_id
            }), 403
        threading.Thread(target=run_via_tool_method, args=(tool, 'install', task_id), daemon=True).start()
        return jsonify({'task_id': task_id, 'command': ' && '.join(cmds)})

    elif action == 'run':
        cmds = getattr(tool, 'RUN_COMMANDS', [])
        if not cmds:
            return jsonify({'error': 'No run commands defined. This tool may need interactive input.'}), 400
        needs_sudo = any(has_any_sudo(c) for c in cmds)
        if needs_sudo and not HAS_SUDO and os.geteuid() != 0:
            return jsonify({
                'error': 'This tool requires sudo but password-less sudo is not available.'
            }), 403
        threading.Thread(target=run_via_tool_method, args=(tool, 'run', task_id), daemon=True).start()
        return jsonify({'task_id': task_id, 'command': ' && '.join(cmds)})

    elif action == 'update':
        cmds = []
        for ic in (getattr(tool, 'INSTALL_COMMANDS', []) or []):
            if 'git clone' in ic:
                parts = ic.split()
                urls = [p for p in parts if p.startswith('http')]
                if urls:
                    d = urls[0].rstrip('/').rsplit('/', 1)[-1].replace('.git', '')
                    cmds.append(f'cd {d} && git pull')
            elif 'pip install' in ic:
                cmds.append(ic.replace('pip install', 'pip install --upgrade'))
            elif 'go install' in ic:
                cmds.append(ic)
        if not cmds:
            return jsonify({'error': 'No update method available'}), 400
        full = ' && '.join(cmd for cmd in cmds if cmd)
        threading.Thread(target=run_shell, args=(full, task_id), daemon=True).start()
        return jsonify({'task_id': task_id, 'command': full})

    elif action == 'info':
        return jsonify(serialize(tool, cat_id, tool_id))

    return jsonify({'error': 'Unknown action'}), 400

@app.route('/api/stream/<task_id>')
def api_stream(task_id):
    def generate():
        last = 0
        while True:
            lines = task_outputs.get(task_id, [])
            if not isinstance(lines, list):
                lines = [str(lines)]
            n = len(lines)
            if n == 0:
                joined = ''
            else:
                joined = lines[-1] if n == 1 else ''.join(lines[last:])
                last = n
            if joined:
                yield joined
            if task_outputs.get(task_id + '_done'):
                if not joined:
                    break
                yield '\n'
                break
            time.sleep(0.15)
    return Response(generate(), mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
