import json
import os
import tempfile
import subprocess
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import urllib.parse as urlparse
from email.parser import BytesParser
from email import policy

APP_TITLE = "Windows Hardening Audit – Browser UI"
FALLBACK_PORT = 8765

# The script can emit timestamped files like WinHardening_Audit_YYYY-mm-dd_HH-MM-SS.json
# or fixed names like Win_Hardening_Audit_v3.json. We'll search for both.
JSON_PATTERNS = [
    "WinHardening_Audit_*.json",
    "Win_Hardening_Audit_v3.json",
]

def _try_ps(exe: str, args: list[str], cwd: str, timeout: int) -> tuple[bool, str | None]:
    try:
        proc = subprocess.run([exe, *args], capture_output=True, text=True, cwd=cwd, timeout=timeout)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return proc.returncode == 0, out
    except FileNotFoundError:
        return False, None
    except Exception as e:
        return False, str(e)

def run_powershell_script(ps1_path: Path, elevate: bool = False) -> tuple[bool, str]:
    """
    Run the PowerShell script from its folder.
    - Always Unblock-File first (best effort).
    - If elevate=True, trigger UAC and run in an elevated PowerShell window.
    Returns (ok, combined_stdout_stderr_or_info).
    """
    if not ps1_path.exists():
        return False, f"Script not found: {ps1_path}"
    cwd = str(ps1_path.parent)

    # Always try to unblock first (ignore errors)
    unblock_cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", f"try {{ Unblock-File -Path '{ps1_path}' -ErrorAction SilentlyContinue }} catch {{}}"
    ]
    try:
        subprocess.run(unblock_cmd, cwd=cwd, capture_output=True, text=True, timeout=30)
    except Exception:
        pass

    if elevate:
        # Launch an elevated window to run the script; we can't capture output, but JSON should be written in cwd.
        # Prefer Windows PowerShell; fallback to pwsh if needed.
        elevated_cmd = (
            "Start-Process PowerShell -Verb RunAs "
            f"-ArgumentList \"-NoProfile -ExecutionPolicy Bypass -File '{ps1_path}'\""
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", elevated_cmd],
                cwd=cwd, capture_output=True, text=True, timeout=900
            )
            note = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            return (proc.returncode == 0, "Elevated run invoked. A UAC prompt may have appeared. " + note)
        except Exception as e:
            return False, f"Failed to launch elevated PowerShell: {e}"

    # Non-elevated: run inline and capture output
    args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1_path)]
    try:
        proc = subprocess.run(["powershell", *args], cwd=cwd, capture_output=True, text=True, timeout=1800)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        if proc.returncode != 0:
            # Attempt PowerShell 7
            proc2 = subprocess.run(["pwsh", *args], cwd=cwd, capture_output=True, text=True, timeout=1800)
            out2 = (proc2.stdout or "") + ("\n" + proc2.stderr if proc2.stderr else "")
            return (proc2.returncode == 0, out + "\n--- pwsh output ---\n" + out2)
        return True, out
    except FileNotFoundError as e:
        return False, f"PowerShell not found: {e}"
    except subprocess.TimeoutExpired:
        return False, "Timed out running script (30 min)."
    except Exception as e:
        return False, str(e)

def find_latest_json(folder: Path) -> Path | None:
    """Pick the most recently modified JSON that matches known patterns."""
    candidates = []
    for pat in JSON_PATTERNS:
        candidates.extend(Path(folder).glob(pat))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)

def load_json(path: Path):
    if not path or not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Windows Hardening Audit – Browser UI</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#101015;color:#ddd;margin:0}
header{background:#151520;border-bottom:1px solid #2a2d34;padding:14px 18px}
h2{margin:0;font-size:18px}
main{padding:16px 18px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
input[type=text]{padding:8px 10px;min-width:420px;background:#171922;border:1px solid #2a2d34;color:#e8e8e8;border-radius:8px}
button,input[type=submit]{padding:10px 12px;background:#1e2029;border:1px solid #2a2d34;color:#e8e8e8;border-radius:8px;cursor:pointer}
button:hover,input[type=submit]:hover{filter:brightness(1.1)}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{border-bottom:1px solid #2a2d34;padding:8px 6px;text-align:left;vertical-align:top}
th{background:#151520;position:sticky;top:0}
small#status{display:block;color:#9aa;margin-top:6px}
.bad{color:#ff8b8b}
.good{color:#7fe07f}
kbd{background:#222;padding:2px 6px;border-radius:4px;border:1px solid #333}
</style>
</head>
<body>
<header><h2>Windows Hardening Audit – Browser UI</h2></header>
<main>
  <div class="row">
    <input id="ps1path" type="text" placeholder="Type full path to Win_Hardening_Audit_Full_v3.3_plus.ps1 (optional)">
    <button onclick="runByPath()">Run (non-admin)</button>
    <button onclick="runByPathElevated()">Run as Administrator</button>
    <form id="uploadForm" method="POST" action="/api/upload" enctype="multipart/form-data">
      <input type="file" name="ps1file" accept=".ps1">
      <input type="submit" value="Upload & Run">
    </form>
  </div>
  <small>Tip: <b>Run by Path</b> runs the script from its own folder. <b>Upload & Run</b> copies your .ps1 into the temp folder (<kbd>%TEMP%</kbd>) and runs it there.</small>

  <div class="row">
    <button onclick="loadResults()">Reload Results</button>
    <span id="count">0 checks</span>
  </div>

  <div class="row">
    <label><input id="failed" type="checkbox" onchange="render()"> Failed only</label>
    <label><input id="high" type="checkbox" onchange="render()"> High severity</label>
    <input id="q" type="text" placeholder="Search" oninput="render()">
  </div>

  <table id="grid">
    <thead>
      <tr><th>Id</th><th>Title</th><th>Category</th><th>Severity</th><th>Passed</th><th>Evidence</th></tr>
    </thead>
    <tbody></tbody>
  </table>
  <small id="status">Idle</small>
</main>

<script>
let rows=[];

async function runByPath(){
  const p=document.getElementById('ps1path').value.trim();
  setStatus('Running (non-admin)…');
  const r=await fetch('/api/run?ps1='+encodeURIComponent(p));
  const j=await r.json();
  setStatus((j.ok?'✅ Success':'❌ Failed') + ' — ' + (j.msg||'(no output)') + (j.json_path? (' | JSON: '+j.json_path):''), j.ok);
  if(j.ok){ await loadResults(); }
}

async function runByPathElevated(){
  const p=document.getElementById('ps1path').value.trim();
  setStatus('Launching elevated PowerShell… Check for UAC prompt.');
  const r=await fetch('/api/run_elevated?ps1='+encodeURIComponent(p));
  const j=await r.json();
  setStatus((j.ok?'✅ Elevated launched':'❌ Failed to launch') + ' — ' + (j.msg||'' ) + (j.json_path? (' | JSON: '+j.json_path):''), j.ok);
  // After elevation, JSON may appear a few seconds later; click Reload Results to refresh.
}

document.getElementById('uploadForm').addEventListener('submit', async e=>{
  e.preventDefault();
  const form=e.target;
  const fd=new FormData(form);
  setStatus('Uploading and running…');
  const resp=await fetch('/api/upload',{method:'POST', body:fd});
  const j=await resp.json();
  setStatus(j.ok ? ('Run completed. JSON: '+ (j.json_path||'not found')) : ('Run failed: '+j.msg), j.ok);
  if(j.ok){ await loadResults(); }
});

async function loadResults(){
  const r=await fetch('/api/results');
  const j=await r.json();
  rows=j.rows||[];
  document.getElementById('count').textContent=rows.length+' checks';
  render();
}

function render(){
  const failed=document.getElementById('failed').checked;
  const high=document.getElementById('high').checked;
  const q=document.getElementById('q').value.trim().toLowerCase();
  let data=rows.filter(r=>{
    if(failed){
      const p=String(r.Passed).toLowerCase();
      if(!(p==='false'||p==='0'))return false;
    }
    if(high){
      if(!String(r.Severity||'').toLowerCase().startsWith('high'))return false;
    }
    if(q){
      const hay=(r.Id+' '+r.Title+' '+r.Category+' '+r.Severity+' '+r.Evidence).toLowerCase();
      if(!hay.includes(q))return false;
    }
    return true;
  });
  const tb=document.querySelector('#grid tbody');
  tb.innerHTML=data.map(r=>'<tr>'
    +'<td>'+esc(r.Id)+'</td>'
    +'<td>'+esc(r.Title)+'</td>'
    +'<td>'+esc(r.Category)+'</td>'
    +'<td>'+esc(r.Severity)+'</td>'
    +'<td>'+esc(r.Passed)+'</td>'
    +'<td>'+esc(r.Evidence)+'</td>'
    +'</tr>').join('');
  setStatus(`Showing ${data.length} of ${rows.length} checks.`);
}
function esc(s){return String(s||'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function setStatus(t,ok){const el=document.getElementById('status');el.textContent=t;el.className=ok===false?'bad':(ok===true?'good':'');}
loadResults().catch(()=>{});
</script>
</body></html>
"""

_last_rows = []
_last_json_path: str | None = None

def _sanitize_filename(name: str) -> str:
    keep = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(c for c in name if c in keep) or "script.ps1"

class API(BaseHTTPRequestHandler):
    def _send(self, data, ctype="application/json"):
        body = data.encode("utf-8") if isinstance(data, str) else data
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global _last_rows, _last_json_path
        parsed = urlparse.urlparse(self.path)
        if parsed.path == "/":
            return self._send(_HTML, "text/html; charset=utf-8")

        if parsed.path == "/api/run":
            qs = urlparse.parse_qs(parsed.query)
            ps1 = (qs.get("ps1", [""])[0] or "").strip()
            ps1_path = Path(ps1) if ps1 else Path(__file__).with_name("Win_Hardening_Audit_Full_v3.3_plus.ps1")
            ok, msg = run_powershell_script(ps1_path, elevate=False)
            _last_rows = []
            _last_json_path = None
            if ok:
                j = find_latest_json(ps1_path.parent)
                _last_json_path = str(j) if j else None
                _last_rows = load_json(j) if j else []
            return self._send(json.dumps({"ok": ok, "msg": msg, "count": len(_last_rows), "json_path": _last_json_path}))

        if parsed.path == "/api/run_elevated":
            qs = urlparse.parse_qs(parsed.query)
            ps1 = (qs.get("ps1", [""])[0] or "").strip()
            ps1_path = Path(ps1) if ps1 else Path(__file__).with_name("Win_Hardening_Audit_Full_v3.3_plus.ps1")
            ok, msg = run_powershell_script(ps1_path, elevate=True)
            _last_rows = []
            _last_json_path = None
            # We may not have data immediately; try to read whatever exists now.
            j = find_latest_json(ps1_path.parent)
            if j:
                _last_json_path = str(j)
                _last_rows = load_json(j)
            return self._send(json.dumps({"ok": ok, "msg": msg, "count": len(_last_rows), "json_path": _last_json_path}))

        if parsed.path == "/api/results":
            return self._send(json.dumps({"rows": _last_rows, "json_path": _last_json_path}))

        self.send_error(404)

    def do_POST(self):
        global _last_rows, _last_json_path
        parsed = urlparse.urlparse(self.path)
        if parsed.path != "/api/upload":
            return self.send_error(404)

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type or "boundary=" not in content_type:
            return self._send(json.dumps({"ok": False, "msg": "Expected multipart/form-data with boundary"}))

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        pseudo = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        msg = BytesParser(policy=policy.default).parsebytes(pseudo)

        ps1_data = None
        filename = "uploaded.ps1"

        for part in msg.iter_attachments():
            disp = part.get("Content-Disposition", "")
            if not disp or 'name="ps1file"' not in disp:
                continue
            filename = part.get_filename() or filename
            ps1_data = part.get_payload(decode=True)
            break

        if not ps1_data:
            return self._send(json.dumps({"ok": False, "msg": "No file uploaded"}))

        try:
            safe_name = _sanitize_filename(filename)
            tempdir = Path(tempfile.gettempdir())
            out_path = tempdir / f"uploaded_{safe_name}"
            with open(out_path, "wb") as f:
                f.write(ps1_data)

            ok, msgtxt = run_powershell_script(out_path, elevate=False)
            _last_rows = []
            _last_json_path = None
            if ok:
                j = find_latest_json(out_path.parent)
                _last_json_path = str(j) if j else None
                _last_rows = load_json(j) if j else []
            return self._send(json.dumps({"ok": ok, "msg": msgtxt, "count": len(_last_rows), "json_path": _last_json_path, "ps1": str(out_path)}))
        except Exception as e:
            return self._send(json.dumps({"ok": False, "msg": str(e)}))

def main():
    addr = ("127.0.0.1", FALLBACK_PORT)
    print(f"Starting Browser UI → http://{addr[0]}:{addr[1]}/")
    webbrowser.open(f"http://{addr[0]}:{addr[1]}/")
    ThreadingHTTPServer(addr, API).serve_forever()

if __name__ == "__main__":
    main()
