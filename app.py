#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Cloud Backup App — NO KEYRING EDITION
- Stores the GitHub token in ~/.github_cloud_backup_app.json (plaintext).
- Compatible with PyInstaller one-file builds (uses sys._MEIPASS for templates/static).
- All features retained: clean/orphan branch creation, multi-branch sync, last-updated column,
  streaming per-file upload progress (NDJSON), .ghcb.json branch → folder mapping.
"""
import os
import sys
import io
import json
import time
import base64
import hashlib
import threading
import platform
import getpass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable

import requests
from flask import Flask, request, jsonify, render_template, Response, stream_with_context

APP_NAME = "GitHubCloudBackupApp"
DEFAULT_BRANCH = "main"
PERSIST_PATH = Path.home() / ".github_cloud_backup_app.json"
META_FILENAME = ".ghcb.json"
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

def resource_path(*parts):
    """
    Works with PyInstaller/Nuitka onefile and normal runs.
    - If a bundle temp dir exists (PyInstaller-style), use it.
    - Else, use the executable folder (installed by Inno) or script dir.
    """
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)   # set by PyInstaller; sometimes also by others
    if meipass:
        candidates.append(Path(meipass))
    if getattr(sys, "frozen", False):          # onefile (Nuitka or PyInstaller)
        candidates.append(Path(sys.executable).parent)
    candidates.append(Path(__file__).parent)   # dev run

    for base in candidates:
        p = base.joinpath(*parts)
        if p.exists():
            return str(p)
    # fallback to the exe folder
    return str((Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent).joinpath(*parts))

# ------------------- Persistence -------------------

def load_persisted_state() -> Dict:
    if PERSIST_PATH.exists():
        try:
            with open(PERSIST_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_persisted_state(data: Dict):
    try:
        with open(PERSIST_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        try:
            alt = Path(__file__).parent / "app_state.json"
            with open(alt, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

def get_folder_map(persist: Dict) -> Dict[str, str]:
    return persist.get("folders_map", {})

def set_folder_map(persist: Dict, owner: str, repo: str, branch: str, folder: str):
    key = f"{owner}/{repo}/{branch}"
    fmap = persist.setdefault("folders_map", {})
    fmap[key] = folder

def lookup_folder(persist: Dict, owner: str, repo: str, branch: str) -> Optional[str]:
    return get_folder_map(persist).get(f"{owner}/{repo}/{branch}")

# ------------------- Machine identity -------------------

def machine_id() -> str:
    s = f"{platform.node()}|{getpass.getuser()}|{platform.system()}|{platform.release()}"
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def machine_name() -> str:
    return platform.node()

# ------------------- Token (NO KEYRING) -------------------

_persist = load_persisted_state()

def get_token() -> Optional[str]:
    # Prefer env var if set
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok.strip()
    # Else read from persisted JSON
    return _persist.get("token")

def set_token(token: str):
    if token:
        _persist["token"] = token.strip()
        save_persisted_state(_persist)

# ------------------- GitHub helpers -------------------

def sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def list_files(base_dir: Path) -> List[Dict]:
    files = []
    for root, _, filenames in os.walk(base_dir):
        for name in filenames:
            p = Path(root) / name
            rel = str(p.relative_to(base_dir)).replace("\\", "/")
            files.append({
                "relative_path": rel,
                "size": p.stat().st_size,
                "sha1": sha1_file(p),
            })
    files.sort(key=lambda x: x["relative_path"].lower())
    return files

def github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": APP_NAME,
    }

def ensure_repo_exists(owner: str, repo: str, token: str) -> Tuple[bool, str, Optional[Dict]]:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    r = requests.get(url, headers=github_headers(token))
    if r.status_code == 200:
        return True, "OK", r.json()
    if r.status_code == 404:
        return False, "Repository not found or no access", None
    return False, f"Error {r.status_code}: {r.text}", None

def github_get_file_sha_if_exists(owner: str, repo: str, path: str, branch: str, token: str) -> Optional[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = requests.get(url, headers=github_headers(token), params={"ref": branch})
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, dict) and "sha" in data:
            return data["sha"]
    return None

def github_put_file(owner: str, repo: str, path: str, branch: str, token: str, content_bytes: bytes, message: str) -> Dict:
    b64 = base64.b64encode(content_bytes).decode("ascii")
    sha_existing = github_get_file_sha_if_exists(owner, repo, path, branch, token)
    payload = {"message": message, "content": b64, "branch": branch}
    if sha_existing:
        payload["sha"] = sha_existing
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = requests.put(url, headers=github_headers(token), json=payload)
    try:
        data = r.json()
    except Exception:
        data = {"error": r.text}
    data["_status_code"] = r.status_code
    return data

def github_branch_sha(owner: str, repo: str, branch: str, token: str) -> Optional[str]:
    ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}"
    r = requests.get(ref_url, headers=github_headers(token))
    if r.status_code != 200:
        return None
    return r.json().get("object", {}).get("sha")

def github_branch_exists(owner: str, repo: str, branch: str, token: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}"
    r = requests.get(url, headers=github_headers(token))
    return r.status_code == 200

def github_tree(owner: str, repo: str, branch: str, token: str) -> Dict:
    sha = github_branch_sha(owner, repo, branch, token)
    if not sha:
        return {"error": f"Cannot resolve branch '{branch}'"}
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}"
    r = requests.get(tree_url, headers=github_headers(token), params={"recursive": 1})
    if r.status_code != 200:
        return {"error": f"tree error: {r.status_code} {r.text}"}
    return r.json()

def github_blob(owner: str, repo: str, sha: str, token: str) -> Optional[bytes]:
    url = f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{sha}"
    r = requests.get(url, headers=github_headers(token))
    if r.status_code != 200:
        return None
    data = r.json()
    if data.get("encoding") == "base64":
        return base64.b64decode(data["content"])
    return None

def github_get_json_file(owner: str, repo: str, path: str, branch: str, token: str) -> Optional[Dict]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = requests.get(url, headers=github_headers(token), params={"ref": branch})
    if r.status_code != 200:
        return None
    data = r.json()
    if isinstance(data, dict) and data.get("encoding") == "base64":
        try:
            raw = base64.b64decode(data["content"])
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None
    return None

def github_create_root_commit_from_empty_tree(owner: str, repo: str, token: str, message: str) -> Tuple[bool, Optional[str], str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/git/commits"
    payload = {"message": message, "tree": EMPTY_TREE_SHA, "parents": []}
    r = requests.post(url, headers=github_headers(token), json=payload)
    if r.status_code != 201:
        try:
            err = r.json()
        except Exception:
            err = {"error": r.text}
        return False, None, f"{r.status_code}: {err}"
    return True, r.json().get("sha"), "created"

def create_clean_branch(owner: str, repo: str, new_branch: str, token: str) -> Tuple[bool, str]:
    ok, commit_sha, msg = github_create_root_commit_from_empty_tree(
        owner, repo, token, f"Initialize clean branch '{new_branch}'"
    )
    if not ok or not commit_sha:
        return False, f"Failed to create root commit from empty tree: {msg}"
    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
    payload = {"ref": f"refs/heads/{new_branch}", "sha": commit_sha}
    r = requests.post(url, headers=github_headers(token), json=payload)
    if r.status_code != 201:
        try:
            err = r.json()
        except Exception:
            err = {"error": r.text}
        return False, f"{r.status_code}: {err}"
    return True, "created"

def write_branch_meta(owner: str, repo: str, branch: str, token: str, local_folder: str) -> Dict:
    existing = github_get_json_file(owner, repo, META_FILENAME, branch, token) or {}
    schema = existing.get("schema", 1)
    mappings = existing.get("mappings", [])

    mid = machine_id()
    nowz = datetime.now(timezone.utc).isoformat()
    entry = {
        "machine_id": mid,
        "machine_name": machine_name(),
        "path": local_folder,
        "os": platform.system(),
        "last_updated": nowz,
    }
    replaced = False
    for i, m in enumerate(mappings):
        if m.get("machine_id") == mid:
            mappings[i] = entry
            replaced = True
            break
    if not replaced:
        mappings.append(entry)

    meta = {
        "schema": schema,
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "mappings": mappings,
        "updated_at": nowz,
    }
    content = json.dumps(meta, indent=2).encode("utf-8")
    res = github_put_file(owner, repo, META_FILENAME, branch, token, content, message=f"Update {META_FILENAME} for branch mapping")
    return {"status_code": res.get("_status_code", 0), "result": res}

def pick_mapped_folder(meta: Optional[Dict]) -> Optional[str]:
    if not meta:
        return None
    mids = meta.get("mappings", [])
    if not mids:
        return None
    mid = machine_id()
    for m in mids:
        if m.get("machine_id") == mid and m.get("path"):
            return m.get("path")
    for m in mids:
        if m.get("path"):
            return m.get("path")
    return None

def github_branch_last_update(owner: str, repo: str, branch: str, token: str) -> Optional[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    r = requests.get(url, headers=github_headers(token), params={"sha": branch, "per_page": 1})
    if r.status_code != 200:
        return None
    arr = r.json()
    if not isinstance(arr, list) or not arr:
        return None
    commit = arr[0].get("commit", {})
    date = (commit.get("committer") or {}).get("date") or (commit.get("author") or {}).get("date")
    return date

# ------------------- Flask App -------------------

app = Flask(__name__, static_folder=resource_path("static"), template_folder=resource_path("templates"))

STATE = {
    "selected_folder": None,  # session-only
    "owner": _persist.get("owner", ""),
    "repo": _persist.get("repo", ""),
    "branch": _persist.get("branch", DEFAULT_BRANCH),
}

def persist_now():
    _persist["owner"] = STATE["owner"]
    _persist["repo"] = STATE["repo"]
    _persist["branch"] = STATE["branch"]
    save_persisted_state(_persist)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        mapped = None
        if STATE["owner"] and STATE["repo"] and STATE["branch"]:
            mapped = lookup_folder(_persist, STATE["owner"], STATE["repo"], STATE["branch"])
            if not mapped:
                tok = get_token()
                if tok:
                    meta = github_get_json_file(STATE["owner"], STATE["repo"], META_FILENAME, STATE["branch"], tok)
                    mapped = pick_mapped_folder(meta)
        return jsonify({
            "owner": STATE["owner"],
            "repo": STATE["repo"],
            "branch": STATE["branch"],
            "has_token": get_token() is not None,
            "selected_folder": STATE["selected_folder"],
            "mapped_folder": mapped,
        })
    data = request.get_json(force=True)
    STATE["owner"] = data.get("owner", "").strip()
    STATE["repo"] = data.get("repo", "").strip()
    STATE["branch"] = data.get("branch", DEFAULT_BRANCH).strip() or DEFAULT_BRANCH
    token = (data.get("token") or "").strip()
    if token:
        set_token(token)
    persist_now()
    return jsonify({"status": "ok"})

@app.route("/api/branches", methods=["GET"])
def api_branches():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner = STATE["owner"]
    repo = STATE["repo"]
    if not (owner and repo):
        return jsonify({"error": "Missing owner/repo"}), 400
    ok, msg, repo_obj = ensure_repo_exists(owner, repo, token)
    if not ok:
        return jsonify({"error": msg}), 400
    default_branch = (repo_obj or {}).get("default_branch")

    names = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/branches"
        r = requests.get(url, headers=github_headers(token), params={"per_page": 100, "page": page})
        if r.status_code != 200:
            break
        arr = r.json()
        if not isinstance(arr, list) or not arr:
            break
        names.extend([b.get("name") for b in arr if "name" in b])
        if len(arr) < 100:
            break
        page += 1
    names = sorted(set([b for b in names if b]))

    out = []
    for b in names:
        meta = github_get_json_file(owner, repo, META_FILENAME, b, token)
        mapped = pick_mapped_folder(meta)
        last = github_branch_last_update(owner, repo, b, token)
        out.append({"name": b, "mapped_folder": mapped, "is_default": (b == default_branch), "last_updated": last})
    return jsonify({"branches": out, "default_branch": default_branch})

@app.route("/api/create-branch", methods=["POST"])
def api_create_branch():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner = STATE["owner"]
    repo = STATE["repo"]
    data = request.get_json(force=True)
    new_branch = data.get("name", "").strip()
    if not (owner and repo and new_branch):
        return jsonify({"error": "Missing owner/repo or new branch name"}), 400

    # idempotent: succeed if already exists
    if github_branch_exists(owner, repo, new_branch, token):
        STATE["branch"] = new_branch
        persist_now()
        return jsonify({"status": "exists", "branch": new_branch, "base": "clean"})

    ok, msg = create_clean_branch(owner, repo, new_branch, token)
    if not ok:
        return jsonify({"error": msg}), 400

    STATE["branch"] = new_branch
    persist_now()
    return jsonify({"status": "created", "branch": new_branch, "base": "clean"})

@app.route("/api/scan", methods=["GET"])
def api_scan():
    base = STATE["selected_folder"]
    if not base:
        return jsonify({"error": "No folder selected"}), 400
    base_path = Path(base)
    if not base_path.exists():
        return jsonify({"error": "Selected folder does not exist"}), 400
    files = list_files(base_path)
    return jsonify({"files": files, "count": len(files)})

def iter_upload(owner: str, repo: str, branch: str, base_path: Path, token: str) -> Iterable[bytes]:
    files = list_files(base_path)
    total = len(files)
    sent = 0
    yield (json.dumps({"event": "start", "total": total}) + "\n").encode("utf-8")
    for f in files:
        rel = f["relative_path"]
        p = base_path / rel
        try:
            content = p.read_bytes()
            resp = github_put_file(owner, repo, rel, branch, token, content, message=f"Upload {rel}")
            code = resp.get("_status_code", 0)
            err = None if 200 <= code < 300 else resp
        except Exception as e:
            code, err = 0, {"error": str(e)}
        sent += 1
        yield (json.dumps({"event": "file", "path": rel, "status_code": code, "error": err, "done": sent, "total": total}) + "\n").encode("utf-8")
    yield (json.dumps({"event": "end", "total": total}) + "\n").encode("utf-8")

@app.route("/api/upload", methods=["POST"])
def api_upload():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner = STATE["owner"]
    repo = STATE["repo"]
    branch = STATE["branch"]
    base = STATE["selected_folder"]
    if not (owner and repo and base):
        return jsonify({"error": "Missing owner/repo or selected folder"}), 400
    ok, msg, _repo_obj = ensure_repo_exists(owner, repo, token)
    if not ok:
        return jsonify({"error": msg}), 400

    base_path = Path(base)

    # Persist mapping for download convenience
    set_folder_map(_persist, owner, repo, branch, str(base_path))
    _ = write_branch_meta(owner, repo, branch, token, str(base_path))
    persist_now()

    return Response(stream_with_context(iter_upload(owner, repo, branch, base_path, token)),
                    mimetype="application/x-ndjson")

@app.route("/api/download", methods=["POST"])
def api_download():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner = STATE["owner"]
    repo = STATE["repo"]
    branch = STATE["branch"]

    base = None
    meta = github_get_json_file(owner, repo, META_FILENAME, branch, token)
    mapped = pick_mapped_folder(meta)
    if mapped:
        base = mapped
    if not base:
        base = lookup_folder(_persist, owner, repo, branch)
    if not base and STATE["selected_folder"]:
        base = STATE["selected_folder"]
    if not (owner and repo and base):
        return jsonify({"error": "Missing owner/repo or resolved folder"}), 400

    ok, msg, _repo_obj = ensure_repo_exists(owner, repo, token)
    if not ok:
        return jsonify({"error": msg}), 400

    base_path = Path(base)
    try:
        base_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return jsonify({"error": f"Failed to create target folder '{base}': {e}"}), 400

    tree = github_tree(owner, repo, branch, token)
    if "error" in tree:
        return jsonify(tree), 400

    written = []
    for item in tree.get("tree", []):
        if item.get("type") == "blob":
            path = item["path"]
            blob = github_blob(owner, repo, item["sha"], token)
            if blob is None:
                continue
            target = base_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as f:
                f.write(blob)
            written.append(path)

    set_folder_map(_persist, owner, repo, branch, str(base_path))
    persist_now()

    return jsonify({"downloaded": written, "total": len(written), "used_path": str(base_path)})

@app.route("/api/sync-multi", methods=["POST"])
def api_sync_multi():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner, repo = STATE["owner"], STATE["repo"]
    data = request.get_json(force=True)
    branches = data.get("branches", [])
    if not isinstance(branches, list) or not branches:
        return jsonify({"error": "No branches specified"}), 400

    results = {}
    for branch in branches:
        try:
            meta = github_get_json_file(owner, repo, META_FILENAME, branch, token)
            target = pick_mapped_folder(meta) or lookup_folder(_persist, owner, repo, branch) or STATE["selected_folder"]
            if not target:
                results[branch] = {"error": "No mapping or selected folder available"}
                continue
            base_path = Path(target)
            base_path.mkdir(parents=True, exist_ok=True)
            tree = github_tree(owner, repo, branch, token)
            if "error" in tree:
                results[branch] = tree
                continue
            written = []
            for item in tree.get("tree", []):
                if item.get("type") == "blob":
                    blob = github_blob(owner, repo, item["sha"], token)
                    if not blob: 
                        continue
                    dest = base_path / item["path"]
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with open(dest, "wb") as f:
                        f.write(blob)
                    written.append(item["path"])
            set_folder_map(_persist, owner, repo, branch, str(base_path))
            results[branch] = {"downloaded": len(written), "folder": str(base_path)}
        except Exception as e:
            results[branch] = {"error": str(e)}
    persist_now()
    return jsonify(results)

# ------------------- PyWebView glue -------------------

try:
    import webview

    class JSBridge:
        def select_folder(self):
            win = webview.windows[0]
            result = win.create_file_dialog(webview.FOLDER_DIALOG)
            if result and len(result) > 0:
                STATE["selected_folder"] = result[0]
                if STATE["owner"] and STATE["repo"] and STATE["branch"]:
                    set_folder_map(_persist, STATE["owner"], STATE["repo"], STATE["branch"], STATE["selected_folder"])
                return {"selected_folder": STATE["selected_folder"]}
            return {"selected_folder": None}

    def start_server():
        app.run(host="127.0.0.1", port=5555, debug=False)

    if __name__ == "__main__":
        t = threading.Thread(target=start_server, daemon=True)
        t.start()
        window = webview.create_window(
            "GitHub Cloud Backup",
            "http://127.0.0.1:5555",
            width=1200,
            height=780,
            js_api=JSBridge()
        )
        webview.start(debug=False)
except Exception:
    # Fallback to plain Flask if pywebview not present
    if __name__ == "__main__":
        app.run(host="127.0.0.1", port=5555, debug=False)
