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
        "Authorization": f"token {token}",   # classic PATs need "token", not "Bearer"
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

def github_get_file_sha_if_exists(owner: str, repo: str, path: str, branch: str, token: str):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = requests.get(url, headers=github_headers(token), params={"ref": branch})
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, dict):
            return data.get("sha")
    return None

def put_file_overwrite(owner: str, repo: str, branch: str, token: str,
                       rel_path: str, content_bytes: bytes, message: str = None):
    """
    Always overwrite: if file exists, include its sha; otherwise create.
    Returns a dict with "_status_code" so existing code paths still work.
    """
    sha = github_get_file_sha_if_exists(owner, repo, rel_path, branch, token)
    commit_msg = message or f"Update {rel_path}"
    resp = github_put_file(owner, repo, rel_path, branch, token,
                           content_bytes, message=commit_msg, sha=sha) or {}
    code = resp.get("_status_code", 0)
    if code == 409:
        # fetch fresh sha and retry once
        sha = github_get_file_sha_if_exists(owner, repo, rel_path, branch, token)
        resp = github_put_file(owner, repo, rel_path, branch, token,
                               content_bytes, message=f"Force overwrite {rel_path}", sha=sha)
        code = resp.get("_status_code", 0)
    resp["_status_code"] = code
    return resp


def github_put_file(owner: str, repo: str, path: str, branch: str, token: str,
                    content_bytes: bytes, message: str, sha: Optional[str] = None) -> Dict:
    """
    Create or update a file via GitHub Contents API.
    If sha is provided, it updates; otherwise it creates.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    b64 = base64.b64encode(content_bytes).decode("ascii")
    payload = {"message": message, "content": b64, "branch": branch}
    if sha:
        payload["sha"] = sha
    r = requests.put(url, headers=github_headers(token), json=payload)
    out = {}
    try:
        out = r.json()
    except Exception:
        out = {"_text": r.text}
    out["_status_code"] = r.status_code
    return out

def github_branch_sha(owner: str, repo: str, branch: str, token: str) -> Optional[str]:
    # Correct endpoint: /git/refs/heads/{branch}
    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}"
    r = requests.get(url, headers=github_headers(token))
    if r.status_code == 200:
        data = r.json()
        obj = data.get("object") or {}
        sha = obj.get("sha") or data.get("sha")
        if isinstance(sha, str) and len(sha) == 40:
            return sha

    # Fallback to branches API
    url2 = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}"
    r2 = requests.get(url2, headers=github_headers(token))
    if r2.status_code == 200:
        d2 = r2.json()
        sha = (d2.get("commit") or {}).get("sha")
        if isinstance(sha, str) and len(sha) == 40:
            return sha
    return None

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
    """
    Create a root commit (no parents) pointing to the empty tree.
    Returns (ok, error_message, commit_sha).
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/commits"
    payload = {"message": message, "tree": EMPTY_TREE_SHA, "parents": []}
    r = requests.post(url, headers=github_headers(token), json=payload)
    if r.status_code not in (200, 201):
        return False, f"commit error: {r.status_code} {r.text}", ""
    sha = (r.json() or {}).get("sha") or ""
    if not isinstance(sha, str) or len(sha) != 40:
        return False, f"commit sha invalid: {sha!r}", ""
    return True, None, sha

def github_create_ref(owner: str, repo: str, ref: str, sha: str, token: str) -> Tuple[bool, str]:
    """
    Create a new Git reference (e.g., refs/heads/branch-name) pointing to a commit SHA.
    Returns (ok, message).
    """
    if not isinstance(sha, str) or len(sha) != 40:
        return False, f"ref error: invalid sha length {len(sha) if isinstance(sha, str) else 'N/A'}"
    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
    payload = {"ref": ref, "sha": sha}
    r = requests.post(url, headers=github_headers(token), json=payload)
    if r.status_code in (200, 201):
        return True, "OK"
    if r.status_code == 422 and "Reference already exists" in r.text:
        # Treat as success for idempotency
        return True, "exists"
    return False, f"ref error: {r.status_code} {r.text}"


def create_clean_branch(owner: str, repo: str, branch: str, token: str) -> Tuple[bool, str]:
    """
    Create an orphan (clean) branch: a root commit with no parents, then a ref.
    Idempotent if the ref already exists.
    """
    # Already exists?
    if github_branch_sha(owner, repo, branch, token):
        return True, "exists"

    ok, err, commit_sha = github_create_root_commit_from_empty_tree(
        owner, repo, token, f"Initialize clean branch {branch}"
    )
    if not ok:
        return False, err or "failed to create root commit"

    if not commit_sha or len(commit_sha) != 40:
        return False, f"invalid commit sha: {commit_sha!r}"

    ok, msg = github_create_ref(owner, repo, f"refs/heads/{branch}", commit_sha, token)
    if not ok and "exists" not in (msg or ""):
        return False, msg
    return True, "created" if ok else "exists"

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

# Fetch branches (names only)
def github_list_branches(owner: str, repo: str, token: str) -> list:
    url = f"https://api.github.com/repos/{owner}/{repo}/branches"
    out, page = [], 1
    while True:
        r = requests.get(url, headers=github_headers(token), params={"per_page": 100, "page": page})
        if r.status_code != 200:
            break
        batch = r.json() or []
        out.extend([b.get("name") for b in batch if isinstance(b, dict) and b.get("name")])
        if len(batch) < 100:
            break
        page += 1
    return out

# Load remote .ghcb.json for a branch and pick a folder for THIS machine
def mapped_folder_from_remote(owner: str, repo: str, branch: str, token: str) -> str | None:
    try:
        meta = github_get_json_file(owner, repo, ".ghcb.json", branch, token)
        if not isinstance(meta, dict):
            return None
        # Reuse your existing resolution logic (hostname/user-specific mapping)
        base = pick_mapped_folder(meta)
        return str(base) if base else None
    except Exception:
        return None

def hydrate_folders_map_from_remote_on_boot():
    """
    On app start: read remote .ghcb.json for each branch and persist any mapped folders
    into ~/.github_cloud_backup_app.json so OneClick flows work immediately.
    Non-fatal if token/owner/repo are missing.
    """
    try:
        token = get_token()
        owner = STATE.get("owner")
        repo  = STATE.get("repo")
        if not (token and owner and repo):
            return

        # Get all branches (fallback to current if list fails)
        branches = github_list_branches(owner, repo, token) or [STATE.get("branch")] or []
        if not branches:
            return

        fmap = _persist.setdefault("folders_map", {})

        updated = False
        for br in branches:
            # If already known, skip
            key = f"{owner}/{repo}/{br}"
            if fmap.get(key):
                continue

            base = mapped_folder_from_remote(owner, repo, br, token)
            if base:
                # Record mapping; do not overwrite an existing one
                fmap[key] = base
                updated = True

        if updated:
            save_persisted_state(_persist)
    except Exception:
        # Never crash app on boot; just skip hydration
        pass


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
            resp = put_file_overwrite(owner, repo, branch, token, rel, content, message=f"Upload {rel}")
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

@app.route("/api/delete-branch", methods=["POST"])
def api_delete_branch():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400

    owner = STATE.get("owner")
    repo = STATE.get("repo")
    data = request.get_json(force=True) or {}
    branch = (data.get("name") or "").strip()

    if not (owner and repo and branch):
        return jsonify({"error": "Missing owner/repo or branch name"}), 400

    # Don’t allow deleting main/master for safety
    if branch in ("main", "master"):
        return jsonify({"error": f"Refusing to delete protected branch '{branch}'"}), 400

    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}"
    r = requests.delete(url, headers=github_headers(token))

    if r.status_code == 204:
        return jsonify({"status": "deleted", "branch": branch})
    elif r.status_code == 404:
        return jsonify({"status": "not_found", "branch": branch})
    else:
        return jsonify({"error": f"delete error: {r.status_code} {r.text}"}), 400

@app.route("/api/download-checked-to-path", methods=["POST"])
def api_download_checked_to_path():
    """
    Download checked branches to an explicit folder chosen by the user.
    Request JSON: {"branches": ["br1","br2", ...], "target_folder": "C:/some/folder"}
    Streams NDJSON progress: start/context/file/note/context_end/end
    """
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400

    owner = STATE.get("owner")
    repo  = STATE.get("repo")

    data = request.get_json(silent=True) or {}
    branches = data.get("branches") or []
    target_folder = (data.get("target_folder") or "").strip()

    if not owner or not repo:
        return jsonify({"error": "Missing owner/repo"}), 400
    if not branches:
        return jsonify({"error": "No branches specified"}), 400
    if not target_folder:
        return jsonify({"error": "No target folder provided"}), 400

    base_path = Path(target_folder)
    try:
        base_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return jsonify({"error": f"Cannot create target folder: {e}"}), 400

    def streamer():
        yield (json.dumps({"event": "start", "total": 0}) + "\n").encode("utf-8")

        ok, msg, _repo = ensure_repo_exists(owner, repo, token)
        if not ok:
            yield (json.dumps({"event": "note",
                               "message": f"[{owner}/{repo}] {msg}."}) + "\n").encode("utf-8")
            yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")
            return

        for br in branches:
            target_root = base_path / br  # per-branch subfolder
            yield (json.dumps({"event": "context",
                               "owner": owner, "repo": repo, "branch": br,
                               "base": str(target_root)}) + "\n").encode("utf-8")

            try:
                target_root.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                yield (json.dumps({"event": "note",
                                   "message": f"[{br}] Cannot create folder: {e}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue

            # List repo tree for the branch
            try:
                tree = github_tree(owner, repo, br, token)
            except Exception as e:
                yield (json.dumps({"event": "note",
                                   "message": f"[{owner}/{repo}:{br}] Failed listing tree: {e}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue

            for item in tree.get("tree", []):
                if item.get("type") != "blob":
                    continue
                rel = item["path"]
                try:
                    blob = github_blob(owner, repo, item["sha"], token)
                    if blob is None:
                        yield (json.dumps({"event": "note",
                                           "message": f"[{owner}/{repo}:{br}] Skip {rel}: blob missing."}) + "\n").encode("utf-8")
                        continue
                    outp = target_root / rel
                    outp.parent.mkdir(parents=True, exist_ok=True)
                    with outp.open("wb") as f:
                        f.write(blob)
                    yield (json.dumps({"event": "file",
                                       "path": str(outp), "status_code": 200}) + "\n").encode("utf-8")
                except Exception as e:
                    yield (json.dumps({"event": "note",
                                       "message": f"[{owner}/{repo}:{br}] Error {rel}: {e}."}) + "\n").encode("utf-8")

            yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")

        yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")

    return Response(stream_with_context(streamer()), mimetype="application/x-ndjson")

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


def iter_skip(reason: str):
    """
    Stream a minimal NDJSON no-op with a reason message.
    Used by mapped endpoints when nothing to do.
    """
    yield (json.dumps({"event": "start", "total": 0}) + "\n").encode("utf-8")
    yield (json.dumps({"event": "note", "message": reason}) + "\n").encode("utf-8")
    yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")

@app.route("/api/create-branch", methods=["POST"])
def api_create_branch():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400

    owner = STATE.get("owner")
    repo  = STATE.get("repo")
    data = request.get_json(force=True) or {}
    new_branch = (data.get("name") or "").strip()

    if not (owner and repo and new_branch):
        return jsonify({"error": "Missing owner/repo or new branch name"}), 400

    # Idempotent: if exists, just switch to it
    if github_branch_exists(owner, repo, new_branch, token):
        STATE["branch"] = new_branch
        persist_now()
        return jsonify({"status": "exists", "branch": new_branch, "base": "clean"})

    # Create orphan (clean) branch
    ok, msg = create_clean_branch(owner, repo, new_branch, token)
    if not ok:
        return jsonify({"error": msg}), 400

    # --- ADD README ON NEW BRANCH (best-effort) ----------------------------
    try:
        readme_path = "README.md"
        # Optional: include a tiny, useful README
        content = f"# {repo}:{new_branch}\n\n" \
                  f"Created as a clean/orphan branch.\n\n" \
                  f"- Owner/Repo: `{owner}/{repo}`\n" \
                  f"- Branch: `{new_branch}`\n" \
                  f"- Created by GitHub Cloud Backup app.\n"
        content_bytes = content.encode("utf-8")

        # If you have this helper, it’s perfect to handle create/update logic:
        #   github_put_file(owner, repo, path, branch, token, content_bytes, message)
        # If README already exists (unlikely on a fresh orphan), you can fetch its SHA first:
        sha = github_get_file_sha_if_exists(owner, repo, readme_path, new_branch, token)
        res = github_put_file(
            owner, repo, readme_path, new_branch, token, content_bytes,
            message=f"Add starter README to {new_branch}",
            sha=sha  # many helpers accept sha=None; pass when you have it
        )
        # You can ignore ‘res’ or log it
    except Exception:
        # Best-effort; don’t fail branch creation if README write hiccups
        pass
    # -----------------------------------------------------------------------

    STATE["branch"] = new_branch
    persist_now()
    return jsonify({"status": "created", "branch": new_branch, "base": "clean"})

@app.route("/api/download-all-mapped", methods=["POST"])
def api_download_all_mapped():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    fmap = _persist.get("folders_map", {})
    if not fmap:
        # keep behavior consistent with other mapped endpoints: stream a note
        return Response(stream_with_context(iter_skip("No persisted mappings found.")),
                        mimetype="application/x-ndjson")

    def streamer():
        yield (json.dumps({"event": "start", "total": 0}) + "\n").encode("utf-8")
        # fmap is flat: key "owner/repo/branch" -> folder
        for key, base in fmap.items():
            try:
                owner, repo, br = key.split("/", 2)
            except ValueError:
                # unexpected key format; skip
                continue
            # ensure repo exists / credentials OK once per repo
            ok, msg, _repo_obj = ensure_repo_exists(owner, repo, token)
            if not ok:
                yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}] {msg}."}) + "\n").encode("utf-8")
                continue

            base_path = Path(base)
            # Announce context
            yield (json.dumps({"event": "context", "owner": owner, "repo": repo, "branch": br, "base": str(base_path)}) + "\n").encode("utf-8")
            try:
                base_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}:{br}] Cannot create base folder: {e}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue
            # Download tree
            try:
                tree = github_tree(owner, repo, br, token)
            except Exception as e:
                yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}:{br}] Failed listing tree: {e}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue
            for item in tree.get("tree", []):
                if item.get("type") != "blob":
                    continue
                path = item["path"]
                try:
                    blob = github_blob(owner, repo, item["sha"], token)
                    if blob is None:
                        yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}:{br}] Skip {path}: blob missing."}) + "\n").encode("utf-8")
                        continue
                    target = base_path / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("wb") as f:
                        f.write(blob)
                    yield (json.dumps({"event": "file", "path": str(target), "status_code": 200}) + "\n").encode("utf-8")
                except Exception as e:
                    yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}:{br}] Error {path}: {e}."}) + "\n").encode("utf-8")
            yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
        yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")

    return Response(stream_with_context(streamer()), mimetype="application/x-ndjson")

@app.route("/api/upload-multi-mapped", methods=["POST"])
def api_upload_multi_mapped():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner, repo = STATE["owner"], STATE["repo"]
    data = request.get_json(force=True) or {}
    branches = data.get("branches") or []
    if not branches:
        return jsonify({"error": "No branches specified"}), 400
    ok, msg, _ = ensure_repo_exists(owner, repo, token)
    if not ok:
        return jsonify({"error": msg}), 400

    def streamer():
        yield (json.dumps({"event":"start","total":0}) + "\n").encode()
        for br in branches:
            # resolve mapped folder for this branch
            meta = github_get_json_file(owner, repo, META_FILENAME, br, token)
            base = pick_mapped_folder(meta) or lookup_folder(_persist, owner, repo, br)
            if not base:
                yield (json.dumps({"event":"note",
                                   "message": f"[{owner}/{repo}:{br}] No mapped folder, skipping."}) + "\n").encode()
                continue
            base_path = Path(base)
            if not base_path.exists():
                yield (json.dumps({"event":"note",
                                   "message": f"[{owner}/{repo}:{br}] Folder missing: {base}"}) + "\n").encode()
                continue
            yield (json.dumps({"event":"context",
                               "owner": owner, "repo": repo, "branch": br,
                               "base": str(base_path)}) + "\n").encode()
            for f in list_files(base_path):
                rel = f["relative_path"]
                try:
                    content = (base_path / rel).read_bytes()
                    resp = put_file_overwrite(owner, repo, br, token, rel, content)
                    code = resp.get("_status_code", 0)
                    err = None if 200 <= code < 300 else resp
                except Exception as e:
                    code, err = 0, {"error": str(e)}
                yield (json.dumps({"event":"file","path":rel,
                                   "status_code": code,"error": err}) + "\n").encode()
            yield (json.dumps({"event":"context_end","branch": br}) + "\n").encode()
        yield (json.dumps({"event":"end","total":0}) + "\n").encode()

    return Response(stream_with_context(streamer()), mimetype="application/x-ndjson")


@app.route("/api/sync-multi", methods=["POST"])
def api_sync_multi():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400
    owner, repo = STATE["owner"], STATE["repo"]

    data = request.get_json(force=True) or {}
    branches = data.get("branches", [])
    if not isinstance(branches, list) or not branches:
        return jsonify({"error": "No branches specified"}), 400

    def streamer():
        # overall start (we’ll compute a rough total = sum of blobs across branches)
        yield (json.dumps({"event": "start", "total": 0}) + "\n").encode("utf-8")

        for branch in branches:
            try:
                # Resolve target folder (same logic you had)
                meta = github_get_json_file(owner, repo, META_FILENAME, branch, token)
                target = pick_mapped_folder(meta) or lookup_folder(_persist, owner, repo, branch) or STATE.get("selected_folder")
                if not target:
                    yield (json.dumps({"event":"note","message": f"[{branch}] No mapping or selected folder available."}) + "\n").encode("utf-8")
                    continue

                base_path = Path(target)
                try:
                    base_path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    yield (json.dumps({"event":"note","message": f"[{branch}] Cannot create folder: {e}."}) + "\n").encode("utf-8")
                    continue

                # Announce branch context
                yield (json.dumps({"event": "context",
                                   "owner": owner, "repo": repo,
                                   "branch": branch, "base": str(base_path)}) + "\n").encode("utf-8")

                # List tree and compute per-branch total files
                tree = github_tree(owner, repo, branch, token)
                if isinstance(tree, dict) and tree.get("error"):
                    yield (json.dumps({"event":"note","message": f"[{branch}] {tree.get('error')}"}) + "\n").encode("utf-8")
                    yield (json.dumps({"event":"context_end","branch": branch}) + "\n").encode("utf-8")
                    continue

                items = [it for it in (tree.get("tree") or []) if it.get("type") == "blob"]
                for item in items:
                    rel = item["path"]
                    try:
                        blob = github_blob(owner, repo, item["sha"], token)
                        if not blob:
                            yield (json.dumps({"event":"note","message": f"[{branch}] Skip {rel}: blob missing."}) + "\n").encode("utf-8")
                            continue
                        dest = base_path / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with open(dest, "wb") as f:
                            f.write(blob)
                        # Stream one file completion
                        yield (json.dumps({"event":"file","path": str(dest), "status_code": 200}) + "\n").encode("utf-8")
                    except Exception as e:
                        yield (json.dumps({"event":"note","message": f"[{branch}] Error {rel}: {e}."}) + "\n").encode("utf-8")

                # Persist the mapping like before
                set_folder_map(_persist, owner, repo, branch, str(base_path))

                # Close context for branch
                yield (json.dumps({"event":"context_end","branch": branch}) + "\n").encode("utf-8")

            except Exception as e:
                yield (json.dumps({"event":"note","message": f"[{branch}] {e}."}) + "\n").encode("utf-8")

        # Save state and finish
        persist_now()
        yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")

    return Response(stream_with_context(streamer()),
                    mimetype="application/x-ndjson")

def load_remote_folders_map(owner, repo, branch, token):
    try:
        data = github_get_json_file(owner, repo, ".ghcb.json", branch, token)
        if data and isinstance(data, dict):
            fmap = data.get("folders_map")
            if isinstance(fmap, dict):
                return fmap
    except Exception as e:
        print("Failed to load remote .ghcb.json:", e)
    return {}

@app.route("/api/upload-all-mapped", methods=["POST"])
def api_upload_all_mapped():
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400

    fmap = _persist.get("folders_map", {})

    # 🔹 If no local mappings, try to pull from GitHub
    if not fmap:
        remote_map = load_remote_folders_map(STATE["owner"], STATE["repo"], STATE["branch"], token)
        fmap.update(remote_map)
        _persist["folders_map"] = fmap
        save_persisted_state(_persist)

    if not fmap:
        return Response(stream_with_context(iter_skip("No persisted mappings found.")),
                        mimetype="application/x-ndjson")

    def streamer():
        yield (json.dumps({"event": "start", "total": 0}) + "\n").encode("utf-8")
        # fmap is flat: "owner/repo/branch" -> folder
        for key, base in fmap.items():
            try:
                owner, repo, br = key.split("/", 2)
            except ValueError:
                continue
            ok, msg, _repo_obj = ensure_repo_exists(owner, repo, token)
            if not ok:
                yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}] {msg}."}) + "\n").encode("utf-8")
                continue
            base_path = Path(base)
            yield (json.dumps({"event": "context", "owner": owner, "repo": repo, "branch": br, "base": str(base_path)}) + "\n").encode("utf-8")
            if not base_path.exists():
                yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}:{br}] Local folder not found: {base}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue
            try:
                # Stream file uploads for this branch/folder
                for chunk in iter_upload(owner, repo, br, base_path, token):
                    yield chunk
            except Exception as e:
                yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}:{br}] Upload error: {e}."}) + "\n").encode("utf-8")
            yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
        yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")

    return Response(stream_with_context(streamer()), mimetype="application/x-ndjson")


@app.route("/api/download-checked-mapped", methods=["POST"])
def api_download_checked_mapped():
    """
    Download the specified branches' files to their mapped folders only
    (preferring .ghcb.json mapping, then persisted mapping), ignoring the Selected Folder.
    Streams NDJSON for progress.
    """
    token = get_token()
    if not token:
        return jsonify({"error": "No GitHub token configured"}), 400

    owner = STATE.get("owner")
    repo = STATE.get("repo")
    if not (owner and repo):
        return jsonify({"error": "Missing owner/repo"}), 400

    data = request.get_json(silent=True) or {}
    branches = data.get("branches") or []
    if not branches:
        return jsonify({"error": "No branches specified"}), 400

    def resolve_mapped_folder(br):
        # Prefer .ghcb.json mapping
        meta = github_get_json_file(owner, repo, META_FILENAME, br, token)
        mapped = pick_mapped_folder(meta)
        if mapped:
            return mapped
        # Fallback to persisted mapping
        return lookup_folder(_persist, owner, repo, br)

    def streamer():
        yield (json.dumps({"event": "start", "total": 0}) + "\n").encode("utf-8")

        ok, msg, _ = ensure_repo_exists(owner, repo, token)
        if not ok:
            yield (json.dumps({"event": "note", "message": f"[{owner}/{repo}] {msg}."}) + "\n").encode("utf-8")
            yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")
            return

        for br in branches:
            base = resolve_mapped_folder(br)
            if not base:
                yield (json.dumps({"event": "note", "message": f"[{br}] No mapped folder found."}) + "\n").encode("utf-8")
                continue
            base_path = Path(base)
            yield (json.dumps({"event": "context", "owner": owner, "repo": repo, "branch": br, "base": str(base_path)}) + "\n").encode("utf-8")
            try:
                base_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                yield (json.dumps({"event": "note", "message": f"[{br}] Cannot create folder: {e}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue

            try:
                tree = github_tree(owner, repo, br, token)
            except Exception as e:
                yield (json.dumps({"event": "note", "message": f"[{br}] Failed listing tree: {e}."}) + "\n").encode("utf-8")
                yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")
                continue

            for item in tree.get("tree", []):
                if item.get("type") != "blob":
                    continue
                rel = item["path"]
                try:
                    blob = github_blob(owner, repo, item["sha"], token)
                    if blob is None:
                        yield (json.dumps({"event": "note", "message": f"[{br}] Skip {rel}: blob missing."}) + "\n").encode("utf-8")
                        continue
                    outp = base_path / rel
                    outp.parent.mkdir(parents=True, exist_ok=True)
                    with outp.open("wb") as f:
                        f.write(blob)
                    yield (json.dumps({"event": "file", "path": str(outp), "status_code": 200}) + "\n").encode("utf-8")
                except Exception as e:
                    yield (json.dumps({"event": "note", "message": f"[{br}] Error {rel}: {e}."}) + "\n").encode("utf-8")

            yield (json.dumps({"event": "context_end", "branch": br}) + "\n").encode("utf-8")

        yield (json.dumps({"event": "end", "total": 0}) + "\n").encode("utf-8")

    return Response(stream_with_context(streamer()), mimetype="application/x-ndjson")
# ------------------- PyWebView glue -------------------

try:
    import webview

    hydrate_folders_map_from_remote_on_boot()
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
            "Steam Game Cloud Backup - by BihiBihi",
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
