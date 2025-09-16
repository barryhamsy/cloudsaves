# GitHub Cloud Backup (PyWebView + Flask)

Back up and restore local folders to **GitHub branches** with a clean UI.  
Built with **Flask** (backend) and **PyWebView** (desktop wrapper).

> TL;DR: Pick a folder → **Upload** to a GitHub branch (clean/orphan).  
> Later, pick the branch → **Download** back to the original location.  
> Supports **multi-branch sync**, **live progress**, and **auto path mapping** via `.ghcb.json` stored in each branch.

---

## ✨ Features

- **Clean/orphan branch creation** by default (no history / not based on `main`).
- **Select local folder** to back up; scan and upload with **per-file progress** (live log via NDJSON).
- **Download** restores files to the **original location** using a saved mapping.
- **Branch list** with:
  - **Last updated** (from latest commit time),
  - **Mapped folder** (from `.ghcb.json`),
  - **Checkboxes** → **SYNC ALL CHECKED** (bulk download).
- **Current Branch dropdown** (UI can hide `main` if desired).
- **Repository mapping** persisted locally in `~/.github_cloud_backup_app.json` and in-repo as `.ghcb.json` for portability.
- Works standalone as a Flask app or as a packaged desktop app (Nuitka/Inno, PyInstaller).

---

## 🧱 Requirements

- Python **3.10+** recommended
- GitHub **Personal Access Token** (classic or fine-grained)
  - Public repos: `public_repo`
  - Private repos: `repo` (or fine-grained equivalent)
- OS: Windows/macOS/Linux

---

## 🔐 Token Storage (No-Keyring Edition)

This build **does not use keyring**. Your token is stored in **plaintext** inside your local config:

```
~/.github_cloud_backup_app.json
```

You can also supply `GITHUB_TOKEN` as an **environment variable**, which takes precedence.

> Want secure OS keychain storage instead? Use a build with `keyring` (Windows Credential Manager / macOS Keychain / Secret Service).

---

## 📁 Config File

`~/.github_cloud_backup_app.json`
```jsonc
{
  "owner": "your-username",
  "repo": "your-repo",
  "branch": "main",
  "token": "ghp_xxx",                   // only in no-keyring build
  "folders_map": {
    "your-username/your-repo/save-1": "C:\\Games\\Save1",
    "your-username/your-repo/save-2": "D:\\Backups\\Save2"
  }
}
```

Each branch also stores a repo-side mapping file:

`.ghcb.json` **(committed to the branch)**:
```json
{
  "schema": 1,
  "owner": "your-username",
  "repo": "your-repo",
  "branch": "save-1",
  "mappings": [
    {
      "machine_id": "SHA1(host|user|os|release)",
      "machine_name": "MYPC",
      "os": "Windows",
      "path": "C:\\Games\\Save1",
      "last_updated": "2025-09-17T00:00:00+00:00"
    }
  ],
  "updated_at": "2025-09-17T00:00:00+00:00"
}
```

The app prefers **machine-specific** mapping; otherwise the first valid path.

---

## 🚀 Run (Dev)

```bash
pip install -r requirements.txt
python app.py
# App will open a PyWebView window to http://127.0.0.1:5555
```

### Configure
1. **Owner/Repo** → Save  
2. Paste your **GitHub Token** → Save  
3. **Select Local Folder** → Scan → Upload  
4. For download, choose the **branch**, then **Download** (uses mapping from `.ghcb.json` or local map).

> The UI can optionally **hide `main`** from the dropdown and the checklist.  
> Multi-select branches and click **SYNC ALL CHECKED** to bulk download.

---

## 🧰 Build Options

You can ship this as a single EXE (Windows) with **Nuitka** or **PyInstaller**. The app includes a resource resolver so it can find `templates/` and `static/` whether they are bundled or installed next to the EXE.

### Option A — Bundle assets with Nuitka (single EXE)

```bat
nuitka --standalone --onefile ^
  --windows-icon-from-ico=cloudsaves.ico ^
  --windows-uac-admin ^
  --include-module=flask --include-module=jinja2 ^
  --include-data-dir=static=static ^
  --include-data-dir=templates=templates ^
  app.py
```

### Option B — Install assets with Inno Setup (don’t bundle in EXE)
Build without data dirs:
```bat
nuitka --standalone --onefile ^
  --windows-icon-from-ico=cloudsaves.ico ^
  --windows-uac-admin ^
  --include-module=flask --include-module=jinja2 ^
  app.py
```

In **Inno Setup**, ship the folders:

```ini
[Files]
Source: "dist\GitHubCloudBackup.exe"; DestDir: "{app}"
Source: "templates\*"; DestDir: "{app}\templates"; Flags: recursesubdirs createallsubdirs
Source: "static\*";    DestDir: "{app}\static";    Flags: recursesubdirs createallsubdirs
```

> The app resolves assets in this priority: **EXE dir** → `_MEIPASS` (temp bundle) → script dir.

### PyInstaller (alternative)

```bat
pyinstaller --noconfirm --clean --onefile ^
  --add-data "templates;templates" ^
  --add-data "static;static" ^
  --name GitHubCloudBackup app.py
```

---

## 🖱️ UI Walkthrough

- **Configure GitHub**
  - Owner / Repository
  - Current Branch (dropdown; `main` can be hidden)
  - Create **Clean Branch** (orphan starting from empty tree)
  - Token field (saved to config in no-keyring build)

- **Select Local Folder**
  - Browse for the folder you want to back up
  - **Scan** shows a table of files (path, size, SHA1)

- **Sync**
  - **Upload** → per-file live progress + log (NDJSON streaming)
  - **Download** → uses `.ghcb.json` mapping → writes files to mapped path
  - **Branch List** → check multiple → **SYNC ALL CHECKED**

---

## 🧪 API (Internal Endpoints)

- `GET /api/config` / `POST /api/config` — owner/repo/branch + token persistence
- `GET /api/branches` — list branches with mapping + last updated
- `POST /api/create-branch` — create clean/orphan branch (idempotent in newer builds)
- `GET /api/scan` — list files in selected folder
- `POST /api/upload` — NDJSON streaming per file
- `POST /api/download` — restore branch files to mapped folder
- `POST /api/sync-multi` — bulk download selected branches

---

## 🧩 Tips

- **Orphan branch** means zero history: first commit uses Git’s **empty tree SHA** so the branch starts clean.
- **Hide `main`** in UI to focus on content branches (toggle in `static/main.js` if you prefer).
- **Environment token** (`GITHUB_TOKEN`) overrides the JSON token.
- **Public vs Private** repo scopes: use `public_repo` for public-only projects; otherwise `repo`.

---

## 🛠️ Troubleshooting

- **`TemplateNotFound: index.html`**  
  Ensure `templates/` (and `static/`) are **available at runtime**. If using Inno, verify they are installed next to the EXE. If bundling with Nuitka/PyInstaller, include them via build flags.

- **Branch already exists (422)**  
  The server may report that the ref exists if a branch of that name is already present. Newer builds handle this idempotently and simply select the branch.

- **No token / 401**  
  Paste a valid GitHub token in the UI and click **Save** (or set `GITHUB_TOKEN` in the environment).

- **Progress bar not moving**  
  Ensure you’re running the packaged app or `python app.py` in a console—logs stream per file over NDJSON.

---

## 📄 License

MIT (feel free to adjust to your preference).

---

## 🙌 Acknowledgements

- Flask
- PyWebView
- Nuitka / PyInstaller
- GitHub REST API
