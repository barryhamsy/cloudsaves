let __CREATING_BRANCH = false;
let BRANCH_META = {}; // name -> {mapped_folder, last_updated, is_default}
let DEFAULT_BRANCH = null;
let LAST_CFG = {};

async function getJSON(url, opts={}){
  const r = await fetch(url, Object.assign({headers:{'Content-Type':'application/json'}}, opts));
  if(!r.ok){
    const t = await r.text();
    throw new Error(t || (r.status + ' ' + r.statusText));
  }
  const ct = r.headers.get('content-type') || '';
  if(ct.includes('application/x-ndjson')){
    // special case for upload stream; caller should handle via fetch()
    return r;
  }
  return r.json();
}
function log(line){
  const el = document.getElementById('log');
  el.textContent += line + "\n";
  el.scrollTop = el.scrollHeight;
}
function setMappedTip(mapped){
  const tip = document.getElementById('mapped-folder-tip');
  if(mapped){ tip.textContent = `Mapped folder for this branch: ${mapped}`; }
  else{ tip.textContent = ''; }
}
function fmtDateIsoLocal(iso){
  if(!iso) return '—';
  try{
    const d = new Date(iso);
    return d.toLocaleString();
  }catch(e){ return iso; }
}

async function refreshConfig(){
  try{
    const cfg = await getJSON('/api/config');
    LAST_CFG = cfg;
    document.getElementById('owner').value = cfg.owner || '';
    document.getElementById('repo').value = cfg.repo || '';
    document.getElementById('branch').value = cfg.branch || 'main';

    const dd = document.getElementById('branch-dd'); if(dd){ dd.value = cfg.branch || 'main'; }
    document.getElementById('selected-folder').value = cfg.selected_folder || '';
    document.getElementById('status-dot').classList.toggle('ok', !!cfg.has_token);
    document.getElementById('status-dot').title = cfg.has_token ? 'Token stored' : 'No token';
    setMappedTip(cfg.mapped_folder);
    updateUIState();
  }catch(e){ console.error(e); }
}

async function saveConfig(){
  const owner = document.getElementById('owner').value.trim();
  const repo = document.getElementById('repo').value.trim();
  const branch = document.getElementById('branch').value.trim() || 'main';
  const token = document.getElementById('token').value.trim();
  await getJSON('/api/config', {method:'POST', body:JSON.stringify({owner, repo, branch, token})});
  document.getElementById('token').value = '';
  document.getElementById('config-status').textContent = 'Saved.';
  await refreshConfig();
  await loadBranches();
  updateUIState();
}

async function selectFolder(){
  try{
    const result = await window.pywebview.api.select_folder();
    document.getElementById('selected-folder').value = result.selected_folder || '';
    await refreshConfig();
  }catch(e){
    alert('Folder dialog not available. Are we running in PyWebView?');
  }
}

function renderFiles(files){
  const box = document.getElementById('files');
  if(!files || files.length===0){
    box.innerHTML = '<div class="muted">No files found. Click Scan.</div>';
    return;
  }
  let html = `
    <div class="file-row" style="font-weight:700">
      <div>Path</div><div>Size (bytes)</div><div>SHA1</div>
    </div>`;
  for(const f of files){
    html += `
      <div class="file-row">
        <div>${f.relative_path}</div>
        <div>${f.size}</div>
        <div style="font-family:monospace">${f.sha1}</div>
      </div>`;
  }
  box.innerHTML = html;
}

async function scan(){
  try{
    const data = await getJSON('/api/scan');
    document.getElementById('scan-count').textContent = `${data.count} files`;
    renderFiles(data.files);
  }catch(e){
    log('Scan error: ' + e.message);
  }
}


function updateUIState(){
  const hasOwnerRepo = !!(LAST_CFG.owner && LAST_CFG.repo);
  const hasToken = !!LAST_CFG.has_token;
  const current = (document.getElementById('branch').value || '').trim();
  const meta = BRANCH_META[current] || {};
  const hasMapping = !!meta.mapped_folder;

  // Checklist indicators
  const ok = (b) => b ? '✅' : '⚠️';
  const el = (id) => document.getElementById(id);
  if (el('check-token')) el('check-token').textContent = `Token: ${ok(hasToken)}`;
  if (el('check-repo')) el('check-repo').textContent = `Repo access: ${ok(hasOwnerRepo)}`;
  if (el('check-branch')) el('check-branch').textContent = `Save Data List: ${ok(!!current)}`;
  if (el('check-mapping')) el('check-mapping').textContent = `Directory Mapping: ${ok(hasMapping)}`;

  // Enable/disable buttons based on readiness
  const buttons = [
    'btn-scan','btn-upload','btn-upload-mapped','btn-upload-checked-mapped','btn-upload-all-mapped','btn-download','sync-all'
  ];
  const enableAll = hasOwnerRepo && hasToken;
  for (const id of buttons){
    const b = document.getElementById(id);
    if (!b) continue;
    b.disabled = !enableAll;
  }
  // More granular: mapped uploads require mapping
  const needMap = ['btn-upload-mapped'];
  for (const id of needMap){
    const b = document.getElementById(id);
    if (b) b.disabled = !(enableAll && hasMapping);
  }
}
async function loadBranches(){
  try{
    const data = await getJSON('/api/branches');
    BRANCH_META = {};
    DEFAULT_BRANCH = data.default_branch || null;
    const list = document.getElementById('branch-list');
    list.innerHTML = '';

    // header row
    const head = document.createElement('div');
    head.className = 'branch-row branch-head';
    head.innerHTML = `<div></div><div>Save Data</div><div>Mapped Folder</div><div>Last Updated</div>`;
    list.appendChild(head);

    const filtered = (data.branches || []).filter(b => b.name !== 'main');

    for(const b of filtered){
      const row = document.createElement('div');
      row.className = 'branch-row';
      BRANCH_META[b.name] = {mapped_folder: b.mapped_folder || null, last_updated: b.last_updated || null, is_default: !!b.is_default};

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = b.name;
      cb.title = b.name;

      const name = document.createElement('div');
      name.innerHTML = `${b.name}${b.is_default ? ' <span class="badge">default</span>' : ''}`;

      const mapped = document.createElement('div');
      mapped.textContent = b.mapped_folder || '—';

      const last = document.createElement('div');
      last.className = 'branch-updated';
      last.textContent = fmtDateIsoLocal(b.last_updated);

      row.appendChild(cb);
      row.appendChild(name);
      row.appendChild(mapped);
      row.appendChild(last);
      list.appendChild(row);
    }
    document.getElementById('branch-count').textContent = `${(filtered || data.branches || []).length} branches`;


    // Populate the branch dropdown with latest list
    let currentBranch = (document.getElementById('branch').value || 'main');
    if(currentBranch === 'main' || !filtered.some(b => b.name === currentBranch)){
      const fb = filtered.find(b => b.is_default) || filtered[0];
      currentBranch = fb ? fb.name : '';
    }
    populateBranchDropdown(filtered, currentBranch);
    const dd = document.getElementById('branch-dd');
    if(dd && !dd._wired){
      dd.addEventListener('change', onBranchDropdownChange);
      dd._wired = true;
    }
    // Update mapped hint for current branch
    document.getElementById('branch').value = currentBranch;
    const current = document.getElementById('branch').value.trim();
    const meta = BRANCH_META[current];
    if(meta && meta.mapped_folder){
      setMappedTip(meta.mapped_folder);
    }
  }catch(e){
    // silent
  }
}

function _streamMappedResponse(resp, labelComplete){
  const progress = document.getElementById('progress');
  progress.value = 0;
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = '', total = 0, doneCount = 0;

  return (async () => {
    while(true){
      const {value, done} = await reader.read();
      if(done) break;
      buf += decoder.decode(value, {stream:true});
      let idx;
      while((idx = buf.indexOf('\n')) >= 0){
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx+1);
        if(!line) continue;
        try{
          const evt = JSON.parse(line);
          if(evt.event === 'start'){
            total = evt.total || 0;
            progress.value = total ? 0 : 10; // give a tiny bump so bar is visible
          }else if(evt.event === 'file'){
            doneCount++;
            if(evt.status_code >= 200 && evt.status_code < 300){
              log(`✓ ${evt.path} [${evt.status_code}]`);
            }else{
              log(`✗ ${evt.path} ${evt.error ? JSON.stringify(evt.error) : ''}`);
            }
            if(total){
              progress.value = Math.min(100, Math.round((doneCount / total) * 100));
            }
          }else if(evt.event === 'note'){
            log(`ℹ ${evt.message}`);
          }else if(evt.event === 'context'){
            log(`--- ${evt.owner}/${evt.repo}:${evt.branch} (${evt.base}) ---`);
          }else if(evt.event === 'context_end'){
            log(`--- done: ${evt.branch} ---`);
          }else if(evt.event === 'end'){
            progress.value = 100;
            log(labelComplete || 'Done.');
          }
        }catch(e){ /* ignore malformed line */ }
      }
    }
  })();
}

async function syncAll(){
  const boxes = Array.from(document.querySelectorAll('#branch-list input[type=checkbox]:checked'));
  const checked = boxes.map(b => b.value);
  if(checked.length === 0){ alert('Select at least one branch.'); return; }
  log('Syncing branches: ' + checked.join(', '));
  try{
    const r = await fetch('/api/sync-multi', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({branches: checked})
    });
    if(!r.ok){ throw new Error(await r.text()); }
    // stream & update progress
    await _streamMappedResponse(r, 'Sync complete.');
  }catch(e){
    log('Sync error: ' + e.message);
  }
}

async function upload(){
  // legacy: selected-folder upload

  log('Starting upload to branch…');
  const progress = document.getElementById('progress');
  progress.value = 0;
  try{
    // Use fetch manually to read NDJSON stream
    const r = await fetch('/api/upload', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    if(!r.ok){ throw new Error(await r.text()); }
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let total = 0, doneCount = 0;
    while(true){
      const {value, done} = await reader.read();
      if(done) break;
      buf += decoder.decode(value, {stream:true});
      let idx;
      while((idx = buf.indexOf('\n')) >= 0){
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx+1);
        if(!line) continue;
        try{
          const evt = JSON.parse(line);
          if(evt.event === 'start'){
            total = evt.total || 0;
            progress.value = total ? 0 : 100;
          }else if(evt.event === 'file'){
            doneCount = evt.done || doneCount + 1;
            if(evt.status_code && evt.status_code >= 200 && evt.status_code < 300){
              log(`✓ ${evt.path} [${evt.status_code}]`);
            }else{
              log(`✗ ${evt.path} ${evt.error ? JSON.stringify(evt.error) : ''}`);
            }
            if(total){
              progress.value = Math.round((doneCount / total) * 100);
            }
          }else if(evt.event === 'end'){
            if(total){ progress.value = 100; }
            log('Upload complete.');
          }
        }catch(e){ /* ignore malformed line */ }
      }
    }
  }catch(e){
    log('Upload error: ' + e.message);
  }
}


async function uploadMapped(){
  log('Starting upload from mapped folder…');
  const progress = document.getElementById('progress');
  progress.value = 0;
  try{
    const r = await fetch('/api/upload-mapped', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    if(!r.ok){ throw new Error(await r.text()); }
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let total = 0, doneCount = 0;
    while(true){
      const {value, done} = await reader.read();
      if(done) break;
      buf += decoder.decode(value, {stream:true});
      let idx;
      while((idx = buf.indexOf('\n')) >= 0){
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx+1);
        if(!line) continue;
        try{
          const evt = JSON.parse(line);
          if(evt.event === 'start'){
            total = evt.total || 0;
            progress.value = total ? 0 : 100;
          }else if(evt.event === 'file'){
            doneCount = evt.done || doneCount + 1;
            if(evt.status_code && evt.status_code >= 200 && evt.status_code < 300){
              log(`✓ ${evt.path} [${evt.status_code}]`);
            }else{
              log(`✗ ${evt.path} ${evt.error ? JSON.stringify(evt.error) : ''}`);
            }
            if(total){
              progress.value = Math.round((doneCount / total) * 100);
            }
          }else if(evt.event === 'note'){
            log(`ℹ ${evt.message}`);
          }else if(evt.event === 'end'){
            if(total){ progress.value = 100; }
            log('Upload (mapped) complete.');
          }
        }catch(e){ /* ignore malformed line */ }
      }
    }
  }catch(e){
    log('Upload (mapped) error: ' + e.message);
  }
}


function _streamMappedResponse(r, labelComplete){
  const progress = document.getElementById('progress');
  progress.value = 0;
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let total = 0, doneCount = 0;
  return (async () => {
    while(true){
      const {value, done} = await reader.read();
      if(done) break;
      buf += decoder.decode(value, {stream:true});
      let idx;
      while((idx = buf.indexOf('\n')) >= 0){
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx+1);
        if(!line) continue;
        try{
          const evt = JSON.parse(line);
          if(evt.event === 'start'){
            total = evt.total || 0;
            progress.value = total ? 0 : 100;
          }else if(evt.event === 'file'){
            doneCount = evt.done || doneCount + 1;
            if(evt.status_code && evt.status_code >= 200 && evt.status_code < 300){
              log(`✓ ${evt.path} [${evt.status_code}]`);
            }else{
              log(`✗ ${evt.path} ${evt.error ? JSON.stringify(evt.error) : ''}`);
            }
            if(total){
              progress.value = Math.round((doneCount / total) * 100);
            }
          }else if(evt.event === 'note'){
            log(`ℹ ${evt.message}`);
          }else if(evt.event === 'context'){
            log(`--- ${evt.owner}/${evt.repo}:${evt.branch} (${evt.base}) ---`);
          }else if(evt.event === 'context_end'){
            log(`--- done: ${evt.branch} ---`);
          }else if(evt.event === 'end'){
            if(total){ progress.value = 100; }
            log(labelComplete || 'Upload complete.');
          }
        }catch(e){ /* ignore malformed line */ }
      }
    }
  })();
}

async function download_(){
  log('Starting download from branch…');
  try{
    const res = await getJSON('/api/download', {method:'POST', body:'{}'});
    log(`Downloaded ${res.total} file(s) to: ${res.used_path}`);
    for(const p of res.downloaded){ log(`↓ ${p}`); }
  }catch(e){
    log('Download error: ' + e.message);
  }
}


async function createBranch(){
  const name = document.getElementById('new-branch-name').value.trim();
  if(!name){ alert('Enter a new branch name.'); return; }
  try{
    log('Creating clean branch: ' + name + ' …');
    const res = await getJSON('/api/create-branch', {method:'POST', body:JSON.stringify({name})});
    if(res.status === 'exists'){ log(`Branch already exists: ${res.branch}`); } else { log(`Branch created: ${res.branch} (clean)`); }
    document.getElementById('branch').value = res.branch;
    await saveConfig();
    await loadBranches();
  updateUIState();
  }catch(e){
    alert('Create branch failed: ' + e.message);
  }
}


function populateBranchDropdown(branches, current){
  const dd = document.getElementById('branch-dd');
  if(!dd) return;
  dd.innerHTML = '';
  for(const b of branches){
    if (b.name === 'main') continue;
    const opt = document.createElement('option');
    opt.value = b.name;
    opt.textContent = b.name + (b.is_default ? ' [default]' : '');
    dd.appendChild(opt);
  }
  if(current && dd.querySelector(`option[value="${current}"]`)){
    dd.value = current;
  } else if (dd.options.length){
    dd.selectedIndex = 0;
  }
}

async function onBranchDropdownChange(){
  const dd = document.getElementById('branch-dd');
  if(!dd) return;
  const newBranch = dd.value;
  const owner = document.getElementById('owner').value.trim();
  const repo = document.getElementById('repo').value.trim();
  // Post only the fields we need; token left blank
  await fetch('/api/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({owner, repo, branch: newBranch, token: ''})
  });
  document.getElementById('branch').value = newBranch; // keep hidden input in sync
  log('Switched current branch to: ' + newBranch);
  await refreshConfig();
  await loadBranches();
  updateUIState();
}

function bind(id, fn){ const el = document.getElementById(id); if(el){ el.addEventListener('click', fn); } }

document.addEventListener('DOMContentLoaded', async () => {
  const _cb = document.getElementById('create-branch'); if(_cb){ _cb.addEventListener('click', (e)=>{ e.preventDefault(); createBranch(); }); }

  await refreshConfig();
  await loadBranches();
  updateUIState();

  bind('save-config', saveConfig);
  bind('btn-select', selectFolder);
  bind('btn-scan', scan);
  bind('btn-upload', upload);
  bind('btn-upload-mapped', uploadMapped);
  bind('btn-download', download_);
  bind('load-branches', loadBranches);
  bind('sync-all', syncAll);
  bind('btn-download-all-mapped', downloadAllMapped);
  bind('btn-upload-all-mapped', uploadMappedAll);
  bind('btn-upload-checked-mapped', uploadMappedChecked);
  bind('create-branch', ()=>{ createBranch(); });
  bind('delete-branch', ()=>{ deleteBranch(); });
  bind('btn-download-checked-selected', downloadCheckedToSelected);
  bind('btn-download-checked-chosen', downloadCheckedToChosenFolder);

});

window.createBranch = createBranch;

async function uploadMappedChecked(){
  const boxes = Array.from(document.querySelectorAll('#branch-list input[type=checkbox]:checked'));
  const branches = boxes.map(b => b.value);
  if(branches.length === 0){ alert('Select at least one branch.'); return; }
  log('Starting upload (mapped) for checked branches: ' + branches.join(', '));
  try{
    const r = await fetch('/api/upload-multi-mapped', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({branches})});
    if(!r.ok){ throw new Error(await r.text()); }
    await _streamMappedResponse(r, 'Upload (checked, mapped) complete.');
  }catch(e){
    log('Upload (checked, mapped) error: ' + e.message);
  }
}

async function uploadMappedAll(){
  log('Starting upload for ALL mapped repos/branches…');
  try{
    const r = await fetch('/api/upload-all-mapped', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    if(!r.ok){ throw new Error(await r.text()); }
    await _streamMappedResponse(r, 'Upload (ALL mapped) complete.');
  }catch(e){
    log('Upload (ALL mapped) error: ' + e.message);
  }
}

async function downloadAllMapped(){
  log('Starting Download ALL Save Data (mapped)…');
  try{
    const r = await fetch('/api/download-all-mapped', {method:'POST', headers:{'Content-Type':'application/json'}, body: '{}'});
    if(!r.ok){ throw new Error(await r.text()); }


async function downloadCheckedMapped(){
  const boxes = Array.from(document.querySelectorAll('#branch-list input[type=checkbox]:checked'));
  const branches = boxes.map(b => b.value);
  if(branches.length === 0){
    alert('Select at least one save data to download.');
    return;
  }
  log('Downloading checked save data to MAPPED folders…');
  try{
    const r = await fetch('/api/download-checked-mapped', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({branches})
    });
    if(!r.ok){ throw new Error(await r.text()); }
    await _streamMappedResponse(r, 'Download to MAPPED folders complete.');
  }catch(e){
    log('Download (checked → mapped) error: ' + e.message);
  }
}
    await _streamMappedResponse(r, 'Download ALL Save Data complete.');
  }catch(e){
    log('Download ALL Save Data error: ' + e.message);
  }
}
async function createBranch(){
  const name = document.getElementById('new-branch-name').value.trim();
  if(!name){
    alert('Enter a new branch name.');
    return;
  }
  try{
    log('Creating clean branch: ' + name + ' …');
    const res = await getJSON('/api/create-branch', {
      method:'POST',
      body: JSON.stringify({name})
    });

    if(res.status === 'exists'){
      log(`Branch already exists: ${res.branch}`);
    } else {
      log(`Branch created: ${res.branch} (clean)`);
    }

    // Update current branch and refresh UI
    document.getElementById('branch').value = res.branch;
    await saveConfig();
    await loadBranches();
  }catch(e){
    alert('Create branch failed: ' + e.message);
  }
}
async function deleteBranch(){
  const name = document.getElementById('new-branch-name').value.trim();
  if(!name){
    alert('Enter backup save data folder name to delete.');
    return;
  }
  if(!confirm(`Are you sure you want to delete branch "${name}"?`)) return;

  try{
    log('Deleting branch: ' + name + ' …');
    const res = await getJSON('/api/delete-branch', {
      method:'POST',
      body: JSON.stringify({name})
    });

    if(res.status === 'deleted'){
      log(`Branch deleted: ${res.branch}`);
      if(document.getElementById('branch').value === res.branch){
        document.getElementById('branch').value = ''; // clear if deleted
      }
      await loadBranches();
    }else if(res.status === 'not_found'){
      log(`Branch not found: ${res.branch}`);
    }else if(res.error){
      alert('Delete branch failed: ' + res.error);
    }
  }catch(e){
    alert('Delete branch failed: ' + e.message);
  }
}
async function downloadCheckedToSelected(){
  const boxes = Array.from(document.querySelectorAll('#branch-list input[type=checkbox]:checked'));
  const branches = boxes.map(b => b.value);
  if(branches.length === 0){ alert('Select at least one save data.'); return; }
  log('Downloading checked save data to Selected Folder…');
  try{
    const r = await fetch('/api/download-checked-to-selected', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({branches})
    });
    if(!r.ok){ throw new Error(await r.text()); }
    await _streamMappedResponse(r, 'Download (checked → selected) complete.');
  }catch(e){
    log('Download (checked → selected) error: ' + e.message);
  }
}



async function downloadCheckedToChosenFolder(){
  // collect checked branches from the Step 3 list
  const boxes = Array.from(document.querySelectorAll('#branch-list input[type=checkbox]:checked'));
  const branches = boxes.map(b => b.value);
  if(branches.length === 0){
    alert('Select at least one save data to download.');
    return;
  }

  // ask for a target folder via pywebview
  let target = null;
  try{
    if (window.pywebview && window.pywebview.api && window.pywebview.api.select_folder){
      const result = await window.pywebview.api.select_folder();
      target = result && result.selected_folder;
    } else {
      alert('Folder picker not available in this environment. Please run the desktop app (pywebview build).');
      return;
    }
  }catch(e){
    alert('Folder selection failed: ' + e.message);
    return;
  }
  if(!target){
    log('Download cancelled: no folder chosen.');
    return;
  }

  log('Downloading checked save data to: ' + target);
  try{
    const r = await fetch('/api/download-checked-to-path', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({branches, target_folder: target})
    });
    if(!r.ok){ throw new Error(await r.text()); }
    // stream NDJSON so the progress bar and log update
    await _streamMappedResponse(r, 'Download to chosen folder complete.');
  }catch(e){
    log('Download (checked → chosen) error: ' + e.message);
  }
}