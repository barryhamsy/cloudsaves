let __CREATING_BRANCH = false;
let BRANCH_META = {}; // name -> {mapped_folder, last_updated, is_default}
let DEFAULT_BRANCH = null;

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
    document.getElementById('owner').value = cfg.owner || '';
    document.getElementById('repo').value = cfg.repo || '';
    document.getElementById('branch').value = cfg.branch || 'main';
    
    const dd = document.getElementById('branch-dd'); if(dd){ dd.value = cfg.branch || 'main'; }
    document.getElementById('selected-folder').value = cfg.selected_folder || '';
    document.getElementById('status-dot').classList.toggle('ok', !!cfg.has_token);
    document.getElementById('status-dot').title = cfg.has_token ? 'Token stored' : 'No token';
    setMappedTip(cfg.mapped_folder);
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
    head.innerHTML = `<div></div><div>Branch</div><div>Mapped Folder</div><div>Last Updated</div>`;
    list.appendChild(head);

    // Build filtered branch list (hide "main")
    const all = data.branches || [];
    const filtered = all.filter(b => b.name !== 'main');

    // rows
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
    document.getElementById('branch-count').textContent = `${filtered.length} branches`;

    // Figure out a safe current branch (avoid "main" or missing from filtered)
    let currentBranch = (document.getElementById('branch').value || data.default_branch || 'main');
    if (
      currentBranch === 'main' ||
      !filtered.some(b => b.name === currentBranch)
    ) {
      const fallback = filtered.find(b => b.is_default) || filtered[0];
      currentBranch = fallback ? fallback.name : '';
    }

    // Populate the branch dropdown with latest filtered list
    populateBranchDropdown(filtered, currentBranch);
    const dd = document.getElementById('branch-dd');
    if(dd && !dd._wired){
      dd.addEventListener('change', onBranchDropdownChange);
      dd._wired = true;
    }

    // Keep hidden input in sync with the final current branch
    document.getElementById('branch').value = currentBranch || '';

    // Update mapped hint for current branch
    const meta = BRANCH_META[currentBranch];
    if(meta && meta.mapped_folder){
      setMappedTip(meta.mapped_folder);
    } else {
      setMappedTip('');
    }
  }catch(e){
    // silent
  }
}

async function syncAll(){
  const boxes = Array.from(document.querySelectorAll('#branch-list input[type=checkbox]:checked'));
  const checked = boxes.map(b => b.value);
  if(checked.length === 0){ alert('Select at least one branch.'); return; }
  log('Syncing branches: ' + checked.join(', '));
  try{
    const res = await getJSON('/api/sync-multi', {method:'POST', body:JSON.stringify({branches:checked})});
    for(const [branch, info] of Object.entries(res)){
      if(info.error){ log(`✗ ${branch}: ${info.error}`); }
      else{ log(`✓ ${branch}: Downloaded ${info.downloaded} files to ${info.folder}`); }
    }
  }catch(e){
    log('Sync error: ' + e.message);
  }
}

async function upload(){
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
  }catch(e){
    alert('Create branch failed: ' + e.message);
  }
}


function populateBranchDropdown(branches, current){
  const dd = document.getElementById('branch-dd');
  if(!dd) return;
  dd.innerHTML = '';
  for(const b of branches){
    if (b.name === 'main') continue; // 🚫 skip main in dropdown
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
  if (newBranch === 'main') { // defensive guard (in case someone injects it)
    log('Refusing to switch to "main" (hidden).');
    return;
  }
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
}

document.addEventListener('DOMContentLoaded', async () => {
  const _cb = document.getElementById('create-branch'); if(_cb){ _cb.addEventListener('click', (e)=>{ e.preventDefault(); createBranch(); }); }

  await refreshConfig();
  await loadBranches();

  document.getElementById('save-config').addEventListener('click', saveConfig);
  document.getElementById('btn-select').addEventListener('click', selectFolder);
  document.getElementById('btn-scan').addEventListener('click', scan);
  document.getElementById('btn-upload').addEventListener('click', upload);
  document.getElementById('btn-download').addEventListener('click', download_);
  document.getElementById('load-branches').addEventListener('click', loadBranches);
  document.getElementById('sync-all').addEventListener('click', syncAll);
});

window.createBranch = createBranch;
