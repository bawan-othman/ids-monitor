// ─── IDS Monitor - Main JS ────────────────────────────────────────────────────

// Live clock
function updateClock() {
  const el = document.getElementById('liveClock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString('en-US', { hour12: false }) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// Format numbers with commas
function fmt(n) {
  return Number(n).toLocaleString();
}

// Animate counter
function animateCounter(el, target) {
  if (!el) return;
  const start = parseInt(el.textContent.replace(/,/g, '')) || 0;
  const diff  = target - start;
  if (diff === 0) return;
  const steps = 20;
  let step = 0;
  const timer = setInterval(() => {
    step++;
    el.textContent = fmt(Math.round(start + (diff * step / steps)));
    if (step >= steps) { el.textContent = fmt(target); clearInterval(timer); }
  }, 16);
}

// Load and update stats
async function loadStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    animateCounter(document.getElementById('statTotal'),     data.total_packets);
    animateCounter(document.getElementById('statMalicious'), data.malicious_packets);
    animateCounter(document.getElementById('statAlerts'),    data.new_alerts);
    animateCounter(document.getElementById('statBlocked'),   data.blocked_ips);
    if (window.donutChart) {
      window.donutChart.data.datasets[0].data = [
        data.total_packets - data.malicious_packets,
        data.malicious_packets
      ];
      window.donutChart.update();
    }
  } catch (e) { console.warn('Stats error:', e); }
}

// Load recent logs
async function loadLogs() {
  try {
    const res  = await fetch('/api/logs');
    const logs = await res.json();
    const tbody = document.getElementById('recentTable');
    if (!tbody) return;
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">📡</div><div class="empty-text">Awaiting traffic data...</div></div></td></tr>`;
      return;
    }
    tbody.innerHTML = logs.slice(0, 15).map(l => `
      <tr class="${l.prediction === 'MALICIOUS' ? 'malicious-row' : ''}">
        <td class="mono" style="color:var(--text-muted)">${l.captured_at.split(' ')[1]}</td>
        <td class="mono">${l.src_ip}</td>
        <td class="mono" style="color:var(--text-muted)">${l.dst_ip}</td>
        <td>${l.protocol || '-'}</td>
        <td class="mono" style="color:var(--text-muted)">${l.length} B</td>
        <td>${l.prediction === 'MALICIOUS'
          ? '<span class="badge badge-red">⚠ Malicious</span>'
          : '<span class="badge badge-green">✓ Normal</span>'}</td>
        <td class="mono" style="color:var(--text-muted)">${Math.round(l.confidence * 100)}%</td>
      </tr>
    `).join('');
  } catch (e) { console.warn('Logs error:', e); }
}

// Load alerts
async function loadAlerts() {
  try {
    const res    = await fetch('/api/alerts');
    const alerts = await res.json();
    const tbody  = document.getElementById('alertsTable');
    if (!tbody) return;

    const sevFilter    = document.getElementById('filterSeverity')?.value || '';
    const statusFilter = document.getElementById('filterStatus')?.value   || '';
    let filtered = alerts;
    if (sevFilter)    filtered = filtered.filter(a => a.severity === sevFilter);
    if (statusFilter) filtered = filtered.filter(a => a.status   === statusFilter);

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">🔔</div><div class="empty-text">No alerts found</div></div></td></tr>`;
      return;
    }

    const sevClass  = { high: 'badge-red', medium: 'badge-orange', low: 'badge-gray' };
    const statClass = { new: 'badge-red', acknowledged: 'badge-orange', resolved: 'badge-green' };

    tbody.innerHTML = filtered.map(a => `
      <tr>
        <td class="mono" style="color:var(--text-muted); font-size:11px">${a.created_at}</td>
        <td><span class="badge ${sevClass[a.severity] || 'badge-gray'}">${a.severity}</span></td>
        <td><span class="badge ${statClass[a.status]  || 'badge-gray'}">${a.status}</span></td>
        <td style="color:var(--text-primary)">${a.title}</td>
        <td style="color:var(--text-muted); font-size:12px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">${a.description}</td>
        <td class="mono" style="color:var(--text-muted)">#${a.log_id}</td>
        <td>
          <div style="display:flex; gap:6px;">
            ${a.status === 'new' ? `<button class="btn btn-primary btn-xs" onclick="ackAlert(${a.alert_id})">Ack</button>` : ''}
            ${a.status !== 'resolved' ? `<button class="btn btn-success btn-xs" onclick="resolveAlert(${a.alert_id})">Resolve</button>` : ''}
          </div>
        </td>
      </tr>
    `).join('');
  } catch (e) { console.warn('Alerts error:', e); }
}

async function ackAlert(id) {
  await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
  loadAlerts();
}

async function resolveAlert(id) {
  await fetch(`/api/alerts/${id}/resolve`, { method: 'POST' });
  loadAlerts();
}

// Load blocklist
async function loadBlocklist() {
  try {
    const res  = await fetch('/api/blocklist');
    const data = await res.json();
    const tbody = document.getElementById('blocklistTable');
    if (!tbody) return;
    if (data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🚫</div><div class="empty-text">No blocked IPs</div></div></td></tr>`;
      return;
    }
    tbody.innerHTML = data.map(b => `
      <tr>
        <td class="mono" style="color:var(--accent-cyan)">${b.ip_address}</td>
        <td style="color:var(--text-secondary)">${b.reason}</td>
        <td><span class="badge ${b.source === 'auto' ? 'badge-cyan' : 'badge-purple'}">${b.source}</span></td>
        <td><span class="badge ${b.is_active ? 'badge-red' : 'badge-gray'}">${b.is_active ? 'Active' : 'Inactive'}</span></td>
        <td class="mono" style="color:var(--text-muted); font-size:11px">${b.added_at}</td>
        <td><button class="btn btn-ghost btn-xs" onclick="removeBlock(${b.block_id})">Remove</button></td>
      </tr>
    `).join('');
  } catch (e) { console.warn('Blocklist error:', e); }
}

async function removeBlock(id) {
  if (!confirm('Remove this IP from blocklist?')) return;
  await fetch(`/api/blocklist/${id}`, { method: 'DELETE' });
  loadBlocklist();
}

// Load users
async function loadUsers() {
  try {
    const res   = await fetch('/api/users');
    const users = await res.json();
    const tbody = document.getElementById('usersTable');
    if (!tbody) return;
    const roleClass = { admin: 'badge-cyan', analyst: 'badge-orange', viewer: 'badge-gray' };
    tbody.innerHTML = users.map(u => `
      <tr>
        <td style="font-weight:600; color:var(--text-primary)">${u.username}</td>
        <td class="mono" style="color:var(--text-muted)">${u.email}</td>
        <td><span class="badge ${roleClass[u.role] || 'badge-gray'}">${u.role}</span></td>
        <td><span class="badge ${u.is_active ? 'badge-green' : 'badge-red'}">${u.is_active ? 'Active' : 'Inactive'}</span></td>
        <td class="mono" style="color:var(--text-muted); font-size:11px">${u.created_at}</td>
        <td class="mono" style="color:var(--text-muted); font-size:11px">${u.last_login_at}</td>
        <td>
          <button class="btn btn-danger btn-xs" onclick="deactivateUser(${u.user_id})">Deactivate</button>
        </td>
      </tr>
    `).join('');

    // Update user count
    const countEl = document.getElementById('userCount');
    if (countEl) countEl.textContent = `${users.length} users`;
  } catch (e) { console.warn('Users error:', e); }
}

async function deactivateUser(id) {
  if (!confirm('Deactivate this user?')) return;
  await fetch(`/api/users/${id}/deactivate`, { method: 'POST' });
  loadUsers();
}

// Modal helpers
function openModal(id)  { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }

// Add block IP
async function submitBlockIP() {
  const ip     = document.getElementById('blockIP')?.value.trim();
  const reason = document.getElementById('blockReason')?.value.trim();
  if (!ip) { alert('Please enter an IP address'); return; }
  await fetch('/api/blocklist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address: ip, reason: reason || 'Manual block' })
  });
  closeModal('addBlockModal');
  document.getElementById('blockIP').value     = '';
  document.getElementById('blockReason').value = '';
  loadBlocklist();
}

// Add user
async function submitAddUser() {
  const username = document.getElementById('newUsername')?.value.trim();
  const email    = document.getElementById('newEmail')?.value.trim();
  const password = document.getElementById('newPassword')?.value.trim();
  const role     = document.getElementById('newRole')?.value;
  if (!username || !email || !password) { alert('Please fill all fields'); return; }
  const res  = await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, role })
  });
  const data = await res.json();
  if (data.success) { closeModal('addUserModal'); loadUsers(); }
  else alert(data.message || 'Error adding user');
}

// Chart defaults
Chart.defaults.color = '#4a5568';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Space Mono', monospace";
Chart.defaults.font.size = 11;