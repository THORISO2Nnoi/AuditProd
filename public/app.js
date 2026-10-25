/**
 * AUDITPRO — COMPLIANT 3-DATABASE SECURE AUDIT CLIENT
 */
const AuditProApp = (() => {
  // Application State
  const state = {
    currentUser: null,
    accessToken: localStorage.getItem('auditpro_access_token') || null,
    refreshToken: localStorage.getItem('auditpro_refresh_token') || null,
    currentJti: localStorage.getItem('auditpro_jti') || null,
    currentTab: 'compliance',
    auditFilters: {
      page: 1,
      limit: 12,
      username: '',
      event: '',
      status: '',
      entity_type: '',
      search: '',
      dateFrom: '',
      dateTo: ''
    },
    cachedAuditLogs: [],
    searchDebounceTimer: null
  };

  /**
   * Centralized Fetch Wrapper with Automatic 401 JWT Refresh Interceptor
   */
  async function apiRequest(endpoint, options = {}) {
    const headers = options.headers || {};
    
    if (state.accessToken) {
      headers['Authorization'] = `Bearer ${state.accessToken}`;
    }
    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const config = {
      ...options,
      headers
    };

    let response = await fetch(endpoint, config);

    // 401 Interceptor: Access token expired -> Attempt seamless refresh
    if (response.status === 401 && state.refreshToken) {
      try {
        const refreshRes = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken: state.refreshToken })
        });

        if (refreshRes.ok) {
          const refreshData = await refreshRes.json();
          state.accessToken = refreshData.accessToken;
          state.refreshToken = refreshData.refreshToken;
          state.currentJti = refreshData.jti;

          localStorage.setItem('auditpro_access_token', state.accessToken);
          localStorage.setItem('auditpro_refresh_token', state.refreshToken);
          localStorage.setItem('auditpro_jti', state.currentJti);

          updateJtiDisplay();

          // Retry original request with newly rotated token
          headers['Authorization'] = `Bearer ${state.accessToken}`;
          response = await fetch(endpoint, { ...options, headers });
        } else {
          // Refresh failed or revoked: force login
          logout(false);
          throw new Error('Session expired. Please sign in again.');
        }
      } catch (err) {
        logout(false);
        throw err;
      }
    }

    return response;
  }

  /**
   * Toast notification helper
   */
  function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';
    if (type === 'warning') icon = '⚠️';
    if (type === 'purple') icon = '🛡️';

    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  /**
   * Initialize Application
   */
  async function init() {
    updateJtiDisplay();

    if (state.accessToken) {
      try {
        const res = await apiRequest('/api/auth/me');
        if (res.ok) {
          const data = await res.json();
          state.currentUser = data.user;
          state.currentJti = data.jti || state.currentJti;
          applyRoleExperience();
          loadDashboardData();
          return;
        }
      } catch (e) {
        console.warn('Existing session validation failed, resetting demo credentials');
      }
    }

    // Default to Admin session on initial load for immediate interactive demonstration
    await quickSwitch('admin', true);
  }

  /**
   * Apply Role-Aware UI Experience (Admin = Red, Auditor = Purple, User = Blue)
   */
  function applyRoleExperience() {
    const user = state.currentUser;
    if (!user) {
      document.getElementById('authModalOverlay').style.display = 'flex';
      return;
    }

    document.getElementById('authModalOverlay').style.display = 'none';

    const body = document.getElementById('appBody');
    const role = user.role.toLowerCase();

    // Body Theme Tinting
    body.className = `theme-${role}`;

    // Header Profile updates
    document.getElementById('userNameLabel').textContent = user.full_name || user.username;
    const roleEmoji = role === 'admin' ? '👑' : role === 'auditor' ? '🔍' : '👤';
    document.getElementById('userRolePill').textContent = `${roleEmoji} ${role.toUpperCase()}`;
    document.getElementById('userAvatar').textContent = user.username.substring(0, 2).toUpperCase();

    // Role Switch Buttons active state
    document.querySelectorAll('.btn-role-chip').forEach(btn => btn.classList.remove('active'));
    if (user.username === 'admin') document.getElementById('btnSwitchAdmin')?.classList.add('active');
    else if (user.username === 'auditor') document.getElementById('btnSwitchAuditor')?.classList.add('active');
    else if (user.username === 'alice') document.getElementById('btnSwitchAlice')?.classList.add('active');
    else if (user.username === 'bob') document.getElementById('btnSwitchBob')?.classList.add('active');

    // Role Context Banner
    const bannerTitle = document.getElementById('bannerTitle');
    const bannerSubtitle = document.getElementById('bannerSubtitle');
    const bannerIcon = document.getElementById('bannerIconBadge');

    if (role === 'admin') {
      bannerTitle.textContent = 'Admin Control Center';
      bannerSubtitle.textContent = 'Full administrative control over Auth DB, Business DB, and Audit Forensics with 3-DB isolation.';
      bannerIcon.textContent = '👑';
    } else if (role === 'auditor') {
      bannerTitle.textContent = 'Compliance & Forensics Center';
      bannerSubtitle.textContent = 'Immutable forensic audit inspection, cryptographic JTI tracing, and read-only operational oversight.';
      bannerIcon.textContent = '🔍';
    } else {
      bannerTitle.textContent = `${user.full_name}'s Isolated Workspace`;
      bannerSubtitle.textContent = 'Operational task workspace. Strict identity isolation ensures zero access to peer data or audit records.';
      bannerIcon.textContent = '👤';
    }

    // Role-Aware Navigation Tabs Visibility
    const tabCompliance = document.getElementById('tabCompliance');
    const tabAuditLogs = document.getElementById('tabAuditLogs');
    const tabJwtForensics = document.getElementById('tabJwtForensics');
    const tabUsers = document.getElementById('tabUsers');
    const btnCreateProduct = document.getElementById('btnCreateProduct');
    const productsNotice = document.getElementById('productsAuditorNotice');
    const userWorkspaceNotice = document.getElementById('userWorkspaceNotice');
    const tasksTabTitle = document.getElementById('tasksTabTitle');

    if (role === 'admin') {
      tabCompliance.style.display = 'inline-flex';
      tabAuditLogs.style.display = 'inline-flex';
      tabJwtForensics.style.display = 'inline-flex';
      tabUsers.style.display = 'inline-flex';
      btnCreateProduct.style.display = 'inline-flex';
      productsNotice.style.display = 'none';
      userWorkspaceNotice.style.display = 'none';
      tasksTabTitle.textContent = 'All System Tasks';
    } else if (role === 'auditor') {
      tabCompliance.style.display = 'inline-flex';
      tabAuditLogs.style.display = 'inline-flex';
      tabJwtForensics.style.display = 'inline-flex';
      tabUsers.style.display = 'none'; // Auditor doesn't manage identities
      btnCreateProduct.style.display = 'none'; // Auditor is strictly read-only
      productsNotice.style.display = 'block';
      userWorkspaceNotice.style.display = 'none';
      tasksTabTitle.textContent = 'Tasks (Audit Oversight)';
    } else {
      // Regular User (Alice / Bob)
      tabCompliance.style.display = 'none';
      tabAuditLogs.style.display = 'none';
      tabJwtForensics.style.display = 'none';
      tabUsers.style.display = 'none';
      btnCreateProduct.style.display = 'none';
      productsNotice.style.display = 'none';
      userWorkspaceNotice.style.display = 'block';
      tasksTabTitle.textContent = 'My Assigned Tasks';

      // If user was on a forbidden tab, move them to tasks
      if (['compliance', 'auditLogs', 'jwtForensics', 'users'].includes(state.currentTab)) {
        switchTab('tasks');
      }
    }

    updateJtiDisplay();
  }

  function updateJtiDisplay() {
    const el = document.getElementById('sessionJtiDisplay');
    if (el) {
      el.textContent = state.currentJti ? state.currentJti : 'No Active Session';
    }
  }

  /**
   * Tab Switching
   */
  function switchTab(tabId) {
    state.currentTab = tabId;

    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

    const tabMap = {
      compliance: { btn: 'tabCompliance', pane: 'paneCompliance', loader: loadComplianceStats },
      auditLogs: { btn: 'tabAuditLogs', pane: 'paneAuditLogs', loader: loadAuditLogs },
      jwtForensics: { btn: 'tabJwtForensics', pane: 'paneJwtForensics', loader: loadJwtEvents },
      products: { btn: 'tabProducts', pane: 'paneProducts', loader: loadProducts },
      tasks: { btn: 'tabTasks', pane: 'paneTasks', loader: loadTasks },
      users: { btn: 'tabUsers', pane: 'paneUsers', loader: loadUsers }
    };

    const target = tabMap[tabId];
    if (target) {
      document.getElementById(target.btn)?.classList.add('active');
      document.getElementById(target.pane)?.classList.add('active');
      if (target.loader) target.loader();
    }
  }

  /**
   * Load Data for all active screens
   */
  function loadDashboardData() {
    if (state.currentUser.role === 'user') {
      switchTab('tasks');
    } else {
      loadComplianceStats();
      if (state.currentTab === 'auditLogs') loadAuditLogs();
      if (state.currentTab === 'products') loadProducts();
      if (state.currentTab === 'tasks') loadTasks();
      if (state.currentTab === 'users') loadUsers();
    }
  }

  /* ================= 1. COMPLIANCE & HEALTH STATS ================= */
  async function loadComplianceStats() {
    if (state.currentUser.role === 'user') return;

    try {
      const res = await apiRequest('/api/reports/stats');
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('metricHealthScore').textContent = data.healthScore || '100%';
      document.getElementById('metricTotalLogs').textContent = (data.totalLogs || 0).toLocaleString();
      document.getElementById('metricTodayLogs').textContent = (data.todayLogs || 0).toLocaleString();
      document.getElementById('metricAccessDenied').textContent = (data.deniedCount || 0).toLocaleString();
      document.getElementById('metricDeniedCount').textContent = (data.deniedCount || 0);
      document.getElementById('metricFailedLogins').textContent = (data.failedCount || 0).toLocaleString();
      document.getElementById('metricTrackedJtis').textContent = (data.uniqueJtis || 0).toLocaleString();
      document.getElementById('metricTamperBlocked').textContent = (data.blockedCount || 0).toLocaleString();
    } catch (e) {
      console.error('Failed to load compliance stats:', e);
    }
  }

  /* ================= 2. FORENSIC AUDIT LOGS ================= */
  async function loadAuditLogs() {
    if (state.currentUser.role === 'user') return;

    const tbody = document.getElementById('auditLogsBody');
    tbody.innerHTML = `<tr><td colspan="9" class="text-center">Querying immutable records from audit.db...</td></tr>`;

    const params = new URLSearchParams({
      page: state.auditFilters.page,
      limit: state.auditFilters.limit,
      username: state.auditFilters.username,
      event: state.auditFilters.event,
      status: state.auditFilters.status,
      entity_type: state.auditFilters.entity_type,
      search: state.auditFilters.search,
      dateFrom: state.auditFilters.dateFrom,
      dateTo: state.auditFilters.dateTo
    });

    try {
      const res = await apiRequest(`/api/audit/logs?${params.toString()}`);
      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger">Failed to load audit logs.</td></tr>`;
        return;
      }

      const data = await res.json();
      state.cachedAuditLogs = data.logs || [];

      // Update pagination
      document.getElementById('pageInfo').textContent = `Showing page ${data.page} of ${data.totalPages || 1} (${data.total} records)`;
      document.getElementById('btnPrevPage').disabled = data.page <= 1;
      document.getElementById('btnNextPage').disabled = data.page >= data.totalPages;

      if (state.cachedAuditLogs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No audit records match the current filter criteria.</td></tr>`;
        return;
      }

      tbody.innerHTML = state.cachedAuditLogs.map(log => {
        let statusBadge = 'badge-success';
        if (log.status === 'DENIED') statusBadge = 'badge-danger';
        else if (log.status === 'FAILED') statusBadge = 'badge-warning';
        else if (log.status === 'BLOCKED') statusBadge = 'badge-purple';

        const jtiDisplay = log.jti ? log.jti.substring(0, 8) + '...' : 'SYSTEM';

        return `
          <tr class="clickable-row" onclick="AuditProApp.inspectLogDiff(${log.id})" title="Click to view Before/After Yellow Diff">
            <td class="mono">#${log.id}</td>
            <td class="text-muted" style="font-size:0.78rem;">${new Date(log.timestamp).toLocaleString()}</td>
            <td><span class="badge ${log.event.includes('DENIED') ? 'badge-danger' : log.event.includes('LOGIN') ? 'badge-blue' : 'badge-purple'}">${log.event}</span></td>
            <td><strong>${log.username || 'system'}</strong> <span class="text-muted">(${log.role || 'sys'})</span></td>
            <td><span class="badge ${statusBadge}">${log.status}</span></td>
            <td>${escapeHtml(log.action || '')}</td>
            <td><span class="tag">${log.entity_type || '—'}</span></td>
            <td class="mono text-muted" title="${log.jti || ''}">${jtiDisplay}</td>
            <td>
              <button class="btn btn-sm btn-outline-accent" onclick="event.stopPropagation(); AuditProApp.inspectLogDiff(${log.id})">
                Inspect Diff
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger">Error: ${e.message}</td></tr>`;
    }
  }

  function applyFilters() {
    state.auditFilters.username = document.getElementById('filterUsername').value;
    state.auditFilters.event = document.getElementById('filterEvent').value;
    state.auditFilters.status = document.getElementById('filterStatus').value;
    state.auditFilters.page = 1;
    loadAuditLogs();
  }

  function debouncedFilter() {
    clearTimeout(state.searchDebounceTimer);
    state.searchDebounceTimer = setTimeout(() => {
      state.auditFilters.search = document.getElementById('filterSearch').value;
      state.auditFilters.page = 1;
      loadAuditLogs();
    }, 300);
  }

  function resetFilters() {
    document.getElementById('filterSearch').value = '';
    document.getElementById('filterUsername').value = '';
    document.getElementById('filterEvent').value = '';
    document.getElementById('filterStatus').value = '';
    state.auditFilters = {
      page: 1,
      limit: 12,
      username: '',
      event: '',
      status: '',
      entity_type: '',
      search: '',
      dateFrom: '',
      dateTo: ''
    };
    loadAuditLogs();
  }

  function changePage(delta) {
    state.auditFilters.page = Math.max(1, state.auditFilters.page + delta);
    loadAuditLogs();
  }

  /* ================= 3. 🌟 BEFORE/AFTER YELLOW DIFF INSPECTOR ================= */
  async function inspectLogDiff(logId) {
    try {
      const res = await apiRequest(`/api/audit/logs/${logId}`);
      if (!res.ok) {
        showToast('Could not load log details', 'error');
        return;
      }

      const { log } = await res.json();

      document.getElementById('diffLogId').textContent = `#${log.id}`;
      document.getElementById('diffTimestamp').textContent = new Date(log.timestamp).toLocaleString();
      document.getElementById('diffActor').textContent = `${log.username} (${log.role})`;
      document.getElementById('diffIp').textContent = `${log.ip_address} | UA: ${log.user_agent ? log.user_agent.substring(0, 30) + '...' : 'Unknown'}`;
      document.getElementById('diffJti').textContent = log.jti || 'N/A';
      document.getElementById('diffActionText').textContent = log.action;
      document.getElementById('diffModalEventBadge').textContent = log.event;

      // Populate Snapshots JSON
      document.getElementById('rawBeforeJson').textContent = log.before_snapshot_parsed ? JSON.stringify(log.before_snapshot_parsed, null, 2) : 'null (Created or Initial State)';
      document.getElementById('rawAfterJson').textContent = log.after_snapshot_parsed ? JSON.stringify(log.after_snapshot_parsed, null, 2) : 'null (Deleted)';

      // Render Yellow Highlighted Diff
      const diffContainer = document.getElementById('diffCardsContainer');
      const diffCountBadge = document.getElementById('diffCountBadge');

      const diff = log.diff_parsed || {};
      const diffKeys = Object.keys(diff);

      if (diffKeys.length === 0) {
        diffCountBadge.textContent = 'No delta recorded';
        diffContainer.innerHTML = `
          <div class="diff-card-item" style="border-color: rgba(255,255,255,0.1); background: rgba(255,255,255,0.03);">
            <div class="diff-field-name" style="color: var(--text-muted);">Action did not modify record fields directly (e.g. Authentication or Access Check)</div>
          </div>
        `;
      } else {
        diffCountBadge.textContent = `${diffKeys.length} field${diffKeys.length > 1 ? 's' : ''} modified`;
        diffContainer.innerHTML = diffKeys.map(key => {
          const item = diff[key];
          let beforeVal = '—';
          let afterVal = '—';

          if (item && typeof item === 'object' && ('before' in item || 'after' in item)) {
            beforeVal = item.before !== undefined && item.before !== null ? (typeof item.before === 'object' ? JSON.stringify(item.before) : String(item.before)) : 'null';
            afterVal = item.after !== undefined && item.after !== null ? (typeof item.after === 'object' ? JSON.stringify(item.after) : String(item.after)) : 'null';
          } else {
            afterVal = typeof item === 'object' ? JSON.stringify(item) : String(item);
          }

          return `
            <div class="diff-card-item">
              <div class="diff-field-header">
                <span class="badge badge-warning">MODIFIED FIELD</span>
                <span class="diff-field-name">${escapeHtml(key)}</span>
              </div>
              <div class="diff-compare-row">
                <div class="diff-box before" title="Value Before Mutation">
                  ${escapeHtml(beforeVal)}
                </div>
                <div class="diff-arrow">➔</div>
                <div class="diff-box after" title="Value After Mutation">
                  ${escapeHtml(afterVal)}
                </div>
              </div>
            </div>
          `;
        }).join('');
      }

      document.getElementById('diffModalOverlay').style.display = 'flex';
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function closeDiffModal() {
    document.getElementById('diffModalOverlay').style.display = 'none';
  }

  /* ================= 4. EXPORT AUDIT TRAIL ================= */
  async function exportAudit(format = 'csv') {
    const params = new URLSearchParams({
      username: state.auditFilters.username,
      event: state.auditFilters.event,
      status: state.auditFilters.status,
      entity_type: state.auditFilters.entity_type,
      search: state.auditFilters.search
    });

    try {
      const url = `/api/audit/export/${format}?${params.toString()}`;
      const res = await apiRequest(url);

      if (!res.ok) {
        showToast('Export failed', 'error');
        return;
      }

      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `auditpro-export-${new Date().toISOString().substring(0, 10)}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      showToast(`Exported audit logs to ${format.toUpperCase()} (Action was audited!)`, 'success');

      // Refresh logs so the EXPORT_REPORT action appears in the audit list
      setTimeout(() => loadAuditLogs(), 800);
    } catch (e) {
      showToast(`Export error: ${e.message}`, 'error');
    }
  }

  /* ================= 5. LIVE IMMUTABILITY TAMPER LAB ================= */
  function openImmutabilityModal() {
    document.getElementById('immutabilityModalOverlay').style.display = 'flex';
  }

  function closeImmutabilityModal() {
    document.getElementById('immutabilityModalOverlay').style.display = 'none';
  }

  async function runTamperTest(type = 'UPDATE') {
    const consoleOutput = document.getElementById('tamperConsoleOutput');
    consoleOutput.innerHTML = `[Executing] Dispatching malicious raw SQL ${type} attempt against audit.db...`;

    try {
      const res = await apiRequest('/api/audit/test-immutability', {
        method: 'POST',
        body: JSON.stringify({ type })
      });

      const data = await res.json();

      if (data.blocked) {
        consoleOutput.innerHTML = `
<span class="blocked-msg">🛑 [ATTACK BLOCKED] SQLite Engine Trigger Executed ABORT!</span>
Simulated Rogue SQL:  <code>${escapeHtml(data.simulatedQuery)}</code>
Database Error:       <strong>${escapeHtml(data.errorMessage)}</strong>
Trigger Active:       ${data.triggerActive}
Audit DB Logged:      IMMUTABILITY_TAMPER_ATTEMPT recorded with status BLOCKED

<span class="success-proof">✅ Proof Verified: Direct UPDATE/DELETE statements are unconditionally rejected at the SQLite engine level.</span>
        `;
        showToast(`Trigger intercepted ${type}! Engine aborted tamper attempt.`, 'purple');
        loadComplianceStats();
        if (state.currentTab === 'auditLogs') loadAuditLogs();
      } else {
        consoleOutput.innerHTML = `[Warning] Query was not blocked: ${JSON.stringify(data)}`;
      }
    } catch (err) {
      consoleOutput.innerHTML = `<span class="blocked-msg">Error executing test: ${err.message}</span>`;
    }
  }

  /* ================= 6. JWT FORENSICS ================= */
  async function loadJwtEvents() {
    if (state.currentUser.role === 'user') return;

    const tbody = document.getElementById('jwtEventsBody');
    tbody.innerHTML = `<tr><td colspan="8" class="text-center">Loading JWT lifecycle events...</td></tr>`;

    try {
      const res = await apiRequest('/api/audit/jwt-events?limit=50');
      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">Failed to load JWT events</td></tr>`;
        return;
      }

      const data = await res.json();
      const events = data.events || [];

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No JWT events recorded yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = events.map(ev => {
        let evBadge = 'badge-blue';
        if (ev.event_type === 'REVOKED' || ev.event_type === 'EXPIRED') evBadge = 'badge-danger';
        else if (ev.event_type === 'REFRESHED') evBadge = 'badge-warning';
        else if (ev.event_type === 'ISSUED') evBadge = 'badge-success';

        return `
          <tr>
            <td class="mono">#${ev.id}</td>
            <td class="text-muted" style="font-size:0.78rem;">${new Date(ev.timestamp).toLocaleString()}</td>
            <td><span class="badge ${evBadge}">${ev.event_type}</span></td>
            <td class="mono bold" style="color: #fef08a;">${ev.jti}</td>
            <td><strong>${ev.username || '—'}</strong></td>
            <td class="mono text-muted">${ev.endpoint || '—'}</td>
            <td>${ev.ip_address || '127.0.0.1'}</td>
            <td class="text-muted" style="font-size:0.75rem;" title="${ev.user_agent || ''}">${(ev.user_agent || '').substring(0, 25)}...</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">Error: ${e.message}</td></tr>`;
    }
  }

  /* ================= 7. PRODUCTS CATALOG ================= */
  async function loadProducts() {
    const tbody = document.getElementById('productsBody');
    tbody.innerHTML = `<tr><td colspan="7" class="text-center">Loading operational products catalog from business.db...</td></tr>`;

    try {
      const res = await apiRequest('/api/products');
      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load products</td></tr>`;
        return;
      }

      const data = await res.json();
      const products = data.products || [];

      if (products.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No products found.</td></tr>`;
        return;
      }

      const isAdmin = state.currentUser.role === 'admin';
      const isAuditor = state.currentUser.role === 'auditor';

      tbody.innerHTML = products.map(prod => `
        <tr>
          <td class="mono bold">${escapeHtml(prod.sku)}</td>
          <td>
            <strong>${escapeHtml(prod.name)}</strong>
            <div class="text-muted" style="font-size:0.75rem;">${escapeHtml(prod.description || '')}</div>
          </td>
          <td><span class="tag">${escapeHtml(prod.category)}</span></td>
          <td class="mono bold" style="color: #34d399;">$${Number(prod.price).toFixed(2)}</td>
          <td>${prod.stock}</td>
          <td><span class="text-muted">${escapeHtml(prod.created_by)}</span></td>
          <td>
            ${isAdmin ? `
              <div style="display:flex; gap:0.4rem;">
                <button class="btn btn-sm btn-outline" onclick='AuditProApp.openProductModal(${JSON.stringify(prod)})'>Edit</button>
                <button class="btn btn-sm btn-outline-danger" onclick="AuditProApp.deleteProduct('${prod.id}')">Delete</button>
              </div>
            ` : isAuditor ? `
              <span class="badge badge-purple">Read-Only</span>
            ` : `
              <span class="badge badge-muted">Catalog</span>
            `}
          </td>
        </tr>
      `).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error: ${e.message}</td></tr>`;
    }
  }

  function openProductModal(prod = null) {
    if (state.currentUser.role !== 'admin') {
      showToast('Only Administrators can modify the product catalog', 'warning');
      return;
    }

    const form = document.getElementById('productForm');
    form.reset();

    if (prod) {
      document.getElementById('productModalTitle').textContent = `Edit Product: ${prod.sku}`;
      document.getElementById('productId').value = prod.id;
      document.getElementById('prodName').value = prod.name;
      document.getElementById('prodSku').value = prod.sku;
      document.getElementById('prodCategory').value = prod.category;
      document.getElementById('prodPrice').value = prod.price;
      document.getElementById('prodStock').value = prod.stock;
      document.getElementById('prodDescription').value = prod.description || '';
    } else {
      document.getElementById('productModalTitle').textContent = 'Add Product (business.db)';
      document.getElementById('productId').value = '';
    }

    document.getElementById('productModalOverlay').style.display = 'flex';
  }

  function closeProductModal() {
    document.getElementById('productModalOverlay').style.display = 'none';
  }

  async function handleProductSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('productId').value;
    const body = {
      name: document.getElementById('prodName').value,
      sku: document.getElementById('prodSku').value,
      category: document.getElementById('prodCategory').value,
      price: parseFloat(document.getElementById('prodPrice').value),
      stock: parseInt(document.getElementById('prodStock').value),
      description: document.getElementById('prodDescription').value
    };

    try {
      const url = id ? `/api/products/${id}` : '/api/products';
      const method = id ? 'PUT' : 'POST';

      const res = await apiRequest(url, { method, body: JSON.stringify(body) });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || 'Failed to save product', 'error');
        return;
      }

      showToast(`Product ${id ? 'updated' : 'created'} & audited in audit.db!`, 'success');
      closeProductModal();
      loadProducts();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function deleteProduct(id) {
    if (!confirm('Are you sure you want to delete this product? Action will be permanently logged.')) return;

    try {
      const res = await apiRequest(`/api/products/${id}`, { method: 'DELETE' });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || 'Delete failed', 'error');
        return;
      }

      showToast('Product deleted and logged in forensic audit trail!', 'success');
      loadProducts();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ================= 8. TASKS WORKSPACE ================= */
  async function loadTasks() {
    const tbody = document.getElementById('tasksBody');
    tbody.innerHTML = `<tr><td colspan="7" class="text-center">Loading tasks from business.db...</td></tr>`;

    try {
      const res = await apiRequest('/api/tasks');
      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load tasks</td></tr>`;
        return;
      }

      const data = await res.json();
      const tasks = data.tasks || [];

      if (tasks.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No tasks in your workspace.</td></tr>`;
        return;
      }

      const role = state.currentUser.role;
      const isAuditor = role === 'auditor';

      tbody.innerHTML = tasks.map(task => {
        let priBadge = 'badge-muted';
        if (task.priority === 'urgent') priBadge = 'badge-danger';
        else if (task.priority === 'high') priBadge = 'badge-warning';
        else if (task.priority === 'medium') priBadge = 'badge-blue';

        let statusBadge = 'badge-muted';
        if (task.status === 'completed') statusBadge = 'badge-success';
        else if (task.status === 'in_progress') statusBadge = 'badge-purple';

        return `
          <tr>
            <td><span class="badge ${priBadge}">${task.priority}</span></td>
            <td><span class="badge ${statusBadge}">${task.status.replace('_', ' ')}</span></td>
            <td>
              <strong>${escapeHtml(task.title)}</strong>
              <div class="text-muted" style="font-size:0.75rem;">${escapeHtml(task.description || '')}</div>
            </td>
            <td><strong>${escapeHtml(task.assigned_to)}</strong></td>
            <td class="text-muted">${task.due_date || '—'}</td>
            <td><span class="text-muted">${escapeHtml(task.created_by)}</span></td>
            <td>
              ${isAuditor ? `
                <span class="badge badge-purple">Read-Only</span>
              ` : `
                <div style="display:flex; gap:0.4rem;">
                  <button class="btn btn-sm btn-outline" onclick='AuditProApp.openTaskModal(${JSON.stringify(task)})'>Edit</button>
                  <button class="btn btn-sm btn-outline-danger" onclick="AuditProApp.deleteTask('${task.id}')">Delete</button>
                </div>
              `}
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error: ${e.message}</td></tr>`;
    }
  }

  function openTaskModal(task = null) {
    const form = document.getElementById('taskForm');
    form.reset();

    const role = state.currentUser.role;
    const assigneeGroup = document.getElementById('taskAssigneeGroup');

    // If standard user, hide reassign dropdown (users only work on their own tasks)
    if (role === 'user') {
      assigneeGroup.style.display = 'none';
    } else {
      assigneeGroup.style.display = 'block';
    }

    if (task) {
      document.getElementById('taskModalTitle').textContent = `Edit Task`;
      document.getElementById('taskId').value = task.id;
      document.getElementById('taskTitle').value = task.title;
      document.getElementById('taskPriority').value = task.priority;
      document.getElementById('taskStatus').value = task.status;
      document.getElementById('taskAssignee').value = task.assigned_to;
      document.getElementById('taskDueDate').value = task.due_date || '';
      document.getElementById('taskDesc').value = task.description || '';
    } else {
      document.getElementById('taskModalTitle').textContent = 'Create Task';
      document.getElementById('taskId').value = '';
    }

    document.getElementById('taskModalOverlay').style.display = 'flex';
  }

  function closeTaskModal() {
    document.getElementById('taskModalOverlay').style.display = 'none';
  }

  async function handleTaskSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('taskId').value;
    const body = {
      title: document.getElementById('taskTitle').value,
      priority: document.getElementById('taskPriority').value,
      status: document.getElementById('taskStatus').value,
      assigned_to: document.getElementById('taskAssignee').value,
      due_date: document.getElementById('taskDueDate').value || null,
      description: document.getElementById('taskDesc').value
    };

    try {
      const url = id ? `/api/tasks/${id}` : '/api/tasks';
      const method = id ? 'PUT' : 'POST';

      const res = await apiRequest(url, { method, body: JSON.stringify(body) });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || 'Failed to save task', 'error');
        return;
      }

      showToast(`Task ${id ? 'updated' : 'created'} & audited!`, 'success');
      closeTaskModal();
      loadTasks();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function deleteTask(id) {
    if (!confirm('Are you sure you want to delete this task?')) return;

    try {
      const res = await apiRequest(`/api/tasks/${id}`, { method: 'DELETE' });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || 'Delete failed', 'error');
        return;
      }

      showToast('Task deleted and audited', 'success');
      loadTasks();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ================= 9. IDENTITY & USER DIRECTORY (ADMIN ONLY) ================= */
  async function loadUsers() {
    if (state.currentUser.role !== 'admin') return;

    const tbody = document.getElementById('usersBody');
    tbody.innerHTML = `<tr><td colspan="5" class="text-center">Loading users from auth.db...</td></tr>`;

    try {
      const res = await apiRequest('/api/users');
      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Failed to load users</td></tr>`;
        return;
      }

      const data = await res.json();
      const users = data.users || [];

      tbody.innerHTML = users.map(u => {
        let roleBadge = 'badge-blue';
        if (u.role === 'admin') roleBadge = 'badge-danger';
        else if (u.role === 'auditor') roleBadge = 'badge-purple';

        return `
          <tr>
            <td><strong>${escapeHtml(u.username)}</strong></td>
            <td>${escapeHtml(u.full_name)}</td>
            <td><span class="badge ${roleBadge}">${u.role.toUpperCase()}</span></td>
            <td class="text-muted" style="font-size:0.78rem;">${new Date(u.created_at).toLocaleDateString()}</td>
            <td>
              <div style="display:flex; gap:0.4rem;">
                <button class="btn btn-sm btn-outline" onclick='AuditProApp.openUserModal(${JSON.stringify(u)})'>Edit</button>
                ${u.id !== state.currentUser.id ? `
                  <button class="btn btn-sm btn-outline-danger" onclick="AuditProApp.deleteUser('${u.id}', '${u.username}')">Delete</button>
                ` : `<span class="text-muted" style="font-size:0.75rem;">(Active Self)</span>`}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Error: ${e.message}</td></tr>`;
    }
  }

  function openUserModal(user = null) {
    const form = document.getElementById('userForm');
    form.reset();

    if (user) {
      document.getElementById('userModalTitle').textContent = `Edit Identity: ${user.username}`;
      document.getElementById('userId').value = user.id;
      document.getElementById('userUsername').value = user.username;
      document.getElementById('userUsername').disabled = true; // username immutable
      document.getElementById('userFullName').value = user.full_name;
      document.getElementById('userRoleSelect').value = user.role;
      document.getElementById('userPasswordNote').textContent = '(Leave blank to keep existing password)';
      document.getElementById('userPassword').required = false;
    } else {
      document.getElementById('userModalTitle').textContent = 'Provision Identity (auth.db)';
      document.getElementById('userId').value = '';
      document.getElementById('userUsername').disabled = false;
      document.getElementById('userPasswordNote').textContent = '(Required)';
      document.getElementById('userPassword').required = true;
    }

    document.getElementById('userModalOverlay').style.display = 'flex';
  }

  function closeUserModal() {
    document.getElementById('userModalOverlay').style.display = 'none';
  }

  async function handleUserSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('userId').value;
    const body = {
      username: document.getElementById('userUsername').value,
      full_name: document.getElementById('userFullName').value,
      role: document.getElementById('userRoleSelect').value,
      password: document.getElementById('userPassword').value
    };

    try {
      const url = id ? `/api/users/${id}` : '/api/users';
      const method = id ? 'PUT' : 'POST';

      const res = await apiRequest(url, { method, body: JSON.stringify(body) });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || 'Failed to save user', 'error');
        return;
      }

      showToast(`User identity ${id ? 'updated' : 'provisioned'} and audited!`, 'success');
      closeUserModal();
      loadUsers();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function deleteUser(id, username) {
    if (!confirm(`Permanently remove identity '${username}'? Action is strictly audited.`)) return;

    try {
      const res = await apiRequest(`/api/users/${id}`, { method: 'DELETE' });
      const data = await res.json();

      if (!res.ok) {
        showToast(data.error || 'Delete failed', 'error');
        return;
      }

      showToast(`Identity '${username}' removed and logged!`, 'success');
      loadUsers();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ================= 10. AUTHENTICATION & QUICK SWITCHING ================= */
  async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Authentication failed', 'error');
        return;
      }

      state.currentUser = data.user;
      state.accessToken = data.accessToken;
      state.refreshToken = data.refreshToken;
      state.currentJti = data.jti;

      localStorage.setItem('auditpro_access_token', state.accessToken);
      localStorage.setItem('auditpro_refresh_token', state.refreshToken);
      localStorage.setItem('auditpro_jti', state.currentJti);

      showToast(`Welcome back, ${data.user.full_name}! (JTI logged)`, 'success');
      applyRoleExperience();
      loadDashboardData();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function fillAndLogin(username, password) {
    document.getElementById('loginUsername').value = username;
    document.getElementById('loginPassword').value = password;
    document.getElementById('loginForm').dispatchEvent(new Event('submit', { cancelable: true }));
  }

  async function quickSwitch(targetUsername, silent = false) {
    try {
      const res = await fetch('/api/auth/quick-switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUsername })
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Switch failed', 'error');
        return;
      }

      state.currentUser = data.user;
      state.accessToken = data.accessToken;
      state.refreshToken = data.refreshToken;
      state.currentJti = data.jti;

      localStorage.setItem('auditpro_access_token', state.accessToken);
      localStorage.setItem('auditpro_refresh_token', state.refreshToken);
      localStorage.setItem('auditpro_jti', state.currentJti);

      if (!silent) {
        showToast(`Switched context to ${data.user.role.toUpperCase()} (${data.user.username})`, 'success');
      }

      applyRoleExperience();
      loadDashboardData();
    } catch (err) {
      showToast(`Quick switch error: ${err.message}`, 'error');
    }
  }

  async function logout(callServer = true) {
    if (callServer && state.accessToken) {
      try {
        await apiRequest('/api/auth/logout', {
          method: 'POST',
          body: JSON.stringify({ refreshToken: state.refreshToken })
        });
      } catch (e) {
        // ignore logout network errors
      }
    }

    state.currentUser = null;
    state.accessToken = null;
    state.refreshToken = null;
    state.currentJti = null;

    localStorage.removeItem('auditpro_access_token');
    localStorage.removeItem('auditpro_refresh_token');
    localStorage.removeItem('auditpro_jti');

    document.getElementById('authModalOverlay').style.display = 'flex';
    showToast('Signed out of session', 'warning');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Auto-init on page ready
  document.addEventListener('DOMContentLoaded', init);

  // Public Interface
  return {
    init,
    switchTab,
    applyFilters,
    debouncedFilter,
    resetFilters,
    changePage,
    inspectLogDiff,
    closeDiffModal,
    exportAudit,
    openImmutabilityModal,
    closeImmutabilityModal,
    runTamperTest,
    loadJwtEvents,
    openProductModal,
    closeProductModal,
    handleProductSubmit,
    deleteProduct,
    openTaskModal,
    closeTaskModal,
    handleTaskSubmit,
    deleteTask,
    openUserModal,
    closeUserModal,
    handleUserSubmit,
    deleteUser,
    handleLogin,
    fillAndLogin,
    quickSwitch,
    logout
  };
})();
