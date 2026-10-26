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
    searchDebounceTimer: null,
    sessionStartTime: parseInt(localStorage.getItem('auditpro_session_start')) || Date.now(),
    sessionTimerInterval: null,
    heartbeatInterval: null,
    footprintFilters: {
      actor: '',
      type: '',
      search: ''
    },
    footprintPagination: {
      page: 1,
      limit: 15,
      total: 0,
      totalPages: 1
    }
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
          startSessionTimers();
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
      bannerSubtitle.textContent = 'Full operational oversight, user presence tracking, and immutable activity auditing.';
      bannerIcon.textContent = '👑';
    } else if (role === 'auditor') {
      bannerTitle.textContent = 'Compliance & Forensics Center';
      bannerSubtitle.textContent = 'Forensic audit inspection, user presence tracking, and read-only operational oversight.';
      bannerIcon.textContent = '🔍';
    } else {
      bannerTitle.textContent = `${user.full_name}'s Isolated Workspace`;
      bannerSubtitle.textContent = 'Operational task workspace. Tasks created by other users cannot be modified or deleted.';
      bannerIcon.textContent = '👤';
    }

    // Role-Aware Navigation Tabs Visibility (5 Unified Tabs)
    const tabCompliance = document.getElementById('tabCompliance');
    const tabFootprints = document.getElementById('tabFootprints');
    const tabProducts = document.getElementById('tabProducts');
    const tabTasks = document.getElementById('tabTasks');
    const tabUsers = document.getElementById('tabUsers');
    const btnCreateProduct = document.getElementById('btnCreateProduct');
    const productsNotice = document.getElementById('productsAuditorNotice');
    const userWorkspaceNotice = document.getElementById('userWorkspaceNotice');
    const tasksTabTitle = document.getElementById('tasksTabTitle');

    if (role === 'admin') {
      if (tabCompliance) tabCompliance.style.display = 'inline-flex';
      if (tabFootprints) tabFootprints.style.display = 'inline-flex';
      if (tabProducts) tabProducts.style.display = 'inline-flex';
      if (tabTasks) tabTasks.style.display = 'inline-flex';
      if (tabUsers) tabUsers.style.display = 'inline-flex';
      if (btnCreateProduct) btnCreateProduct.style.display = 'inline-flex';
      if (productsNotice) productsNotice.style.display = 'none';
      if (userWorkspaceNotice) userWorkspaceNotice.style.display = 'none';
      if (tasksTabTitle) tasksTabTitle.textContent = 'All System Tasks';
    } else if (role === 'auditor') {
      if (tabCompliance) tabCompliance.style.display = 'inline-flex';
      if (tabFootprints) tabFootprints.style.display = 'inline-flex';
      if (tabProducts) tabProducts.style.display = 'inline-flex';
      if (tabTasks) tabTasks.style.display = 'inline-flex';
      if (tabUsers) tabUsers.style.display = 'none'; // Auditor doesn't manage identities
      if (btnCreateProduct) btnCreateProduct.style.display = 'none'; // Auditor is strictly read-only
      if (productsNotice) productsNotice.style.display = 'block';
      if (userWorkspaceNotice) userWorkspaceNotice.style.display = 'none';
      if (tasksTabTitle) tasksTabTitle.textContent = 'Tasks (Audit Oversight)';
    } else {
      // Regular User (Alice / Bob)
      if (tabCompliance) tabCompliance.style.display = 'none';
      if (tabFootprints) tabFootprints.style.display = 'none';
      if (tabProducts) tabProducts.style.display = 'inline-flex';
      if (tabTasks) tabTasks.style.display = 'inline-flex';
      if (tabUsers) tabUsers.style.display = 'none';
      if (btnCreateProduct) btnCreateProduct.style.display = 'none';
      if (productsNotice) productsNotice.style.display = 'none';
      if (userWorkspaceNotice) userWorkspaceNotice.style.display = 'block';
      if (tasksTabTitle) tasksTabTitle.textContent = 'My Assigned Tasks';

      // If user was on a forbidden tab, move them to tasks
      if (['compliance', 'footprints', 'users'].includes(state.currentTab)) {
        switchTab('tasks');
      }
    }

    updateJtiDisplay();
  }

  /* ================= REAL-TIME SESSION DWELL TIME & HEARTBEAT ================= */
  function startSessionTimers() {
    if (!state.sessionStartTime) {
      state.sessionStartTime = Date.now();
      localStorage.setItem('auditpro_session_start', state.sessionStartTime);
    }

    if (state.sessionTimerInterval) clearInterval(state.sessionTimerInterval);
    if (state.heartbeatInterval) clearInterval(state.heartbeatInterval);

    function updateTimerUI() {
      const elapsedSec = Math.max(0, Math.floor((Date.now() - state.sessionStartTime) / 1000));
      const mins = Math.floor(elapsedSec / 60);
      const secs = elapsedSec % 60;
      const el = document.getElementById('sessionTimerDisplay');
      if (el) {
        el.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
      }
    }

    updateTimerUI();
    state.sessionTimerInterval = setInterval(updateTimerUI, 1000);

    // Sync live heartbeat to server every 20 seconds
    async function sendHeartbeat() {
      if (!state.accessToken || !state.currentUser) return;
      const elapsedSec = Math.max(0, Math.floor((Date.now() - state.sessionStartTime) / 1000));
      try {
        await apiRequest('/api/auth/heartbeat', {
          method: 'POST',
          body: JSON.stringify({
            durationSeconds: elapsedSec,
            currentView: state.currentTab || 'Dashboard'
          })
        });
      } catch (err) {
        // non-blocking
      }
    }

    sendHeartbeat();
    state.heartbeatInterval = setInterval(sendHeartbeat, 20000);
  }

  function stopSessionTimers() {
    if (state.sessionTimerInterval) clearInterval(state.sessionTimerInterval);
    if (state.heartbeatInterval) clearInterval(state.heartbeatInterval);
    state.sessionTimerInterval = null;
    state.heartbeatInterval = null;
    state.sessionStartTime = null;
    localStorage.removeItem('auditpro_session_start');
    const el = document.getElementById('sessionTimerDisplay');
    if (el) el.textContent = '00:00';
  }

  /**
   * Automatically records an uneditable view footprint whenever a user visits or views a screen
   */
  async function recordViewFootprint(tabId) {
    if (!state.accessToken || !state.currentUser) return;
    const tabNames = {
      compliance: 'System Overview & Metrics',
      footprints: 'User Footprints & Audit Trail',
      products: 'Products Inventory',
      tasks: 'System Tasks Workspace',
      users: 'User Accounts & Directory'
    };
    const viewName = tabNames[tabId] || tabId;
    const elapsedSec = state.sessionStartTime ? Math.max(0, Math.floor((Date.now() - state.sessionStartTime) / 1000)) : 0;

    try {
      await apiRequest('/api/audit/view', {
        method: 'POST',
        body: JSON.stringify({
          viewName,
          entityType: 'screen_view',
          entityId: tabId,
          durationInView: elapsedSec
        })
      });
    } catch (e) {
      // non-blocking
    }
  }

  function updateJtiDisplay() {
    // JWT information is hidden from display per requirements
  }

  /**
   * Tab Switching (Unified 5-Tab Architecture)
   */
  function switchTab(tabId) {
    state.currentTab = tabId;

    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

    const tabMap = {
      compliance: { btn: 'tabCompliance', pane: 'paneCompliance', loader: loadComplianceStats },
      footprints: { btn: 'tabFootprints', pane: 'paneFootprints', loader: loadFootprintsTab },
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

    // Immutably record view footprint into audit trail
    recordViewFootprint(tabId);
  }

  /**
   * Load Data for all active screens
   */
  function loadDashboardData() {
    if (state.currentUser && state.currentUser.role === 'user') {
      switchTab('tasks');
    } else {
      loadComplianceStats();
      if (state.currentTab === 'footprints') loadFootprintsTab();
      if (state.currentTab === 'products') loadProducts();
      if (state.currentTab === 'tasks') loadTasks();
      if (state.currentTab === 'users') loadUsers();
    }
  }

  /* ================= 1. COMPLIANCE & HEALTH STATS ================= */
  async function loadComplianceStats() {
    if (!state.currentUser || state.currentUser.role === 'user') return;

    try {
      const res = await apiRequest('/api/reports/stats');
      if (!res.ok) return;
      const data = await res.json();

      const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

      setEl('metricHealthScore', data.healthScore || '100%');
      setEl('metricTotalLogs', (data.totalLogs || 0).toLocaleString());
      setEl('metricTodayLogs', (data.todayLogs || 0).toLocaleString());
      setEl('metricAccessDenied', (data.deniedCount || 0).toLocaleString());
      setEl('metricDeniedCount', data.deniedCount || 0);
      setEl('metricFailedLogins', (data.failedCount || 0).toLocaleString());

      if (data.sessionStats) {
        setEl('overviewActiveUsers', data.sessionStats.activeUsersCount || 0);
        setEl('overviewAvgStay', data.sessionStats.averageStayFormatted || '0s');
        setEl('footprintsActiveUsers', data.sessionStats.activeUsersCount || 0);
        setEl('footprintsAvgStay', data.sessionStats.averageStayFormatted || '0s');
        setEl('footprintsTotalSessions', data.sessionStats.totalSessions || 0);
        setEl('footprintsTotalFootprints', (data.totalLogs || 0).toLocaleString());
      }
    } catch (e) {
      console.error('Failed to load compliance stats:', e);
    }
  }

  /* ================= 2. 🌟 BEFORE/AFTER DIFF INSPECTOR ================= */
  async function inspectLogDiff(logId) {
    try {
      const res = await apiRequest(`/api/audit/logs/${logId}`);
      if (!res.ok) {
        showToast('Could not load log details', 'error');
        return;
      }

      const { log } = await res.json();

      const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

      setEl('diffLogId', `#${log.id}`);
      setEl('diffTimestamp', new Date(log.timestamp).toLocaleString());
      setEl('diffActor', `${log.username} (${log.role})`);
      setEl('diffIp', log.ip_address || 'Unknown');
      setEl('diffActionText', log.action);
      setEl('diffEntityId', log.entity_id || '—');
      setEl('diffStatus', log.status || 'SUCCESS');
      setEl('diffModalEventBadge', log.event);

      document.getElementById('diffModalOverlay').style.display = 'flex';
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function closeDiffModal() {
    document.getElementById('diffModalOverlay').style.display = 'none';
  }

  /* ================= 3. EXPORT AUDIT TRAIL ================= */
  async function exportAudit(format = 'csv') {
    const params = new URLSearchParams({
      username: state.footprintFilters.actor || '',
      event: state.footprintFilters.type || '',
      search: state.footprintFilters.search || ''
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
      a.download = `auditpro-footprints-${new Date().toISOString().substring(0, 10)}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      showToast(`Exported user footprints & activity trail to ${format.toUpperCase()}`, 'success');

      // Refresh activity footprints list
      setTimeout(() => loadFootprintsStream(), 800);
    } catch (e) {
      showToast(`Export error: ${e.message}`, 'error');
    }
  }

  /* ================= 4. PRODUCTS CATALOG ================= */
  async function loadProducts() {
    const tbody = document.getElementById('productsBody');
    tbody.innerHTML = `<tr><td colspan="7" class="text-center">Loading product catalog...</td></tr>`;

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
      document.getElementById('productModalTitle').textContent = 'Add Product';
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

      showToast(`Product ${id ? 'updated' : 'created'} and recorded in audit trail!`, 'success');
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

      showToast('Product deleted and logged in activity trail!', 'success');
      loadProducts();
      loadComplianceStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ================= 5. TASKS WORKSPACE ================= */
  async function loadTasks() {
    const tbody = document.getElementById('tasksBody');
    tbody.innerHTML = `<tr><td colspan="7" class="text-center">Loading tasks...</td></tr>`;

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

      const currentUsername = state.currentUser ? state.currentUser.username : '';
      const isAuditor = state.currentUser && state.currentUser.role === 'auditor';

      tbody.innerHTML = tasks.map(task => {
        let priBadge = 'badge-muted';
        if (task.priority === 'urgent') priBadge = 'badge-danger';
        else if (task.priority === 'high') priBadge = 'badge-warning';
        else if (task.priority === 'medium') priBadge = 'badge-blue';

        let statusBadge = 'badge-muted';
        if (task.status === 'completed') statusBadge = 'badge-success';
        else if (task.status === 'in_progress') statusBadge = 'badge-purple';

        // Compliance Rule: Nobody (including Admin) can edit tasks created by other users
        const isOwner = task.created_by === currentUsername;

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
              ` : isOwner ? `
                <div style="display:flex; gap:0.4rem;">
                  <button class="btn btn-sm btn-outline" onclick='AuditProApp.openTaskModal(${JSON.stringify(task)})'>Edit</button>
                  <button class="btn btn-sm btn-outline-danger" onclick="AuditProApp.deleteTask('${task.id}')">Delete</button>
                </div>
              ` : `
                <span class="badge badge-muted" title="Protected: Tasks created by '${escapeHtml(task.created_by)}' cannot be modified or deleted by other users or administrators">
                  🔒 Created by ${escapeHtml(task.created_by)}
                </span>
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

    const role = state.currentUser ? state.currentUser.role : 'user';
    const currentUsername = state.currentUser ? state.currentUser.username : '';
    const assigneeGroup = document.getElementById('taskAssigneeGroup');

    // If standard user, hide reassign dropdown (users only work on their own tasks)
    if (role === 'user') {
      assigneeGroup.style.display = 'none';
    } else {
      assigneeGroup.style.display = 'block';
    }

    if (task) {
      // Prevent non-creator (even admin) from editing someone else's task
      if (task.created_by !== currentUsername) {
        showToast(`Protected: You cannot edit tasks created by ${task.created_by}`, 'warning');
        return;
      }

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

  /* ================= 6. USER ACCOUNTS & DIRECTORY (ADMIN ONLY) ================= */
  async function loadUsers() {
    if (!state.currentUser || state.currentUser.role !== 'admin') return;

    const tbody = document.getElementById('usersBody');
    tbody.innerHTML = `<tr><td colspan="5" class="text-center">Loading user accounts...</td></tr>`;

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
      document.getElementById('userModalTitle').textContent = `Edit User: ${user.username}`;
      document.getElementById('userId').value = user.id;
      document.getElementById('userUsername').value = user.username;
      document.getElementById('userUsername').disabled = true; // username immutable
      document.getElementById('userFullName').value = user.full_name;
      document.getElementById('userRoleSelect').value = user.role;
      document.getElementById('userPasswordNote').textContent = '(Leave blank to keep existing password)';
      document.getElementById('userPassword').required = false;
    } else {
      document.getElementById('userModalTitle').textContent = 'Provision User Account';
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

  /* ================= 7. USER FOOTPRINTS & PRESENCE AUDITING ================= */
  async function loadFootprintsTab() {
    if (!state.currentUser || state.currentUser.role === 'user') return;
    await Promise.all([
      loadUserSessions(),
      loadFootprintsStream(),
      loadComplianceStats()
    ]);
  }

  async function loadUserSessions() {
    const tbody = document.getElementById('userSessionsBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="9" class="text-center">Querying active sessions and dwell times...</td></tr>`;

    try {
      const res = await apiRequest('/api/audit/sessions?limit=50');
      if (!res.ok) throw new Error('Failed to load user sessions');
      const data = await res.json();
      const sessions = data.sessions || [];

      if (sessions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No session dwell times recorded yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = sessions.map(s => {
        const isOnline = s.status === 'ACTIVE';
        const isLoggedOut = s.status === 'LOGGED_OUT';
        const statusBadge = isOnline ? 'badge-success' : isLoggedOut ? 'badge-blue' : 'badge-warning';
        const statusText = isOnline ? '🟢 Logged In (Active)' : isLoggedOut ? '⚪ Logged Out' : '⏱️ Timed Out';
        const roleEmoji = s.role === 'admin' ? '👑' : s.role === 'auditor' ? '🔍' : '👤';
        const logoutDisplay = s.logout_time ? `<span class="mono" style="font-size:0.78rem;">${new Date(s.logout_time).toLocaleTimeString()}</span>` : isOnline ? `<span class="badge badge-success">Active Now</span>` : `<span class="text-muted">—</span>`;

        return `
          <tr>
            <td>
              <div style="display:flex; align-items:center; gap:8px;">
                <div class="user-avatar" style="width:26px; height:26px; font-size:0.7rem;">${(s.username || 'U').substring(0, 2).toUpperCase()}</div>
                <strong>${escapeHtml(s.username)}</strong>
              </div>
            </td>
            <td><span class="role-pill" style="font-size:0.72rem;">${roleEmoji} ${(s.role || '').toUpperCase()}</span></td>
            <td><span class="badge ${statusBadge}">${statusText}</span></td>
            <td class="text-muted mono" style="font-size:0.78rem;">${new Date(s.login_time).toLocaleTimeString()}</td>
            <td>${logoutDisplay}</td>
            <td>
              <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #34d399; font-family: var(--font-mono); font-weight: 700; font-size: 0.85rem; border: 1px solid rgba(16, 185, 129, 0.3);">
                ⏱️ ${s.formatted_duration || '0s'}
              </span>
            </td>
            <td>
              <span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; font-family: var(--font-mono); font-weight: 700; font-size: 0.82rem; border: 1px solid rgba(59, 130, 246, 0.3);">
                🎯 ${s.total_actions || 0}
              </span>
            </td>
            <td class="text-muted mono" style="font-size:0.78rem;">${new Date(s.last_active).toLocaleTimeString()}</td>
            <td><span class="tag">${escapeHtml(s.last_view || 'Dashboard')}</span></td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger">Error: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  async function loadFootprintsStream() {
    const tbody = document.getElementById('footprintsStreamBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7" class="text-center">Querying recorded activity...</td></tr>`;

    try {
      const params = new URLSearchParams({
        page: state.footprintPagination.page,
        limit: state.footprintPagination.limit,
        username: state.footprintFilters.actor || '',
        search: state.footprintFilters.search || ''
      });

      if (state.footprintFilters.type) {
        params.append('event', state.footprintFilters.type);
      }

      const res = await apiRequest(`/api/audit/logs?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load activity footprints');
      const data = await res.json();
      const logs = data.logs || [];

      // Update pagination controls
      state.footprintPagination.total = data.total || 0;
      state.footprintPagination.totalPages = data.totalPages || 1;

      const pageInfo = document.getElementById('footprintsPageInfo');
      if (pageInfo) {
        pageInfo.textContent = `Showing page ${data.page} of ${data.totalPages || 1} (${data.total || 0} activities recorded)`;
      }
      const prevBtn = document.getElementById('btnFootprintPrev');
      if (prevBtn) prevBtn.disabled = data.page <= 1;
      const nextBtn = document.getElementById('btnFootprintNext');
      if (nextBtn) nextBtn.disabled = data.page >= (data.totalPages || 1);

      if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No activity footprints matching filters.</td></tr>`;
        return;
      }

      tbody.innerHTML = logs.map(l => {
        let categoryBadge = '<span class="footprint-badge view">👁️ VIEW SCREEN</span>';
        if (l.event.startsWith('VIEW_')) {
          categoryBadge = '<span class="footprint-badge view">👁️ VIEW SCREEN</span>';
        } else if (l.event.includes('CREATE')) {
          categoryBadge = '<span class="footprint-badge mutation">➕ CREATE ITEM</span>';
        } else if (l.event.includes('UPDATE')) {
          categoryBadge = '<span class="footprint-badge mutation">✏️ UPDATE ITEM</span>';
        } else if (l.event.includes('DELETE')) {
          categoryBadge = '<span class="footprint-badge mutation" style="border-color: rgba(239, 68, 68, 0.4); color: #f87171;">🗑️ DELETE ITEM</span>';
        } else if (l.event.includes('LOGIN') || l.event.includes('LOGOUT')) {
          categoryBadge = '<span class="footprint-badge auth">🔐 SIGN IN / OUT</span>';
        } else if (l.event.includes('DENIED')) {
          categoryBadge = '<span class="footprint-badge security" style="border-color: rgba(239, 68, 68, 0.4); color: #f87171;">🚫 ACCESS BLOCKED</span>';
        } else {
          categoryBadge = '<span class="footprint-badge security">🛡️ SYSTEM AUDIT</span>';
        }

        return `
          <tr class="clickable-row" onclick="AuditProApp.inspectLogDiff(${l.id})" title="Click to view full details">
            <td class="mono">#${l.id}</td>
            <td class="text-muted mono" style="font-size:0.78rem;">${new Date(l.timestamp).toLocaleTimeString()}</td>
            <td><strong>${escapeHtml(l.username || 'system')}</strong> <span class="text-muted" style="font-size:0.75rem;">(${l.role || ''})</span></td>
            <td>${categoryBadge}</td>
            <td>${escapeHtml(l.action || '')}</td>
            <td><span class="tag">${escapeHtml(l.entity_id || '—')}</span></td>
            <td>
              <button class="btn btn-sm btn-outline-accent" onclick="event.stopPropagation(); AuditProApp.inspectLogDiff(${l.id})">
                Inspect Details
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  function changeFootprintPage(delta) {
    state.footprintPagination.page = Math.max(1, state.footprintPagination.page + delta);
    loadFootprintsStream();
  }

  function applyFootprintFilters() {
    state.footprintFilters.actor = document.getElementById('filterFootprintActor').value;
    state.footprintFilters.type = document.getElementById('filterFootprintType').value;
    state.footprintPagination.page = 1;
    loadFootprintsStream();
  }

  function resetFootprintFilters() {
    document.getElementById('filterFootprintActor').value = '';
    document.getElementById('filterFootprintType').value = '';
    document.getElementById('searchFootprint').value = '';
    state.footprintFilters.actor = '';
    state.footprintFilters.type = '';
    state.footprintFilters.search = '';
    state.footprintPagination.page = 1;
    loadFootprintsStream();
  }

  function debounceFootprintSearch() {
    clearTimeout(state.searchDebounceTimer);
    state.searchDebounceTimer = setTimeout(() => {
      state.footprintFilters.search = document.getElementById('searchFootprint').value;
      state.footprintPagination.page = 1;
      loadFootprintsStream();
    }, 300);
  }

  /* ================= 8. AUTHENTICATION & QUICK SWITCHING ================= */
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

      state.sessionStartTime = Date.now();
      localStorage.setItem('auditpro_session_start', state.sessionStartTime);
      startSessionTimers();

      showToast(`Welcome back, ${data.user.full_name}!`, 'success');
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
    const elapsedSec = state.sessionStartTime ? Math.max(0, Math.floor((Date.now() - state.sessionStartTime) / 1000)) : 0;
    try {
      const res = await fetch('/api/auth/quick-switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUsername,
          previousJti: state.currentJti,
          previousUsername: state.currentUser ? state.currentUser.username : null,
          previousRole: state.currentUser ? state.currentUser.role : null,
          previousDurationSeconds: elapsedSec
        })
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

      state.sessionStartTime = Date.now();
      localStorage.setItem('auditpro_session_start', state.sessionStartTime);
      startSessionTimers();

      if (!silent) {
        showToast(`Switched context to ${data.user.role.toUpperCase()} (${data.user.username})`, 'success');
      }

      applyRoleExperience();
      loadDashboardData();
    } catch (err) {
      showToast(`Quick switch error: ${err.message}`, 'error');
    }
  }

  /**
   * Manual SSMS Database Synchronization
   */
  async function manualSsmsSync() {
    const btn = document.getElementById('btnSyncSsms');
    if (btn) btn.textContent = '⏳ Syncing to SSMS...';
    try {
      const res = await apiRequest('/api/audit/sync-ssms', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showToast(`🗄️ Database synchronized with SSMS: ${data.stats?.auditLogsCount || 0} logs, ${data.stats?.userSessionsCount || 0} sessions`, 'success');
      } else {
        showToast(`Sync notice: ${data.error || 'Completed'}`, 'warning');
      }
    } catch (e) {
      showToast(`Sync error: ${e.message}`, 'error');
    } finally {
      if (btn) btn.textContent = '🗄️ Sync Database to SSMS';
      loadUserSessions();
      loadFootprintsStream();
      loadComplianceStats();
    }
  }

  async function logout(callServer = true) {
    const elapsedSec = state.sessionStartTime ? Math.max(0, Math.floor((Date.now() - state.sessionStartTime) / 1000)) : 0;
    const mins = Math.floor(elapsedSec / 60);
    const secs = elapsedSec % 60;
    const formattedStay = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;

    if (callServer && state.accessToken) {
      try {
        await apiRequest('/api/auth/logout', {
          method: 'POST',
          body: JSON.stringify({ 
            refreshToken: state.refreshToken,
            durationSeconds: elapsedSec 
          })
        });
      } catch (e) {
        // ignore logout network errors
      }
    }

    stopSessionTimers();
    state.currentUser = null;
    state.accessToken = null;
    state.refreshToken = null;
    state.currentJti = null;

    localStorage.removeItem('auditpro_access_token');
    localStorage.removeItem('auditpro_refresh_token');
    localStorage.removeItem('auditpro_jti');

    document.getElementById('authModalOverlay').style.display = 'flex';
    showToast(`Signed out of session. Total time stayed: ${formattedStay}`, 'warning');
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
    inspectLogDiff,
    closeDiffModal,
    exportAudit,
    loadFootprintsTab,
    loadUserSessions,
    loadFootprintsStream,
    changeFootprintPage,
    applyFootprintFilters,
    resetFootprintFilters,
    debounceFootprintSearch,
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
    logout,
    manualSsmsSync
  };
})();
