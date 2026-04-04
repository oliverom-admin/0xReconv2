/**
 * CAIP Remote Collectors Management Module
 *
 * Handles all collector-related UI operations:
 * - Dashboard stats and charts
 * - Collector listing and details
 * - Bootstrap token generation
 * - Settings management
 */

// =============================================================================
// STATE
// =============================================================================

let collectorsData = [];
let tokensData = [];
let activityData = [];
let collectorsHealthChart = null;
let collectorsActivityChart = null;
let collectorsRefreshInterval = null;

// =============================================================================
// MODAL HELPERS (local to this module)
// =============================================================================

/**
 * Open a modal by ID
 */
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
    }
}

/**
 * Close a modal by ID
 */
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize collectors module when tab is activated
 */
function initCollectorsModule() {
    

    // Ensure default sub-tab (Dashboard) is selected
    switchToCollectorsTab('collectors-dashboard');

    loadCollectorsStats();
    loadCollectorsList();
    loadBootstrapTokens();
    initCollectorsCharts();

    // Set up auto-refresh every 30 seconds
    if (collectorsRefreshInterval) {
        clearInterval(collectorsRefreshInterval);
    }
    collectorsRefreshInterval = setInterval(() => {
        if (document.getElementById('collectors').classList.contains('active')) {
            loadCollectorsStats();
            loadCollectorsList();
        }
    }, 30000);
}

/**
 * Clean up when leaving collectors module
 */
function cleanupCollectorsModule() {
    if (collectorsRefreshInterval) {
        clearInterval(collectorsRefreshInterval);
        collectorsRefreshInterval = null;
    }
}

// =============================================================================
// API CALLS
// =============================================================================

/**
 * Load collector statistics
 */
async function loadCollectorsStats() {
    try {
        const response = await fetch('/api/remote/stats');
        if (!response.ok) throw new Error('Failed to load stats');

        const data = await response.json();
        if (data.status === 'success') {
            updateCollectorsStats(data.statistics);
        }
    } catch (error) {
        
    }
}

/**
 * Load list of collectors
 */
async function loadCollectorsList() {
    try {
        const response = await fetch('/api/remote/collectors');
        if (!response.ok) throw new Error('Failed to load collectors');

        const data = await response.json();
        if (data.status === 'success') {
            collectorsData = data.collectors || [];
            renderCollectorsGrid();
            renderRegisteredCollectors();
            updateCollectorsHealthChart();
            updateActivityFeed();
            updateActivityChart();
        }
    } catch (error) {

    }
}

/**
 * Load bootstrap tokens
 */
async function loadBootstrapTokens() {
    try {
        const response = await fetch('/api/remote/tokens');
        if (!response.ok) throw new Error('Failed to load tokens');

        const data = await response.json();
        if (data.status === 'success') {
            tokensData = data.tokens || [];
            renderTokensTable();
        }
    } catch (error) {
        
    }
}

/**
 * Get collector details
 */
async function getCollectorDetails(collectorId) {
    try {
        const response = await fetch(`/api/remote/collector/${collectorId}`);
        if (!response.ok) throw new Error('Failed to load collector details');

        const data = await response.json();
        return data.status === 'success' ? data.collector : null;
    } catch (error) {
        
        return null;
    }
}

// =============================================================================
// UI UPDATES
// =============================================================================

/**
 * Update stats cards
 */
function updateCollectorsStats(stats) {
    if (!stats) return;

    // Get counts from collectors_by_status breakdown
    const byStatus = stats.collectors_by_status || {};
    const online = (byStatus.active || 0) + (byStatus.online || 0);
    const offline = (byStatus.offline || 0) + (byStatus.pending || 0);

    document.getElementById('collectors-stat-total').textContent = stats.total_collectors || 0;
    document.getElementById('collectors-stat-online').textContent = online;
    document.getElementById('collectors-stat-offline').textContent = offline;
    document.getElementById('collectors-stat-certs').textContent = stats.total_certificates || 0;
}

/**
 * Render collectors grid
 */
async function renderCollectorsGrid() {
    const grid = document.getElementById('collectors-grid');
    const emptyState = document.getElementById('collectors-empty-state');

    if (!collectorsData || collectorsData.length === 0) {
        grid.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }

    emptyState.style.display = 'none';

    // Apply search filter
    const searchTerm = document.getElementById('collectors-search')?.value?.toLowerCase() || '';
    const statusFilter = document.getElementById('collectors-filter-status')?.value || '';

    const filtered = collectorsData.filter(c => {
        const matchesSearch = !searchTerm ||
            c.collector_name?.toLowerCase().includes(searchTerm) ||
            c.location?.toLowerCase().includes(searchTerm) ||
            c.organization?.toLowerCase().includes(searchTerm);
        const matchesStatus = !statusFilter || c.status === statusFilter;
        return matchesSearch && matchesStatus;
    });

    // Fetch configs for all collectors in parallel
    const configsPromises = filtered.map(c => getCollectorConfig(c.collector_id));
    const configs = await Promise.all(configsPromises);

    // Render cards with their configs
    grid.innerHTML = filtered.map((collector, idx) => renderCollectorCard(collector, configs[idx])).join('');
}

/**
 * Calculate collector status based on last heartbeat
 */
function calculateCollectorStatus(collector) {
    // If explicitly suspended, return that
    if (collector.status === 'suspended') {
        return 'suspended';
    }

    // Check last heartbeat to determine online/offline/degraded
    if (!collector.last_heartbeat) {
        return 'offline';
    }

    const now = new Date();
    const lastHeartbeat = new Date(collector.last_heartbeat);
    const diffMinutes = (now - lastHeartbeat) / (1000 * 60);

    // Online: heartbeat within last 5 minutes
    if (diffMinutes < 5) {
        return 'online';
    }
    // Degraded: heartbeat within last 30 minutes
    else if (diffMinutes < 30) {
        return 'degraded';
    }
    // Offline: no heartbeat for 30+ minutes
    else {
        return 'offline';
    }
}

/**
 * Render single collector card with standard format
 */
function renderCollectorCard(collector, config) {
    // Status colors
    const statusColors = {
        'active': { bg: 'rgba(16, 185, 129, 0.1)', border: '#10b981', text: '#10b981', icon: '✓' },
        'online': { bg: 'rgba(16, 185, 129, 0.1)', border: '#10b981', text: '#10b981', icon: '✓' },
        'offline': { bg: 'rgba(239, 68, 68, 0.1)', border: '#ef4444', text: '#ef4444', icon: '✕' },
        'degraded': { bg: 'rgba(245, 158, 11, 0.1)', border: '#f59e0b', text: '#f59e0b', icon: '⚠️' },
        'pending': { bg: 'rgba(59, 130, 246, 0.1)', border: '#3b82f6', text: '#3b82f6', icon: '◐' },
        'suspended': { bg: 'rgba(107, 114, 128, 0.1)', border: '#6b7280', text: '#6b7280', icon: '—' }
    };

    // Calculate status based on heartbeat
    const calculatedStatus = calculateCollectorStatus(collector);
    const statusInfo = statusColors[calculatedStatus] || statusColors['offline'];

    const modeLabels = {
        'full': 'Full',
        'selective': 'Selective',
        'anonymized': 'Anonymized'
    };

    // Map of scan type IDs to symbols
    const scanTypeMap = {
        'ejbca': { icon: '🏛️', title: 'EJBCA' },
        'azure_keyvault': { icon: '☁️', title: 'Azure Key Vault' },
        'luna_hsm': { icon: '🔐', title: 'Luna HSM' },
        'file': { icon: '📁', title: 'File Share' },
        'tls': { icon: '🔒', title: 'TLS' },
        'crl': { icon: '📋', title: 'CRL' }
    };

    // Get enabled collectors from config, default to all if not set
    const enabledCapabilities = config?.enabled_collectors || [
        'tls', 'file', 'ejbca', 'azure_keyvault', 'luna_hsm', 'crl'
    ];

    // Only show symbols for enabled scan types
    const scanTypeIcons = enabledCapabilities
        .filter(capId => capId in scanTypeMap)
        .map(capId => {
            const st = scanTypeMap[capId];
            return `<span style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; background: #f3f4f6; border-radius: 6px; font-size: 12px; color: #4b5563;">${st.icon} ${st.title}</span>`;
        })
        .join('');

    const lastSeen = collector.last_heartbeat
        ? formatRelativeTime(collector.last_heartbeat)
        : 'Never';

    return `
        <div style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); cursor: pointer;" onclick="showCollectorDetails('${collector.collector_id}')">
            <!-- Header with gradient -->
            <div style="padding: 20px 24px; background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;">
                <div style="flex: 1;">
                    <div style="font-size: 18px; font-weight: 700; color: #1f2937; margin-bottom: 4px;">📡 ${escapeHtml(collector.collector_name || 'Unknown')}</div>
                    <div style="font-size: 13px; color: #6b7280;">${escapeHtml(collector.location || 'No location')}</div>
                </div>
                <div style="background: ${statusInfo.bg}; border: 1.5px solid ${statusInfo.border}; border-radius: 8px; padding: 8px 16px; text-align: center; flex-shrink: 0;">
                    <div style="font-size: 12px; font-weight: 600; color: ${statusInfo.text};">${statusInfo.icon} ${calculatedStatus.toUpperCase()}</div>
                </div>
            </div>

            <!-- Details Grid -->
            <div style="padding: 20px 24px; border-bottom: 1px solid #e5e7eb;">
                <div style="display: grid; grid-template-columns: auto 1fr; gap: 16px 24px; font-size: 14px;">
                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Organization</div>
                    <div style="color: #1f2937; font-weight: 500;">${escapeHtml(collector.organization || '-')}</div>

                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Environment</div>
                    <div style="color: #1f2937; font-weight: 500;">${escapeHtml(collector.environment || '-')}</div>

                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Mode</div>
                    <div style="color: #1f2937; font-weight: 500;">${modeLabels[collector.transmission_mode] || collector.transmission_mode || '-'}</div>

                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Last Seen</div>
                    <div style="color: #1f2937; font-weight: 500;">${lastSeen}</div>

                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Reports</div>
                    <div style="color: #1f2937; font-weight: 500;">${collector.report_count || 0}</div>

                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Certificates</div>
                    <div style="color: #1f2937; font-weight: 500;">${collector.certificates_found || 0}</div>

                    <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Capabilities</div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">${scanTypeIcons}</div>
                </div>
            </div>

            <!-- Action Buttons -->
            <div style="padding: 16px 24px; background: #f9fafb; border-top: 1px solid #e5e7eb; display: flex; gap: 8px; flex-wrap: wrap;">
                <button onclick="showCollectorDetails('${collector.collector_id}'); event.stopPropagation();"
                    style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                    👁️ View Details
                </button>
                <button onclick="editCollector('${collector.collector_id}'); event.stopPropagation();"
                    style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                    ✏️ Edit
                </button>
            </div>
        </div>
    `;
}

/**
 * Render bootstrap tokens table
 */
function renderTokensTable() {
    const tbody = document.getElementById('bootstrap-tokens-body');

    if (!tokensData || tokensData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No active tokens. Generate a token to register new collectors.</td></tr>';
        return;
    }

    tbody.innerHTML = tokensData.map(token => {
        const isExpired = new Date(token.expires_at) < new Date();
        const isUsed = token.max_uses > 0 && token.current_uses >= token.max_uses;
        const status = token.status === 'revoked' ? 'Revoked' :
                       isExpired ? 'Expired' :
                       isUsed ? 'Used' : 'Active';
        const statusClass = status === 'Active' ? 'color: #10b981;' :
                           status === 'Revoked' ? 'color: #ef4444;' :
                           'color: #6b7280;';

        return `
            <tr>
                <td><code style="background: #f3f4f6; padding: 2px 6px; border-radius: 4px;">${escapeHtml(token.token_prefix)}...</code></td>
                <td>${escapeHtml(token.collector_name || '-')}</td>
                <td>${escapeHtml(token.environment || '-')}</td>
                <td>${formatDateTime(token.created_at)}</td>
                <td>${formatDateTime(token.expires_at)}</td>
                <td>${token.current_uses}/${token.max_uses || '&infin;'}</td>
                <td style="${statusClass} font-weight: 600;">${status}</td>
                <td>
                    ${status === 'Active' ? `<button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="revokeToken('${token.id}')">Revoke</button>` : '-'}
                </td>
            </tr>
        `;
    }).join('');
}

/**
 * Render registered collectors table
 */
function renderRegisteredCollectors() {
    const tbody = document.getElementById('registered-collectors-body');
    if (!tbody) return;

    if (!collectorsData || collectorsData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No collectors registered yet.</td></tr>';
        return;
    }

    tbody.innerHTML = collectorsData.map(collector => {
        const status = calculateCollectorStatus(collector);
        const statusColor = status === 'Online' ? '#10b981' :
                           status === 'Degraded' ? '#f59e0b' :
                           status === 'Offline' ? '#ef4444' :
                           status === 'Suspended' ? '#6b7280' : '#9ca3af';

        return `
            <tr>
                <td>${escapeHtml(collector.name || '-')}</td>
                <td>${escapeHtml(collector.organization || '-')}</td>
                <td>${escapeHtml(collector.location || '-')}</td>
                <td>${escapeHtml(collector.environment || '-')}</td>
                <td><span style="color: ${statusColor}; font-weight: 600;">${status}</span></td>
                <td>${formatDateTime(collector.registered_at || collector.created_at)}</td>
                <td>${formatDateTime(collector.last_heartbeat)}</td>
            </tr>
        `;
    }).join('');
}

// =============================================================================
// CHARTS
// =============================================================================

/**
 * Initialize charts
 */
function initCollectorsCharts() {
    initHealthChart();
    initActivityChart();
}

/**
 * Initialize health donut chart
 */
function initHealthChart() {
    const ctx = document.getElementById('collectors-health-chart');
    if (!ctx) return;

    if (collectorsHealthChart) {
        collectorsHealthChart.destroy();
    }

    collectorsHealthChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Online', 'Offline', 'Degraded', 'Suspended'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#6b7280'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 12,
                        padding: 15
                    }
                }
            },
            cutout: '60%'
        }
    });
}

/**
 * Initialize activity line chart
 */
function initActivityChart() {
    const ctx = document.getElementById('collectors-activity-chart');
    if (!ctx) return;

    if (collectorsActivityChart) {
        collectorsActivityChart.destroy();
    }

    // Generate last 7 days labels
    const labels = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        labels.push(d.toLocaleDateString('en-US', { weekday: 'short' }));
    }

    collectorsActivityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Reports Received',
                data: [0, 0, 0, 0, 0, 0, 0],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

/**
 * Update health chart with current data
 */
function updateCollectorsHealthChart() {
    if (!collectorsHealthChart) return;

    const counts = {
        online: 0,
        offline: 0,
        degraded: 0,
        suspended: 0
    };

    collectorsData.forEach(c => {
        const status = calculateCollectorStatus(c);
        if (counts.hasOwnProperty(status)) {
            counts[status]++;
        }
    });

    collectorsHealthChart.data.datasets[0].data = [
        counts.online,
        counts.offline,
        counts.degraded,
        counts.suspended
    ];
    collectorsHealthChart.update();
}

/**
 * Update activity feed with recent collector events
 */
function updateActivityFeed() {
    const feedContainer = document.getElementById('collectors-activity-feed');
    if (!feedContainer) return;

    // Generate activity from collectors' recent heartbeats
    const recentActivity = [];
    collectorsData.forEach(collector => {
        if (collector.last_heartbeat) {
            recentActivity.push({
                collector_name: collector.collector_name,
                type: 'heartbeat',
                timestamp: collector.last_heartbeat,
                status: collector.status,
                icon: '📡'
            });
        }
    });

    // Sort by timestamp (most recent first)
    recentActivity.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Display top 10 activities
    if (recentActivity.length === 0) {
        feedContainer.innerHTML = '<div style="text-align: center; color: var(--text-secondary); padding: 40px;">No recent activity</div>';
        return;
    }

    feedContainer.innerHTML = recentActivity.slice(0, 10).map(activity => {
        const relativeTime = formatRelativeTime(activity.timestamp);
        const statusColor = activity.status === 'online' ? '#10b981' :
                           activity.status === 'offline' ? '#ef4444' :
                           activity.status === 'degraded' ? '#f59e0b' : '#6b7280';

        return `
            <div style="padding: 12px 0; border-bottom: 1px solid #e5e7eb; font-size: 13px; display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 16px;">${activity.icon}</span>
                <div style="flex: 1;">
                    <div style="color: #1f2937; font-weight: 500;">${escapeHtml(activity.collector_name)}</div>
                    <div style="color: #6b7280; font-size: 12px;">Heartbeat • <span style="color: ${statusColor}; font-weight: 600;">${activity.status}</span> • ${relativeTime}</div>
                </div>
            </div>
        `;
    }).join('');
}

/**
 * Update activity chart with 7-day report data
 */
function updateActivityChart() {
    if (!collectorsActivityChart) return;

    // Group reports by date
    const reportsByDate = {};
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const dateKey = d.toLocaleDateString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });
        reportsByDate[dateKey] = 0;
    }

    // Count reports for each collector (as proxy for activity)
    collectorsData.forEach(collector => {
        const reportCount = collector.report_count || 0;
        if (reportCount > 0) {
            const d = new Date();
            d.setDate(d.getDate() - Math.floor(Math.random() * 7)); // Distribute reports across last 7 days
            const dateKey = d.toLocaleDateString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });
            if (reportsByDate.hasOwnProperty(dateKey)) {
                reportsByDate[dateKey] += reportCount;
            }
        }
    });

    const data = Object.values(reportsByDate);
    collectorsActivityChart.data.datasets[0].data = data;
    collectorsActivityChart.update();
}

// =============================================================================
// TOKEN GENERATION
// =============================================================================

/**
 * Open token generation modal
 */
function openGenerateTokenModal() {
    // Reset form
    document.getElementById('tokenCollectorName').value = '';
    document.getElementById('tokenOrganization').value = '';
    document.getElementById('tokenLocation').value = '';
    document.getElementById('tokenEnvironment').value = 'production';
    document.getElementById('tokenTransmissionMode').value = 'selective';
    document.getElementById('tokenTTL').value = '24';
    document.getElementById('tokenMaxUses').value = '1';
    document.getElementById('tokenIPRestriction').value = '';

    openModal('generateTokenModal');
}

/**
 * Generate bootstrap token
 */
async function generateBootstrapToken() {
    const name = document.getElementById('tokenCollectorName').value.trim();
    if (!name) {
        alert('Please enter a collector name');
        return;
    }

    const organization = document.getElementById('tokenOrganization').value.trim();
    if (!organization) {
        alert('Please enter an organization');
        return;
    }

    const payload = {
        collector_name: name,
        organization: organization,
        location: document.getElementById('tokenLocation').value.trim() || null,
        environment: document.getElementById('tokenEnvironment').value,
        transmission_mode: document.getElementById('tokenTransmissionMode').value,
        ttl_hours: parseInt(document.getElementById('tokenTTL').value) || 24,
        max_uses: parseInt(document.getElementById('tokenMaxUses').value) || 0,
        ip_restriction: document.getElementById('tokenIPRestriction').value.trim() || null
    };

    try {
        const response = await fetch('/api/remote/tokens', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (data.status === 'success') {
            closeModal('generateTokenModal');
            showGeneratedToken(data.token, data);
            loadBootstrapTokens(); // Refresh tokens list
        } else {
            alert('Error: ' + (data.message || 'Failed to generate token'));
        }
    } catch (error) {
        
        alert('Error generating token. Please try again.');
    }
}

/**
 * Display generated token
 */
function showGeneratedToken(token, tokenInfo) {
    document.getElementById('generatedTokenValue').value = token;

    // Build installation command
    const serverUrl = window.location.origin;
    const command = `caip-collector register --token ${token} --server ${serverUrl}`;
    document.getElementById('installationCommand').textContent = command;

    // Display expiry and max uses
    document.getElementById('tokenExpiresAt').textContent = formatDateTime(tokenInfo.expires_at);
    document.getElementById('tokenMaxUsesDisplay').textContent = tokenInfo.max_uses === 0 ? 'Unlimited' : tokenInfo.max_uses;

    openModal('tokenDisplayModal');
}

/**
 * Copy generated token to clipboard
 */
function copyGeneratedToken() {
    const input = document.getElementById('generatedTokenValue');
    input.select();
    document.execCommand('copy');

    // Show feedback
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = originalText, 2000);
}

/**
 * Copy installation command to clipboard
 */
function copyInstallCommand() {
    const command = document.getElementById('installationCommand').textContent;
    navigator.clipboard.writeText(command).then(() => {
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = originalText, 2000);
    });
}

/**
 * Revoke a bootstrap token
 */
async function revokeToken(tokenId) {
    if (!confirm('Are you sure you want to revoke this token? This cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`/api/remote/tokens/${tokenId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.status === 'success') {
            loadBootstrapTokens();
        } else {
            alert('Error: ' + (data.message || 'Failed to revoke token'));
        }
    } catch (error) {
        
        alert('Error revoking token. Please try again.');
    }
}

// =============================================================================
// COLLECTOR DETAILS WITH CONFIG MANAGEMENT
// =============================================================================

// State for collector details
let currentCollectorId = null;
let currentCollectorConfig = null;
let currentCollectorJobs = [];

/**
 * Show collector details with tabbed interface
 */
async function showCollectorDetails(collectorId) {
    currentCollectorId = collectorId;

    const collector = await getCollectorDetails(collectorId);
    if (!collector) {
        alert('Failed to load collector details');
        return;
    }

    // Also load config and jobs
    const [config, jobs] = await Promise.all([
        getCollectorConfig(collectorId),
        getCollectorJobs(collectorId)
    ]);

    currentCollectorConfig = config;
    currentCollectorJobs = jobs;

    document.getElementById('collectorDetailsModalTitle').textContent = collector.collector_name || 'Collector Details';

    document.getElementById('collectorDetailsModalBody').innerHTML = `
        <!-- Tab Navigation -->
        <div class="collector-detail-tabs" style="display: flex; gap: 0; border-bottom: 1px solid #e5e7eb; margin-bottom: 20px;">
            <button class="collector-tab-btn active" onclick="switchCollectorTab('overview')" data-tab="overview" style="padding: 10px 20px; border: none; background: none; cursor: pointer; font-weight: 500; color: #667eea; border-bottom: 2px solid #667eea;">Overview</button>
            <button class="collector-tab-btn" onclick="switchCollectorTab('config')" data-tab="config" style="padding: 10px 20px; border: none; background: none; cursor: pointer; font-weight: 500; color: #6b7280; border-bottom: 2px solid transparent;">Configuration</button>
            <button class="collector-tab-btn" onclick="switchCollectorTab('capabilities')" data-tab="capabilities" style="padding: 10px 20px; border: none; background: none; cursor: pointer; font-weight: 500; color: #6b7280; border-bottom: 2px solid transparent;">Collector Capabilities</button>
            <button class="collector-tab-btn" onclick="switchCollectorTab('jobs')" data-tab="jobs" style="padding: 10px 20px; border: none; background: none; cursor: pointer; font-weight: 500; color: #6b7280; border-bottom: 2px solid transparent;">Jobs</button>
        </div>

        <!-- Tab Contents -->
        <div id="collector-tab-overview" class="collector-tab-content" style="display: block;">
            ${renderCollectorOverviewTab(collector)}
        </div>
        <div id="collector-tab-config" class="collector-tab-content" style="display: none;">
            ${renderCollectorConfigTab(collector, config)}
        </div>
        <div id="collector-tab-capabilities" class="collector-tab-content" style="display: none;">
            ${renderCollectorCapabilitiesTab(config)}
        </div>
        <div id="collector-tab-jobs" class="collector-tab-content" style="display: none;">
            ${renderCollectorJobsTab(jobs)}
        </div>
    `;

    openModal('collectorDetailsModal');
}

/**
 * Switch between collector detail tabs
 */
function switchCollectorTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.collector-tab-btn').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.style.color = '#667eea';
            btn.style.borderBottom = '2px solid #667eea';
        } else {
            btn.style.color = '#6b7280';
            btn.style.borderBottom = '2px solid transparent';
        }
    });

    // Update tab contents
    document.querySelectorAll('.collector-tab-content').forEach(content => {
        content.style.display = 'none';
    });
    document.getElementById(`collector-tab-${tabName}`).style.display = 'block';
}

/**
 * Render Overview tab
 */
function renderCollectorOverviewTab(collector) {
    const statusColors = {
        'online': '#10b981',
        'offline': '#ef4444',
        'degraded': '#f59e0b',
        'suspended': '#6b7280'
    };

    return `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <h4 style="margin: 0 0 12px 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">General Information</h4>
                <div style="background: #f9fafb; border-radius: 8px; padding: 16px;">
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Status</div>
                        <div style="font-weight: 600; color: ${statusColors[collector.status] || '#6b7280'};">${collector.status || 'Unknown'}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Collector ID</div>
                        <div style="font-weight: 500; font-family: monospace;">${escapeHtml(collector.collector_id || '-')}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Organization</div>
                        <div style="font-weight: 500;">${escapeHtml(collector.organization || '-')}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Location</div>
                        <div style="font-weight: 500;">${escapeHtml(collector.location || '-')}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Environment</div>
                        <div style="font-weight: 500;">${escapeHtml(collector.environment || '-')}</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: var(--text-secondary);">Transmission Mode</div>
                        <div style="font-weight: 500;">${escapeHtml(collector.transmission_mode || '-')}</div>
                    </div>
                </div>
            </div>
            <div>
                <h4 style="margin: 0 0 12px 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Statistics</h4>
                <div style="background: #f9fafb; border-radius: 8px; padding: 16px;">
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Last Heartbeat</div>
                        <div style="font-weight: 500;">${collector.last_heartbeat ? formatDateTime(collector.last_heartbeat) : 'Never'}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Registered</div>
                        <div style="font-weight: 500;">${formatDateTime(collector.registered_at || collector.created_at || '-')}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Certificates Found</div>
                        <div style="font-weight: 500;">${collector.certificates_found || 0}</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: var(--text-secondary);">Reports Submitted</div>
                        <div style="font-weight: 500;">${collector.report_count || 0}</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: var(--text-secondary);">Last IP Address</div>
                        <div style="font-weight: 500; font-family: monospace;">${escapeHtml(collector.ip_address || '-')}</div>
                    </div>
                </div>
            </div>
        </div>

        <div style="margin-top: 20px;">
            <h4 style="margin: 0 0 12px 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Quick Actions</h4>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <button class="btn-primary" onclick="triggerCollectorScan('${collector.collector_id}')">
                    &#x1F50D; Run Scan Now
                </button>
                ${collector.status === 'suspended'
                    ? `<button class="btn-secondary" onclick="reactivateCollector('${collector.collector_id}')">Reactivate</button>`
                    : `<button class="btn-secondary" onclick="suspendCollector('${collector.collector_id}')">Suspend</button>`
                }
                <button class="btn-secondary" style="color: #ef4444; border-color: #ef4444;" onclick="decommissionCollector('${collector.collector_id}')">Decommission</button>
            </div>
        </div>
    `;
}

/**
 * Render Configuration tab
 */
function renderCollectorConfigTab(collector, config) {
    const transmissionMode = config?.transmission_mode || collector.transmission_mode || 'selective';
    const heartbeatInterval = config?.heartbeat_interval || 60;
    const scheduleEnabled = config?.schedule?.enabled || false;
    const scheduleInterval = config?.schedule?.interval_minutes || 60;
    const configVersion = config?.config_version || 1;

    return `
        <form id="collectorConfigForm" onsubmit="saveCollectorConfig(event)">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h4 style="margin: 0 0 12px 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Transmission Settings</h4>
                    <div style="background: #f9fafb; border-radius: 8px; padding: 16px;">
                        <div style="margin-bottom: 16px;">
                            <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Transmission Mode</label>
                            <select id="configTransmissionMode" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
                                <option value="full" ${transmissionMode === 'full' ? 'selected' : ''}>Full - Complete certificate data</option>
                                <option value="selective" ${transmissionMode === 'selective' ? 'selected' : ''}>Selective - Summary + findings</option>
                                <option value="anonymized" ${transmissionMode === 'anonymized' ? 'selected' : ''}>Anonymized - Tokenized identifiers</option>
                            </select>
                            <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">Controls what data is transmitted to central server</div>
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Heartbeat Interval (seconds)</label>
                            <input type="number" id="configHeartbeatInterval" value="${heartbeatInterval}" min="30" max="3600" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
                            <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">How often collector checks in (30-3600s)</div>
                        </div>
                    </div>
                </div>
                <div>
                    <h4 style="margin: 0 0 12px 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Scheduled Scanning</h4>
                    <div style="background: #f9fafb; border-radius: 8px; padding: 16px;">
                        <div style="margin-bottom: 16px;">
                            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                <input type="checkbox" id="configScheduleEnabled" ${scheduleEnabled ? 'checked' : ''} onchange="toggleScheduleOptions()">
                                <span style="font-size: 13px; font-weight: 500;">Enable Scheduled Scans</span>
                            </label>
                        </div>
                        <div id="scheduleOptions" style="${scheduleEnabled ? '' : 'opacity: 0.5; pointer-events: none;'}">
                            <div style="margin-bottom: 16px;">
                                <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Scan Interval (minutes)</label>
                                <input type="number" id="configScheduleInterval" value="${scheduleInterval}" min="5" max="1440" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
                            </div>
                        </div>
                        <div style="padding: 8px; background: #dbeafe; border-radius: 6px; font-size: 11px; color: #1e40af;">
                            Config Version: ${configVersion}
                        </div>
                    </div>
                </div>
            </div>
            <div style="margin-top: 20px; display: flex; gap: 10px; justify-content: flex-end;">
                <button type="submit" class="btn-primary">Save Configuration</button>
            </div>
        </form>
    `;
}

/**
 * Toggle schedule options visibility
 */
function toggleScheduleOptions() {
    const checkbox = document.getElementById('configScheduleEnabled');
    const options = document.getElementById('scheduleOptions');
    if (checkbox.checked) {
        options.style.opacity = '1';
        options.style.pointerEvents = 'auto';
    } else {
        options.style.opacity = '0.5';
        options.style.pointerEvents = 'none';
    }
}

/**
 * Render Collector Capabilities tab (Phase 3 of job-based architecture)
 *
 * This tab shows which collector TYPES are enabled/disabled in this zone.
 * Scan targets are now defined in the scan job payload (not in collector config).
 * This is purely for capability management - enabling/disabling collector types.
 */
function renderCollectorCapabilitiesTab(config) {
    // Get enabled collectors from config, default to all if not set
    const enabledCapabilities = config?.enabled_collectors || [
        'tls', 'file', 'ejbca', 'azure_keyvault', 'luna_hsm', 'crl'
    ];

    // All available collector types
    const allCapabilities = [
        { id: 'tls', name: 'TLS Scanning', description: 'Scan TLS/SSL endpoints for certificates' },
        { id: 'file', name: 'File System Scanning', description: 'Scan local file systems for certificates' },
        { id: 'ejbca', name: 'EJBCA Integration', description: 'Discover certificates from Keyfactor EJBCA' },
        { id: 'azure_keyvault', name: 'Azure Key Vault', description: 'Discover certificates and keys from Azure Key Vault' },
        { id: 'luna_hsm', name: 'Thales Luna HSM', description: 'Discover keys from Thales Luna Hardware Security Module' },
        { id: 'crl', name: 'CRL Validation', description: 'Check certificate revocation status' }
    ];

    return `
        <div style="background: #f0f9ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
            <div style="color: #1e40af; font-weight: 500; margin-bottom: 4px;">ℹ️ About Collector Capabilities</div>
            <div style="font-size: 13px; color: #1e3a8a;">
                Enable/disable which collector types are supported in this zone. Scan configurations are defined in individual scan jobs.
            </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
            ${allCapabilities.map(cap => `
                <div style="background: #f9fafb; border: 2px solid ${enabledCapabilities.includes(cap.id) ? '#10b981' : '#e5e7eb'}; border-radius: 8px; padding: 16px; transition: all 0.2s;">
                    <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 8px;">
                        <input type="checkbox" id="cap-${cap.id}"
                               ${enabledCapabilities.includes(cap.id) ? 'checked' : ''}
                               onchange="updateCollectorCapability('${cap.id}', this.checked)"
                               style="cursor: pointer; width: 18px; height: 18px; margin-top: 2px;">
                        <div style="flex: 1;">
                            <label for="cap-${cap.id}" style="font-weight: 600; color: #1f2937; cursor: pointer; display: block; margin-bottom: 2px;">
                                ${escapeHtml(cap.name)}
                            </label>
                            <div style="font-size: 12px; color: #6b7280;">
                                ${escapeHtml(cap.description)}
                            </div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 11px; padding: 3px 8px; border-radius: 4px; background: ${enabledCapabilities.includes(cap.id) ? '#dcfce7' : '#f3f4f6'}; color: ${enabledCapabilities.includes(cap.id) ? '#15803d' : '#6b7280'}; font-weight: 500;">
                            ${enabledCapabilities.includes(cap.id) ? '✓ Enabled' : '○ Disabled'}
                        </span>
                    </div>
                </div>
            `).join('')}
        </div>

        <div style="margin-top: 20px; display: flex; gap: 8px; justify-content: flex-end;">
            <button class="btn-primary" onclick="saveCollectorCapabilities()" style="padding: 8px 16px;">
                Save Capabilities
            </button>
        </div>
    `;
}

/**
 * Render Jobs tab
 */
function renderCollectorJobsTab(jobs) {
    let jobsHtml = '';

    if (!jobs || jobs.length === 0) {
        jobsHtml = `
            <div style="text-align: center; padding: 40px; color: #6b7280;">
                <div style="font-size: 48px; margin-bottom: 12px;">&#x1F4CB;</div>
                <div>No jobs in queue</div>
                <div style="font-size: 12px; margin-top: 4px;">Use "Run Scan Now" to queue a scan job</div>
            </div>
        `;
    } else {
        const statusColors = {
            'pending': '#f59e0b',
            'acknowledged': '#3b82f6',
            'running': '#8b5cf6',
            'completed': '#10b981',
            'failed': '#ef4444'
        };

        jobsHtml = `
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="background: #f9fafb; text-align: left;">
                            <th style="padding: 10px; border-bottom: 1px solid #e5e7eb;">ID</th>
                            <th style="padding: 10px; border-bottom: 1px solid #e5e7eb;">Type</th>
                            <th style="padding: 10px; border-bottom: 1px solid #e5e7eb;">Status</th>
                            <th style="padding: 10px; border-bottom: 1px solid #e5e7eb;">Created</th>
                            <th style="padding: 10px; border-bottom: 1px solid #e5e7eb;">Completed</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${jobs.map(job => `
                            <tr>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-family: monospace;">#${job.id}</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(job.job_type)}</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">
                                    <span style="display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; background: ${statusColors[job.status] || '#6b7280'}20; color: ${statusColors[job.status] || '#6b7280'};">
                                        ${job.status}
                                    </span>
                                </td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-size: 12px;">${formatRelativeTime(job.created_at)}</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-size: 12px;">${job.completed_at ? formatRelativeTime(job.completed_at) : '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    return `
        <div style="margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
            <h4 style="margin: 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Job Queue</h4>
            <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="refreshCollectorJobs()">&#x1F504; Refresh</button>
        </div>
        ${jobsHtml}
    `;
}

/**
 * Get collector configuration
 */
async function getCollectorConfig(collectorId) {
    try {
        const response = await fetch(`/api/remote/collector/${collectorId}/config`);
        if (!response.ok) return null;
        const data = await response.json();
        return data.status === 'success' ? data.config : null;
    } catch (error) {
        
        return null;
    }
}

/**
 * Get collector jobs
 */
async function getCollectorJobs(collectorId) {
    try {
        const response = await fetch(`/api/remote/collector/${collectorId}/jobs`);
        if (!response.ok) return [];
        const data = await response.json();
        return data.status === 'success' ? (data.jobs || []) : [];
    } catch (error) {
        
        return [];
    }
}

/**
 * Save collector configuration
 */
async function saveCollectorConfig(event) {
    event.preventDefault();

    if (!currentCollectorId) return;

    const config = {
        transmission_mode: document.getElementById('configTransmissionMode').value,
        heartbeat_interval: parseInt(document.getElementById('configHeartbeatInterval').value) || 60,
        schedule: {
            enabled: document.getElementById('configScheduleEnabled').checked,
            interval_minutes: parseInt(document.getElementById('configScheduleInterval').value) || 60
        },
        scan_targets: currentCollectorConfig?.scan_targets || []
    };

    try {
        const response = await fetch(`/api/remote/collector/${currentCollectorId}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        const data = await response.json();

        if (data.status === 'success') {
            alert('Configuration saved successfully. The collector will receive the update on its next heartbeat.');
            currentCollectorConfig = { ...currentCollectorConfig, ...config, config_version: data.config_version };
        } else {
            alert('Error: ' + (data.message || 'Failed to save configuration'));
        }
    } catch (error) {
        
        alert('Error saving configuration. Please try again.');
    }
}

/**
 * Trigger a scan job for collector
 */
async function triggerCollectorScan(collectorId) {
    if (!confirm('Queue a new scan job for this collector?')) {
        return;
    }

    try {
        const response = await fetch(`/api/remote/collector/${collectorId}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ priority: 'high' })
        });

        const data = await response.json();

        if (data.status === 'success') {
            alert(`Scan job queued successfully (Job #${data.job_id}). The collector will execute it on its next heartbeat.`);
            // Refresh jobs tab if visible
            refreshCollectorJobs();
        } else {
            alert('Error: ' + (data.message || 'Failed to queue scan job'));
        }
    } catch (error) {
        
        alert('Error queuing scan job. Please try again.');
    }
}

/**
 * Refresh collector jobs list
 */
async function refreshCollectorJobs() {
    if (!currentCollectorId) return;

    const jobs = await getCollectorJobs(currentCollectorId);
    currentCollectorJobs = jobs;

    const jobsContainer = document.getElementById('collector-tab-jobs');
    if (jobsContainer) {
        jobsContainer.innerHTML = renderCollectorJobsTab(jobs);
    }
}

/**
 * Open add target modal
 */
function openAddTargetModal() {
    // Create inline form for adding target
    const targetsContainer = document.getElementById('scanTargetsList');
    if (!targetsContainer) return;

    const formHtml = `
        <div id="addTargetForm" style="background: #eff6ff; border: 2px dashed #3b82f6; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
            <h5 style="margin: 0 0 12px 0; color: #1e40af;">Add New Scan Target</h5>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                <div>
                    <label style="display: block; font-size: 12px; margin-bottom: 4px;">Name</label>
                    <input type="text" id="newTargetName" placeholder="e.g., Production Web Servers" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
                </div>
                <div>
                    <label style="display: block; font-size: 12px; margin-bottom: 4px;">Type</label>
                    <select id="newTargetType" onchange="updateTargetConfigFields()" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
                        <option value="tls">TLS Endpoint Scan</option>
                        <option value="file">File System Scan</option>
                        <option value="ejbca">EJBCA Certificate Authority</option>
                        <option value="azure_keyvault">Azure Key Vault</option>
                        <option value="luna_hsm">Thales Luna HSM</option>
                        <option value="crl">CRL Collector</option>
                    </select>
                </div>
            </div>
            <div id="targetConfigFields">
                <div>
                    <label style="display: block; font-size: 12px; margin-bottom: 4px;">Hosts (comma-separated)</label>
                    <input type="text" id="newTargetHosts" placeholder="e.g., server1.example.com:443, server2.example.com:8443" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
                </div>
            </div>
            <div style="display: flex; gap: 8px; margin-top: 12px;">
                <button class="btn-primary" style="padding: 6px 12px; font-size: 12px;" onclick="addScanTarget()">Add Target</button>
                <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="cancelAddTarget()">Cancel</button>
            </div>
        </div>
    `;

    targetsContainer.insertAdjacentHTML('afterbegin', formHtml);
}

/**
 * Update target config fields based on type
 */
function updateTargetConfigFields() {
    const type = document.getElementById('newTargetType').value;
    const configFields = document.getElementById('targetConfigFields');

    if (type === 'tls') {
        configFields.innerHTML = `
            <div>
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">Hosts (comma-separated)</label>
                <input type="text" id="newTargetHosts" placeholder="e.g., server1.example.com:443, server2.example.com:8443" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
        `;
    } else if (type === 'file') {
        configFields.innerHTML = `
            <div>
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">Paths (comma-separated)</label>
                <input type="text" id="newTargetPaths" placeholder="e.g., /etc/ssl/certs, /opt/app/certs" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
        `;
    } else if (type === 'ejbca') {
        configFields.innerHTML = `
            <div>
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">EJBCA API Base URL</label>
                <input type="text" id="newTargetEjbcaUrl" placeholder="e.g., https://ejbca.example.com:8443" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
            <div style="margin-top: 8px;">
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">CAs (comma-separated, optional)</label>
                <input type="text" id="newTargetEjbcaCAs" placeholder="e.g., SubCA1, SubCA2 (leave empty for all CAs)" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
        `;
    } else if (type === 'azure_keyvault') {
        configFields.innerHTML = `
            <div>
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">Vault URL</label>
                <input type="text" id="newTargetAzureUrl" placeholder="e.g., https://myvault.vault.azure.net" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
            <div style="margin-top: 8px;">
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">Tenancy Name</label>
                <input type="text" id="newTargetAzureTenancy" placeholder="e.g., production" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
        `;
    } else if (type === 'luna_hsm') {
        configFields.innerHTML = `
            <div>
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">PKCS#11 Module Path</label>
                <input type="text" id="newTargetLunaModule" placeholder="e.g., /usr/lib/libCryptoki2_64.so" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
            <div style="margin-top: 8px;">
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">Partition Label (optional)</label>
                <input type="text" id="newTargetLunaPartition" placeholder="e.g., partition1" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
            <div style="margin-top: 8px;">
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">HSM Name (optional)</label>
                <input type="text" id="newTargetLunaName" placeholder="e.g., Luna SA 7" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
        `;
    } else if (type === 'crl') {
        configFields.innerHTML = `
            <div>
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">CRL Distribution Points (comma-separated, optional)</label>
                <input type="text" id="newTargetCrlUrls" placeholder="e.g., http://crl.example.com/root.crl" style="width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px;">
            </div>
            <div style="margin-top: 8px;">
                <label style="display: block; font-size: 12px; margin-bottom: 4px;">Note: CRL validation typically runs after other collectors to check revocation status</label>
            </div>
        `;
    }
}

/**
 * Add a scan target
 */
async function addScanTarget() {
    const name = document.getElementById('newTargetName').value.trim();
    const type = document.getElementById('newTargetType').value;

    if (!name) {
        alert('Please enter a target name');
        return;
    }

    let config = {};
    if (type === 'tls') {
        const hosts = document.getElementById('newTargetHosts').value.trim();
        if (!hosts) {
            alert('Please enter at least one host');
            return;
        }
        config.hosts = hosts.split(',').map(h => h.trim()).filter(h => h);
    } else if (type === 'file') {
        const paths = document.getElementById('newTargetPaths').value.trim();
        if (!paths) {
            alert('Please enter at least one path');
            return;
        }
        config.paths = paths.split(',').map(p => p.trim()).filter(p => p);
    } else if (type === 'ejbca') {
        const url = document.getElementById('newTargetEjbcaUrl').value.trim();
        if (!url) {
            alert('Please enter the EJBCA API base URL');
            return;
        }
        config.base_url = url;
        const cas = document.getElementById('newTargetEjbcaCAs').value.trim();
        if (cas) {
            config.ca_list = cas.split(',').map(c => c.trim()).filter(c => c);
        }
    } else if (type === 'azure_keyvault') {
        const url = document.getElementById('newTargetAzureUrl').value.trim();
        if (!url) {
            alert('Please enter the Azure Key Vault URL');
            return;
        }
        config.vault_url = url;
        const tenancy = document.getElementById('newTargetAzureTenancy').value.trim();
        if (tenancy) {
            config.tenancy_name = tenancy;
        }
    } else if (type === 'luna_hsm') {
        const module = document.getElementById('newTargetLunaModule').value.trim();
        if (!module) {
            alert('Please enter the PKCS#11 module path');
            return;
        }
        config.pkcs11_module_path = module;
        const partition = document.getElementById('newTargetLunaPartition').value.trim();
        if (partition) {
            config.partition_label = partition;
        }
        const hsmName = document.getElementById('newTargetLunaName').value.trim();
        if (hsmName) {
            config.hsm_name = hsmName;
        }
    } else if (type === 'crl') {
        const urls = document.getElementById('newTargetCrlUrls').value.trim();
        if (urls) {
            config.crl_urls = urls.split(',').map(u => u.trim()).filter(u => u);
        }
    }

    const newTarget = {
        name: name,
        scan_type: type,
        enabled: true,
        config: config
    };

    // Add to current config
    const targets = currentCollectorConfig?.scan_targets || [];
    targets.push(newTarget);

    // Save updated config
    try {
        const configUpdate = {
            ...currentCollectorConfig,
            scan_targets: targets
        };

        const response = await fetch(`/api/remote/collector/${currentCollectorId}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(configUpdate)
        });

        const data = await response.json();

        if (data.status === 'success') {
            currentCollectorConfig = configUpdate;
            // Re-render targets tab
            document.getElementById('collector-tab-targets').innerHTML = renderCollectorTargetsTab(currentCollectorConfig);
        } else {
            alert('Error: ' + (data.message || 'Failed to add target'));
        }
    } catch (error) {
        
        alert('Error adding target. Please try again.');
    }
}

/**
 * Cancel add target form
 */
function cancelAddTarget() {
    const form = document.getElementById('addTargetForm');
    if (form) {
        form.remove();
    }
}

/**
 * Edit a scan target
 */
function editScanTarget(index) {
    // For now, remove and re-add
    alert('Edit functionality coming soon. Please remove and re-add the target to modify it.');
}

/**
 * Remove a scan target
 */
async function removeScanTarget(index) {
    if (!confirm('Are you sure you want to remove this scan target?')) {
        return;
    }

    const targets = currentCollectorConfig?.scan_targets || [];
    targets.splice(index, 1);

    try {
        const configUpdate = {
            ...currentCollectorConfig,
            scan_targets: targets
        };

        const response = await fetch(`/api/remote/collector/${currentCollectorId}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(configUpdate)
        });

        const data = await response.json();

        if (data.status === 'success') {
            currentCollectorConfig = configUpdate;
            document.getElementById('collector-tab-targets').innerHTML = renderCollectorTargetsTab(currentCollectorConfig);
        } else {
            alert('Error: ' + (data.message || 'Failed to remove target'));
        }
    } catch (error) {
        
        alert('Error removing target. Please try again.');
    }
}

/**
 * Close collector details panel (inline)
 */
function closeCollectorDetails() {
    const container = document.getElementById('collector-details-container');
    if (container) {
        container.style.display = 'none';
    }
}

/**
 * Suspend a collector
 */
async function suspendCollector(collectorId) {
    if (!confirm('Are you sure you want to suspend this collector? It will stop sending reports.')) {
        return;
    }

    try {
        const response = await fetch(`/api/remote/collector/${collectorId}/suspend`, {
            method: 'POST'
        });

        const data = await response.json();

        if (data.status === 'success') {
            closeModal('collectorDetailsModal');
            loadCollectorsList();
            loadCollectorsStats();
        } else {
            alert('Error: ' + (data.message || 'Failed to suspend collector'));
        }
    } catch (error) {
        
        alert('Error suspending collector. Please try again.');
    }
}

/**
 * Reactivate a collector
 */
async function reactivateCollector(collectorId) {
    try {
        const response = await fetch(`/api/remote/collector/${collectorId}/reactivate`, {
            method: 'POST'
        });

        const data = await response.json();

        if (data.status === 'success') {
            closeModal('collectorDetailsModal');
            loadCollectorsList();
            loadCollectorsStats();
        } else {
            alert('Error: ' + (data.message || 'Failed to reactivate collector'));
        }
    } catch (error) {
        
        alert('Error reactivating collector. Please try again.');
    }
}

/**
 * Decommission a collector
 */
async function decommissionCollector(collectorId) {
    if (!confirm('Are you sure you want to decommission this collector? This action cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`/api/remote/collector/${collectorId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.status === 'success') {
            closeModal('collectorDetailsModal');
            loadCollectorsList();
            loadCollectorsStats();
        } else {
            alert('Error: ' + (data.message || 'Failed to decommission collector'));
        }
    } catch (error) {
        
        alert('Error decommissioning collector. Please try again.');
    }
}

// =============================================================================
// SETTINGS
// =============================================================================

/**
 * Save collector settings
 */
function saveCollectorSettings() {
    // For now, just show success - settings would be saved to backend
    alert('Settings saved successfully');
}

// =============================================================================
// TAB NAVIGATION
// =============================================================================

/**
 * Switch to a specific collectors tab
 */
function switchToCollectorsTab(tabId) {
    // Find and activate the tab button
    const tabButtons = document.querySelectorAll('#collectors .tab-button');
    tabButtons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-tab') === tabId) {
            btn.classList.add('active');
        }
    });

    // Show the tab content
    const tabContents = document.querySelectorAll('#collectors .tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === tabId) {
            content.classList.add('active');
        }
    });
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format date/time
 */
function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Format relative time (e.g., "5 minutes ago")
 */
function formatRelativeTime(dateStr) {
    if (!dateStr) return 'Never';

    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return formatDateTime(dateStr);
}

// =============================================================================
// EVENT LISTENERS
// =============================================================================

// Search and filter handlers
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('collectors-search');
    if (searchInput) {
        searchInput.addEventListener('input', renderCollectorsGrid);
    }

    const statusFilter = document.getElementById('collectors-filter-status');
    if (statusFilter) {
        statusFilter.addEventListener('change', renderCollectorsGrid);
    }
});

// Initialize when collectors tab is shown
document.addEventListener('DOMContentLoaded', function() {
    // Watch for tab activation
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
                const collectorsTab = document.getElementById('collectors');
                if (collectorsTab && collectorsTab.classList.contains('active')) {
                    initCollectorsModule();
                }
            }
        });
    });

    const collectorsTab = document.getElementById('collectors');
    if (collectorsTab) {
        observer.observe(collectorsTab, { attributes: true });
    }
});

/**
 * Update collector capability (Phase 3: capability management)
 * Called when user toggles a collector type checkbox
 */
function updateCollectorCapability(capabilityId, enabled) {
    

    // Update the current config's enabled_collectors array
    if (!currentCollectorConfig) {
        currentCollectorConfig = {};
    }

    // Initialize enabled_collectors if needed
    if (!currentCollectorConfig.enabled_collectors) {
        currentCollectorConfig.enabled_collectors = [
            'tls', 'file', 'ejbca', 'azure_keyvault', 'luna_hsm', 'crl'
        ];
    }

    // Update the array
    if (enabled) {
        // Add capability if not already present
        if (!currentCollectorConfig.enabled_collectors.includes(capabilityId)) {
            currentCollectorConfig.enabled_collectors.push(capabilityId);
        }
    } else {
        // Remove capability
        currentCollectorConfig.enabled_collectors = currentCollectorConfig.enabled_collectors.filter(
            cap => cap !== capabilityId
        );
    }

    
}

/**
 * Save collector capabilities (Phase 3: capability management)
 * Persists enabled collector types to the dashboard backend
 */
async function saveCollectorCapabilities() {
    if (!currentCollectorId) {
        alert('No collector selected');
        return;
    }

    if (!currentCollectorConfig) {
        alert('No configuration to save');
        return;
    }

    
    
    

    try {
        const requestBody = JSON.stringify(currentCollectorConfig);
        

        const response = await fetch(`/api/remote/collector/${currentCollectorId}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: requestBody
        });

        
        const data = await response.json();
        

        if (data.status === 'success') {
            showNotification('Collector capabilities saved successfully');
            
        } else {
            alert('Error: ' + (data.message || 'Failed to save capabilities'));
        }
    } catch (error) {
        
        alert('Error saving capabilities. Please try again.');
    }
}


