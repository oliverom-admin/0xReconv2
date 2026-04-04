/**
 * Environment Metrics UI Integration - Phase 5
 *
 * Handles:
 * - Environment badge rendering
 * - Environment filtering
 * - Auto-discovered metadata display
 * - Blast radius visualization
 * - Dependency summary displays
 */

// =========================================================================
// ENVIRONMENT BADGE RENDERING
// =========================================================================

/**
 * Get CSS class for environment type
 */
function getEnvironmentBadgeClass(envType) {
    const envTypeMap = {
        'production': 'badge-env-production',
        'staging': 'badge-env-staging',
        'development': 'badge-env-development',
        'testing': 'badge-env-testing',
        'unknown': 'badge-env-unknown'
    };
    return envTypeMap[envType] || 'badge-env-unknown';
}

/**
 * Render environment badge HTML
 */
function renderEnvironmentBadge(asset) {
    const envType = asset._environment_type || 'unknown';
    const confidence = asset._discovery_confidence || 0;
    const discoveryMethod = asset._discovery_method || 'unknown';

    const confidencePercent = Math.round(confidence * 100);
    const tooltipText = `${discoveryMethod} (${confidencePercent}% confidence)`;

    return `
        <span class="badge badge-env ${getEnvironmentBadgeClass(envType)}"
              title="${tooltipText}">
            ${envType}
        </span>
    `;
}

/**
 * Render service name badge HTML
 */
function renderServiceBadge(asset) {
    if (!asset._service_name) {
        return '';
    }

    return `
        <span class="badge badge-service" title="Service: ${asset._service_name}">
            ${asset._service_name}
        </span>
    `;
}

/**
 * Add environment badges to certificate/key table rows
 */
function enhanceTableWithEnvironmentBadges() {
    // Enhance certificate table rows
    document.querySelectorAll('.certificate-table-row').forEach(row => {
        const assetId = row.dataset.assetId;
        const envCell = row.querySelector('.env-cell');

        if (envCell && window.assetsMap && window.assetsMap[assetId]) {
            const asset = window.assetsMap[assetId];
            const badgesHtml = renderEnvironmentBadge(asset) + ' ' + renderServiceBadge(asset);
            envCell.innerHTML = badgesHtml;

            // Store environment type in dataset for filtering
            row.dataset.environment = asset._environment_type || 'unknown';
        }
    });

    // Enhance key table rows
    document.querySelectorAll('.key-table-row').forEach(row => {
        const assetId = row.dataset.assetId;
        const envCell = row.querySelector('.env-cell');

        if (envCell && window.assetsMap && window.assetsMap[assetId]) {
            const asset = window.assetsMap[assetId];
            const badgesHtml = renderEnvironmentBadge(asset) + ' ' + renderServiceBadge(asset);
            envCell.innerHTML = badgesHtml;

            // Store environment type in dataset for filtering
            row.dataset.environment = asset._environment_type || 'unknown';
        }
    });
}

// =========================================================================
// ENVIRONMENT FILTERING
// =========================================================================

/**
 * Filter assets by selected environment
 */
function filterAssetsByEnvironment() {
    const selectedEnv = document.getElementById('environment-filter')?.value || '';

    // Filter certificates
    document.querySelectorAll('.certificate-table-row').forEach(row => {
        const envType = row.dataset.environment || 'unknown';
        const shouldShow = !selectedEnv || envType === selectedEnv;
        row.style.display = shouldShow ? '' : 'none';
    });

    // Filter keys
    document.querySelectorAll('.key-table-row').forEach(row => {
        const envType = row.dataset.environment || 'unknown';
        const shouldShow = !selectedEnv || envType === selectedEnv;
        row.style.display = shouldShow ? '' : 'none';
    });
}

/**
 * Update environment filter counts
 */
function updateEnvironmentFilterCounts() {
    const breakdown = {
        production: 0,
        staging: 0,
        development: 0,
        testing: 0,
        unknown: 0
    };

    // Count assets by environment
    const certs = window.assetsCurrentCerts || [];
    const keys = window.assetsCurrentKeys || [];
    const allAssets = [...certs, ...keys];

    allAssets.forEach(asset => {
        const env = asset._environment_type || 'unknown';
        if (env in breakdown) {
            breakdown[env]++;
        }
    });

    // Update filter dropdown
    const filterSelect = document.getElementById('environment-filter');
    if (filterSelect) {
        // Update option counts
        Object.keys(breakdown).forEach(env => {
            const option = filterSelect.querySelector(`option[value="${env}"]`);
            if (option) {
                const count = breakdown[env];
                option.textContent = `${env.charAt(0).toUpperCase() + env.slice(1)} (${count})`;
            }
        });
    }

    return breakdown;
}

/**
 * Update environment breakdown summary card
 */
function updateEnvironmentBreakdown() {
    const breakdown = updateEnvironmentFilterCounts();

    // Update summary card
    Object.keys(breakdown).forEach(env => {
        const el = document.getElementById(`env-count-${env}`);
        if (el) {
            el.textContent = breakdown[env];
        }
    });
}

// =========================================================================
// AUTO-DISCOVERED METADATA DISPLAY
// =========================================================================

/**
 * Populate auto-discovered section in enrichment modal
 */
function populateAutoDiscoveredMetadata(asset) {
    const autoEnv = asset._environment_type || 'Not detected';
    const autoService = asset._service_name || 'Not detected';
    const autoApp = asset._application_name || 'Not detected';
    const confidence = asset._discovery_confidence || 0;
    const method = asset._discovery_method || 'N/A';

    // Update read-only fields
    const envInput = document.getElementById('enrichment-auto-environment');
    const serviceInput = document.getElementById('enrichment-auto-service');
    const appInput = document.getElementById('enrichment-auto-application');
    const confidenceBadge = document.getElementById('enrichment-confidence-badge');
    const methodSmall = document.getElementById('enrichment-discovery-method');

    if (envInput) envInput.value = autoEnv;
    if (serviceInput) serviceInput.value = autoService;
    if (appInput) appInput.value = autoApp;
    if (confidenceBadge) {
        confidenceBadge.textContent = `Confidence: ${Math.round(confidence * 100)}%`;
        // Color code confidence
        if (confidence >= 0.8) {
            confidenceBadge.className = 'badge badge-success';
        } else if (confidence >= 0.5) {
            confidenceBadge.className = 'badge badge-info';
        } else {
            confidenceBadge.className = 'badge badge-warning';
        }
    }
    if (methodSmall) methodSmall.textContent = `Source: ${method}`;

    // Show auto-discovered section if we have any data
    const autoDiscoveredSection = document.querySelector('.auto-discovered-section');
    if (autoDiscoveredSection && (autoEnv !== 'Not detected' || autoService !== 'Not detected')) {
        autoDiscoveredSection.style.display = 'block';
    }
}

/**
 * Override auto-discovered values with manual values
 */
function overrideAutoDiscovered() {
    const autoEnv = document.getElementById('enrichment-auto-environment')?.value || '';
    const autoService = document.getElementById('enrichment-auto-service')?.value || '';
    const autoApp = document.getElementById('enrichment-auto-application')?.value || '';

    // Look for manual enrichment fields and populate them
    // Adjust field IDs based on actual form structure
    const envField = document.getElementById('enrichment-manual-environment') ||
                     document.querySelector('input[name="environment_type"]');
    const serviceField = document.getElementById('enrichment-manual-service') ||
                        document.querySelector('input[name="service_name"]');
    const appField = document.getElementById('enrichment-manual-application') ||
                    document.querySelector('input[name="application_name"]');

    if (envField && autoEnv && autoEnv !== 'Not detected') {
        envField.value = autoEnv;
    }
    if (serviceField && autoService && autoService !== 'Not detected') {
        serviceField.value = autoService;
    }
    if (appField && autoApp && autoApp !== 'Not detected') {
        appField.value = autoApp;
    }

    // Highlight the fields that were populated
    [envField, serviceField, appField].forEach(field => {
        if (field && field.value) {
            field.classList.add('highlighted-field');
            setTimeout(() => field.classList.remove('highlighted-field'), 2000);
        }
    });
}

// =========================================================================
// BLAST RADIUS VISUALIZATION
// =========================================================================

/**
 * Load and display blast radius for an asset
 */
async function loadAndDisplayBlastRadius(assetId) {
    try {
        const response = await fetch(`/api/v1/assets/${assetId}/blast-radius`);
        if (!response.ok) {
            console.warn(`Blast radius API returned ${response.status}`);
            return;
        }

        const data = await response.json();

        // Update badge in tab
        const blastRadiusBadge = document.getElementById('blast-radius-badge');
        if (blastRadiusBadge) {
            blastRadiusBadge.textContent = data.dependent_count;
            blastRadiusBadge.style.display = 'inline-block';
        }

        // Update metric card
        const blastRadiusCount = document.getElementById('blast-radius-count');
        if (blastRadiusCount) {
            blastRadiusCount.textContent = data.dependent_count;
        }

        // Render relationship list
        if (data.dependent_assets && data.dependent_assets.length > 0) {
            renderBlastRadiusRelationships(data.dependent_assets);
        } else {
            const relationshipList = document.getElementById('relationship-list');
            if (relationshipList) {
                relationshipList.innerHTML = '<p class="text-muted">No dependent assets found.</p>';
            }
        }

    } catch (error) {
        console.error('Error loading blast radius:', error);
        const relationshipList = document.getElementById('relationship-list');
        if (relationshipList) {
            relationshipList.innerHTML = '<p class="text-danger">Error loading blast radius data.</p>';
        }
    }
}

/**
 * Render blast radius relationships as a tree
 */
function renderBlastRadiusRelationships(dependents) {
    const listEl = document.getElementById('relationship-list');
    if (!listEl) return;

    listEl.innerHTML = '';

    if (dependents.length === 0) {
        listEl.innerHTML = '<p class="text-muted">No dependent assets found.</p>';
        return;
    }

    // Group by depth for better visualization
    const byDepth = {};
    dependents.forEach(dep => {
        const depth = dep.depth || 1;
        if (!byDepth[depth]) {
            byDepth[depth] = [];
        }
        byDepth[depth].push(dep);
    });

    // Render as collapsible sections by depth
    Object.keys(byDepth).sort((a, b) => parseInt(a) - parseInt(b)).forEach(depth => {
        const section = document.createElement('div');
        section.className = 'relationship-depth-section';

        const header = document.createElement('div');
        header.className = 'depth-header';
        header.innerHTML = `<strong>Depth ${depth}</strong> (${byDepth[depth].length} assets)`;

        const list = document.createElement('ul');
        list.className = 'relationship-tree';

        byDepth[depth].forEach(dep => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span class="relationship-type badge badge-secondary" title="Relationship type">
                    ${dep.relationship_type}
                </span>
                <span class="asset-id" title="Asset: ${dep.asset_id}">
                    ${dep.asset_id.substring(0, 16)}...
                </span>
                <span class="asset-type badge badge-light">
                    ${dep.asset_type}
                </span>
            `;
            list.appendChild(li);
        });

        section.appendChild(header);
        section.appendChild(list);
        listEl.appendChild(section);
    });
}

// =========================================================================
// DEPENDENCY SUMMARY DISPLAY
// =========================================================================

/**
 * Load and display dependency summary for an asset
 */
async function loadDependencySummary(assetId) {
    try {
        const response = await fetch(`/api/v1/assets/${assetId}/dependency-summary`);
        if (!response.ok) {
            console.warn(`Dependency summary API returned ${response.status}`);
            return null;
        }

        const summary = await response.json();

        // Update dependency level badge if present
        const depLevelEl = document.getElementById('dependency-level-badge');
        if (depLevelEl) {
            depLevelEl.textContent = summary.dependency_level;
            depLevelEl.className = `badge badge-dependency badge-dep-${summary.dependency_level.split(' ')[0].toLowerCase()}`;
        }

        return summary;

    } catch (error) {
        console.error('Error loading dependency summary:', error);
        return null;
    }
}

// =========================================================================
// INITIALIZATION
// =========================================================================

/**
 * Initialize environment UI enhancements
 * Call this after assets are loaded
 */
function initializeEnvironmentUI() {
    // Enhance tables with badges
    enhanceTableWithEnvironmentBadges();

    // Initialize filters
    updateEnvironmentBreakdown();

    // Add event listeners
    const envFilter = document.getElementById('environment-filter');
    if (envFilter) {
        envFilter.addEventListener('change', filterAssetsByEnvironment);
    }

    // Add CSS for highlighted fields if needed
    if (!document.getElementById('environment-ui-styles')) {
        const style = document.createElement('style');
        style.id = 'environment-ui-styles';
        style.textContent = `
            .badge-env {
                padding: 0.25rem 0.5rem;
                font-size: 0.75rem;
                font-weight: 600;
                border-radius: 0.25rem;
                margin-right: 0.25rem;
            }

            .badge-env-production {
                background-color: #dc3545;
                color: white;
            }

            .badge-env-staging {
                background-color: #ffc107;
                color: #212529;
            }

            .badge-env-development {
                background-color: #17a2b8;
                color: white;
            }

            .badge-env-testing {
                background-color: #6c757d;
                color: white;
            }

            .badge-env-unknown {
                background-color: #e9ecef;
                color: #495057;
            }

            .badge-service {
                background-color: #28a745;
                color: white;
                margin-left: 0.25rem;
            }

            .auto-discovered-section {
                background-color: #f8f9fa;
                padding: 1rem;
                border-radius: 0.25rem;
                margin-bottom: 1rem;
                border-left: 4px solid #17a2b8;
            }

            .auto-discovered-section .form-control-plaintext {
                background-color: white;
                border: 1px solid #dee2e6;
                padding: 0.375rem 0.75rem;
                border-radius: 0.25rem;
            }

            .metric-card {
                text-align: center;
                padding: 1.5rem;
                background-color: #f8f9fa;
                border-radius: 0.25rem;
                margin-bottom: 1rem;
                border: 1px solid #dee2e6;
            }

            .metric-value {
                font-size: 2.5rem;
                font-weight: bold;
                color: #007bff;
                margin-bottom: 0.5rem;
            }

            .metric-label {
                font-size: 0.875rem;
                color: #6c757d;
                font-weight: 500;
            }

            .relationship-tree {
                list-style: none;
                padding-left: 0;
                margin-top: 0.75rem;
            }

            .relationship-tree li {
                padding: 0.75rem;
                border-left: 3px solid #dee2e6;
                margin-bottom: 0.5rem;
                background-color: #fff;
                border-radius: 0.25rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .relationship-type {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                background-color: #e9ecef;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                font-weight: 600;
                flex-shrink: 0;
            }

            .asset-id {
                font-family: monospace;
                font-size: 0.85rem;
                color: #495057;
                flex: 1;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .asset-type {
                flex-shrink: 0;
            }

            .relationship-depth-section {
                margin-bottom: 1rem;
                padding: 0.75rem;
                background-color: #f8f9fa;
                border-radius: 0.25rem;
            }

            .depth-header {
                padding: 0.5rem 0;
                margin-bottom: 0.5rem;
                border-bottom: 1px solid #dee2e6;
                color: #495057;
            }

            .environment-breakdown {
                display: flex;
                flex-direction: column;
                gap: 0.75rem;
            }

            .env-stat {
                display: flex;
                align-items: center;
                gap: 0.75rem;
                padding: 0.5rem;
                background-color: #f8f9fa;
                border-radius: 0.25rem;
            }

            .env-stat .label {
                flex: 1;
                font-weight: 500;
                color: #495057;
            }

            .env-stat strong {
                color: #212529;
                font-size: 1.1rem;
            }

            .highlighted-field {
                background-color: #fff3cd !important;
                transition: background-color 0.3s ease;
            }

            .badge-dependency {
                padding: 0.375rem 0.75rem;
                font-weight: 600;
            }

            .badge-dep-none {
                background-color: #e9ecef;
                color: #495057;
            }

            .badge-dep-low {
                background-color: #28a745;
                color: white;
            }

            .badge-dep-medium {
                background-color: #ffc107;
                color: #212529;
            }

            .badge-dep-high {
                background-color: #dc3545;
                color: white;
            }
        `;
        document.head.appendChild(style);
    }
}

// Export for use in other scripts
window.EnvironmentUI = {
    initializeEnvironmentUI,
    filterAssetsByEnvironment,
    updateEnvironmentBreakdown,
    populateAutoDiscoveredMetadata,
    overrideAutoDiscovered,
    loadAndDisplayBlastRadius,
    loadDependencySummary,
    renderEnvironmentBadge,
    renderServiceBadge
};
