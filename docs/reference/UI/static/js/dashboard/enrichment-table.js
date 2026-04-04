/**
 * Enrichment Table Component
 *
 * Displays paginated table of assets with enrichment data:
 * - Inferred (auto-discovered) metadata
 * - Manual (user-provided) enrichment
 * - Inline editing of enrichment fields
 * - Bulk selection and operations
 */

class EnrichmentTable {
    constructor(containerSelector, onRowChange) {
        this.container = document.querySelector(containerSelector);
        this.onRowChange = onRowChange;
        this.selectedRows = new Set();
        this.currentPage = 1;
        this.totalPages = 1;
        this.assets = [];
    }

    /**
     * Render table with asset data
     */
    render(assets, pagination) {
        this.assets = assets;
        this.currentPage = pagination.page;
        this.totalPages = pagination.pages;

        const tableHtml = `
            ${this.selectedRows.size >= 2 ? this.renderBulkActionBar() : ''}

            <div class="enrichment-table-container" style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="background: #f3f4f6; border-bottom: 1px solid #d1d5db;">
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; width: 40px;">
                                <input type="checkbox" id="select-all" style="cursor: pointer;">
                            </th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Asset ID</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Source</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Environment</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Cloud</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Tier</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Criticality</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Business Unit</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Classification</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Owner</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${assets.map((asset, idx) => this.renderRow(asset, idx)).join('')}
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div style="display: flex; justify-content: center; align-items: center; gap: 12px; margin-top: 20px;">
                <button id="btn-prev-page" style="padding: 6px 12px; border: 1px solid #d1d5db; border-radius: 4px; cursor: pointer; background: white;">← Previous</button>
                <span style="font-size: 13px; color: #6b7280;">
                    Page <strong>${this.currentPage}</strong> of <strong>${this.totalPages}</strong>
                </span>
                <button id="btn-next-page" style="padding: 6px 12px; border: 1px solid #d1d5db; border-radius: 4px; cursor: pointer; background: white;">Next →</button>
            </div>
        `;

        this.container.innerHTML = tableHtml;
        this.attachEventListeners();
    }

    /**
     * Render bulk action bar (shown when 2+ rows selected)
     */
    renderBulkActionBar() {
        return `
            <div id="bulk-action-bar" style="display:flex; align-items:center; gap:10px; padding:10px;
                 background:#eff6ff; border:1px solid #bfdbfe; border-radius:6px; margin-bottom:12px;">
                <span style="font-weight:600; font-size:13px; color:#1e40af;">${this.selectedRows.size} selected</span>
                <select id="bulk-field-select" style="padding:6px 8px; border:1px solid #bfdbfe; border-radius:4px; font-size:12px;">
                    <option value="">Set field for selected...</option>
                    <option value="environment_type">Environment Type</option>
                    <option value="extracted_cloud_provider">Cloud Provider</option>
                    <option value="extracted_service_tier">Service Tier</option>
                    <option value="extracted_criticality_tier">Criticality</option>
                    <option value="business_unit">Business Unit</option>
                    <option value="data_classification">Data Classification</option>
                </select>
                <select id="bulk-value-select" style="padding:6px 8px; border:1px solid #bfdbfe; border-radius:4px; font-size:12px; display:none;"></select>
                <button id="btn-apply-bulk" style="padding:6px 12px; background:#3b82f6; color:white; border:none; border-radius:4px; cursor:pointer; font-weight:600; font-size:12px;">
                    Apply to Selected
                </button>
            </div>
        `;
    }

    /**
     * Render single table row with inline editable fields
     */
    renderRow(asset, idx) {
        const statusBg = this.getStatusColor(asset.enrichment_status);

        // Determine current and inferred values for each field
        const envCurrent = asset.manual.environment_type || asset.inferred.environment_type;
        const envInferred = asset.inferred.environment_type || '(none)';
        const envBg = asset.manual.environment_type ? '#fff' : '#f9fafb';
        const envFg = asset.manual.environment_type ? '#111827' : '#9ca3af';

        const cloudCurrent = asset.manual.extracted_cloud_provider || asset.extracted?.cloud_provider;
        const cloudInferred = asset.extracted?.cloud_provider || '(none)';
        const cloudBg = asset.manual.extracted_cloud_provider ? '#fff' : '#f9fafb';
        const cloudFg = asset.manual.extracted_cloud_provider ? '#111827' : '#9ca3af';

        const tierCurrent = asset.manual.extracted_service_tier || asset.extracted?.service_tier;
        const tierInferred = asset.extracted?.service_tier || '(none)';
        const tierBg = asset.manual.extracted_service_tier ? '#fff' : '#f9fafb';
        const tierFg = asset.manual.extracted_service_tier ? '#111827' : '#9ca3af';

        const critCurrent = asset.manual.extracted_criticality_tier || asset.extracted?.criticality_tier;
        const critInferred = asset.extracted?.criticality_tier || '(none)';
        const critBg = asset.manual.extracted_criticality_tier ? '#fff' : '#f9fafb';
        const critFg = asset.manual.extracted_criticality_tier ? '#111827' : '#9ca3af';

        const buCurrent = asset.manual.business_unit;
        const buBg = buCurrent ? '#fff' : '#f9fafb';
        const buFg = buCurrent ? '#111827' : '#9ca3af';

        const classCurrent = asset.manual.data_classification;
        const classBg = classCurrent ? '#fff' : '#f9fafb';
        const classFg = classCurrent ? '#111827' : '#9ca3af';

        const ownerCurrent = asset.manual.owner;
        const ownerBg = ownerCurrent ? '#fff' : '#f9fafb';
        const ownerFg = ownerCurrent ? '#111827' : '#9ca3af';

        return `
            <tr data-asset-id="${asset.asset_id}" data-index="${idx}"
                style="border-bottom: 1px solid #e5e7eb; transition: background 0.2s; hover: {background: #f9fafb};">
                <td style="padding: 8px; text-align: center;">
                    <input type="checkbox" class="row-checkbox" style="cursor: pointer;">
                </td>
                <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #4b5563;">
                    ${asset.asset_id.substring(0, 16)}...
                </td>
                <td style="padding: 8px; color: #374151; font-size: 12px;">
                    <span style="font-size: 11px; background: #e0e7ff; color: #3730a3; padding: 2px 6px; border-radius: 3px;">
                        ${asset.integration_name}
                    </span>
                </td>
                <!-- Environment Type -->
                <td style="padding: 6px;">
                    <select class="inline-field" data-asset-id="${asset.asset_id}" data-field="environment_type"
                            style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                   font-size: 11px; background: ${envBg}; color: ${envFg};">
                        <option value="">— ${envInferred}</option>
                        <option value="production" ${envCurrent==='production'?'selected':''}>Production</option>
                        <option value="staging" ${envCurrent==='staging'?'selected':''}>Staging</option>
                        <option value="development" ${envCurrent==='development'?'selected':''}>Development</option>
                        <option value="testing" ${envCurrent==='testing'?'selected':''}>Testing</option>
                    </select>
                </td>
                <!-- Cloud Provider -->
                <td style="padding: 6px;">
                    <select class="inline-field" data-asset-id="${asset.asset_id}" data-field="extracted_cloud_provider"
                            style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                   font-size: 11px; background: ${cloudBg}; color: ${cloudFg};">
                        <option value="">— ${cloudInferred}</option>
                        <option value="azure" ${cloudCurrent==='azure'?'selected':''}>Azure</option>
                        <option value="aws" ${cloudCurrent==='aws'?'selected':''}>AWS</option>
                        <option value="gcp" ${cloudCurrent==='gcp'?'selected':''}>GCP</option>
                        <option value="on-prem" ${cloudCurrent==='on-prem'?'selected':''}>On-Prem</option>
                    </select>
                </td>
                <!-- Service Tier -->
                <td style="padding: 6px;">
                    <select class="inline-field" data-asset-id="${asset.asset_id}" data-field="extracted_service_tier"
                            style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                   font-size: 11px; background: ${tierBg}; color: ${tierFg};">
                        <option value="">— ${tierInferred}</option>
                        <option value="application" ${tierCurrent==='application'?'selected':''}>Application</option>
                        <option value="database" ${tierCurrent==='database'?'selected':''}>Database</option>
                        <option value="web" ${tierCurrent==='web'?'selected':''}>Web</option>
                        <option value="api" ${tierCurrent==='api'?'selected':''}>API</option>
                    </select>
                </td>
                <!-- Criticality Tier -->
                <td style="padding: 6px;">
                    <select class="inline-field" data-asset-id="${asset.asset_id}" data-field="extracted_criticality_tier"
                            style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                   font-size: 11px; background: ${critBg}; color: ${critFg};">
                        <option value="">— ${critInferred}</option>
                        <option value="critical" ${critCurrent==='critical'?'selected':''}>Critical</option>
                        <option value="high" ${critCurrent==='high'?'selected':''}>High</option>
                        <option value="standard" ${critCurrent==='standard'?'selected':''}>Standard</option>
                    </select>
                </td>
                <!-- Business Unit -->
                <td style="padding: 6px;">
                    <select class="inline-field" data-asset-id="${asset.asset_id}" data-field="business_unit"
                            style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                   font-size: 11px; background: ${buBg}; color: ${buFg};">
                        <option value="">Select...</option>
                        <option value="IT Operations" ${buCurrent==='IT Operations'?'selected':''}>IT Ops</option>
                        <option value="Security" ${buCurrent==='Security'?'selected':''}>Security</option>
                        <option value="Infrastructure" ${buCurrent==='Infrastructure'?'selected':''}>Infra</option>
                        <option value="Development" ${buCurrent==='Development'?'selected':''}>Dev</option>
                        <option value="Other" ${buCurrent==='Other'?'selected':''}>Other</option>
                    </select>
                </td>
                <!-- Data Classification -->
                <td style="padding: 6px;">
                    <select class="inline-field" data-asset-id="${asset.asset_id}" data-field="data_classification"
                            style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                   font-size: 11px; background: ${classBg}; color: ${classFg};">
                        <option value="">Select...</option>
                        <option value="Restricted" ${classCurrent==='Restricted'?'selected':''}>Restricted</option>
                        <option value="Confidential" ${classCurrent==='Confidential'?'selected':''}>Confidential</option>
                        <option value="Internal" ${classCurrent==='Internal'?'selected':''}>Internal</option>
                        <option value="Public" ${classCurrent==='Public'?'selected':''}>Public</option>
                    </select>
                </td>
                <!-- Owner -->
                <td style="padding: 6px;">
                    <input type="email" class="inline-field-owner" data-asset-id="${asset.asset_id}" data-field="owner"
                           value="${ownerCurrent || ''}" placeholder="owner@company.com"
                           style="width: 100%; padding: 3px 4px; border: 1px solid #d1d5db; border-radius: 3px;
                                  font-size: 11px; background: ${ownerBg}; color: ${ownerFg};">
                </td>
                <!-- Status -->
                <td style="padding: 8px;">
                    <span style="background: ${statusBg}; color: white; padding: 3px 6px; border-radius: 3px; font-size: 10px; font-weight: 600;">
                        ${asset.enrichment_status.replace(/_/g, ' ')}
                    </span>
                </td>
            </tr>
        `;
    }

    /**
     * Get color for enrichment status
     */
    getStatusColor(status) {
        if (status === 'complete') return '#10b981';
        if (status === 'partial') return '#f59e0b';
        return '#ef4444';
    }

    /**
     * Attach row event listeners
     */
    attachEventListeners() {
        // Select all checkbox
        document.getElementById('select-all').addEventListener('change', (e) => {
            document.querySelectorAll('.row-checkbox').forEach(cb => {
                cb.checked = e.target.checked;
            });
            this.updateSelectedRows();
        });

        // Individual row checkboxes
        document.querySelectorAll('.row-checkbox').forEach(cb => {
            cb.addEventListener('change', () => {
                this.updateSelectedRows();
            });
        });

        // Inline select field changes
        document.querySelectorAll('.inline-field').forEach(select => {
            select.addEventListener('change', (e) => {
                const assetId = e.target.dataset.assetId;
                const field = e.target.dataset.field;
                const value = e.target.value || null;

                // Update background color (white = manual, gray = inferred)
                if (value) {
                    e.target.style.background = '#fff';
                    e.target.style.color = '#111827';
                } else {
                    e.target.style.background = '#f9fafb';
                    e.target.style.color = '#9ca3af';
                }

                this.onRowChange({
                    asset_id: assetId,
                    field: field,
                    value: value
                });
            });
        });

        // Inline owner input blur
        document.querySelectorAll('.inline-field-owner').forEach(input => {
            input.addEventListener('blur', (e) => {
                const assetId = e.target.dataset.assetId;
                const field = e.target.dataset.field;
                const value = e.target.value || null;

                // Update background color
                if (value) {
                    e.target.style.background = '#fff';
                    e.target.style.color = '#111827';
                } else {
                    e.target.style.background = '#f9fafb';
                    e.target.style.color = '#9ca3af';
                }

                this.onRowChange({
                    asset_id: assetId,
                    field: field,
                    value: value
                });
            });
        });

        // Bulk field select
        const bulkFieldSelect = document.getElementById('bulk-field-select');
        if (bulkFieldSelect) {
            bulkFieldSelect.addEventListener('change', (e) => {
                const field = e.target.value;
                const valueSelect = document.getElementById('bulk-value-select');

                if (!field) {
                    valueSelect.style.display = 'none';
                    valueSelect.innerHTML = '';
                    return;
                }

                // Populate value select based on field
                const options = this.getBulkValueOptions(field);
                valueSelect.innerHTML = `<option value="">Select value...</option>` +
                    options.map(opt => `<option value="${opt.value}">${opt.label}</option>`).join('');
                valueSelect.style.display = 'block';
            });
        }

        // Bulk apply button
        const bulkApplyBtn = document.getElementById('btn-apply-bulk');
        if (bulkApplyBtn) {
            bulkApplyBtn.addEventListener('click', () => {
                const field = document.getElementById('bulk-field-select').value;
                const value = document.getElementById('bulk-value-select').value;

                if (!field || !value) {
                    alert('Please select a field and value');
                    return;
                }

                this.applyBulkValue(field, value, Array.from(this.selectedRows));
            });
        }

        // Pagination
        const prevBtn = document.getElementById('btn-prev-page');
        const nextBtn = document.getElementById('btn-next-page');

        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (this.currentPage > 1) this.onPageChange(this.currentPage - 1);
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                if (this.currentPage < this.totalPages) this.onPageChange(this.currentPage + 1);
            });
        }
    }

    /**
     * Get bulk value options for a field
     */
    getBulkValueOptions(field) {
        const options = {
            environment_type: [
                { value: 'production', label: 'Production' },
                { value: 'staging', label: 'Staging' },
                { value: 'development', label: 'Development' },
                { value: 'testing', label: 'Testing' }
            ],
            extracted_cloud_provider: [
                { value: 'azure', label: 'Azure' },
                { value: 'aws', label: 'AWS' },
                { value: 'gcp', label: 'GCP' },
                { value: 'on-prem', label: 'On-Premise' }
            ],
            extracted_service_tier: [
                { value: 'application', label: 'Application' },
                { value: 'database', label: 'Database' },
                { value: 'web', label: 'Web' },
                { value: 'api', label: 'API' }
            ],
            extracted_criticality_tier: [
                { value: 'critical', label: 'Critical' },
                { value: 'high', label: 'High' },
                { value: 'standard', label: 'Standard' }
            ],
            business_unit: [
                { value: 'IT Operations', label: 'IT Operations' },
                { value: 'Security', label: 'Security' },
                { value: 'Infrastructure', label: 'Infrastructure' },
                { value: 'Development', label: 'Development' },
                { value: 'Other', label: 'Other' }
            ],
            data_classification: [
                { value: 'Restricted', label: 'Restricted' },
                { value: 'Confidential', label: 'Confidential' },
                { value: 'Internal', label: 'Internal' },
                { value: 'Public', label: 'Public' }
            ]
        };

        return options[field] || [];
    }

    /**
     * Apply bulk value to selected rows
     */
    applyBulkValue(field, value, assetIds) {
        assetIds.forEach(assetId => {
            const selector = `.inline-field[data-asset-id="${assetId}"][data-field="${field}"]`;
            const el = this.container.querySelector(selector);

            if (el) {
                el.value = value;
                el.style.background = '#fff';
                el.style.color = '#111827';

                this.onRowChange({
                    asset_id: assetId,
                    field: field,
                    value: value
                });
            }
        });
    }

    /**
     * Update selected rows set and re-render bulk bar
     */
    updateSelectedRows() {
        this.selectedRows.clear();
        document.querySelectorAll('.row-checkbox:checked').forEach(cb => {
            const tr = cb.closest('tr');
            const assetId = tr.dataset.assetId;
            this.selectedRows.add(assetId);
        });

        // Re-render bulk action bar if selected count changes
        if (this.selectedRows.size >= 2) {
            const bulkBar = document.getElementById('bulk-action-bar');
            if (!bulkBar) {
                // Re-render entire table with bulk bar
                this.render(this.assets, {
                    page: this.currentPage,
                    pages: this.totalPages,
                    per_page: 10,
                    total: this.assets.length * this.totalPages
                });
            } else {
                // Update selected count in existing bar
                bulkBar.querySelector('span').textContent = `${this.selectedRows.size} selected`;
            }
        } else {
            // Remove bulk bar if < 2 selected
            const bulkBar = document.getElementById('bulk-action-bar');
            if (bulkBar) bulkBar.remove();
        }
    }

    /**
     * Get selected asset IDs
     */
    getSelectedAssets() {
        return Array.from(this.selectedRows);
    }

    /**
     * Set pagination change callback
     */
    setOnPageChange(callback) {
        this.onPageChange = callback;
    }
}
