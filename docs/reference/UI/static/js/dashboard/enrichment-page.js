/**
 * Enrichment Page Component
 *
 * Main coordinator for bulk asset enrichment UI:
 * - Integrates filters, table, and bulk actions
 * - Handles API communication
 * - Manages state and pagination
 */

class EnrichmentPage {
    constructor(engagementId) {
        this.engagementId = engagementId;
        this.filters = new EnrichmentFilters('#enrichment-filters', this.onFilterChange.bind(this));
        this.table = new EnrichmentTable('#enrichment-table', this.onRowChange.bind(this));
        this.table.setOnPageChange(this.onPageChange.bind(this));
        this.pendingChanges = new Map();
        this.currentPage = 1;
        this.currentFilters = {};

        this.loadAssets();
    }

    /**
     * Load assets from API
     */
    async loadAssets() {
        try {
            const filters = this.filters.getFilters();
            this.currentFilters = filters;

            const params = new URLSearchParams({
                engagement_id: this.engagementId,
                page: this.currentPage,
                limit: 50,
                sort_by: filters.sort_by || 'confidence'
            });

            if (filters.source) params.append('source', filters.source);
            if (filters.confidence_min !== null) params.append('confidence_min', filters.confidence_min);
            if (filters.confidence_max !== null) params.append('confidence_max', filters.confidence_max);
            if (filters.enrichment_status) params.append('enrichment_status', filters.enrichment_status);

            const response = await fetch(`/api/v1/assets/enrichment/list?${params}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            this.table.render(data.assets, data.pagination);
            this.showSuccessMessage(`Loaded ${data.assets.length} assets`);

        } catch (error) {
            console.error('Error loading assets:', error);
            this.showErrorMessage(`Failed to load assets: ${error.message}`);
        }
    }

    /**
     * Handle filter change
     */
    onFilterChange(filters) {
        this.currentPage = 1; // Reset to page 1
        this.loadAssets();
    }

    /**
     * Handle row change
     */
    onRowChange(change) {
        const assetId = change.asset_id;

        if (!this.pendingChanges.has(assetId)) {
            this.pendingChanges.set(assetId, {});
        }

        const updates = this.pendingChanges.get(assetId);

        if (change.field === 'multiple') {
            Object.assign(updates, change.value);
        } else {
            updates[change.field] = change.value;
        }

        this.updateSaveStatus();
    }

    /**
     * Handle page change
     */
    onPageChange(newPage) {
        if (this.pendingChanges.size > 0) {
            if (!confirm('You have unsaved changes. Discard and go to page ' + newPage + '?')) {
                return;
            }
        }

        this.currentPage = newPage;
        this.loadAssets();
    }

    /**
     * Update save button status
     */
    updateSaveStatus() {
        const btn = document.getElementById('btn-save-enrichment');
        const count = this.pendingChanges.size;

        if (count > 0) {
            btn.disabled = false;
            btn.textContent = `Save Changes (${count} assets)`;
            btn.style.background = '#10b981';
        } else {
            btn.disabled = true;
            btn.textContent = 'Save Changes';
            btn.style.background = '#d1d5db';
            btn.style.cursor = 'not-allowed';
        }
    }

    /**
     * Save all pending changes
     */
    async saveChanges() {
        if (this.pendingChanges.size === 0) {
            this.showInfoMessage('No changes to save');
            return;
        }

        const btn = document.getElementById('btn-save-enrichment');
        btn.disabled = true;
        btn.textContent = 'Saving...';

        try {
            const operations = Array.from(this.pendingChanges.entries()).map(([assetId, updates]) => ({
                asset_id: assetId,
                updates: updates
            }));

            const response = await fetch('/api/v1/assets/enrichment/save', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-User-ID': this.getCurrentUserId() || 'system'
                },
                body: JSON.stringify({
                    engagement_id: this.engagementId,
                    operations: operations
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();

            if (result.success) {
                this.pendingChanges.clear();
                this.updateSaveStatus();
                this.showSuccessMessage(`✓ Saved ${result.updated_count} asset(s) - Operation ID: ${result.operation_id}`);
                // Reload to show updated state
                setTimeout(() => this.loadAssets(), 500);
            } else {
                this.showErrorMessage('Save failed');
            }

        } catch (error) {
            console.error('Error saving changes:', error);
            this.showErrorMessage(`Save failed: ${error.message}`);
        } finally {
            this.updateSaveStatus();
        }
    }

    /**
     * Bulk fill from inferred data
     */
    async bulkFillInferred() {
        const selectedAssets = this.table.getSelectedAssets();
        if (selectedAssets.length === 0) {
            this.showInfoMessage('Select assets first');
            return;
        }

        const confirmed = confirm(`Bulk-fill inferred data for ${selectedAssets.length} asset(s)?`);
        if (!confirmed) return;

        // Field mapping: API field -> extraction path
        const INFERRED_FIELD_MAP = {
            environment_type: a => a.inferred?.environment_type,
            service_name: a => a.inferred?.service_name,
            application_name: a => a.inferred?.application_name,
            extracted_cloud_provider: a => a.extracted?.cloud_provider,
            extracted_region: a => a.extracted?.region,
            extracted_service_tier: a => a.extracted?.service_tier,
            extracted_domain_type: a => a.extracted?.domain_type,
            extracted_primary_purpose: a => a.extracted?.primary_purpose,
            extracted_ca_tier: a => a.extracted?.ca_tier,
            extracted_issuing_organization: a => a.extracted?.issuing_organization,
            extracted_criticality_tier: a => a.extracted?.criticality_tier,
            extracted_data_residency: a => a.extracted?.data_residency,
            extracted_crypto_strength: a => a.extracted?.crypto_strength,
            extracted_pqc_migration_needed: a => a.extracted?.pqc_migration_needed,
            extracted_ha_enabled: a => a.extracted?.ha_enabled,
            extracted_replication_count: a => a.extracted?.replication_count,
            extracted_san_base_name: a => a.extracted?.san_base_name,
            extracted_is_replicated: a => a.extracted?.is_replicated
        };

        selectedAssets.forEach(assetId => {
            const asset = this.table.assets.find(a => a.asset_id === assetId);
            if (!asset) return;

            const updates = {};

            // Only fill fields that have inferred values AND no manual override already set
            Object.entries(INFERRED_FIELD_MAP).forEach(([field, accessor]) => {
                const inferredValue = accessor(asset);

                // Get current manual value (avoid overwriting existing manual values)
                const manualValue = asset.manual?.[field];

                // Only fill if inferred value exists AND no manual override
                if (inferredValue && !manualValue) {
                    updates[field] = inferredValue;
                }
            });

            if (Object.keys(updates).length > 0) {
                this.onRowChange({
                    asset_id: assetId,
                    field: 'multiple',
                    value: updates
                });
            }
        });

        this.showSuccessMessage(`Prepared ${selectedAssets.length} asset(s) with inferred data`);
    }

    /**
     * Get current user ID from session/DOM
     */
    getCurrentUserId() {
        // Try to get from global app state or DOM
        if (window.currentUser) return window.currentUser.id;
        const userEl = document.querySelector('[data-user-id]');
        return userEl ? userEl.dataset.userId : null;
    }

    /**
     * Show success message
     */
    showSuccessMessage(message) {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #10b981;
            color: white;
            padding: 12px 16px;
            border-radius: 4px;
            font-size: 13px;
            z-index: 999;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        `;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    /**
     * Show error message
     */
    showErrorMessage(message) {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #ef4444;
            color: white;
            padding: 12px 16px;
            border-radius: 4px;
            font-size: 13px;
            z-index: 999;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        `;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    /**
     * Show info message
     */
    showInfoMessage(message) {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #3b82f6;
            color: white;
            padding: 12px 16px;
            border-radius: 4px;
            font-size: 13px;
            z-index: 999;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        `;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }
}

/**
 * Initialize enrichment page when DOM is ready
 */
function initEnrichmentPage(engagementId) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.enrichmentPage = new EnrichmentPage(engagementId);
        });
    } else {
        window.enrichmentPage = new EnrichmentPage(engagementId);
    }
}
