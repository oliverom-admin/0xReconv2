/**
 * Enrichment Filters Component
 *
 * Handles filtering and sorting of enrichment assets:
 * - Source (integration name)
 * - Confidence range (0.0-1.0)
 * - Enrichment status (not_enriched, partial, complete)
 * - Sort order (confidence, source, last_seen)
 */

class EnrichmentFilters {
    constructor(containerSelector, onFilterChange) {
        this.container = document.querySelector(containerSelector);
        this.onFilterChange = onFilterChange;
        this.currentFilters = {
            source: null,
            environment_type: null,
            cloud_provider: null,
            confidence_min: null,
            confidence_max: null,
            enrichment_status: null,
            sort_by: 'confidence'
        };

        this.render();
        this.attachEventListeners();
    }

    /**
     * Render filter UI
     */
    render() {
        this.container.innerHTML = `
            <div class="enrichment-filters" style="padding: 16px; background: #f8fafc; border-radius: 8px; border: 1px solid #e5e7eb; margin-bottom: 16px;">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">

                    <!-- Source Filter -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Source
                        </label>
                        <select id="filter-source" style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                            <option value="">All Sources</option>
                            <option value="EJBCA">EJBCA</option>
                            <option value="Azure">Azure Key Vault</option>
                            <option value="Luna">Luna HSM</option>
                            <option value="TLS">TLS Scanner</option>
                            <option value="File">File Scanner</option>
                        </select>
                    </div>

                    <!-- Environment Type Filter -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Environment Type
                        </label>
                        <select id="filter-environment-type" style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                            <option value="">All Environments</option>
                            <option value="production">Production</option>
                            <option value="staging">Staging</option>
                            <option value="development">Development</option>
                            <option value="testing">Testing</option>
                        </select>
                    </div>

                    <!-- Cloud Provider Filter -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Cloud Provider
                        </label>
                        <select id="filter-cloud-provider" style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                            <option value="">All Providers</option>
                            <option value="azure">Azure</option>
                            <option value="aws">AWS</option>
                            <option value="gcp">GCP</option>
                            <option value="on-prem">On-Premise</option>
                        </select>
                    </div>

                    <!-- Confidence Min Filter -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Min Confidence
                        </label>
                        <input type="number" id="filter-confidence-min"
                               min="0" max="1" step="0.1" placeholder="0.0"
                               style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                    </div>

                    <!-- Confidence Max Filter -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Max Confidence
                        </label>
                        <input type="number" id="filter-confidence-max"
                               min="0" max="1" step="0.1" placeholder="1.0"
                               style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                    </div>

                    <!-- Enrichment Status Filter -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Enrichment Status
                        </label>
                        <select id="filter-status" style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                            <option value="">All</option>
                            <option value="not_enriched">Not Enriched</option>
                            <option value="partial">Partial</option>
                            <option value="complete">Complete</option>
                        </select>
                    </div>

                    <!-- Sort By -->
                    <div>
                        <label style="display: block; font-size: 12px; font-weight: 600; color: #6b7280; margin-bottom: 6px;">
                            Sort By
                        </label>
                        <select id="filter-sort" style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-size: 13px;">
                            <option value="confidence">Confidence (High→Low)</option>
                            <option value="source">Source (A→Z)</option>
                            <option value="last_seen">Last Seen (Recent)</option>
                        </select>
                    </div>

                    <!-- Action Buttons -->
                    <div style="display: flex; gap: 8px; align-items: flex-end;">
                        <button id="btn-apply-filters"
                                style="flex: 1; padding: 8px; background: #3b82f6; color: white; border: none; border-radius: 4px; font-size: 13px; font-weight: 600; cursor: pointer;">
                            Apply Filters
                        </button>
                        <button id="btn-clear-filters"
                                style="flex: 1; padding: 8px; background: #e5e7eb; color: #374151; border: none; border-radius: 4px; font-size: 13px; font-weight: 600; cursor: pointer;">
                            Clear All
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        document.getElementById('filter-source').addEventListener('change', (e) => {
            this.currentFilters.source = e.target.value || null;
        });

        document.getElementById('filter-environment-type').addEventListener('change', (e) => {
            this.currentFilters.environment_type = e.target.value || null;
        });

        document.getElementById('filter-cloud-provider').addEventListener('change', (e) => {
            this.currentFilters.cloud_provider = e.target.value || null;
        });

        document.getElementById('filter-confidence-min').addEventListener('change', (e) => {
            this.currentFilters.confidence_min = e.target.value ? parseFloat(e.target.value) : null;
        });

        document.getElementById('filter-confidence-max').addEventListener('change', (e) => {
            this.currentFilters.confidence_max = e.target.value ? parseFloat(e.target.value) : null;
        });

        document.getElementById('filter-status').addEventListener('change', (e) => {
            this.currentFilters.enrichment_status = e.target.value || null;
        });

        document.getElementById('filter-sort').addEventListener('change', (e) => {
            this.currentFilters.sort_by = e.target.value;
        });

        document.getElementById('btn-apply-filters').addEventListener('click', () => {
            this.onFilterChange(this.currentFilters);
        });

        document.getElementById('btn-clear-filters').addEventListener('click', () => {
            this.clearFilters();
        });

        // Apply filters on Enter key
        document.querySelectorAll('#filter-confidence-min, #filter-confidence-max').forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.onFilterChange(this.currentFilters);
                }
            });
        });
    }

    /**
     * Clear all filters
     */
    clearFilters() {
        this.currentFilters = {
            source: null,
            environment_type: null,
            cloud_provider: null,
            confidence_min: null,
            confidence_max: null,
            enrichment_status: null,
            sort_by: 'confidence'
        };

        document.getElementById('filter-source').value = '';
        document.getElementById('filter-environment-type').value = '';
        document.getElementById('filter-cloud-provider').value = '';
        document.getElementById('filter-confidence-min').value = '';
        document.getElementById('filter-confidence-max').value = '';
        document.getElementById('filter-status').value = '';
        document.getElementById('filter-sort').value = 'confidence';

        this.onFilterChange(this.currentFilters);
    }

    /**
     * Get current filters
     */
    getFilters() {
        return { ...this.currentFilters };
    }

    /**
     * Set filters programmatically
     */
    setFilters(filters) {
        if (filters.source) {
            document.getElementById('filter-source').value = filters.source;
            this.currentFilters.source = filters.source;
        }
        if (filters.confidence_min !== undefined && filters.confidence_min !== null) {
            document.getElementById('filter-confidence-min').value = filters.confidence_min;
            this.currentFilters.confidence_min = filters.confidence_min;
        }
        if (filters.confidence_max !== undefined && filters.confidence_max !== null) {
            document.getElementById('filter-confidence-max').value = filters.confidence_max;
            this.currentFilters.confidence_max = filters.confidence_max;
        }
        if (filters.enrichment_status) {
            document.getElementById('filter-status').value = filters.enrichment_status;
            this.currentFilters.enrichment_status = filters.enrichment_status;
        }
        if (filters.sort_by) {
            document.getElementById('filter-sort').value = filters.sort_by;
            this.currentFilters.sort_by = filters.sort_by;
        }
    }
}
