/**
 * Secret Picker Component
 *
 * Reusable modal for selecting secrets from registered secret stores.
 * Integrates with credential fields in configuration forms.
 *
 * Usage:
 *   SecretPicker.open({
 *       onSelect: (secretRef) => {  },
 *       targetFieldId: 'myPasswordField'
 *   });
 */

const SecretPicker = (() => {
    const API_BASE = '/api/secret-stores';
    let currentCallbackFn = null;
    let currentTargetField = null;
    let stores = [];
    let selectedStoreId = null;

    /**
     * Initialize the secret picker
     */
    function init() {
        
        setupEventHandlers();
    }

    /**
     * Setup event handlers for the modal
     */
    function setupEventHandlers() {
        const modal = document.getElementById('secretPickerModal');
        if (!modal) return;

        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                close();
            }
        });
    }

    /**
     * Open the secret picker modal
     * @param {Object} options - Configuration options
     * @param {Function} options.onSelect - Callback when secret is selected
     * @param {String} options.targetFieldId - ID of field to populate (optional)
     */
    async function open(options = {}) {
        
        currentCallbackFn = options.onSelect || null;
        currentTargetField = options.targetFieldId || null;

        const modal = document.getElementById('secretPickerModal');
        if (!modal) {
            
            return;
        }

        
        // Show modal by adding .active class (follows dashboard CSS pattern)
        modal.classList.add('active');

        
        // Load stores
        try {
            await loadStores();
            
        } catch (error) {
            
        }

        // Reset UI
        
        resetUI();
        
    }

    /**
     * Close the secret picker modal
     */
    function close() {
        
        const modal = document.getElementById('secretPickerModal');
        if (modal) {
            modal.classList.remove('active');
        }
        currentCallbackFn = null;
        currentTargetField = null;
        selectedStoreId = null;
    }

    /**
     * Load available secret stores
     */
    async function loadStores() {
        
        try {
            const response = await fetch(`${API_BASE}`);
            

            const data = await response.json();
            

            if (data.success && data.stores) {
                
                stores = data.stores;
                displayStoresList();
            } else {
                
                showError('Failed to load secret stores: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            
            showError('Error loading stores: ' + error.message);
        }
    }

    /**
     * Display list of available stores
     */
    function displayStoresList() {
        const storesContainer = document.getElementById('secretPickerStoresList');
        if (!storesContainer) return;

        if (stores.length === 0) {
            storesContainer.innerHTML = `
                <div style="padding: 20px; text-align: center; color: #6b7280;">
                    <p>No secret stores registered yet.</p>
                    <p style="font-size: 13px; margin-top: 10px;">
                        Register a secret store in the <strong>Secret Stores</strong> section first.
                    </p>
                </div>
            `;
            return;
        }

        let html = '<div style="display: grid; gap: 12px;">';

        stores.forEach(store => {
            const statusClass = `status-${store.status || 'pending'}`;
            const statusLabel = store.status === 'active' ? '✓ Active' :
                               store.status === 'locked' ? '🔒 Locked' :
                               store.status === 'error' ? '⚠ Error' : '⏳ Pending';

            html += `
                <div class="secret-picker-store-card" onclick="SecretPicker.selectStore('${store.id}')">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div style="flex: 1;">
                            <div style="font-weight: 600; color: #1f2937; margin-bottom: 4px;">${escapeHtml(store.name)}</div>
                            <div style="font-size: 13px; color: #6b7280;">
                                ${escapeHtml(store.provider_type)} • ${store.secret_count || 0} secrets
                            </div>
                        </div>
                        <div style="font-size: 12px; padding: 4px 12px; border-radius: 4px; margin-left: 12px;" class="status-badge ${statusClass}">
                            ${statusLabel}
                        </div>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        storesContainer.innerHTML = html;
    }

    /**
     * Select a store and load its secrets
     */
    async function selectStore(storeId) {
        selectedStoreId = storeId;

        // Update UI
        updateStoreSelection(storeId);

        // Load secrets for this store
        try {
            showLoading('Loading secrets...');

            const response = await fetch(`${API_BASE}/${storeId}/secrets`);
            const data = await response.json();

            hideLoading();

            if (data.success && data.secrets) {
                displaySecretsList(data.secrets);
            } else {
                showError('Failed to load secrets: ' + (data.error || 'Unknown error'));
                displaySecretsList([]);
            }
        } catch (error) {
            
            showError('Error loading secrets: ' + error.message);
            hideLoading();
            displaySecretsList([]);
        }
    }

    /**
     * Update store selection UI
     */
    function updateStoreSelection(storeId) {
        const cards = document.querySelectorAll('.secret-picker-store-card');
        cards.forEach(card => {
            card.classList.remove('selected');
        });

        // Mark selected store
        const selectedStore = stores.find(s => s.id === storeId);
        if (selectedStore) {
            const cards = document.querySelectorAll('.secret-picker-store-card');
            const index = stores.indexOf(selectedStore);
            if (cards[index]) {
                cards[index].classList.add('selected');
            }
        }
    }

    /**
     * Display list of secrets for selected store
     */
    function displaySecretsList(secrets) {
        const secretsContainer = document.getElementById('secretPickerSecretsList');
        if (!secretsContainer) return;

        if (secrets.length === 0) {
            secretsContainer.innerHTML = `
                <div style="padding: 20px; text-align: center; color: #6b7280;">
                    <p>No secrets found in this store.</p>
                </div>
            `;
            return;
        }

        let html = '<div style="display: grid; gap: 10px;">';

        secrets.forEach(secret => {
            const displayName = secret.name || secret.path;
            const displayPath = secret.path || 'N/A';

            html += `
                <div class="secret-picker-secret-item" onclick="SecretPicker.selectSecret('${escapeHtml(secret.path)}')">
                    <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
                        <div style="flex: 1;">
                            <div style="font-weight: 500; color: #1f2937;">${escapeHtml(displayName)}</div>
                            <div style="font-size: 12px; color: #9ca3af; margin-top: 2px; font-family: monospace;">
                                ${escapeHtml(displayPath)}
                            </div>
                        </div>
                        <div style="font-size: 11px; color: #6b7280; white-space: nowrap; margin-left: 12px;">
                            v${secret.version || '1'}
                        </div>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        secretsContainer.innerHTML = html;
    }

    /**
     * Select a specific secret
     */
    function selectSecret(secretPath) {
        if (!selectedStoreId) {
            showError('No store selected');
            return;
        }

        // Create secret reference object
        const secretRef = {
            store_id: selectedStoreId,
            path: secretPath,
            version: 'latest'
        };

        // Callback if provided
        if (currentCallbackFn) {
            try {
                currentCallbackFn(secretRef);
            } catch (error) {
                
            }
        }

        // Update target field if specified
        if (currentTargetField) {
            
            const field = document.getElementById(currentTargetField);
            if (field) {
                
                // Store secret reference in data attribute
                field.setAttribute('data-secret-ref', JSON.stringify(secretRef));
                
                // Display friendly representation
                field.value = `Secret: ${secretPath}`;
                
                field.style.color = '#0ea5e9';
                
                
                
            } else {
                
            }
        }

        // Close modal
        close();

        // Show success message
        showSuccess('Secret selected: ' + secretPath);
    }

    /**
     * Reset UI to initial state
     */
    function resetUI() {
        selectedStoreId = null;

        const storesContainer = document.getElementById('secretPickerStoresList');
        const secretsContainer = document.getElementById('secretPickerSecretsList');

        if (storesContainer) {
            displayStoresList();
        }

        if (secretsContainer) {
            secretsContainer.innerHTML = `
                <div style="padding: 20px; text-align: center; color: #9ca3af;">
                    <p>Select a store to browse its secrets</p>
                </div>
            `;
        }
    }

    /**
     * Show loading indicator
     */
    function showLoading(message = 'Loading...') {
        const indicator = document.getElementById('secretPickerLoading');
        if (indicator) {
            indicator.textContent = message;
            indicator.style.display = 'flex';
        }
    }

    /**
     * Hide loading indicator
     */
    function hideLoading() {
        const indicator = document.getElementById('secretPickerLoading');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    /**
     * Show error message
     */
    function showError(message) {
        const alert = document.getElementById('secretPickerAlert');
        if (alert) {
            alert.className = 'secret-picker-alert alert-error';
            alert.textContent = message;
            alert.style.display = 'block';
        }
    }

    /**
     * Show success message
     */
    function showSuccess(message) {
        const alert = document.getElementById('secretPickerAlert');
        if (alert) {
            alert.className = 'secret-picker-alert alert-success';
            alert.textContent = message;
            alert.style.display = 'block';

            // Auto-hide after 3 seconds
            setTimeout(() => {
                alert.style.display = 'none';
            }, 3000);
        }
    }

    /**
     * HTML escape utility
     */
    function escapeHtml(unsafe) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return unsafe.replace(/[&<>"']/g, m => map[m]);
    }

    // Public API
    return {
        init: init,
        open: open,
        close: close,
        selectStore: selectStore,
        selectSecret: selectSecret
    };
})();

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', () => {
    SecretPicker.init();
});
