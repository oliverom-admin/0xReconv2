/**
 * Secret Stores Management Module
 *
 * Manages the lifecycle of external secret stores (Azure KV, HashiCorp, AWS, Encrypted Files).
 * Handles registration, testing, unlocking, and secret operations.
 */

const SecretStoresManagement = (() => {
    const API_BASE = '/api/secret-stores';
    let currentStore = null;
    let providers = [];

    /**
     * Initialize the secret stores management module
     */
    async function init() {


        // Load provider list
        await loadProviders();

        // Set up event handlers
        setupEventHandlers();

        // Load initial stores list
        await refreshStoresList();

        // Load system vault after stores are displayed
        await displaySystemVaults();
    }

    /**
     * Load available providers from API
     */
    async function loadProviders() {
        try {
            const response = await fetch(`${API_BASE}/providers`);
            const data = await response.json();

            if (data.success) {
                providers = data.providers;
                updateProviderDropdown();
                
            } else {
                showError('Failed to load providers: ' + data.error);
            }
        } catch (error) {
            
            showError('Failed to load providers');
        }
    }

    /**
     * Update provider dropdown in register form
     */
    function updateProviderDropdown() {
        const select = document.getElementById('providerType');
        if (!select) return;

        select.innerHTML = '<option value="">Select a provider...</option>';
        providers.forEach(provider => {
            const option = document.createElement('option');
            option.value = provider.type;
            option.textContent = `${provider.name}${provider.requires_unlock ? ' (requires unlock)' : ''}`;
            select.appendChild(option);
        });
    }

    /**
     * Set up event handlers
     */
    function setupEventHandlers() {
        // Register store form
        const registerBtn = document.getElementById('registerStoreBtn');
        if (registerBtn) {
            registerBtn.addEventListener('click', showRegisterDialog);
        }

        // Initialize vault form
        const initializeBtn = document.getElementById('initializeVaultBtn');
        if (initializeBtn) {
            initializeBtn.addEventListener('click', showInitializeVaultDialog);
        }

        // Provider type change
        const providerSelect = document.getElementById('providerType');
        if (providerSelect) {
            providerSelect.addEventListener('change', updateProviderConfig);
        }

        // Close modals when clicking outside
        const registerModal = document.getElementById('registerStoreModal');
        const secretsModal = document.getElementById('secretsModal');
        const initializeVaultModal = document.getElementById('initializeVaultModal');

        if (registerModal) {
            registerModal.addEventListener('click', (e) => {
                if (e.target === registerModal) {
                    registerModal.style.display = 'none';
                }
            });
        }

        if (secretsModal) {
            secretsModal.addEventListener('click', (e) => {
                if (e.target === secretsModal) {
                    secretsModal.style.display = 'none';
                }
            });
        }

        if (initializeVaultModal) {
            initializeVaultModal.addEventListener('click', (e) => {
                if (e.target === initializeVaultModal) {
                    initializeVaultModal.style.display = 'none';
                }
            });
        }
    }

    /**
     * Show register dialog
     */
    function showRegisterDialog() {
        const modal = document.getElementById('registerStoreModal');
        if (modal) {
            modal.style.display = 'flex';
            resetRegisterForm();
        }
    }

    /**
     * Hide register dialog
     */
    function hideRegisterDialog() {
        const modal = document.getElementById('registerStoreModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    /**
     * Reset register form
     */
    function resetRegisterForm() {
        const form = document.getElementById('registerStoreForm');
        if (form) {
            form.reset();
        }
        updateProviderConfig();
    }

    /**
     * Update provider configuration form based on selected provider
     */
    function updateProviderConfig() {
        const providerType = document.getElementById('providerType')?.value;
        const configFields = document.getElementById('providerConfigFields');

        if (!configFields) return;

        // Clear previous fields
        configFields.innerHTML = '';

        if (!providerType) return;

        const provider = providers.find(p => p.type === providerType);
        if (!provider) return;

        // Add provider-specific fields
        switch (providerType) {
            case 'azure_key_vault':
                addAzureFields(configFields);
                break;
            case 'hashicorp_vault':
                addHashiCorpFields(configFields);
                break;
            case 'aws_secrets_manager':
                addAWSFields(configFields);
                break;
            case 'encrypted_file':
                addEncryptedFileFields(configFields);
                break;
        }
    }

    /**
     * Add Azure Key Vault configuration fields
     */
    function addAzureFields(container) {
        container.innerHTML = `
            <div class="form-group">
                <label for="vaultUrl">Vault URL *</label>
                <input type="text" id="vaultUrl" class="form-control" placeholder="https://myvault.vault.azure.net/" required>
            </div>
            <div class="form-group">
                <label for="authMethod">Authentication Method *</label>
                <select id="authMethod" class="form-control" onchange="updateAzureAuthFields()">
                    <option value="managed_identity">Managed Identity (Recommended)</option>
                    <option value="service_principal">Service Principal</option>
                    <option value="default">Default Credentials</option>
                </select>
            </div>
            <div id="azureAuthFields"></div>
        `;
        updateAzureAuthFields();
    }

    /**
     * Update Azure auth method specific fields
     */
    window.updateAzureAuthFields = function() {
        const method = document.getElementById('authMethod')?.value;
        const fieldsDiv = document.getElementById('azureAuthFields');

        if (!fieldsDiv) return;

        fieldsDiv.innerHTML = '';

        if (method === 'service_principal') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="clientId">Client ID *</label>
                    <input type="text" id="clientId" class="form-control" placeholder="00000000-0000-0000-0000-000000000000" required>
                </div>
                <div class="form-group">
                    <label for="clientSecret">Client Secret *</label>
                    <input type="password" id="clientSecret" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="tenantId">Tenant ID *</label>
                    <input type="text" id="tenantId" class="form-control" placeholder="00000000-0000-0000-0000-000000000000" required>
                </div>
            `;
        }
    };

    /**
     * Add HashiCorp Vault configuration fields
     */
    function addHashiCorpFields(container) {
        container.innerHTML = `
            <div class="form-group">
                <label for="vaultAddress">Vault Address *</label>
                <input type="text" id="vaultAddress" class="form-control" placeholder="https://vault.example.com:8200" required>
            </div>
            <div class="form-group">
                <label for="secretEnginePath">Secret Engine Path</label>
                <input type="text" id="secretEnginePath" class="form-control" placeholder="secret" value="secret">
            </div>
            <div class="form-group">
                <label for="vaultAuthMethod">Authentication Method *</label>
                <select id="vaultAuthMethod" class="form-control" onchange="updateHashiCorpAuthFields()">
                    <option value="token">Token</option>
                    <option value="approle">AppRole</option>
                    <option value="userpass">Username/Password</option>
                </select>
            </div>
            <div id="hashiCorpAuthFields"></div>
        `;
        updateHashiCorpAuthFields();
    }

    /**
     * Update HashiCorp auth method specific fields
     */
    window.updateHashiCorpAuthFields = function() {
        const method = document.getElementById('vaultAuthMethod')?.value;
        const fieldsDiv = document.getElementById('hashiCorpAuthFields');

        if (!fieldsDiv) return;

        fieldsDiv.innerHTML = '';

        if (method === 'token') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="vaultToken">Token *</label>
                    <input type="password" id="vaultToken" class="form-control" required>
                </div>
            `;
        } else if (method === 'approle') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="roleId">Role ID *</label>
                    <input type="text" id="roleId" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="secretId">Secret ID *</label>
                    <input type="password" id="secretId" class="form-control" required>
                </div>
            `;
        } else if (method === 'userpass') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="vaultUsername">Username *</label>
                    <input type="text" id="vaultUsername" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="vaultPassword">Password *</label>
                    <input type="password" id="vaultPassword" class="form-control" required>
                </div>
            `;
        }
    };

    /**
     * Add AWS Secrets Manager configuration fields
     */
    function addAWSFields(container) {
        container.innerHTML = `
            <div class="form-group">
                <label for="awsRegion">AWS Region *</label>
                <input type="text" id="awsRegion" class="form-control" placeholder="us-east-1" value="us-east-1" required>
            </div>
            <div class="form-group">
                <label for="awsAuthMethod">Authentication Method *</label>
                <select id="awsAuthMethod" class="form-control" onchange="updateAWSAuthFields()">
                    <option value="role">IAM Role (Recommended)</option>
                    <option value="credentials">Access Keys</option>
                </select>
            </div>
            <div id="awsAuthFields"></div>
        `;
        updateAWSAuthFields();
    }

    /**
     * Update AWS auth method specific fields
     */
    window.updateAWSAuthFields = function() {
        const method = document.getElementById('awsAuthMethod')?.value;
        const fieldsDiv = document.getElementById('awsAuthFields');

        if (!fieldsDiv) return;

        fieldsDiv.innerHTML = '';

        if (method === 'credentials') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="awsAccessKeyId">Access Key ID *</label>
                    <input type="text" id="awsAccessKeyId" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="awsSecretAccessKey">Secret Access Key *</label>
                    <input type="password" id="awsSecretAccessKey" class="form-control" required>
                </div>
                <div class="form-group">
                    <label for="awsSessionToken">Session Token (Optional)</label>
                    <input type="password" id="awsSessionToken" class="form-control">
                </div>
            `;
        }
    };

    /**
     * Add Encrypted File configuration fields
     */
    function addEncryptedFileFields(container) {
        container.innerHTML = `
            <div class="form-group">
                <label for="vaultFilePath">Vault File Path *</label>
                <input type="text" id="vaultFilePath" class="form-control" placeholder="/path/to/secrets.enc" required>
                <small class="form-text text-muted">Path to age-encrypted vault file (must exist)</small>
            </div>
            <div class="form-group">
                <label for="unlockMethod">Unlock Method *</label>
                <select id="unlockMethod" class="form-control" onchange="updateEncryptedFileFields()">
                    <option value="passphrase">Passphrase</option>
                    <option value="key_file">Key File</option>
                </select>
            </div>
            <div id="encryptedFileAuthFields"></div>
            <div class="alert alert-info">
                <small>
                    <strong>Security Note:</strong> Passphrases are used only during unlock and are never stored by CAIP.
                    Leave passphrase blank to be prompted during unlock.
                </small>
            </div>
        `;
        updateEncryptedFileFields();
    }

    /**
     * Update encrypted file auth method specific fields
     */
    window.updateEncryptedFileFields = function() {
        const method = document.getElementById('unlockMethod')?.value;
        const fieldsDiv = document.getElementById('encryptedFileAuthFields');

        if (!fieldsDiv) return;

        fieldsDiv.innerHTML = '';

        if (method === 'passphrase') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="vaultPassphrase">Passphrase (Optional)</label>
                    <input type="password" id="vaultPassphrase" class="form-control" placeholder="Leave blank to be prompted later">
                    <small class="form-text text-muted">If provided, will be used for automatic unlocking. Otherwise you'll be prompted when needed.</small>
                </div>
            `;
        } else if (method === 'key_file') {
            fieldsDiv.innerHTML = `
                <div class="form-group">
                    <label for="keyFilePath">Age Key File Path *</label>
                    <input type="text" id="keyFilePath" class="form-control" placeholder="/path/to/age-key" required>
                    <small class="form-text text-muted">Path to age encryption key file</small>
                </div>
            `;
        }
    };

    /**
     * Register a new secret store
     */
    async function registerStore() {
        const name = document.getElementById('storeName')?.value;
        const providerType = document.getElementById('providerType')?.value;

        if (!name || !providerType) {
            showError('Please fill in all required fields');
            return;
        }

        const config = buildProviderConfig(providerType);

        if (!config) {
            showError('Please fill in all required provider fields');
            return;
        }

        try {
            showLoading('Registering store...');

            const response = await fetch(API_BASE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name,
                    provider_type: providerType,
                    config: config
                })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showSuccess(`Store '${name}' registered successfully`);
                hideRegisterDialog();
                await refreshStoresList();
            } else {
                showError('Failed to register store: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            
            showError('Error registering store: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    /**
     * Build provider configuration from form fields
     */
    function buildProviderConfig(providerType) {
        const config = {};

        switch (providerType) {
            case 'azure_key_vault':
                config.vault_url = document.getElementById('vaultUrl')?.value;
                config.auth_method = document.getElementById('authMethod')?.value || 'managed_identity';

                if (config.auth_method === 'service_principal') {
                    const clientId = document.getElementById('clientId')?.value;
                    const clientSecret = document.getElementById('clientSecret')?.value;
                    const tenantId = document.getElementById('tenantId')?.value;

                    if (!clientId || !clientSecret || !tenantId) {
                        return null;
                    }

                    // Use "value" source pattern for direct credential values
                    config.client_id_source = 'value';
                    config.client_id_value = clientId;

                    config.client_secret_source = 'value';
                    config.client_secret_value = clientSecret;

                    config.tenant_id_source = 'value';
                    config.tenant_id_value = tenantId;
                }
                break;

            case 'hashicorp_vault':
                config.vault_url = document.getElementById('vaultAddress')?.value;
                config.secret_engine_path = document.getElementById('secretEnginePath')?.value || 'secret';
                config.auth_method = document.getElementById('vaultAuthMethod')?.value || 'token';

                if (config.auth_method === 'token') {
                    const token = document.getElementById('vaultToken')?.value;
                    if (!token) return null;
                    config.token_source = 'value';
                    config.token_value = token;
                } else if (config.auth_method === 'approle') {
                    const roleId = document.getElementById('roleId')?.value;
                    const secretId = document.getElementById('secretId')?.value;
                    if (!roleId || !secretId) return null;
                    config.role_id_source = 'value';
                    config.role_id_value = roleId;
                    config.secret_id_source = 'value';
                    config.secret_id_value = secretId;
                } else if (config.auth_method === 'userpass') {
                    const username = document.getElementById('vaultUsername')?.value;
                    const password = document.getElementById('vaultPassword')?.value;
                    if (!username || !password) return null;
                    config.username_source = 'value';
                    config.username_value = username;
                    config.password_source = 'value';
                    config.password_value = password;
                }
                break;

            case 'aws_secrets_manager':
                config.region = document.getElementById('awsRegion')?.value || 'us-east-1';
                config.auth_method = document.getElementById('awsAuthMethod')?.value || 'role';

                if (config.auth_method === 'credentials') {
                    const accessKeyId = document.getElementById('awsAccessKeyId')?.value;
                    const secretAccessKey = document.getElementById('awsSecretAccessKey')?.value;
                    const sessionToken = document.getElementById('awsSessionToken')?.value;

                    if (!accessKeyId || !secretAccessKey) {
                        return null;
                    }

                    config.access_key_id_source = 'value';
                    config.access_key_id_value = accessKeyId;
                    config.secret_access_key_source = 'value';
                    config.secret_access_key_value = secretAccessKey;
                    if (sessionToken) {
                        config.session_token_source = 'value';
                        config.session_token_value = sessionToken;
                    }
                }
                break;

            case 'encrypted_file':
                config.vault_file_path = document.getElementById('vaultFilePath')?.value;
                config.unlock_method = document.getElementById('unlockMethod')?.value || 'passphrase';

                if (!config.vault_file_path) {
                    return null;
                }

                if (config.unlock_method === 'passphrase') {
                    const passphrase = document.getElementById('vaultPassphrase')?.value;
                    // Passphrase is optional - if not provided, user will be prompted during unlock
                    if (passphrase) {
                        config.passphrase_source = 'value';
                        config.passphrase_value = passphrase;
                    } else {
                        config.passphrase_source = 'prompt'; // User will be prompted during unlock
                    }
                } else if (config.unlock_method === 'key_file') {
                    const keyFilePath = document.getElementById('keyFilePath')?.value;
                    if (!keyFilePath) {
                        return null; // Key file is required when using key_file method
                    }
                    config.key_file_path = keyFilePath;
                }
                break;
        }

        return config;
    }

    /**
     * Refresh stores list
     */
    async function refreshStoresList() {
        try {
            const response = await fetch(API_BASE);
            const data = await response.json();

            if (data.success) {
                displayStores(data.stores);
            } else {
                showError('Failed to load stores: ' + data.error);
            }
        } catch (error) {
            
            showError('Error loading stores');
        }
    }

    /**
     * Display stores in the UI
     */
    function displayStores(stores) {
        const container = document.getElementById('storesContainer');
        if (!container) return;

        if (stores.length === 0) {
            container.innerHTML = '<p class="text-muted">No secret stores registered yet. Register one to get started.</p>';
            return;
        }

        container.innerHTML = stores.map(store => createStoreCard(store)).join('');

        // Add event listeners to store cards
        stores.forEach(store => {
            addStoreCardListeners(store.id);
        });
    }

    /**
     * Create HTML card for a store with professional styling
     */
    function createStoreCard(store) {
        // Determine status badge colors
        let statusBgColor = 'rgba(239, 68, 68, 0.1)';  // Red for default
        let statusBorderColor = '#ef4444';
        let statusTextColor = '#ef4444';
        let statusIcon = '⚠️';

        if (store.status === 'active') {
            statusBgColor = 'rgba(16, 185, 129, 0.1)';  // Green
            statusBorderColor = '#10b981';
            statusTextColor = '#10b981';
            statusIcon = '✓';
        } else if (store.status === 'error') {
            statusBgColor = 'rgba(239, 68, 68, 0.1)';  // Red
            statusBorderColor = '#ef4444';
            statusTextColor = '#ef4444';
            statusIcon = '✕';
        } else if (store.status === 'locked') {
            statusBgColor = 'rgba(245, 158, 11, 0.1)';  // Orange
            statusBorderColor = '#f59e0b';
            statusTextColor = '#f59e0b';
            statusIcon = '🔒';
        }

        const secretCount = store.secret_count !== null ? `${store.secret_count}` : 'N/A';

        // Build action buttons
        let actionButtons = '';

        // Test button
        actionButtons += `
            <button onclick="SecretStoresManagement.testStore('${store.id}')"
                style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                🧪 Test
            </button>
        `;

        // Secrets button
        actionButtons += `
            <button onclick="SecretStoresManagement.viewSecrets('${store.id}')"
                style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                🔑 Secrets
            </button>
        `;

        // Unlock button (only for encrypted files that are locked)
        if (store.requires_unlock && !store.is_unlocked) {
            actionButtons += `
                <button onclick="SecretStoresManagement.showUnlockDialog('${store.id}')"
                    style="padding: 6px 12px; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; border: none; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500; box-shadow: 0 2px 8px rgba(245, 158, 11, 0.3);">
                    🔓 Unlock
                </button>
            `;
        }

        // Lock button (only for encrypted files that are unlocked)
        if (store.requires_unlock && store.is_unlocked) {
            actionButtons += `
                <button onclick="SecretStoresManagement.showLockConfirmModal('${store.id}')"
                    style="padding: 6px 12px; background: white; color: #ef4444; border: 1px solid #fecaca; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                    🔒 Lock
                </button>
            `;
        }

        // Delete button
        actionButtons += `
            <button onclick="SecretStoresManagement.deleteStore('${store.id}')"
                style="padding: 6px 12px; background: white; color: #dc2626; border: 1px solid #fecaca; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                🗑️ Delete
            </button>
        `;

        return `
            <div data-store-id="${store.id}" style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <!-- Header with gradient background -->
                <div style="padding: 20px 24px; background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;">
                    <div style="flex: 1;">
                        <div style="font-size: 18px; font-weight: 700; color: #1f2937; margin-bottom: 4px;">${escapeHtml(store.name)}</div>
                        <div style="font-size: 13px; color: #6b7280; display: flex; align-items: center; gap: 8px;">
                            <span>${store.provider_type === 'encrypted_file' ? '📄' : '☁️'}</span>
                            <span style="text-transform: capitalize;">${store.provider_type.replace(/_/g, ' ')}</span>
                        </div>
                    </div>
                    <div style="background: ${statusBgColor}; border: 1.5px solid ${statusBorderColor}; border-radius: 8px; padding: 8px 16px; text-align: center; flex-shrink: 0;">
                        <div style="font-size: 12px; font-weight: 600; color: ${statusTextColor};">${statusIcon} ${store.status.toUpperCase()}</div>
                    </div>
                </div>

                <!-- Details section -->
                <div style="padding: 20px 24px; border-bottom: 1px solid #e5e7eb;">
                    <div style="display: grid; grid-template-columns: auto 1fr; gap: 16px 24px; font-size: 14px;">
                        <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Secrets</div>
                        <div style="color: #1f2937; font-weight: 500;">${secretCount}</div>

                        <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Details</div>
                        <div style="color: #4b5563; line-height: 1.5;">${store.status_message || 'No details available'}</div>

                        ${store.connection_config?.vault_file_path ? `
                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Address</div>
                            <div style="color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; font-size: 12px; word-break: break-all;">${escapeHtml(store.connection_config.vault_file_path)}</div>
                        ` : ''}

                        ${store.connection_config?.vault_url ? `
                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Address</div>
                            <div style="color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; font-size: 12px; word-break: break-all;">${escapeHtml(store.connection_config.vault_url)}</div>
                        ` : ''}

                        ${store.last_verified_at ? `
                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Last Verified</div>
                            <div style="color: #4b5563;">${new Date(store.last_verified_at).toLocaleString()}</div>
                        ` : ''}
                    </div>
                </div>

                <!-- Action buttons -->
                <div style="padding: 16px 24px; background: #f9fafb; border-top: 1px solid #e5e7eb; display: flex; gap: 8px; flex-wrap: wrap;">
                    ${actionButtons}
                </div>
            </div>
        `;
    }

    /**
     * Add event listeners to store card
     */
    function addStoreCardListeners(storeId) {
        // Could add additional listeners here
    }

    /**
     * Test store connection
     */
    async function testStore(storeId) {
        try {
            showLoading('Testing connection...');

            const response = await fetch(`${API_BASE}/${storeId}/test`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                if (data.connected) {
                    showSuccess(`Connection successful. Secrets available: ${data.secret_count || 'N/A'}`);
                    await refreshStoresList();
                } else {
                    showError(`Connection failed: ${data.message}`);
                }
            } else {
                showError('Test failed: ' + data.error);
            }
        } catch (error) {
            
            showError('Error testing store: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    /**
     * View secrets in a store
     */
    async function viewSecrets(storeId) {
        try {
            showLoading('Loading secrets...');

            const response = await fetch(`${API_BASE}/${storeId}/secrets`);
            const data = await response.json();

            if (response.ok && data.success) {
                displaySecretsDialog(storeId, data.secrets || []);
            } else {
                const errorMsg = data.error || 'Failed to load secrets';
                showError('Failed to load secrets: ' + errorMsg);
            }
        } catch (error) {
            
            showError('Error loading secrets: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    /**
     * Display secrets in a modal
     */
    function displaySecretsDialog(storeId, secrets) {
        const modal = document.getElementById('secretsModal');
        if (!modal) return;

        let content = '';

        if (secrets.length === 0) {
            content = '<p style="color: #6b7280; text-align: center; padding: 20px;">No secrets found in this store.</p>';
        } else {
            content = '<div style="display: grid; gap: 12px;">';
            secrets.forEach(secret => {
                content += `
                    <div style="padding: 16px; border-left: 4px solid #667eea; background: #f9fafb; border-radius: 8px;">
                        <div style="font-weight: 600; color: #1f2937; font-size: 15px;">${escapeHtml(secret.name)}</div>
                        <div style="color: #6b7280; font-size: 13px; margin-top: 4px;">${escapeHtml(secret.path)}</div>
                    </div>
                `;
            });
            content += '</div>';
        }

        const modalBody = modal.querySelector('.modal-body');
        if (modalBody) {
            const secretsContent = modalBody.querySelector('#secretsContent');
            if (secretsContent) {
                secretsContent.innerHTML = content;
            }
            modal.style.display = 'flex';
        }

        hideLoading();
    }

    /**
     * Show unlock dialog for encrypted stores
     */
    function showUnlockDialog(storeId) {
        const store = document.querySelector(`[data-store-id="${storeId}"]`);
        if (!store) return;

        const storeName = store.querySelector('.card-title')?.textContent || 'Store';
        const unlockMethod = store.querySelector('[data-unlock-method]')?.dataset.unlockMethod || 'passphrase';

        let modalContent = `
            <div style="background: white; border-radius: 12px; padding: 32px; max-width: 500px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.3);">
                <div style="text-align: center; margin-bottom: 28px;">
                    <div style="font-size: 32px; margin-bottom: 12px;">🔓</div>
                    <h2 style="margin: 0 0 8px 0; color: #1f2937;">Unlock Vault</h2>
                    <p style="margin: 0; color: #6b7280; font-size: 14px;">${escapeHtml(storeName)}</p>
                </div>

                <div id="unlockAlert" style="display: none; padding: 12px; border-radius: 6px; margin-bottom: 20px; border-left: 4px solid #ef4444;"></div>

                <form id="unlockForm" onsubmit="SecretStoresManagement.submitUnlock('${storeId}'); return false;">
        `;

        if (unlockMethod === 'passphrase') {
            modalContent += `
                    <div class="form-group">
                        <label for="unlockPassphrase" style="display: block; font-weight: 600; margin-bottom: 8px; color: #374151;">Passphrase</label>
                        <input type="password" id="unlockPassphrase" required style="width: 100%; padding: 12px 16px; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 14px; box-sizing: border-box;">
                    </div>
            `;
        } else if (unlockMethod === 'key_file') {
            modalContent += `
                    <div class="form-group">
                        <label for="unlockKeyFile" style="display: block; font-weight: 600; margin-bottom: 8px; color: #374151;">Key File Path</label>
                        <input type="text" id="unlockKeyFile" placeholder="/path/to/age-key" required style="width: 100%; padding: 12px 16px; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 14px; box-sizing: border-box;">
                    </div>
            `;
        }

        modalContent += `
                    <div style="display: flex; gap: 12px; margin-top: 28px;">
                        <button type="submit" style="flex: 1; padding: 12px 24px; background: #0ea5e9; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 14px;">
                            Unlock
                        </button>
                        <button type="button" onclick="SecretStoresManagement.closeUnlockDialog()" style="flex: 1; padding: 12px 24px; background: #e5e7eb; color: #374151; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 14px;">
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        `;

        // Create overlay modal
        let modal = document.getElementById('unlockVaultModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'unlockVaultModal';
            modal.style.position = 'fixed';
            modal.style.top = '0';
            modal.style.left = '0';
            modal.style.width = '100%';
            modal.style.height = '100%';
            modal.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
            modal.style.display = 'flex';
            modal.style.alignItems = 'center';
            modal.style.justifyContent = 'center';
            modal.style.zIndex = '9999';
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    SecretStoresManagement.closeUnlockDialog();
                }
            });
            document.body.appendChild(modal);
        }

        modal.innerHTML = modalContent;
        modal.style.display = 'flex';
        modal.dataset.storeId = storeId;
        modal.dataset.unlockMethod = unlockMethod;

        // Focus on input
        const input = modal.querySelector('input[type="password"], input[type="text"]');
        if (input) {
            setTimeout(() => input.focus(), 100);
        }
    }

    /**
     * Close unlock dialog
     */
    window.closeUnlockDialog = function() {
        const modal = document.getElementById('unlockVaultModal');
        if (modal) {
            modal.style.display = 'none';
        }
    };

    /**
     * Submit unlock request
     */
    window.submitUnlock = function(storeId) {
        const modal = document.getElementById('unlockVaultModal');
        if (!modal) return;

        const unlockMethod = modal.dataset.unlockMethod;
        let passphrase = null;
        let keyFile = null;

        if (unlockMethod === 'passphrase') {
            passphrase = document.getElementById('unlockPassphrase')?.value;
            if (!passphrase) {
                showUnlockError('Please enter a passphrase');
                return;
            }
        } else if (unlockMethod === 'key_file') {
            keyFile = document.getElementById('unlockKeyFile')?.value;
            if (!keyFile) {
                showUnlockError('Please enter the key file path');
                return;
            }
        }

        performUnlock(storeId, passphrase, keyFile);
    };

    /**
     * Perform unlock API call
     */
    async function performUnlock(storeId, passphrase, keyFile) {
        try {
            const alert = document.getElementById('unlockAlert');
            if (alert) {
                alert.style.display = 'none';
            }

            showLoading('Unlocking vault...');

            const payload = {};
            if (passphrase) {
                payload.passphrase = passphrase;
            }
            if (keyFile) {
                payload.key_file = keyFile;
            }

            const response = await fetch(`${API_BASE}/${storeId}/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showSuccess('Vault unlocked successfully');
                SecretStoresManagement.closeUnlockDialog();
                await refreshStoresList();
            } else {
                showUnlockError(data.error || 'Failed to unlock vault');
            }
        } catch (error) {
            
            showUnlockError('Error unlocking vault: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    /**
     * Show error in unlock dialog
     */
    function showUnlockError(message) {
        const alert = document.getElementById('unlockAlert');
        if (alert) {
            alert.textContent = message;
            alert.style.backgroundColor = '#fee2e2';
            alert.style.borderLeftColor = '#ef4444';
            alert.style.color = '#991b1b';
            alert.style.display = 'block';
        }
    }

    /**
     * Delete a store
     */
    async function deleteStore(storeId) {
        if (!confirm('Are you sure you want to delete this store registration? (The actual vault will not be deleted)')) {
            return;
        }

        try {
            showLoading('Deleting store...');

            const response = await fetch(`${API_BASE}/${storeId}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showSuccess('Store deleted successfully');
                await refreshStoresList();
            } else {
                showError('Failed to delete store: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {

            showError('Error deleting store: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    /**
     * Show lock confirmation modal for a vault
     */
    function showLockConfirmModal(storeId) {
        // Create modal container
        const modal_div = document.createElement('div');
        modal_div.id = 'lockConfirmModal';
        modal_div.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.8); backdrop-filter: blur(4px); z-index: 2000; display: flex; align-items: center; justify-content: center; pointer-events: auto;';

        // Create content
        const content = document.createElement('div');
        content.style.cssText = 'max-width: 500px; background: white; border-radius: 12px; box-shadow: 0 20px 25px rgba(0,0,0,0.15); display: flex; flex-direction: column; position: relative;';

        // Create header with warning color
        const header = document.createElement('div');
        header.style.cssText = 'padding: 24px; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; flex-shrink: 0; display: flex; justify-content: space-between; align-items: center;';

        const title = document.createElement('h2');
        title.textContent = 'Lock Vault';
        title.style.cssText = 'margin: 0; font-size: 22px; font-weight: 700; color: white;';

        const closeBtn = document.createElement('button');
        closeBtn.textContent = '×';
        closeBtn.style.cssText = 'background: none; border: none; font-size: 28px; color: white; cursor: pointer; padding: 0; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; transition: all 0.2s; opacity: 0.9;';

        header.appendChild(title);
        header.appendChild(closeBtn);

        // Create body
        const body = document.createElement('div');
        body.style.cssText = 'padding: 32px; flex: 1;';

        const icon = document.createElement('div');
        icon.textContent = '🔒';
        icon.style.cssText = 'font-size: 48px; text-align: center; margin-bottom: 16px;';

        const heading = document.createElement('h3');
        heading.textContent = 'Lock This Vault?';
        heading.style.cssText = 'margin: 0 0 12px 0; text-align: center; color: #1f2937; font-size: 18px; font-weight: 700;';

        const description = document.createElement('p');
        description.textContent = 'You will need to enter the passphrase again to access secrets in this vault.';
        description.style.cssText = 'margin: 0 0 20px 0; text-align: center; color: #6b7280; font-size: 14px; line-height: 1.6;';

        const warning = document.createElement('div');
        warning.style.cssText = 'background: rgba(245, 158, 11, 0.1); border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 6px; color: #92400e; font-size: 13px;';
        warning.innerHTML = '<strong>Note:</strong> Vault will be locked immediately and secrets will not be accessible.';

        body.appendChild(icon);
        body.appendChild(heading);
        body.appendChild(description);
        body.appendChild(warning);

        // Create footer
        const footer = document.createElement('div');
        footer.style.cssText = 'padding: 20px 32px; border-top: 1px solid #e5e7eb; background: #f9fafb; display: flex; justify-content: flex-end; gap: 12px; flex-shrink: 0;';

        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = 'padding: 10px 24px; background: white; color: #374151; border: 1.5px solid #d1d5db; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;';

        const lockBtn = document.createElement('button');
        lockBtn.textContent = 'Lock Vault';
        lockBtn.style.cssText = 'padding: 10px 24px; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;';

        footer.appendChild(cancelBtn);
        footer.appendChild(lockBtn);

        // Assemble modal
        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        modal_div.appendChild(content);

        // Append to document
        document.documentElement.appendChild(modal_div);

        // Add event listeners
        const removeModal = () => {
            if (modal_div && modal_div.parentElement) {
                modal_div.remove();
            }
        };

        closeBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            removeModal();
        });

        cancelBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            removeModal();
        });

        lockBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            removeModal();
            await lockStore(storeId);
        });
    }

    /**
     * Lock a vault (for encrypted file stores)
     */
    async function lockStore(storeId) {
        try {
            showLoading('Locking vault...');

            const response = await fetch(`${API_BASE}/${storeId}/lock`, {
                method: 'POST'
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showSuccess('Vault locked successfully');
                await refreshStoresList();
            } else {
                showError('Failed to lock vault: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            showError('Error locking vault: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    /**
     * Escape HTML special characters
     */
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    /**
     * Show loading indicator (both in modal and global)
     */
    function showLoading(message) {
        // Show in modal if it's open
        const registerModal = document.getElementById('registerStoreModal');
        if (registerModal && registerModal.style.display === 'flex') {
            const modalLoader = document.getElementById('registerStoreLoading');
            if (modalLoader) {
                const loaderText = document.getElementById('registerStoreLoadingText');
                if (loaderText) {
                    loaderText.textContent = message || 'Processing...';
                }
                modalLoader.style.display = 'flex';
            }
        } else {
            // Show in global loader if modal not open
            const loader = document.getElementById('loadingIndicator');
            if (loader) {
                loader.textContent = message || 'Loading...';
                loader.style.display = 'block';
            }
        }
    }

    /**
     * Hide loading indicator (both in modal and global)
     */
    function hideLoading() {
        // Hide modal loader if modal is open
        const registerModal = document.getElementById('registerStoreModal');
        if (registerModal && registerModal.style.display === 'flex') {
            const modalLoader = document.getElementById('registerStoreLoading');
            if (modalLoader) {
                modalLoader.style.display = 'none';
            }
        } else {
            // Hide global loader if modal not open
            const loader = document.getElementById('loadingIndicator');
            if (loader) {
                loader.style.display = 'none';
            }
        }
    }

    /**
     * Show error message (both in modal and global alert)
     */
    function showError(message) {
        // Show in modal if it's open
        const registerModal = document.getElementById('registerStoreModal');
        if (registerModal && registerModal.style.display === 'flex') {
            const modalAlert = document.getElementById('registerStoreAlert');
            if (modalAlert) {
                modalAlert.className = '';
                modalAlert.style.backgroundColor = '#fee2e2';
                modalAlert.style.borderLeftColor = '#ef4444';
                modalAlert.style.color = '#991b1b';
                modalAlert.textContent = message;
                modalAlert.style.display = 'block';

                // Auto-dismiss after 5 seconds
                clearTimeout(modalAlert.dismissTimeout);
                modalAlert.dismissTimeout = setTimeout(() => {
                    modalAlert.style.display = 'none';
                }, 5000);
            }
        } else {
            // Show in global alert if modal not open
            const alert = document.getElementById('alertMessage');
            if (alert) {
                alert.className = 'alert alert-danger';
                alert.textContent = message;
                alert.style.display = 'block';

                // Auto-dismiss after 5 seconds
                clearTimeout(alert.dismissTimeout);
                alert.dismissTimeout = setTimeout(() => {
                    alert.style.display = 'none';
                }, 5000);
            }
        }
    }

    /**
     * Show initialize vault dialog
     */
    function showInitializeVaultDialog() {
        const modal = document.getElementById('initializeVaultModal');
        if (modal) {
            modal.style.display = 'flex';
            document.getElementById('initializeVaultForm').reset();
            document.getElementById('initVaultAutoRegister').checked = true;
            document.getElementById('initializeVaultAlert').style.display = 'none';
            // Show vault name field when dialog opens (since auto-register is checked by default)
            toggleVaultNameField();
        }
    }

    /**
     * Initialize a new encrypted file vault
     */
    window.closeInitializeVaultDialog = function() {
        const modal = document.getElementById('initializeVaultModal');
        if (modal) {
            modal.style.display = 'none';
        }
    };

    function initializeVault() {
        const filePath = document.getElementById('initVaultFilePath')?.value;
        const passphrase = document.getElementById('initVaultPassphrase')?.value;
        const passphraseConfirm = document.getElementById('initVaultPassphraseConfirm')?.value;
        const autoRegister = document.getElementById('initVaultAutoRegister')?.checked;
        const vaultName = document.getElementById('initVaultName')?.value;

        // Validation
        if (!filePath) {
            showInitializeVaultError('Vault file path is required');
            return;
        }

        if (!passphrase) {
            showInitializeVaultError('Passphrase is required');
            return;
        }

        if (passphrase !== passphraseConfirm) {
            showInitializeVaultError('Passphrases do not match');
            return;
        }

        if (passphrase.length < 8) {
            showInitializeVaultError('Passphrase must be at least 8 characters');
            return;
        }

        if (autoRegister && !vaultName) {
            showInitializeVaultError('Vault name is required when auto-registering');
            return;
        }

        performInitializeVault(filePath, passphrase, autoRegister, vaultName);
    }

    /**
     * Perform the vault initialization API call
     */
    async function performInitializeVault(filePath, passphrase, autoRegister, vaultName) {
        try {
            // Show loading
            document.getElementById('initializeVaultLoading').style.display = 'flex';
            document.getElementById('initializeVaultAlert').style.display = 'none';

            const response = await fetch(`${API_BASE}/encrypted-file/initialize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    vault_file_path: filePath,
                    passphrase: passphrase
                })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                // Vault created successfully
                showInitializeVaultSuccess(`Vault created successfully at ${filePath}`);

                if (autoRegister) {
                    // Auto-register the vault with the provided name
                    await autoRegisterVault(filePath, passphrase, vaultName);
                } else {
                    // Just close and refresh
                    setTimeout(() => {
                        closeInitializeVaultDialog();
                        refreshStoresList();
                    }, 1500);
                }
            } else {
                showInitializeVaultError(data.error || 'Failed to initialize vault');
            }
        } catch (error) {
            
            showInitializeVaultError('Error initializing vault: ' + error.message);
        } finally {
            document.getElementById('initializeVaultLoading').style.display = 'none';
        }
    }

    /**
     * Auto-register the newly initialized vault
     */
    async function autoRegisterVault(filePath, passphrase, vaultName) {
        try {
            document.getElementById('initializeVaultLoadingText').textContent = 'Registering vault...';
            document.getElementById('initializeVaultLoading').style.display = 'flex';

            // Register the vault using the standard registration flow
            const registerResponse = await fetch(`${API_BASE}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: vaultName || `Encrypted Vault - ${new Date().toLocaleString()}`,
                    provider_type: 'encrypted_file',
                    config: {
                        vault_file_path: filePath,
                        unlock_method: 'passphrase',
                        passphrase_source: 'value',
                        passphrase_value: passphrase
                    }
                })
            });

            const registerData = await registerResponse.json();

            if (registerResponse.ok && registerData.success) {
                showInitializeVaultSuccess('Vault initialized and registered successfully!');
                setTimeout(() => {
                    closeInitializeVaultDialog();
                    refreshStoresList();
                    // Also refresh the vault file manager's dropdown list
                    if (window.vaultFileManager) {
                        window.vaultFileManager.refreshVaultList();
                    }
                }, 1500);
            } else {
                // Vault was created but registration failed
                showInitializeVaultError(`Vault created but registration failed: ${registerData.error || 'Unknown error'}`);
            }
        } catch (error) {
            
            showInitializeVaultError(`Vault created but registration failed: ${error.message}`);
        } finally {
            document.getElementById('initializeVaultLoading').style.display = 'none';
            document.getElementById('initializeVaultLoadingText').textContent = 'Creating vault...';
        }
    }

    /**
     * Show error in initialize vault dialog
     */
    function showInitializeVaultError(message) {
        const alert = document.getElementById('initializeVaultAlert');
        if (alert) {
            alert.textContent = message;
            alert.style.backgroundColor = '#fee2e2';
            alert.style.borderLeftColor = '#ef4444';
            alert.style.color = '#991b1b';
            alert.style.display = 'block';
        }
    }

    /**
     * Show success in initialize vault dialog
     */
    function showInitializeVaultSuccess(message) {
        const alert = document.getElementById('initializeVaultAlert');
        if (alert) {
            alert.textContent = message;
            alert.style.backgroundColor = '#d1fae5';
            alert.style.borderLeftColor = '#10b981';
            alert.style.color = '#047857';
            alert.style.display = 'block';
        }
    }

    /**
     * Show success message (both in modal and global alert)
     */
    function showSuccess(message) {
        // Show in modal if it's open
        const registerModal = document.getElementById('registerStoreModal');
        if (registerModal && registerModal.style.display === 'flex') {
            const modalAlert = document.getElementById('registerStoreAlert');
            if (modalAlert) {
                modalAlert.className = '';
                modalAlert.style.backgroundColor = '#d1fae5';
                modalAlert.style.borderLeftColor = '#10b981';
                modalAlert.style.color = '#047857';
                modalAlert.textContent = message;
                modalAlert.style.display = 'block';

                // Auto-dismiss after 5 seconds
                clearTimeout(modalAlert.dismissTimeout);
                modalAlert.dismissTimeout = setTimeout(() => {
                    modalAlert.style.display = 'none';
                }, 5000);
            }
        } else {
            // Show in global alert if modal not open
            const alert = document.getElementById('alertMessage');
            if (alert) {
                alert.className = 'alert alert-success';
                alert.textContent = message;
                alert.style.display = 'block';

                // Auto-dismiss after 5 seconds
                clearTimeout(alert.dismissTimeout);
                alert.dismissTimeout = setTimeout(() => {
                    alert.style.display = 'none';
                }, 5000);
            }
        }
    }


    // Public API
    return {
        init: init,
        registerStore: registerStore,
        testStore: testStore,
        viewSecrets: viewSecrets,
        deleteStore: deleteStore,
        lockStore: lockStore,
        showLockConfirmModal: showLockConfirmModal,
        showUnlockDialog: showUnlockDialog,
        closeUnlockDialog: closeUnlockDialog,
        submitUnlock: submitUnlock,
        showRegisterDialog: showRegisterDialog,
        initializeVault: initializeVault,
        refreshStoresList: refreshStoresList,
        displaySystemVaults: displaySystemVaults
    };
})();

// Vault tab switching (for Registered Vaults vs File Vault Mgmt)
function setupVaultTabHandlers() {
    const tabButtons = document.querySelectorAll('.vault-tab-button');
    const tabContents = document.querySelectorAll('.vault-tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active state from all buttons
            tabButtons.forEach(btn => btn.classList.remove('active'));
            // Hide all tab contents
            tabContents.forEach(content => content.style.display = 'none');

            // Add active state to clicked button
            button.classList.add('active');
            // Show corresponding tab content
            const tabName = button.getAttribute('data-vault-tab');
            const tabContent = document.getElementById(tabName);
            if (tabContent) {
                tabContent.style.display = 'block';
            }

            // Update tab button active styling
            button.style.borderBottomColor = '#0284c7';
            button.style.color = '#0284c7';

            // Reset other buttons styling
            tabButtons.forEach(btn => {
                if (!btn.classList.contains('active')) {
                    btn.style.borderBottomColor = 'transparent';
                    btn.style.color = '#666';
                }
            });
        });
    });
}

// Toggle vault name field visibility based on auto-register checkbox
function toggleVaultNameField() {
    const checkbox = document.getElementById('initVaultAutoRegister');
    const nameGroup = document.getElementById('vaultNameGroup');

    if (checkbox && nameGroup) {
        nameGroup.style.display = checkbox.checked ? 'block' : 'none';

        // Make field required when visible
        const nameInput = document.getElementById('initVaultName');
        if (nameInput) {
            nameInput.required = checkbox.checked;
        }
    }
}

// Global modal close functions (called from HTML onclick handlers)
function closeRegisterStoreModal() {
    const modal = document.getElementById('registerStoreModal');
    if (modal) {
        modal.style.display = 'none';
        modal.style.animation = 'none';
    }
}

function closeInitializeVaultModal() {
    const modal = document.getElementById('initializeVaultModal');
    if (modal) {
        modal.style.display = 'none';
        modal.style.animation = 'none';
    }
}

function closeSecretsModal() {
    const modal = document.getElementById('secretsModal');
    if (modal) {
        modal.style.display = 'none';
        modal.style.animation = 'none';
    }
}

/**
 * Show modal with system vault objects broken down by type (PKI keys vs app secrets)
 * Names only - no values displayed for security
 */
function showSystemVaultObjectsModal(secretsList) {
    // Separate secrets into keys and app secrets using type field
    const pkiKeys = secretsList.filter(s => s.type === 'pki_keys');
    const appSecrets = secretsList.filter(s => s.type === 'app_secrets');

    // Create modal
    const modal = document.createElement('div');
    modal.id = 'systemVaultObjectsModal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.8); backdrop-filter: blur(4px); z-index: 2000; display: flex; align-items: center; justify-content: center;';

    const content = document.createElement('div');
    content.style.cssText = 'max-width: 600px; width: 90%; max-height: 80vh; background: white; border-radius: 12px; box-shadow: 0 20px 25px rgba(0,0,0,0.15); display: flex; flex-direction: column; overflow: hidden;';

    // Header
    const header = document.createElement('div');
    header.style.cssText = 'padding: 24px; background: linear-gradient(135deg, #7c3aed 0%, #8b5cf6 100%); color: white; flex-shrink: 0; display: flex; justify-content: space-between; align-items: center;';
    header.innerHTML = `
        <h2 style="margin: 0; font-size: 20px; font-weight: 700;">System Vault Objects</h2>
        <button onclick="document.getElementById('systemVaultObjectsModal').remove()" style="background: none; border: none; font-size: 24px; color: white; cursor: pointer;">×</button>
    `;

    // Body
    const body = document.createElement('div');
    body.style.cssText = 'padding: 24px; overflow-y: auto; flex: 1;';
    body.innerHTML = `
        <div style="margin-bottom: 24px;">
            <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">🔑 PKI Keys (${pkiKeys.length})</h3>
            <div style="background: #f9fafb; border-radius: 8px; padding: 12px; max-height: 200px; overflow-y: auto;">
                ${pkiKeys.length > 0
                    ? pkiKeys.map(k => `<div style="padding: 10px 12px; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                        <span style="color: #374151; font-size: 13px; font-family: monospace; word-break: break-all; flex: 1; min-width: 0;">• ${k.name}</span>
                        <button onclick="deleteVaultSecret('${k.full_path}', '${k.name}', 'pki_keys')" style="background: #dc2626; color: white; border: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; white-space: nowrap; flex-shrink: 0; font-weight: 600; transition: background 0.2s;">Delete</button>
                    </div>`).join('')
                    : '<p style="margin: 0; color: #9ca3af; font-size: 13px; padding: 8px 12px;">No PKI keys</p>'
                }
            </div>
            <p style="margin: 8px 0 0 0; color: #6b7280; font-size: 12px;">Cryptographic keys for certificate management</p>
        </div>

        <div>
            <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">🔐 App Secrets (${appSecrets.length})</h3>
            <div style="background: #f9fafb; border-radius: 8px; padding: 12px; max-height: 200px; overflow-y: auto;">
                ${appSecrets.length > 0
                    ? appSecrets.map(s => `<div style="padding: 10px 12px; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                        <span style="color: #374151; font-size: 13px; font-family: monospace; word-break: break-all; flex: 1; min-width: 0;">• ${s.name}</span>
                        <button onclick="deleteVaultSecret('${s.full_path}', '${s.name}', 'app_secrets')" style="background: #dc2626; color: white; border: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; white-space: nowrap; flex-shrink: 0; font-weight: 600; transition: background 0.2s;">Delete</button>
                    </div>`).join('')
                    : '<p style="margin: 0; color: #9ca3af; font-size: 13px; padding: 8px 12px;">No app secrets</p>'
                }
            </div>
            <p style="margin: 8px 0 0 0; color: #6b7280; font-size: 12px;">Application configuration and credentials</p>
        </div>

        <div style="background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; padding: 12px; border-radius: 6px; margin-top: 16px; font-size: 12px; color: #1e40af;">
            <strong>🔒 Security:</strong> Only object names are shown. Secret values are never displayed and never logged.
        </div>
    `;

    // Footer
    const footer = document.createElement('div');
    footer.style.cssText = 'padding: 16px 24px; border-top: 1px solid #e5e7eb; background: #f9fafb; display: flex; justify-content: flex-end; flex-shrink: 0;';
    footer.innerHTML = `
        <button onclick="document.getElementById('systemVaultObjectsModal').remove()" class="btn btn-secondary" style="margin: 0; padding: 10px 20px;">
            Close
        </button>
    `;

    // Assemble
    content.appendChild(header);
    content.appendChild(body);
    content.appendChild(footer);
    modal.appendChild(content);

    // Close on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });

    document.body.appendChild(modal);
}

/**
 * Delete a secret or PKI key from the system vault
 *
 * @param {string} secretPath - Full path of the secret/key to delete (e.g., "pki_keys/engagement_ca_keys/31/pem")
 * @param {string} secretName - Display name of the secret/key (for UI messages)
 * @param {string} secretType - Type: 'pki_keys' or 'app_secrets'
 */
async function deleteVaultSecret(secretPath, secretName, secretType) {
    // Confirm deletion
    const message = `Are you sure you want to permanently delete "${secretName}" from the ${secretType === 'pki_keys' ? 'PKI keys' : 'app secrets'}?`;
    if (!confirm(message)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/secret-stores/system-vault/secrets`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                path: secretPath
            })
        });

        const data = await response.json();

        if (!response.ok) {
            showError(`Failed to delete ${secretName}: ${data.error || 'Unknown error'}`);
            return;
        }

        // Success - refresh the modal
        showSuccess(`Successfully deleted ${secretName}`);

        // Close current modal and refresh
        const modal = document.getElementById('systemVaultObjectsModal');
        if (modal) {
            modal.remove();
        }

        // Refresh vault display
        await displaySystemVaults();
    } catch (error) {
        console.error('Error deleting secret:', error);
        showError(`Error deleting ${secretName}: ${error.message}`);
    }
}

/**
 * Display system vault information in the Registered Vaults tab
 * System vault is read-only and managed automatically by CAIP
 */
async function displaySystemVaults() {
    const storesContainer = document.getElementById('storesContainer');
    if (!storesContainer) return;

    try {
        // Fetch system vault info
        const response = await fetch('/api/v1/secret-stores/system-vault');
        if (!response.ok) {
            console.log('System vault endpoint not available (expected during setup)');
            return;
        }

        const vaultData = await response.json();

        // Fetch system vault secrets
        const secretsResponse = await fetch('/api/v1/secret-stores/system-vault/secrets');
        const secretsData = await secretsResponse.json();

        // Create vault card HTML
        const vaultCard = document.createElement('div');
        vaultCard.className = 'vault-card system-vault-card';
        vaultCard.style.cssText = `
            background: linear-gradient(135deg, #f3e8ff 0%, #faf5ff 100%);
            border: 2px solid #ddd6fe;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            position: relative;
        `;

        const secretsList = secretsData.secrets || [];
        const createdDate = new Date(vaultData.created_at).toLocaleDateString();

        vaultCard.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
                <div>
                    <h3 style="margin: 0 0 4px 0; color: #7c3aed; font-size: 18px; font-weight: 700;">
                        🔐 ${vaultData.name}
                    </h3>
                    <p style="margin: 0; color: #8b5cf6; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">
                        System Vault
                    </p>
                </div>
                <span style="background: #10b981; color: white; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600;">
                    ${vaultData.status?.toUpperCase() || 'ACTIVE'}
                </span>
            </div>

            <div style="background: white; border-radius: 8px; padding: 12px; margin-bottom: 16px; border-left: 4px solid #8b5cf6;">
                <p style="margin: 0; color: #6b7280; font-size: 13px; line-height: 1.5;">
                    <strong>System vault is managed automatically by CAIP.</strong> This vault stores application secrets and encryption keys. No user action required.
                </p>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
                <div style="background: white; border-radius: 8px; padding: 12px;">
                    <p style="margin: 0 0 4px 0; color: #9ca3af; font-size: 12px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Encryption</p>
                    <p style="margin: 0; color: #1f2937; font-size: 14px; font-weight: 600;">${vaultData.encryption || 'AES-256-GCM'}</p>
                </div>
                <div style="background: white; border-radius: 8px; padding: 12px;">
                    <p style="margin: 0 0 4px 0; color: #9ca3af; font-size: 12px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Secrets</p>
                    <p style="margin: 0; color: #1f2937; font-size: 14px; font-weight: 600;">${secretsList.length} stored</p>
                </div>
            </div>

            <div style="display: flex; gap: 8px; border-top: 1px solid #e9d5ff; padding-top: 16px;">
                <button onclick="showSystemVaultObjectsModal(${JSON.stringify(secretsList).replace(/"/g, '&quot;')})" class="btn btn-secondary" style="flex: 1; margin: 0; padding: 10px;">
                    👁️ View Objects
                </button>
                <button onclick="downloadSystemVaultBackup()" class="btn btn-secondary" style="flex: 1; margin: 0; padding: 10px;">
                    📥 Backup
                </button>
                <p style="flex: 0 0 auto; margin: 0; padding: 10px; color: #6b7280; font-size: 12px; align-self: center; white-space: nowrap;">
                    Created: ${createdDate}
                </p>
            </div>
        `;

        // Prepend system vault card to the main stores container (before registered vaults)
        storesContainer.insertBefore(vaultCard, storesContainer.firstChild);
    } catch (error) {
        console.error('Error displaying system vault:', error);
        // Silently fail - system vault is optional
    }
}

/**
 * Download system vault backup
 */
async function downloadSystemVaultBackup() {
    try {
        const response = await fetch('/api/v1/secret-stores/system-vault/backup');
        if (!response.ok) throw new Error('Failed to download backup');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `system_vault_backup_${new Date().toISOString().split('T')[0]}.enc`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        alert('Failed to download backup: ' + error.message);
    }
}

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', () => {
    SecretStoresManagement.init();
    setupVaultTabHandlers();
});
