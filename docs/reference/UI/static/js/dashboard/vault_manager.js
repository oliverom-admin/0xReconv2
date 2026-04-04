/**
 * Vault File Manager
 *
 * Manages secrets within encrypted vault files that are registered in Secret Stores.
 * This component focuses on file-level operations:
 * - Selecting a vault
 * - Unlocking/locking vaults
 * - Viewing, adding, editing, deleting secrets
 *
 * Vault registration happens in the Secret Stores tab, not here.
 */

class VaultFileManager {
    constructor() {
        this.encryptedStores = [];
        this.selectedStoreId = null;
        this.selectedStore = null;
        this.secrets = [];
        this.init();
    }

    async init() {
        
        this.attachEventListeners();
        await this.loadEncryptedStores();
    }

    /**
     * Public method to refresh vault list (called after registration)
     */
    async refreshVaultList() {
        
        await this.loadEncryptedStores();
    }

    attachEventListeners() {
        // Vault selector dropdown
        const vaultSelector = document.getElementById('vaultSelector');
        if (vaultSelector) {
            vaultSelector.addEventListener('change', (e) => this.selectVault(e.target.value));
        }

        // Unlock button
        const unlockBtn = document.getElementById('unlockVaultBtn');
        if (unlockBtn) {
            unlockBtn.addEventListener('click', () => this.showUnlockModal());
        }

        // Lock button
        const lockBtn = document.getElementById('lockVaultBtn');
        if (lockBtn) {
            lockBtn.addEventListener('click', () => this.lockVault());
        }

        // Refresh button
        const refreshBtn = document.getElementById('refreshVaultBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadVaultSecrets());
        }

        // Add secret button
        const addSecretBtn = document.getElementById('addSecretBtn');
        if (addSecretBtn) {
            addSecretBtn.addEventListener('click', () => this.showAddSecretModal());
        }
    }

    /**
     * Load all encrypted file stores from Secret Stores
     */
    async loadEncryptedStores() {
        try {
            
            const response = await fetch('/api/secret-stores');
            const data = await response.json();

            if (data.success && data.stores) {
                // Filter to only encrypted file stores
                this.encryptedStores = data.stores.filter(store => store.provider_type === 'encrypted_file');
                this.populateVaultDropdown();
                

                // Only show error message if there are no stores at all
                if (this.encryptedStores.length === 0) {
                    // This is not an error - just no vaults registered yet
                    
                }
            } else {
                
                // Don't show error to user on initial load - this is expected if no vaults exist
            }
        } catch (error) {
            
            // Don't show alert on initial load - network errors will be caught by other handlers
        }
    }

    /**
     * Populate vault selector dropdown
     */
    populateVaultDropdown() {
        const vaultSelector = document.getElementById('vaultSelector');
        if (!vaultSelector) return;

        vaultSelector.innerHTML = '<option value="">Choose an encrypted file store...</option>';

        this.encryptedStores.forEach(store => {
            const option = document.createElement('option');
            option.value = store.id;
            option.textContent = `${store.name} (${store.connection_config.vault_file_path})`;
            vaultSelector.appendChild(option);
        });
    }

    /**
     * Select a vault from the dropdown
     */
    async selectVault(storeId) {
        if (!storeId) {
            this.selectedStoreId = null;
            this.selectedStore = null;
            this.secrets = [];
            this.hideVaultInfo();
            return;
        }

        this.selectedStoreId = storeId;
        this.selectedStore = this.encryptedStores.find(s => s.id == storeId);

        if (this.selectedStore) {
            this.showVaultInfo();
            await this.loadVaultSecrets();
        }
    }

    /**
     * Load secrets from selected vault
     */
    async loadVaultSecrets() {
        if (!this.selectedStoreId) {
            
            return;
        }

        try {
            
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/secrets`);
            const data = await response.json();

            if (data.success && data.secrets) {
                this.secrets = data.secrets;
                this.renderSecretsList();
                
            } else if (data.success === false && data.error && data.error.includes('locked')) {
                // Vault is locked - this is expected after page refresh
                
                this.renderLockedState();
            } else if (data.error) {
                
                this.renderErrorState(data.error);
            } else {
                
                this.renderErrorState('Failed to load secrets');
            }
        } catch (error) {
            
            this.renderErrorState('Error loading secrets: ' + error.message);
        }
    }

    /**
     * Display vault information section
     */
    showVaultInfo() {
        const vaultInfo = document.getElementById('vaultInfo');
        if (!vaultInfo) return;

        const config = this.selectedStore.connection_config;
        const isLocked = this.selectedStore.status === 'locked';
        const statusColor = isLocked ? '#ef4444' : '#10b981';
        const statusBg = isLocked ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)';

        vaultInfo.innerHTML = `
            <div style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <!-- Vault Header -->
                <div style="padding: 24px; border-bottom: 1px solid #e5e7eb; background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%);">
                    <div style="display: flex; justify-content: space-between; align-items: start; gap: 16px;">
                        <div>
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                                <span style="font-size: 24px;">🔐</span>
                                <div>
                                    <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: #1f2937;">${this.selectedStore.name}</h3>
                                    <p style="margin: 4px 0 0 0; font-size: 13px; color: #6b7280; font-family: monospace;">${config.vault_file_path}</p>
                                </div>
                            </div>
                        </div>
                        <div style="background: ${statusBg}; border: 1.5px solid ${statusColor}; color: ${statusColor}; padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 13px; white-space: nowrap;">
                            ${isLocked ? '🔒 Locked' : '🔓 Unlocked'}
                        </div>
                    </div>
                </div>

                <!-- Vault Details -->
                <div style="padding: 24px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 24px; border-bottom: 1px solid #e5e7eb;">
                    <div>
                        <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">Unlock Method</p>
                        <p style="margin: 0; font-size: 14px; font-weight: 600; color: #1f2937;">${config.unlock_method}</p>
                    </div>
                    <div>
                        <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">Current Status</p>
                        <p style="margin: 0; font-size: 14px; font-weight: 600; color: ${statusColor}; text-transform: capitalize;">${this.selectedStore.status}</p>
                    </div>
                    <div>
                        <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">Secrets Count</p>
                        <p style="margin: 0; font-size: 14px; font-weight: 600; color: #1f2937;">${this.selectedStore.secret_count || 0} secret${(this.selectedStore.secret_count || 0) !== 1 ? 's' : ''}</p>
                    </div>
                </div>

                <!-- Action Buttons -->
                <div style="padding: 20px 24px; display: flex; gap: 12px; flex-wrap: wrap;">
                    ${isLocked ?
                        `<button id="unlockVaultBtn" class="btn btn-primary" style="padding: 10px 20px; background: linear-gradient(135deg, #0284c7 0%, #0ea5e9 100%); color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);">🔓 Unlock Vault</button>` :
                        `<button id="lockVaultBtn" class="btn btn-secondary" style="padding: 10px 20px; background: white; color: #1f2937; border: 1.5px solid #e5e7eb; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s;">🔒 Lock Vault</button>`
                    }
                    <button id="refreshVaultBtn" class="btn btn-secondary" style="padding: 10px 20px; background: white; color: #1f2937; border: 1.5px solid #e5e7eb; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s;">🔄 Refresh</button>
                </div>
            </div>
        `;

        // Re-attach event listeners
        document.getElementById('unlockVaultBtn')?.addEventListener('click', () => this.showUnlockModal());
        document.getElementById('lockVaultBtn')?.addEventListener('click', () => this.lockVault());
        document.getElementById('refreshVaultBtn')?.addEventListener('click', () => this.loadVaultSecrets());

        vaultInfo.style.display = 'block';

        // Show secrets list if unlocked
        const secretsList = document.getElementById('secretsList');
        if (secretsList) {
            secretsList.style.display = !isLocked ? 'block' : 'none';
        }
    }

    /**
     * Hide vault info section
     */
    hideVaultInfo() {
        const vaultInfo = document.getElementById('vaultInfo');
        const secretsList = document.getElementById('secretsList');
        if (vaultInfo) vaultInfo.style.display = 'none';
        if (secretsList) secretsList.style.display = 'none';
    }

    /**
     * Render locked state message
     */
    renderLockedState() {
        const secretsList = document.getElementById('secretsList');
        if (!secretsList) return;

        secretsList.innerHTML = `
            <div style="padding: 48px 32px; text-align: center; background: linear-gradient(135deg, #fef3c7 0%, #fef08a 100%); border: 1.5px solid #fcd34d; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="font-size: 48px; margin-bottom: 16px;">🔒</div>
                <h3 style="margin: 0 0 12px 0; color: #92400e; font-size: 18px; font-weight: 700;">Vault is Locked</h3>
                <p style="margin: 0 0 24px 0; color: #b45309; font-size: 14px; line-height: 1.6;">Unlock the vault to view and manage secrets.</p>
                <button id="unlockVaultBtn" class="btn btn-primary" style="padding: 12px 28px; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 14px; transition: all 0.2s; box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);">🔓 Unlock Vault</button>
            </div>
        `;
        document.getElementById('unlockVaultBtn')?.addEventListener('click', () => this.showUnlockModal());
        secretsList.style.display = 'block';
    }

    /**
     * Render error state message
     */
    renderErrorState(message) {
        const secretsList = document.getElementById('secretsList');
        if (!secretsList) return;

        secretsList.innerHTML = `
            <div style="padding: 48px 32px; text-align: center; background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border: 1.5px solid #fca5a5; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
                <h3 style="margin: 0 0 12px 0; color: #dc2626; font-size: 18px; font-weight: 700;">Error Loading Vault</h3>
                <p style="margin: 0 0 24px 0; color: #7c2d12; font-size: 14px; line-height: 1.6;">${escapeHtml(message)}</p>
                <button onclick="window.vaultFileManager.loadVaultSecrets()" class="btn btn-secondary" style="padding: 12px 28px; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 14px; transition: all 0.2s; box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);">🔄 Retry</button>
            </div>
        `;
        secretsList.style.display = 'block';
    }

    /**
     * Escape HTML special characters
     */
    escapeHtml(text) {
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
     * Render secrets list
     */
    renderSecretsList() {
        const secretsList = document.getElementById('secretsList');
        if (!secretsList) return;

        if (this.secrets.length === 0) {
            secretsList.innerHTML = `
                <div style="padding: 48px 32px; text-align: center; background: white; border: 1.5px dashed #e5e7eb; border-radius: 12px;">
                    <div style="font-size: 48px; margin-bottom: 16px;">🔑</div>
                    <h3 style="margin: 0 0 8px 0; color: #6b7280; font-size: 16px; font-weight: 600;">No Secrets Yet</h3>
                    <p style="margin: 0 0 24px 0; color: #9ca3af; font-size: 14px;">Create your first secret to get started</p>
                    <button id="addSecretBtn" class="btn btn-primary" style="padding: 10px 24px; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);">➕ Add First Secret</button>
                </div>
            `;
            document.getElementById('addSecretBtn').addEventListener('click', () => this.showAddSecretModal());
            secretsList.style.display = 'block';
            return;
        }

        secretsList.innerHTML = `
            <div style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <!-- Secrets Header -->
                <div style="padding: 20px 24px; border-bottom: 1px solid #e5e7eb; background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: #1f2937;">Secrets in Vault</h3>
                        <p style="margin: 4px 0 0 0; font-size: 13px; color: #6b7280;">${this.secrets.length} secret${this.secrets.length !== 1 ? 's' : ''}</p>
                    </div>
                    <button id="addSecretBtn" class="btn btn-primary" style="padding: 10px 20px; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 13px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3); white-space: nowrap;">➕ Add Secret</button>
                </div>

                <!-- Secrets List -->
                <div style="max-height: 500px; overflow-y: auto;">
                    ${this.secrets.map(secret => `
                        <div style="padding: 16px 24px; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; gap: 16px; transition: background 0.2s;" onmouseover="this.style.background='#f9fafb'" onmouseout="this.style.background='white'">
                            <div style="display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0;">
                                <span style="font-size: 16px; flex-shrink: 0;">🔑</span>
                                <span style="font-size: 14px; font-weight: 500; color: #1f2937; word-break: break-all;">${secret.path}</span>
                            </div>
                            <div style="display: flex; gap: 8px; flex-shrink: 0;">
                                <button onclick="vaultFileManager.showViewSecretModal('${this.escapePath(secret.path)}')" style="background: transparent; border: 1px solid #e5e7eb; border-radius: 6px; padding: 6px 8px; cursor: pointer; transition: all 0.2s; font-size: 14px;" title="View">👁️</button>
                                <button onclick="vaultFileManager.showEditSecretModal('${this.escapePath(secret.path)}')" style="background: transparent; border: 1px solid #e5e7eb; border-radius: 6px; padding: 6px 8px; cursor: pointer; transition: all 0.2s; font-size: 14px;" title="Edit">✎</button>
                                <button onclick="vaultFileManager.showDeleteSecretConfirm('${this.escapePath(secret.path)}')" style="background: transparent; border: 1px solid #fecaca; border-radius: 6px; padding: 6px 8px; cursor: pointer; transition: all 0.2s; font-size: 14px; color: #dc2626;" title="Delete">🗑️</button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        document.getElementById('addSecretBtn').addEventListener('click', () => this.showAddSecretModal());
        secretsList.style.display = 'block';
    }

    /**
     * Escape path for safe use in onclick handlers
     */
    escapePath(path) {
        return path.replace(/'/g, "\\'").replace(/"/g, "&quot;");
    }

    /**
     * Show unlock modal
     */
    showUnlockModal() {
        // Create modal container
        const modal_div = document.createElement('div');
        modal_div.id = 'unlockModal';
        modal_div.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.8); backdrop-filter: blur(4px); z-index: 2000; display: flex; align-items: center; justify-content: center; pointer-events: auto;';

        // Create content
        const content = document.createElement('div');
        content.style.cssText = 'max-width: 500px; background: white; border-radius: 12px; box-shadow: 0 20px 25px rgba(0,0,0,0.15); max-height: 90vh; overflow-y: auto; display: flex; flex-direction: column; position: relative;';

        // Create header with gradient (matching dashboard style)
        const header = document.createElement('div');
        header.style.cssText = 'padding: 24px; background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); color: white; flex-shrink: 0; display: flex; justify-content: space-between; align-items: center; border-bottom: none;';

        const title = document.createElement('h2');
        title.textContent = 'Unlock Vault';
        title.style.cssText = 'margin: 0; font-size: 22px; font-weight: 700; color: white;';

        const closeBtn = document.createElement('button');
        closeBtn.textContent = '×';
        closeBtn.id = 'unlockModalCloseBtn';
        closeBtn.style.cssText = 'background: none; border: none; font-size: 28px; color: white; cursor: pointer; padding: 0; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; transition: all 0.2s; opacity: 0.9;';

        header.appendChild(title);
        header.appendChild(closeBtn);

        // Create body
        const body = document.createElement('div');
        body.style.cssText = 'padding: 32px; flex: 1; overflow-y: auto;';

        const description = document.createElement('p');
        description.textContent = 'Enter your vault passphrase to unlock and access secrets.';
        description.style.cssText = 'margin: 0 0 24px 0; color: #4b5563; font-size: 14px; line-height: 1.6;';

        const formGroup = document.createElement('div');
        formGroup.style.cssText = 'margin-bottom: 24px;';

        const label = document.createElement('label');
        label.textContent = 'Passphrase *';
        label.style.cssText = 'display: block; font-weight: 600; margin-bottom: 8px; color: #374151; font-size: 14px;';

        const input = document.createElement('input');
        input.type = 'password';
        input.id = 'passphraseInput';
        input.placeholder = 'Enter passphrase';
        input.style.cssText = 'width: 100%; padding: 12px 16px; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 14px; box-sizing: border-box; color: #1f2937; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;';

        formGroup.appendChild(label);
        formGroup.appendChild(input);

        const infoBox = document.createElement('div');
        infoBox.innerHTML = '<strong>Note:</strong> The passphrase is not stored by CAIP. It\'s only used to decrypt your vault during this session.';
        infoBox.style.cssText = 'background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; padding: 16px; border-radius: 8px; color: #1e40af; font-size: 13px; line-height: 1.6;';

        body.appendChild(description);
        body.appendChild(formGroup);
        body.appendChild(infoBox);

        // Create footer
        const footer = document.createElement('div');
        footer.style.cssText = 'padding: 20px 32px; border-top: 1px solid #e5e7eb; background: #f9fafb; display: flex; justify-content: flex-end; gap: 12px; flex-shrink: 0;';

        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = 'Cancel';
        cancelBtn.id = 'unlockModalCancelBtn';
        cancelBtn.style.cssText = 'padding: 10px 24px; background: white; color: #374151; border: 1.5px solid #d1d5db; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;';

        const unlockBtn = document.createElement('button');
        unlockBtn.textContent = 'Unlock';
        unlockBtn.id = 'unlockModalSubmitBtn';
        unlockBtn.style.cssText = 'padding: 10px 24px; background: linear-gradient(135deg, #0284c7 0%, #0ea5e9 100%); color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;';

        footer.appendChild(cancelBtn);
        footer.appendChild(unlockBtn);

        // Assemble modal
        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        modal_div.appendChild(content);

        // Append to document
        document.documentElement.appendChild(modal_div);

        // Add event listeners
        input.focus();

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

        unlockBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const passphrase = input.value;

            if (!passphrase || passphrase.trim() === '') {
                showAlert('Passphrase is required', 'error');
                return;
            }

            // Store reference to modal for cleanup after unlock
            window.currentUnlockModal = modal_div;
            this.submitUnlockWithPassphrase(passphrase);
        });

        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const passphrase = input.value;
                if (passphrase && passphrase.trim() !== '') {
                    window.currentUnlockModal = modal_div;
                    this.submitUnlockWithPassphrase(passphrase);
                }
            }
        });
    }

    /**
     * Submit unlock with passphrase
     */
    async submitUnlockWithPassphrase(passphrase) {
        if (!passphrase || passphrase.trim() === '') {
            showAlert('Passphrase is required', 'error');
            return;
        }

        try {
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ passphrase })
            });

            const data = await response.json();

            if (data.success) {
                // Close modal first
                const modal = document.getElementById('unlockModal');
                if (modal) {
                    modal.remove();
                }
                // Also clean up global reference
                if (window.currentUnlockModal) {
                    if (window.currentUnlockModal.parentElement) {
                        window.currentUnlockModal.remove();
                    }
                    window.currentUnlockModal = null;
                }

                showAlert('Vault unlocked successfully', 'success');
                await this.loadEncryptedStores();
                await this.selectVault(this.selectedStoreId);
            } else {
                showAlert(`Failed to unlock: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            showAlert('Error unlocking vault', 'error');
        }
    }

    /**
     * Submit unlock (deprecated - use submitUnlockWithPassphrase)
     */
    async submitUnlock() {
        const passphraseInput = document.getElementById('passphraseInput');
        const passphrase = passphraseInput ? passphraseInput.value : '';
        await this.submitUnlockWithPassphrase(passphrase);
    }

    /**
     * Lock vault
     */
    async lockVault() {
        this.showLockConfirmModal();
    }

    /**
     * Show lock confirmation modal
     */
    showLockConfirmModal() {
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
            await this.submitLock();
        });
    }

    /**
     * Submit lock request to backend
     */
    async submitLock() {
        try {
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/lock`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('Vault locked successfully', 'success');
                await this.loadEncryptedStores();
                await this.selectVault(this.selectedStoreId);
            } else {
                showAlert(`Failed to lock: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            showAlert('Error locking vault', 'error');
        }
    }

    /**
     * Show add secret modal
     */
    showAddSecretModal() {
        const modal = `
            <div id="addSecretModal" class="modal active">
                <div class="modal-content" style="max-width: 600px;">
                    <div class="modal-header">
                        <h2>Add New Secret</h2>
                        <button class="close-btn" onclick="document.getElementById('addSecretModal').remove()">×</button>
                    </div>

                    <div class="modal-body">
                        <div class="form-group">
                            <label>Secret Path *</label>
                            <input type="text" id="secretPathInput" placeholder="/vault/my-secret" autofocus>
                            <small>Example: /ejbca/admin-password or /azure/client-secret</small>
                        </div>

                        <div class="form-group">
                            <label>Secret Value *</label>
                            <input type="password" id="secretValueInput" placeholder="Enter secret value">
                            <small>The secret will be encrypted and never logged</small>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="document.getElementById('addSecretModal').remove()">Cancel</button>
                        <button class="btn btn-primary" onclick="vaultFileManager.submitAddSecret()">Add Secret</button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modal);
        document.getElementById('secretPathInput').focus();
    }

    /**
     * Submit add secret
     */
    async submitAddSecret() {
        const path = document.getElementById('secretPathInput').value.trim();
        const value = document.getElementById('secretValueInput').value;

        if (!path || !value) {
            showAlert('Secret path and value are required', 'error');
            return;
        }

        try {
            
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/secrets`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: path.split('/').pop(),
                    value: value
                })
            });

            const data = await response.json();

            if (data.success) {
                showAlert('Secret added successfully', 'success');
                document.getElementById('addSecretModal').remove();
                await this.loadVaultSecrets();
            } else {
                showAlert(`Failed to add secret: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            
            showAlert('Error adding secret', 'error');
        }
    }

    /**
     * Show view secret modal
     */
    async showViewSecretModal(secretPath) {
        try {
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/secrets/${encodeURIComponent(secretPath)}/resolve`);
            const data = await response.json();

            if (data.success) {
                const modal = `
                    <div id="viewSecretModal" class="modal active">
                        <div class="modal-content" style="max-width: 500px;">
                            <div class="modal-header">
                                <h2>View Secret</h2>
                                <button class="close-btn" onclick="document.getElementById('viewSecretModal').remove()">×</button>
                            </div>

                            <div class="modal-body">
                                <div class="detail-row">
                                    <span class="label">Path:</span>
                                    <span class="value">${secretPath}</span>
                                </div>

                                <div class="form-group" style="margin-top: 20px;">
                                    <label>Secret Value (hidden)</label>
                                    <div class="secret-value-display">
                                        <span id="secretValueDisplay">••••••••••</span>
                                        <button class="btn-icon" onclick="vaultFileManager.toggleSecretDisplay('${this.escapePath(secretPath)}')">👁️</button>
                                    </div>
                                </div>

                                <div class="info-box">
                                    <strong>Security:</strong> Secret values are only displayed in this modal and never logged.
                                </div>
                            </div>

                            <div class="modal-footer">
                                <button class="btn btn-secondary" onclick="document.getElementById('viewSecretModal').remove()">Close</button>
                            </div>
                        </div>
                    </div>
                `;

                document.body.insertAdjacentHTML('beforeend', modal);

                // Store secret value for reveal functionality
                document.getElementById('viewSecretModal').dataset.secretValue = data.value;
            } else {
                showAlert('Failed to retrieve secret', 'error');
            }
        } catch (error) {
            
            showAlert('Error viewing secret', 'error');
        }
    }

    /**
     * Toggle secret display visibility
     */
    toggleSecretDisplay(secretPath) {
        const modal = document.getElementById('viewSecretModal');
        const display = document.getElementById('secretValueDisplay');

        if (display.textContent === '••••••••••') {
            display.textContent = modal.dataset.secretValue;
            display.style.fontFamily = 'monospace';
        } else {
            display.textContent = '••••••••••';
            display.style.fontFamily = 'inherit';
        }
    }

    /**
     * Show edit secret modal
     */
    showEditSecretModal(secretPath) {
        const modal = `
            <div id="editSecretModal" class="modal active">
                <div class="modal-content" style="max-width: 600px;">
                    <div class="modal-header">
                        <h2>Edit Secret</h2>
                        <button class="close-btn" onclick="document.getElementById('editSecretModal').remove()">×</button>
                    </div>

                    <div class="modal-body">
                        <div class="form-group">
                            <label>Secret Path</label>
                            <input type="text" value="${secretPath}" disabled style="background: #f0f0f0;">
                            <small>Path cannot be changed. Delete and create new secret to rename.</small>
                        </div>

                        <div class="form-group">
                            <label>New Secret Value *</label>
                            <input type="password" id="editSecretValueInput" placeholder="Enter new secret value" autofocus>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="document.getElementById('editSecretModal').remove()">Cancel</button>
                        <button class="btn btn-primary" onclick="vaultFileManager.submitEditSecret('${this.escapePath(secretPath)}')">Update Secret</button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modal);
        document.getElementById('editSecretValueInput').focus();
    }

    /**
     * Submit edit secret
     */
    async submitEditSecret(secretPath) {
        const value = document.getElementById('editSecretValueInput').value;

        if (!value) {
            showAlert('Secret value is required', 'error');
            return;
        }

        try {
            
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/secrets/${encodeURIComponent(secretPath)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value })
            });

            const data = await response.json();

            if (data.success) {
                showAlert('Secret updated successfully', 'success');
                document.getElementById('editSecretModal').remove();
                await this.loadVaultSecrets();
            } else {
                showAlert(`Failed to update secret: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            
            showAlert('Error updating secret', 'error');
        }
    }

    /**
     * Show delete secret confirmation
     */
    showDeleteSecretConfirm(secretPath) {
        if (!confirm(`Delete secret: ${secretPath}?\n\nThis action cannot be undone.`)) {
            return;
        }

        this.deleteSecret(secretPath);
    }

    /**
     * Delete secret
     */
    async deleteSecret(secretPath) {
        try {
            
            const response = await fetch(`/api/secret-stores/${this.selectedStoreId}/secrets/${encodeURIComponent(secretPath)}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showAlert('Secret deleted successfully', 'success');
                await this.loadVaultSecrets();
            } else {
                showAlert(`Failed to delete secret: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            
            showAlert('Error deleting secret', 'error');
        }
    }
}

// Initialize vault file manager when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.vaultFileManager = new VaultFileManager();
});
