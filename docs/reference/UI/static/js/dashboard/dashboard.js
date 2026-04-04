// Global data arrays
        let scans = [];
        let configurations = [];
        let policies = [];
        let engagements = [];
        
        // Active engagement context (null = show all)
        let activeEngagementId = null;
        let activeEngagementName = null;
        
        // Runtime tracking
        let scanRuntimeIntervals = {};
        let scanLogIntervals = {};
        let scanStartTimes = {};
        let scanQueuedTimes = {};  // Track when scan entered Queued state
        let inventorySyncStatus = {};  // Inventory sync status keyed by connector_id

        // ==================== UTILITY FUNCTIONS ====================
        
        // Escape HTML special characters to prevent XSS attacks
        function escapeHtml(text) {
            if (!text) return '';
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return String(text).replace(/[&<>"']/g, m => map[m]);
        }

        // Get cookie value by name
        function getCookie(name) {
            const nameEQ = name + '=';
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i].trim();
                if (cookie.indexOf(nameEQ) === 0) {
                    return cookie.substring(nameEQ.length);
                }
            }
            return null;
        }

        // ==================== ENGAGEMENT CONTEXT FUNCTIONS ====================
        
        /**
         * Load engagements for the context selector
         */
        async function loadEngagementsForContext() {
            try {
                const response = await fetch('/api/v1/engagements?status=Active');
                if (!response.ok) throw new Error('Failed to load engagements');
                const data = await response.json();
                engagements = data.engagements || [];
                renderEngagementContextSelector();
            } catch (error) {
                
            }
        }
        
        /**
         * Render the engagement context selector dropdown
         */
        function renderEngagementContextSelector() {
            const select = document.getElementById('engagement-context-select');
            if (!select) return;
            
            select.innerHTML = '<option value="">All Engagements</option>';
            engagements.forEach(eng => {
                const option = document.createElement('option');
                option.value = eng.engagement_id;
                option.textContent = `${eng.customer_name} - ${eng.project_name}`;
                if (eng.engagement_id === activeEngagementId) {
                    option.selected = true;
                }
                select.appendChild(option);
            });
        }
        
        /**
         * Set the active engagement context
         */
        function setEngagementContext(engagementId) {
            activeEngagementId = engagementId || null;
            
            if (activeEngagementId) {
                const engagement = engagements.find(e => e.engagement_id === activeEngagementId);
                activeEngagementName = engagement ? `${engagement.customer_name} - ${engagement.project_name}` : null;
            } else {
                activeEngagementName = null;
            }
            
            // Update the context indicator
            updateEngagementContextIndicator();
            
            // Update button states based on engagement context
            updateEngagementDependentButtons();
            
            // Reload data with new context
            refreshDataForEngagementContext();
        }
        
        /**
         * Update the visual indicator showing active engagement
         */
        function updateEngagementContextIndicator() {
            const indicator = document.getElementById('engagement-context-indicator');
            if (!indicator) return;
            
            if (activeEngagementId && activeEngagementName) {
                indicator.innerHTML = `<span class="context-badge">📁 ${escapeHtml(activeEngagementName)}</span>`;
                indicator.style.display = 'block';
            } else {
                indicator.innerHTML = '';
                indicator.style.display = 'none';
            }
        }
        
        /**
         * Refresh all data based on current engagement context
         */
        async function refreshDataForEngagementContext() {
            await Promise.all([
                loadScans(),
                loadConfigurations(),
                loadDocumentAssessments(),
                loadReassessments(),
                loadAggregations()
            ]);
            // Update doc assessment context indicator if on that tab
            updateDocAssessmentEngagementContext();
        }
        
        /**
         * Get URL params for engagement filtering
         */
        function getEngagementFilterParams() {
            if (activeEngagementId) {
                return `engagement_id=${encodeURIComponent(activeEngagementId)}`;
            }
            return '';
        }
        
        /**
         * Enable/disable buttons that require an engagement context
         */
        function updateEngagementDependentButtons() {
            const buttons = [
                document.getElementById('newScanBtn'),
                document.getElementById('newConfigBtn'),
                document.getElementById('newReassessBtn'),
                document.getElementById('newAggregationBtn'),
                document.getElementById('importConfigBtn'),
                document.getElementById('doc-assess-btn')
            ];
            
            const disabled = !activeEngagementId;
            const tooltip = disabled ? 'Select an engagement first' : '';
            
            buttons.forEach(btn => {
                if (btn) {
                    btn.disabled = disabled;
                    btn.title = tooltip;
                    btn.style.opacity = disabled ? '0.5' : '1';
                    btn.style.cursor = disabled ? 'not-allowed' : 'pointer';
                }
            });
        }
        
        /**
         * Update the document assessment engagement context indicator
         */
        function updateDocAssessmentEngagementContext() {
            const engagementContext = document.getElementById('doc-assessment-engagement-context');
            const engagementNameEl = document.getElementById('doc-assessment-engagement-name');
            
            if (!engagementContext || !engagementNameEl) return;
            
            if (activeEngagementId && activeEngagementName) {
                engagementNameEl.textContent = activeEngagementName;
                engagementContext.style.display = 'block';
            } else {
                engagementContext.style.display = 'none';
            }
        }

        // ==================== ASSESSMENT TYPE FUNCTIONS ====================
        
        // Current selected assessment type
        let currentAssessmentType = 'pki_health_check';
        
        /**
         * Select assessment type in the New Scan modal
         */
        function selectAssessmentType(type) {
            currentAssessmentType = type;
            document.getElementById('scanAssessmentType').value = type;
            
            // Update visual selection
            document.querySelectorAll('.assessment-type-option').forEach(option => {
                option.classList.remove('selected');
            });
            document.querySelector(`.assessment-type-option[data-type="${type}"]`).classList.add('selected');
            
            // Reload policies filtered by assessment type
            loadPoliciesForDropdown(type);
        }
        
        /**
         * Get assessment type display info
         */
        function getAssessmentTypeInfo(type) {
            const types = {
                'pki_health_check': { icon: '🔬', name: 'PKI Health Check', cssClass: 'pki-health-check' },
                'pqc_assessment': { icon: '🔐', name: 'PQC Assessment', cssClass: 'pqc-assessment' }
            };
            return types[type] || types['pki_health_check'];
        }
        
        /**
         * Render assessment type badge HTML
         */
        function renderAssessmentTypeBadge(type) {
            const info = getAssessmentTypeInfo(type);
            return `<span class="assessment-type-badge ${info.cssClass}">${info.icon} ${info.name}</span>`;
        }

        /**
         * Render per-collector success/failure badges
         */
        function renderCollectorBadges(collectorResults) {
            if (!collectorResults) return '';

            const collectorLabels = {
                tls:            'TLS',
                azure_keyvault: 'Azure',
                luna_hsm:       'HSM',
                ejbca:          'EJBCA',
                crl:            'CRL',
                file_scan:      'Files'
            };

            const badges = Object.entries(collectorResults)
                .filter(([key, info]) => info && info.enabled)
                .map(([key, info]) => {
                    const label = collectorLabels[key] || key;
                    const cssClass = info.success
                        ? 'collector-badge-success'
                        : 'collector-badge-failed';
                    const icon = info.success ? '\u2713' : '\u2717';  // ✓ or ✗
                    const title = `${label}: ${info.success ? 'succeeded' : 'failed'}`;
                    return `<span class="collector-badge-mini ${cssClass}" title="${title}">${label} ${icon}</span>`;
                });

            return badges.length
                ? `<div class="collector-badges-row">${badges.join('')}</div>`
                : '';
        }

        function getConnectorIconClass(type) {
            const classes = {
                'EJBCA': 'ejbca',
                'Azure Key Vault': 'azure',
                'Luna HSM': 'luna',
                'Luna': 'luna',
                'File Share': 'file',
                'TLS': 'tls'
            };
            return classes[type] || 'default';
        }
        
        function getConnectorIcon(type) {
            const icons = {
                'EJBCA': '🏛️',
                'Azure Key Vault': '☁️',
                'Luna HSM': '🔐',
                'Luna': '🔐',
                'File Share': '📁',
                'TLS': '🔒'
            };
            return icons[type] || '🔗';
        }
        
        function getConnectorIconClass(type) {
            const classes = {
                'EJBCA': 'ejbca',
                'Azure Key Vault': 'azure',
                'Luna HSM': 'luna',
                'Luna': 'luna',
                'File Share': 'file',
                'TLS': 'tls'
            };
            return classes[type] || 'default';
        }
        
        function getConnectorIcon(type) {
            const icons = {
                'EJBCA': '🏛️',
                'Azure Key Vault': '☁️',
                'Luna HSM': '🔐',
                'Luna': '🔐',
                'File Share': '📁',
                'TLS': '🔒'
            };
            return icons[type] || '🔗';
        }
        
        // Track currently selected connector
        let selectedConnectorId = null;
        
        function toggleConnectorDetails(integrationId) {
            const container = document.getElementById('connector-details-container');
            const titleEl = document.getElementById('connector-details-title');
            const bodyEl = document.getElementById('connector-details-body');
            
            // Remove selected state from all cards
            document.querySelectorAll('.connector-card').forEach(function(card) {
                card.classList.remove('selected');
            });
            
            // If clicking the same card, close the details
            if (selectedConnectorId === integrationId && container.style.display !== 'none') {
                container.style.display = 'none';
                selectedConnectorId = null;
                return;
            }
            
            // Select the clicked card
            var clickedCard = document.getElementById('connectorCard' + integrationId);
            if (clickedCard) {
                clickedCard.classList.add('selected');
            }
            
            // Show loading state
            container.style.display = 'block';
            bodyEl.innerHTML = '<div style="text-align: center; padding: 40px; color: #6b7280;"><div class="loading"></div><div style="margin-top: 12px;">Loading details...</div></div>';
            
            selectedConnectorId = integrationId;
            
            // Load the details
            loadConnectorDetailsContent(integrationId, titleEl, bodyEl);
            
            // Scroll to details
            setTimeout(function() {
                container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }, 100);
        }
        
        function closeConnectorDetails() {
            var container = document.getElementById('connector-details-container');
            container.style.display = 'none';
            selectedConnectorId = null;
            
            // Remove selected state from all cards
            document.querySelectorAll('.connector-card').forEach(function(card) {
                card.classList.remove('selected');
            });
        }
        
        // Track if we're in edit mode
        let editingIntegrationId = null;
        
        async function editCLMIntegration(integrationId) {
            try {
                // Fetch integration details
                const response = await fetch('/api/v1/inventory/integrations');
                const data = await response.json();
                const integration = data.integrations.find(i => i.id === integrationId);
                
                if (!integration) {
                    showAlert('Integration not found', 'error');
                    return;
                }
                
                // Get config - API returns both config (parsed) and config_json (string)
                const config = integration.config || {};
                
                
                
                // Set edit mode
                editingIntegrationId = integrationId;
                
                // Update modal title
                document.querySelector('#newCLMIntegrationModal .modal-header h2').textContent = 'Edit Integration';
                document.querySelector('#newCLMIntegrationModal .modal-footer .btn-primary').textContent = 'Update Integration';
                
                // Populate the name field
                document.getElementById('clmIntegrationName').value = integration.name;
                
                // Set integration type dropdown and trigger display update
                const typeDropdown = document.getElementById('clmIntegrationTypeDropdown');
                
                // Determine the integration category
                if (integration.type === 'EJBCA' || integration.type === 'Azure Key Vault' || integration.type === 'ADCS') {
                    typeDropdown.value = 'certificate-store';
                    updateClmIntegrationDisplay();
                    
                    // Set the store type
                    const storeTypeDropdown = document.getElementById('clmCertificateStoreTypeDropdown');
                    if (integration.type === 'EJBCA') {
                        storeTypeDropdown.value = 'ejbca';
                        updateClmCertificateStoreDisplay();
                        
                        // Clear existing servers and add one with data
                        document.getElementById('clmEjbcaServersList').innerHTML = '';
                        addCLMEJBCAServerForm();
                        
                        // Populate EJBCA fields after form is added
                        var serverEl = document.querySelector('[data-clm-ejbca-server]');
                        if (serverEl) {
                            var nameInput = serverEl.querySelector('[data-clm-ejbca-name]');
                            var urlInput = serverEl.querySelector('[data-clm-ejbca-url]');
                            var p12PathInput = serverEl.querySelector('[data-clm-ejbca-p12-path]');

                            // Get EJBCA server config from nested structure
                            var ejbcaServer = config.ejbca && config.ejbca.servers && config.ejbca.servers[0] ? config.ejbca.servers[0] : {};

                            if (nameInput) nameInput.value = integration.name;
                            if (urlInput) urlInput.value = ejbcaServer.url || '';
                            if (p12PathInput) p12PathInput.value = ejbcaServer.p12_path || '';

                            // Populate credential field using CredentialFieldHelper
                            var credentialWrapper = serverEl.querySelector('.credential-field-wrapper');
                            if (credentialWrapper && ejbcaServer) {
                                // Build credential data from config (handle both flat and hybrid formats)
                                var credentialData = {
                                    plaintext_value: ejbcaServer.p12_password_plaintext || ejbcaServer.p12_password || null,
                                    secret_reference: ejbcaServer.p12_password_reference || null
                                };
                                CredentialFieldHelper.populateCredentialField(credentialWrapper, credentialData);
                            }
                        }
                    } else if (integration.type === 'Azure Key Vault') {
                        storeTypeDropdown.value = 'azure-keyvault';
                        updateClmCertificateStoreDisplay();

                        // Clear existing servers and add one with data
                        document.getElementById('clmAzureKeyVaultServersList').innerHTML = '';
                        addCLMAzureKeyVaultServerForm();

                        // Populate Azure fields after form is added
                        var serverEl = document.querySelector('[data-clm-azure-keyvault-server]');
                        if (serverEl) {
                            var nameInput = serverEl.querySelector('[data-clm-azure-keyvault-name]');
                            var urlInput = serverEl.querySelector('[data-clm-azure-keyvault-url]');
                            var tenantInput = serverEl.querySelector('[data-clm-azure-keyvault-tenant-id]');
                            var clientIdInput = serverEl.querySelector('[data-clm-azure-keyvault-client-id]');

                            // Get Azure Key Vault config from nested structure
                            // Structure: config.azure_keyvault.tenancies[0].service_principals[0]
                            var azureConfig = {};
                            if (config.azure_keyvault && config.azure_keyvault.tenancies && config.azure_keyvault.tenancies[0] &&
                                config.azure_keyvault.tenancies[0].service_principals && config.azure_keyvault.tenancies[0].service_principals[0]) {
                                azureConfig = config.azure_keyvault.tenancies[0].service_principals[0];
                            } else if (config.azure_key_vault && config.azure_key_vault.servers && config.azure_key_vault.servers[0]) {
                                azureConfig = config.azure_key_vault.servers[0];
                            } else if (config.azure_key_vault) {
                                azureConfig = config.azure_key_vault;
                            }

                            if (nameInput) nameInput.value = integration.name;
                            if (urlInput) urlInput.value = azureConfig.vault_url || '';

                            // Handle tenant_id (can be plaintext or from config object)
                            if (tenantInput) {
                                if (azureConfig.tenant_id_plaintext) {
                                    tenantInput.value = azureConfig.tenant_id_plaintext;
                                } else if (azureConfig.tenant_id) {
                                    tenantInput.value = azureConfig.tenant_id;
                                }
                            }

                            // Handle client_id (can be plaintext or from config object)
                            if (clientIdInput) {
                                if (azureConfig.client_id_plaintext) {
                                    clientIdInput.value = azureConfig.client_id_plaintext;
                                } else if (azureConfig.client_id) {
                                    clientIdInput.value = azureConfig.client_id;
                                }
                            }

                            // Populate credential field for client_secret using CredentialFieldHelper
                            var credentialWrapper = serverEl.querySelector('.credential-field-wrapper');
                            if (credentialWrapper && azureConfig) {
                                // Build credential data from config (handle both flat and hybrid formats)
                                var credentialData = {
                                    plaintext_value: azureConfig.client_secret_plaintext || azureConfig.client_secret || null,
                                    secret_reference: azureConfig.client_secret_reference || null
                                };
                                CredentialFieldHelper.populateCredentialField(credentialWrapper, credentialData);
                            }
                        }
                    }
                } else if (integration.type === 'Luna HSM' || integration.type === 'Luna') {
                    typeDropdown.value = 'key-store';
                    updateClmIntegrationDisplay();
                    
                    var keyStoreDropdown = document.getElementById('clmKeyStoreTypeDropdown');
                    keyStoreDropdown.value = 'luna-hsm';
                    updateClmKeyStoreDisplay();
                    
                    // Clear existing devices and add one with data
                    document.getElementById('clmKeyStoreLunaDevicesList').innerHTML = '';
                    addCLMKeyStoreLunaForm();
                    
                    // Get the device form that was just added
                    var deviceEl = document.querySelector('[data-clm-keystore-luna]');
                    if (deviceEl) {
                        var deviceId = deviceEl.getAttribute('data-clm-keystore-luna');

                        // Get Luna HSM config from nested structure
                        var lunaConfig = config.luna_hsm && config.luna_hsm.devices && config.luna_hsm.devices[0] ? config.luna_hsm.devices[0] : config.luna_hsm || {};

                        // Populate device fields
                        var nameInput = deviceEl.querySelector('[data-clm-keystore-luna-name]');
                        var pkcs11Input = deviceEl.querySelector('[data-clm-keystore-luna-pkcs11-path]');

                        if (nameInput) nameInput.value = lunaConfig.device_name || integration.name;
                        if (pkcs11Input) pkcs11Input.value = lunaConfig.library_path || '';

                        // Add a partition form and populate it
                        addCLMKeyStoreLunaPartitionForm(deviceId);

                        var partitionEl = deviceEl.querySelector('[data-clm-keystore-luna-partition]');
                        if (partitionEl) {
                            var partitionNameInput = partitionEl.querySelector('[data-clm-keystore-luna-partition-name]');
                            var slotInput = partitionEl.querySelector('[data-clm-keystore-luna-slot-index]');

                            if (partitionNameInput) partitionNameInput.value = lunaConfig.partition_name || '';
                            if (slotInput) slotInput.value = lunaConfig.slot !== undefined ? lunaConfig.slot : '0';

                            // Populate credential field for partition password using CredentialFieldHelper
                            var credentialWrapper = partitionEl.querySelector('.credential-field-wrapper');
                            if (credentialWrapper && lunaConfig) {
                                // Build credential data from config (handle both flat and hybrid formats)
                                var credentialData = {
                                    plaintext_value: lunaConfig.pin_plaintext || lunaConfig.pin || null,
                                    secret_reference: lunaConfig.pin_reference || null
                                };
                                CredentialFieldHelper.populateCredentialField(credentialWrapper, credentialData);
                            }
                        }
                    }
                }
                
                // Disable type dropdowns in edit mode (can't change type)
                typeDropdown.disabled = true;
                if (document.getElementById('clmCertificateStoreTypeDropdown')) {
                    document.getElementById('clmCertificateStoreTypeDropdown').disabled = true;
                }
                if (document.getElementById('clmKeyStoreTypeDropdown')) {
                    document.getElementById('clmKeyStoreTypeDropdown').disabled = true;
                }
                
                // Open the modal
                var modal = document.getElementById('newCLMIntegrationModal');
                if (modal) {
                    modal.style.display = 'flex';
                    modal.classList.add('active');
                    // Add scrollable content to modal if it's too large
                    var modalContent = modal.querySelector('.modal-content');
                    if (modalContent) {
                        modalContent.style.maxHeight = '85vh';
                        modalContent.style.overflowY = 'auto';
                    }
                }
                
            } catch (error) {
                
                showAlert('Error loading integration: ' + error.message, 'error');
            }
        }
        
        function resetCLMIntegrationModal() {
            // Reset edit mode
            editingIntegrationId = null;
            
            // Reset modal title
            var modalHeader = document.querySelector('#newCLMIntegrationModal .modal-header h2');
            var modalBtn = document.querySelector('#newCLMIntegrationModal .modal-footer .btn-primary');
            if (modalHeader) modalHeader.textContent = 'Add Integration';
            if (modalBtn) modalBtn.textContent = 'Create Integration';
            
            // Clear fields
            var nameField = document.getElementById('clmIntegrationName');
            var typeDropdown = document.getElementById('clmIntegrationTypeDropdown');
            if (nameField) nameField.value = '';
            if (typeDropdown) {
                typeDropdown.value = '';
                typeDropdown.disabled = false;
            }
            
            var certStoreDropdown = document.getElementById('clmCertificateStoreTypeDropdown');
            if (certStoreDropdown) {
                certStoreDropdown.value = '';
                certStoreDropdown.disabled = false;
            }
            
            var keyStoreDropdown = document.getElementById('clmKeyStoreTypeDropdown');
            if (keyStoreDropdown) {
                keyStoreDropdown.value = '';
                keyStoreDropdown.disabled = false;
            }
            
            // Hide all config sections
            var certSection = document.getElementById('clmCertificateStoreSection');
            var keySection = document.getElementById('clmKeyStoreSection');
            if (certSection) certSection.style.display = 'none';
            if (keySection) keySection.style.display = 'none';
            
            // Clear server lists
            var ejbcaList = document.getElementById('clmEjbcaServersList');
            var azureList = document.getElementById('clmAzureKeyVaultServersList');
            var lunaList = document.getElementById('clmKeyStoreLunaDevicesList');
            var keyStoreAzureList = document.getElementById('clmKeyStoreAzureServersList');
            
            if (ejbcaList) ejbcaList.innerHTML = '';
            if (azureList) azureList.innerHTML = '';
            if (lunaList) lunaList.innerHTML = '';
            if (keyStoreAzureList) keyStoreAzureList.innerHTML = '';
        }

        async function loadConnectorDetailsContent(integrationId, titleEl, bodyEl) {
            try {
                // Get integration data
                const response = await fetch('/api/v1/inventory/integrations');
                const data = await response.json();
                const integration = data.integrations.find(i => i.id === integrationId);
                
                if (!integration) {
                    bodyEl.innerHTML = '<div style="color: #ef4444; padding: 12px;">Integration not found</div>';
                    return;
                }
                
                // Update title with icon
                var icon = getConnectorIcon(integration.type);
                titleEl.innerHTML = icon + ' ' + escapeHtml(integration.name);
                
                var html = '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px;">' +
                        '<div style="background: #f8fafc; padding: 16px; border-radius: 8px;">' +
                            '<div style="font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Name</div>' +
                            '<div style="font-weight: 600; color: #374151; font-size: 15px;">' + escapeHtml(integration.name) + '</div>' +
                        '</div>' +
                        '<div style="background: #f8fafc; padding: 16px; border-radius: 8px;">' +
                            '<div style="font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Type</div>' +
                            '<div style="font-weight: 600; color: #374151; font-size: 15px;">' + (integration.type === 'promoted' ? 'Virtual Connector Service' : escapeHtml(integration.type)) + '</div>' +
                        '</div>' +
                        '<div style="background: #f8fafc; padding: 16px; border-radius: 8px;">' +
                            '<div style="font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Status</div>' +
                            '<div style="font-weight: 600; font-size: 15px; color: ' + (integration.status === 'Healthy' ? '#10b981' : '#ef4444') + ';">' + integration.status + '</div>' +
                        '</div>' +
                        '<div style="background: #f8fafc; padding: 16px; border-radius: 8px;">' +
                            '<div style="font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Last Sync</div>' +
                            '<div style="font-weight: 600; color: #374151; font-size: 15px;">' + (integration.last_sync ? new Date(integration.last_sync).toLocaleString() : 'Never') + '</div>' +
                        '</div>' +
                    '</div>';
                
                // If EJBCA, load CA information
                if (integration.type === 'EJBCA') {
                    try {
                        const casResponse = await fetch('/api/v1/inventory/integrations/' + integrationId + '/cas');
                        if (casResponse.ok) {
                            const casData = await casResponse.json();
                            const cas = casData.cas || [];
                            
                            html += '<div style="margin-top: 8px;">' +
                                '<div style="font-size: 14px; font-weight: 600; color: #374151; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">' +
                                    '<span style="font-size: 18px;">🏛️</span> Certificate Authorities' +
                                '</div>';
                            
                            if (cas.length === 0) {
                                html += '<div style="color: #6b7280; font-size: 13px; padding: 20px; background: #f8fafc; border-radius: 8px; text-align: center;">No certificate authorities available.</div>';
                            } else {
                                html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">';
                                cas.forEach(function(ca) {
                                    var isDisabled = !integration.enabled;
                                    var displayStatus = isDisabled ? 'Disabled' : ca.status;
                                    var statusBg = isDisabled ? '#f1f5f9' : (ca.status === 'Active' ? '#dcfce7' : '#fee2e2');
                                    var statusColor = isDisabled ? '#64748b' : (ca.status === 'Active' ? '#166534' : '#991b1b');

                                    // Build display items for extended fields
                                    var extendedInfo = '<div style="margin-top: 8px; margin-bottom: 8px; font-size: 11px; color: #64748b; line-height: 1.5;">';

                                    // Subject DN
                                    if (ca.subject_dn && ca.subject_dn !== ca.name) {
                                        extendedInfo += '<div style="margin-bottom: 4px;"><span style="font-weight: 600;">Subject:</span> ' + escapeHtml(ca.subject_dn) + '</div>';
                                    }

                                    // Issuer DN
                                    if (ca.issuer_dn) {
                                        extendedInfo += '<div style="margin-bottom: 4px;"><span style="font-weight: 600;">Issuer:</span> ' + escapeHtml(ca.issuer_dn) + '</div>';
                                    }

                                    // Expiration date with color coding
                                    if (ca.expiration_date) {
                                        var expDate = new Date(ca.expiration_date);
                                        var now = new Date();
                                        var daysUntilExpiry = Math.floor((expDate - now) / (1000 * 60 * 60 * 24));
                                        var expColor = '#10b981'; // green
                                        var expText = 'Expires: ' + expDate.toLocaleDateString();

                                        if (daysUntilExpiry < 0) {
                                            expColor = '#ef4444'; // red
                                            expText = '⚠️ EXPIRED: ' + expDate.toLocaleDateString();
                                        } else if (daysUntilExpiry < 180) {
                                            expColor = '#f59e0b'; // orange
                                            expText = '⚠️ Expires in ' + daysUntilExpiry + ' days';
                                        }

                                        extendedInfo += '<div style="margin-bottom: 4px; color: ' + expColor + '; font-weight: 500;">' + expText + '</div>';
                                    }

                                    // Key algorithm
                                    if (ca.key_algorithm && ca.key_algorithm !== 'Unknown') {
                                        var keySpec = ca.key_spec && ca.key_spec !== 'Unknown' ? ' ' + ca.key_spec : '';
                                        extendedInfo += '<div style="margin-bottom: 4px;"><span style="font-weight: 600;">Key:</span> ' + escapeHtml(ca.key_algorithm) + keySpec + '</div>';
                                    }

                                    // CRL period
                                    if (ca.crl_period) {
                                        var crlHours = parseInt(ca.crl_period);
                                        var crlText = crlHours < 24 ? crlHours + ' hours' : Math.round(crlHours / 24) + ' days';
                                        extendedInfo += '<div style="margin-bottom: 4px;"><span style="font-weight: 600;">CRL:</span> ' + crlText + '</div>';
                                    }

                                    extendedInfo += '</div>';

                                    html += '<div style="background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e5e7eb; opacity: ' + (isDisabled ? '0.6' : '1') + ';">' +
                                        '<div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">' +
                                            '<div style="font-weight: 600; color: #374151;">' + escapeHtml(ca.name) + '</div>' +
                                            '<span style="padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; background: ' + statusBg + '; color: ' + statusColor + ';">' + displayStatus + '</span>' +
                                        '</div>' +
                                        '<div style="font-size: 12px; color: #6b7280; margin-bottom: 8px; word-break: break-all;">' + escapeHtml(ca.subject) + '</div>' +
                                        extendedInfo +
                                        '<div style="font-size: 13px; color: #374151; font-weight: 500;">📜 ' + ca.certificate_count + ' certificates</div>' +
                                    '</div>';
                                });
                                html += '</div>';
                            }
                            html += '</div>';
                        }
                    } catch (error) {
                        
                        html += '<div style="color: #ef4444; margin-top: 12px; padding: 12px; background: #fef2f2; border-radius: 8px;">Error loading certificate authorities</div>';
                    }
                }

                // If Promoted Scans, show individual scans
                if (integration.type === 'promoted') {
                    try {
                        const scansResponse = await fetch('/api/v1/clm/integrations/' + integrationId + '/promoted-scans');
                        if (scansResponse.ok) {
                            const scansData = await scansResponse.json();
                            const scans = scansData.scans || [];

                            html += '<div style="margin-top: 8px;">' +
                                '<div style="font-size: 14px; font-weight: 600; color: #374151; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">' +
                                    '<span style="font-size: 18px;">📌</span> Promoted Scans' +
                                '</div>';

                            if (scans.length === 0) {
                                html += '<div style="color: #6b7280; font-size: 13px; padding: 20px; background: #f8fafc; border-radius: 8px; text-align: center;">No promoted scans available.</div>';
                            } else {
                                html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">';
                                scans.forEach(function(scan) {
                                    var promotedDate = scan.promoted_at ? new Date(scan.promoted_at).toLocaleDateString() : 'Unknown';

                                    html += '<div style="background: #f8fafc; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; display: flex; align-items: center; justify-content: space-between; gap: 16px; font-size: 13px;">' +
                                        '<div style="display: flex; align-items: center; gap: 12px; flex: 1;">' +
                                            '<div style="font-weight: 600; color: #374151;">' + escapeHtml(scan.name) + '</div>' +
                                            '<span style="padding: 2px 8px; border-radius: 4px; font-weight: 600; background: #fef3c7; color: #92400e; white-space: nowrap;">📌 ' + promotedDate + '</span>' +
                                            '<span style="color: #6b7280;">📜 ' + scan.certificate_count + '</span>' +
                                            '<span style="color: #6b7280;">🔑 ' + scan.key_count + '</span>' +
                                        '</div>' +
                                        '<button onclick="deleteScanAssets(\'' + escapeHtml(scan.name) + '\', ' + integrationId + '); event.stopPropagation();" ' +
                                            'style="padding: 4px 8px; background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; border-radius: 6px; cursor: pointer; font-weight: 500; white-space: nowrap;">' +
                                            '🗑️ Delete' +
                                        '</button>' +
                                    '</div>';
                                });
                                html += '</div>';
                            }
                            html += '</div>';
                        }
                    } catch (error) {
                        html += '<div style="color: #ef4444; margin-top: 12px; padding: 12px; background: #fef2f2; border-radius: 8px;">Error loading promoted scans</div>';
                    }
                }

                // If Azure Key Vault, show vault info
                if (integration.type === 'Azure Key Vault' && integration.config && integration.config.vaults) {
                    html += '<div style="margin-top: 8px;">' +
                        '<div style="font-size: 14px; font-weight: 600; color: #374151; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">' +
                            '<span style="font-size: 18px;">☁️</span> Configured Vaults' +
                        '</div>' +
                        '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">';
                    integration.config.vaults.forEach(function(vault) {
                        html += '<div style="background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e5e7eb;">' +
                            '<div style="font-weight: 600; color: #374151;">' + escapeHtml(vault.vault_url || vault.name || 'Vault') + '</div>' +
                        '</div>';
                    });
                    html += '</div></div>';
                }
                
                // If Luna HSM, show device info
                if ((integration.type === 'Luna HSM' || integration.type === 'Luna') && integration.config && integration.config.servers) {
                    html += '<div style="margin-top: 8px;">' +
                        '<div style="font-size: 14px; font-weight: 600; color: #374151; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">' +
                            '<span style="font-size: 18px;">🔐</span> HSM Devices' +
                        '</div>' +
                        '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">';
                    integration.config.servers.forEach(function(server) {
                        html += '<div style="background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e5e7eb;">' +
                            '<div style="font-weight: 600; color: #374151;">' + escapeHtml(server.host || server.url || 'Device') + '</div>' +
                            (server.partition ? '<div style="font-size: 12px; color: #6b7280; margin-top: 4px;">Partition: ' + escapeHtml(server.partition) + '</div>' : '') +
                        '</div>';
                    });
                    html += '</div></div>';
                }
                
                bodyEl.innerHTML = html;
                
            } catch (error) {
                
                bodyEl.innerHTML = '<div style="color: #ef4444; padding: 20px; text-align: center;">Error loading details: ' + error.message + '</div>';
            }
        }

        async function deleteScanAssets(scanName, integrationId) {
            if (!confirm(`Delete all assets from scan "${scanName}"?\n\nThis will remove:\n- All certificates\n- All keys\n\nCannot be undone.`)) {
                return;
            }

            try {
                const response = await fetch('/api/v1/clm/integrations/' + integrationId + '/promoted-scans/' + encodeURIComponent(scanName), {
                    method: 'DELETE'
                });

                if (!response.ok) throw new Error('Failed to delete');

                const data = await response.json();
                showAlert(`Deleted ${data.deleted_certificates || 0} certificates and ${data.deleted_keys || 0} keys`, 'success');

                // Reload details
                const container = document.getElementById('connector-details-container');
                const titleEl = document.getElementById('connector-details-title');
                const bodyEl = document.getElementById('connector-details-body');

                if (container && bodyEl) {
                    loadConnectorDetailsContent(integrationId, titleEl, bodyEl);
                }

                // Refresh integrations list to update card stats
                await loadCLMIntegrations();

            } catch (error) {
                showAlert('Failed to delete scan assets: ' + error.message, 'error');
            }
        }

        /**
         * Get integration type badge HTML
         */
        function getIntegrationTypeBadge(type) {
            const badges = {
                'EJBCA': { bg: '#dbeafe', color: '#1e40af', icon: '🏛️' },
                'Azure Key Vault': { bg: '#e0e7ff', color: '#4338ca', icon: '☁️' },
                'Luna HSM': { bg: '#fef3c7', color: '#92400e', icon: '🔐' },
                'Luna': { bg: '#fef3c7', color: '#92400e', icon: '🔐' },
                'TLS': { bg: '#d1fae5', color: '#065f46', icon: '🔍'},
                'File Share': { bg: '#f3e8ff', color: '#7c3aed', icon: '📁' }
            };
            
            const badge = badges[type] || { bg: '#f1f5f9', color: '#475569', icon: '🔗' };
            return `<span style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; background: ${badge.bg}; color: ${badge.color};">${badge.icon} ${escapeHtml(type)}</span>`;
        }

        // Current policy assessment type
        let currentPolicyAssessmentType = 'pki_health_check';
        
        /**
         * Select assessment type for policy creation
         */
        function selectPolicyAssessmentType(type) {
            currentPolicyAssessmentType = type;
            
            // Update visual selection
            document.querySelectorAll('.policy-type-radio').forEach(radio => {
                radio.classList.remove('selected');
            });
            document.querySelector(`.policy-type-radio[data-type="${type}"]`).classList.add('selected');
            
            // Auto-select matching category if PQC
            if (type === 'pqc_assessment') {
                document.getElementById('policyV2Category').value = 'pqc-migration';
            }
        }

        function startScanRuntimeUpdate(scanId) {
            if (scanRuntimeIntervals[scanId]) {
                clearInterval(scanRuntimeIntervals[scanId]);
            }

            const scan = scans.find(s => s.id === scanId);
            const isQueued = scan && scan.status === 'Queued';

            // Preserve existing start time if already running/queued, otherwise initialize it
            if (isQueued) {
                if (!scanQueuedTimes[scanId]) {
                    scanQueuedTimes[scanId] = Date.now();
                }
            } else {
                if (!scanStartTimes[scanId]) {
                    if (scan && scan.scanStartTime) {
                        scanStartTimes[scanId] = scan.scanStartTime;
                    } else {
                        scanStartTimes[scanId] = Date.now();
                        if (scan) {
                            scan.scanStartTime = scanStartTimes[scanId];
                        }
                    }
                }
            }

            // Update runtime every second
            scanRuntimeIntervals[scanId] = setInterval(() => {
                const runtimeEl = document.getElementById(`runtime${scanId}`);
                if (runtimeEl) {
                    const timeSource = isQueued ? scanQueuedTimes[scanId] : scanStartTimes[scanId];
                    const elapsed = Math.floor((Date.now() - timeSource) / 1000);
                    const hours = Math.floor(elapsed / 3600);
                    const minutes = Math.floor((elapsed % 3600) / 60);
                    const seconds = elapsed % 60;

                    let timeStr = '';
                    if (hours > 0) {
                        timeStr = `${hours}h ${minutes}m ${seconds}s`;
                    } else if (minutes > 0) {
                        timeStr = `${minutes}m ${seconds}s`;
                    } else {
                        timeStr = `${seconds}s`;
                    }

                    runtimeEl.textContent = `(${timeStr})`;
                } else {
                    clearInterval(scanRuntimeIntervals[scanId]);
                }
            }, 2000);

            // Start log polling only for running scans (not for queued)
            if (!isQueued) {
                startScanLogPolling(scanId);
            }
        }

        function startScanLogPolling(scanId) {
            if (scanLogIntervals[scanId]) {
                clearInterval(scanLogIntervals[scanId]);
            }
            
            scanLogIntervals[scanId] = setInterval(async () => {
                try {
                    const logsResponse = await fetch(`/api/v1/scans/${scanId}/logs`);
                    if (logsResponse.ok) {
                        const logsData = await logsResponse.json();
                        const logLine = document.getElementById(`latestLog${scanId}`);
                        
                        if (logLine && logsData.logs && logsData.logs.length > 0) {
                            // Get the latest log (last one in the array)
                            const latest = logsData.logs[logsData.logs.length - 1];
                            const logText = latest.log_entry;
                            logLine.textContent = `[${new Date(latest.timestamp).toLocaleTimeString()}] ${logText}`;
                            
                            // Check if scan is complete by looking at the last log message
                            // Completion indicators: "Report saved", "ERROR", "Scan completed successfully", "Warning: No JSON"
                            const isComplete = logText.includes('Report saved') || 
                                             logText.includes('ERROR') || 
                                             logText.includes('Scan completed successfully') ||
                                             logText.includes('Warning: No JSON');
                            
                            if (isComplete) {
                                // Scan is done - stop polling and force refresh table to remove elapsed time/logs
                                clearInterval(scanLogIntervals[scanId]);
                                delete scanLogIntervals[scanId];
                                stopScanRuntimeUpdate(scanId);
                                
                                // Force refresh table after short delay to show final state
                                setTimeout(() => {
                                    forceRefreshScansTable();
                                }, 500);
                            }
                        }
                    }
                } catch (error) {
                    
                }
            }, 2000);
        }

        async function forceRefreshScansTable() {
            const tbody = document.getElementById('scans-table-body');
            tbody.innerHTML = '';
            await loadScans();
        }

        function stopScanRuntimeUpdate(scanId) {
            if (scanRuntimeIntervals[scanId]) {
                clearInterval(scanRuntimeIntervals[scanId]);
                delete scanRuntimeIntervals[scanId];
            }
            if (scanLogIntervals[scanId]) {
                clearInterval(scanLogIntervals[scanId]);
                delete scanLogIntervals[scanId];
            }
            if (scanStartTimes[scanId]) {
                delete scanStartTimes[scanId];
            }
            if (scanQueuedTimes[scanId]) {
                delete scanQueuedTimes[scanId];
            }
        }

        // Scan progress tracking
        let currentScanId = null;
        let scanInProgress = false;

        // Initialize
        document.addEventListener('DOMContentLoaded', async function() {
            await loadUserSession(); // Wait for user session first to apply role-based visibility
            setupTabButtons();
            setupModalTabs();
            setupCheckboxes();
            
            // Now that tabs are set up, switch to role-appropriate default tab
            const role = document.body.className.match(/user-role-(\S+)/)?.[1];
            if (role) {
                setDefaultTabByRole(role);
            }
            
            // Load engagement context selector
            await loadEngagementsForContext();
            updateEngagementDependentButtons();
            loadData();
        });

        // Load user session and apply role-based visibility
        async function loadUserSession() {
            try {
                const response = await fetch('/api/session');
                if (!response.ok) {
                    
                    // Don't redirect, just log the error - allow page to load
                    return;
                }
                const data = await response.json();
                const username = data.username || 'User';
                const role = data.role || 'scan-user';
                
                // Update username display
                document.getElementById('currentUsername').textContent = username;
                //document.getElementById('userDropdownUsername').textContent = username;
                
                // Update role display
                const roleDisplay = document.getElementById('currentUserRole');
                if (roleDisplay) {
                    roleDisplay.textContent = role;
                }
                
                // Apply role-based visibility
                document.body.classList.add('role-loaded', `user-role-${role}`);
                
                // Don't switch tabs here - let the main init flow handle it after setupTabButtons
                
            } catch (error) {
                
                // Don't redirect on error, allow page to load with default visibility
            }
        }

        // Set default visible tab based on user role
        function setDefaultTabByRole(role) {
            let defaultTab = 'landing'; // Default to landing page for all roles
            
            // Switch to the default tab for this role
            switchMainTab(defaultTab);

            // Load home page analytics
            loadHomePageAnalytics();
        }

        // Tab switching
        function setupTabButtons() {
            // Setup main tabs (Scanning, CLM, KMS, Settings)
            document.querySelectorAll('[data-main-tab]').forEach(btn => {
                btn.addEventListener('click', function() {
                    const mainTabName = this.dataset.mainTab;
                    switchMainTab(mainTabName);
                });
            });
            
            // Setup sub-tabs (within each main tab)
            document.querySelectorAll('.tabs:not([class*="main"]) .tab-button').forEach(btn => {
                btn.addEventListener('click', function() {
                    const tabName = this.dataset.tab;
                    switchTab(tabName);
                });
            });
        }
        
        function switchMainTab(mainTabName) {
            // Hide all main tabs
            document.querySelectorAll('.main-tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Deactivate all main buttons
            document.querySelectorAll('[data-main-tab]').forEach(btn => {
                btn.classList.remove('active');
             });
            
            // Show selected main tab
            document.getElementById(mainTabName).classList.add('active');
            
            // Activate main button
            document.querySelector(`[data-main-tab="${mainTabName}"]`).classList.add('active');
            
            // Show/hide engagement context bar based on tab
            // Only show for "Discover, Assess & Report" tabs (engagements, scanning, doc-scanning)
            const engagementContextBar = document.getElementById('engagement-context-bar');
            if (engagementContextBar) {
                const assessmentTabs = ['engagements', 'scanning', 'doc-scanning'];
                engagementContextBar.style.display = assessmentTabs.includes(mainTabName) ? 'flex' : 'none';
            }
            
            // Show default subtab for this main tab and load data
            if (mainTabName === 'scanning') {
                // Show scans tab by default
                switchTab('scans');
            } else if (mainTabName === 'doc-scanning') {
                // Show assessments tab by default and load data
                switchTab('doc-assessments');
                loadDocumentAssessments();
                loadDocumentTypes();
                loadDocumentTemplates();
                // Update engagement context indicator
                updateDocAssessmentEngagementContext();
            } else if (mainTabName === 'clm') {
                // Show dashboard tab by default and load data
                switchTab('clm-dashboard');
            } else if (mainTabName === 'kms') {
                // Show keys tab by default
                switchTab('kms-keys');
                loadCollectorKeys();
            } else if (mainTabName === 'settings') {
                // Show users tab by default
                switchTab('settings-users');
                loadUsers();
            } else if (mainTabName === 'engagements') {
                // Load engagements data
                loadEngagements();
            } else if (mainTabName === 'reports') {
                // Show crypto asset scans tab by default
                switchTab('reports-crypto-scans');
                loadCryptoAssetReports();
            } else if (mainTabName === 'landing') {
                // Load home page analytics
                loadHomePageAnalytics();
            } else if (mainTabName === 'connectors') {
                // Load connectors with loading banner
                loadConnectorsWithBanner();
            } else if (mainTabName === 'command-center') {
                // Initialize Command Center dashboard
                initCommandCenter();
            } else if (mainTabName === 'certificate-authorities') {
                // Load certificate authorities module
                if (typeof certificateManagement !== 'undefined') {
                    certificateManagement.loadCertificateManagement();
                }
            }
        }

        async function loadHomePageAnalytics() {
            try {
                // === CONTINUOUS MONITORING (CLM) METRICS ===

                // Fetch certificates from inventory
                const certsResponse = await fetch('/api/v1/inventory/search');
                let totalCerts = 0;
                let expiringCerts = 0;
                if (certsResponse.ok) {
                    const certsData = await certsResponse.json();
                    const certs = certsData.certificates || [];
                    totalCerts = certs.length;

                    // Count expiring certificates (< 30 days)
                    const now = new Date();
                    expiringCerts = certs.filter(cert => {
                        if (!cert.expires_on) return false;
                        const expiryDate = new Date(cert.expires_on);
                        const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
                        return daysUntilExpiry < 30 && daysUntilExpiry >= 0;
                    }).length;
                }

                // Fetch keys from lifecycle rotations
                let totalKeys = 0;
                let pqcRiskKeys = 0;
                const keysResponse = await fetch('/api/v1/lifecycle/rotations');
                if (keysResponse.ok) {
                    const keysData = await keysResponse.json();
                    const keys = keysData.keys || [];
                    totalKeys = keys.length;

                    // Count PQC risk (critical vulnerability level)
                    pqcRiskKeys = keys.filter(key => {
                        const pqcAnalysis = key.pqc_analysis || {};
                        return pqcAnalysis.vulnerability_level === 'critical';
                    }).length;
                }

                const totalAssets = totalCerts + totalKeys;

                // Update CLM metrics
                document.getElementById('home-clm-total-assets').textContent = totalAssets;
                document.getElementById('home-clm-certs').textContent = totalCerts;
                document.getElementById('home-clm-keys').textContent = totalKeys;
                document.getElementById('home-clm-pqc-risk').textContent = pqcRiskKeys;
                document.getElementById('home-clm-expiring').textContent = expiringCerts;

                // === ON-DEMAND DISCOVERY (SCANNING) METRICS ===

                // Fetch scan data
                const scansResponse = await fetch('/api/v1/scans');
                let totalScans = 0;
                let totalFindings = 0;
                let lastScanTime = '-';
                if (scansResponse.ok) {
                    const scansData = await scansResponse.json();
                    const scans = scansData.scans || [];
                    totalScans = scans.length;

                    // Count total findings and get last scan time
                    let lastScanDate = null;
                    scans.forEach(scan => {
                        totalFindings += scan.total_findings || 0;
                        if (scan.created_at) {
                            const scanDate = new Date(scan.created_at);
                            if (!lastScanDate || scanDate > lastScanDate) {
                                lastScanDate = scanDate;
                            }
                        }
                    });

                    if (lastScanDate) {
                        const now = new Date();
                        const hoursAgo = Math.floor((now - lastScanDate) / (1000 * 60 * 60));
                        if (hoursAgo < 24) {
                            lastScanTime = hoursAgo + 'h ago';
                        } else {
                            const daysAgo = Math.floor(hoursAgo / 24);
                            lastScanTime = daysAgo + 'd ago';
                        }
                    }
                }

                // Fetch engagement count
                let engagementCount = 0;
                const engResponse = await fetch('/api/v1/engagements');
                if (engResponse.ok) {
                    const engData = await engResponse.json();
                    engagementCount = (engData.engagements || []).length;
                }

                // Fetch scan configurations count
                let scanConfigCount = 0;
                const configsResponse = await fetch('/api/v1/configurations');
                if (configsResponse.ok) {
                    const configsData = await configsResponse.json();
                    scanConfigCount = (configsData.configurations || []).length;
                }

                // Update scanning metrics
                document.getElementById('home-scan-total').textContent = totalScans;
                document.getElementById('home-scan-engagements').textContent = engagementCount;
                document.getElementById('home-scan-findings').textContent = totalFindings;
                document.getElementById('home-scan-configs').textContent = scanConfigCount;
                document.getElementById('home-scan-last-time').textContent = lastScanTime;

            } catch (error) {

            }
        }

        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });

            // Deactivate all buttons
            document.querySelectorAll('.tabs:not(.main-tabs) .tab-button').forEach(btn => {
                btn.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(tabName).classList.add('active');

            // Activate button
            document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

            // Update sidebar active state for Reports sub-tabs
            if (tabName.startsWith('reports-')) {
                document.querySelectorAll('.sidebar-nav-child').forEach(b => b.classList.remove('active'));
                const sidebarChild = document.querySelector(`.sidebar-nav-child[data-reports-tab="${tabName}"]`);
                if (sidebarChild) {
                    sidebarChild.classList.add('active');
                }
            }

            // Update sidebar active state for Settings sub-tabs
            if (tabName.startsWith('settings-')) {
                document.querySelectorAll('.sidebar-nav-child').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.sidebar-nav-item').forEach(b => b.classList.remove('active'));
                const sidebarChild = document.querySelector(`.sidebar-nav-child[data-settings-tab="${tabName}"]`);
                if (sidebarChild) {
                    sidebarChild.classList.add('active');
                } else {
                    // If it's settings-general, activate the Settings nav item
                    if (tabName === 'settings-general') {
                        const settingsItem = document.querySelector('.sidebar-nav-item[data-settings-tab="settings-general"]');
                        if (settingsItem) {
                            settingsItem.classList.add('active');
                        }
                    }
                }
            }

            // Reload data when switching tabs
            if (tabName === 'scans') loadScans();
            if (tabName === 'configurations') loadConfigurations();
            if (tabName === 'policies') loadPoliciesV2();
            if (tabName === 'engagements') loadEngagements();
            if (tabName === 'reassess') loadReassessments();

            // Assets module tabs
            if (tabName === 'assets-dashboard') {
                loadAssetsDashboard();
            }
            if (tabName === 'assets-certificates') {
                loadAssetsCertificates();
            }
            if (tabName === 'assets-keys') {
                loadAssetsKeys();
            }

            // Compliance module
            if (tabName === 'compliance') {
                initCompliancyTab();
            }

            // Lifecycle module tabs
            if (tabName === 'lifecycle-overview') {
                loadLifecycleOverview();
            }
            if (tabName === 'lifecycle-certificates') {
                loadLifecycleCertificates();
            }
            if (tabName === 'lifecycle-keys') {
                loadLifecycleKeys();
            }
            if (tabName === 'lifecycle-policies') {
                loadLifecyclePolicies();
            }

            // Legacy CLM tabs (backward compatibility)
            if (tabName === 'clm-dashboard') {
                loadCLMIntegrations();
                loadCollectorCertificates();
            }
            if (tabName === 'clm-certificates') {
                loadAssetsCertificates();
            }
            if (tabName === 'clm-compliancy') {
                initCompliancyTab();
            }

            // Reports sub-tabs
            if (tabName === 'reports-crypto-scans') {
                loadCryptoAssetReports();
            }
            if (tabName === 'reports-doc-scans') {
                loadDocumentScanReports();
            }
            if (tabName === 'reports-scan-reporting') {
                loadScanReportingSelectors();
            }
            if (tabName === 'reports-clm-reporting') {
                loadCLMReportingSelectors();
            }
            // RBAC tab initialization
            if (tabName === 'settings-rbac') {
                
                if (typeof initializeRBAC === 'function') {
                    initializeRBAC();
                } else {
                    
                }
            }
        }

        // Background polling for scan status updates
        let scanStatusPollInterval = null;

        function startBackgroundScanPolling() {
            // Poll every 2 seconds for any status changes
            scanStatusPollInterval = setInterval(async () => {
                try {
                    // Get all running and queued scans from current view
                    const runningScans = scans.filter(s => s.status === 'Running' || s.status === 'Queued');

                    if (runningScans.length > 0) {
                        // Check status of each running scan
                        for (const scan of runningScans) {
                            try {
                                const statusResponse = await fetch(`/api/v1/scans/${scan.id}/status`);

                                if (statusResponse.ok) {
                                    const statusData = await statusResponse.json();

                                    // Update the local scan object
                                    const localScan = scans.find(s => s.id === scan.id);
                                    if (localScan) {
                                        const wasRunning = localScan.status === 'Running';
                                        const wasQueued = localScan.status === 'Queued';
                                        const isNowQueued = statusData.status === 'Queued';
                                        const isNowRunning = statusData.status === 'Running';

                                        // Track when scan enters Queued state
                                        if (!wasQueued && isNowQueued) {
                                            scanQueuedTimes[scan.id] = Date.now();
                                        }

                                        // Clear queued time when transitioning away from Queued
                                        if (wasQueued && !isNowQueued && scanQueuedTimes[scan.id]) {
                                            delete scanQueuedTimes[scan.id];
                                        }

                                        localScan.status = statusData.status;
                                        // Also update collector_results if present in response
                                        if (statusData.collector_results) {
                                            localScan.collector_results = statusData.collector_results;
                                        }

                                        // If status changed, fully re-render the table
                                        if (wasRunning && statusData.status !== 'Running') {
                                            // Transitioning away from Running
                                            stopScanRuntimeUpdate(scan.id);
                                            renderScans();
                                        } else if (wasQueued && statusData.status !== 'Queued') {
                                            // Transitioning away from Queued (to Running, Failed, etc.)
                                            stopScanRuntimeUpdate(scan.id);
                                            renderScans();
                                        } else if (!wasQueued && isNowQueued) {
                                            // Just entered Queued state
                                            renderScans();
                                        } else if (isNowQueued && !scanRuntimeIntervals[scan.id]) {
                                            // Queued scan but timer not started yet - start it
                                            startScanRuntimeUpdate(scan.id);
                                        } else {
                                            // Status stays the same (Running remains Running, or other stable states)
                                            // Just update visible elements
                                            const statusBadge = document.getElementById(`status${scan.id}`);
                                            if (statusBadge) {
                                                statusBadge.textContent = statusData.status;
                                                statusBadge.className = `status-badge status-${statusData.status.toLowerCase().replace(' ', '-')}`;
                                            }
                                        }
                                    }
                                }
                            } catch (error) {
                                // Silently handle polling errors
                            }
                        }
                    }
                } catch (error) {
                    // Silently handle main polling loop errors
                }
            }, 2000);  // Poll every 2 seconds
        }

        function stopBackgroundScanPolling() {
            if (scanStatusPollInterval) {
                clearInterval(scanStatusPollInterval);
                scanStatusPollInterval = null;
            }
        }

        // Start polling on page load
        window.addEventListener('load', () => {
            setupUserDropdown();
            setupMainTabListeners();
            startBackgroundScanPolling();
        });

        // Modal tabs
        function setupModalTabs() {
            document.querySelectorAll('.modal-tab-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const tabName = this.dataset.modalTab;
                    const container = this.closest('.modal-content');
                    
                    container.querySelectorAll('.modal-tab-btn').forEach(b => b.classList.remove('active'));
                    container.querySelectorAll('.modal-tab-content').forEach(t => t.classList.remove('active'));
                    
                    this.classList.add('active');
                    container.querySelector(`#${tabName}`).classList.add('active');
                });
            });

            // Setup nested modal tabs
            document.querySelectorAll('.nested-modal-tab-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const tabName = this.dataset.nestedTab;
                    const container = this.closest('.modal-tab-content');
                    
                    container.querySelectorAll('.nested-modal-tab-btn').forEach(b => b.classList.remove('active'));
                    container.querySelectorAll('.nested-modal-tab-content').forEach(t => t.classList.remove('active'));
                    
                    this.classList.add('active');
                    container.querySelector(`#${tabName}`).classList.add('active');
                });
            });
        }

        // Checkbox handling for configuration options (backward compatible with hidden checkboxes)
        function setupCheckboxes() {
            // Setup change listeners on hidden checkboxes for backward compatibility
            document.getElementById('tlsEnabled').addEventListener('change', function() {
                updateConfigSourceUI('tls', this.checked);
            });

            document.getElementById('azureEnabled').addEventListener('change', function() {
                updateConfigSourceUI('azure', this.checked);
            });

            document.getElementById('crlEnabled').addEventListener('change', function() {
                updateConfigSourceUI('crl', this.checked);
            });

            document.getElementById('ejbcaEnabled').addEventListener('change', function() {
                updateConfigSourceUI('ejbca', this.checked);
            });

            document.getElementById('hsmEnabled').addEventListener('change', function() {
                updateConfigSourceUI('hsm', this.checked);
            });

            document.getElementById('fileScanEnabled').addEventListener('change', function() {
                updateConfigSourceUI('filescan', this.checked);
            });
        }

        // New sidebar config modal functions
        function switchConfigPanel(panelId) {
            // Update nav items
            document.querySelectorAll('.config-nav-item').forEach(item => {
                item.classList.remove('active');
            });
            document.querySelector(`.config-nav-item[data-config-panel="${panelId}"]`)?.classList.add('active');

            // Update panels
            document.querySelectorAll('.config-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            document.getElementById(panelId)?.classList.add('active');
        }

        // Toggle config source (called from toggle switches)
        function toggleConfigSource(source) {
            const checkbox = document.getElementById(source === 'filescan' ? 'fileScanEnabled' : `${source}Enabled`);
            if (checkbox) {
                checkbox.checked = !checkbox.checked;
                checkbox.dispatchEvent(new Event('change'));
            }
        }

        // Update UI for config source enable/disable
        function updateConfigSourceUI(source, enabled) {
            // Update toggle switch
            const toggleSwitch = document.getElementById(`${source}Toggle`);
            if (toggleSwitch) {
                if (enabled) {
                    toggleSwitch.classList.add('active');
                } else {
                    toggleSwitch.classList.remove('active');
                }
            }

            // Update options visibility
            const optionsId = source === 'filescan' ? 'fileScanOptions' : `${source}Options`;
            const options = document.getElementById(optionsId);
            if (options) {
                if (enabled) {
                    options.classList.add('enabled');
                } else {
                    options.classList.remove('enabled');
                }
            }

            // Update nav status indicator
            const navStatus = document.getElementById(`nav-status-${source}`);
            if (navStatus) {
                if (enabled) {
                    navStatus.classList.add('enabled');
                } else {
                    navStatus.classList.remove('enabled');
                }
            }

            // Update enabled sources count
            updateEnabledSourcesCount();

            // Update footer status
            updateConfigFooterStatus();
        }

        // Count enabled sources and update display
        function updateEnabledSourcesCount() {
            const sources = ['tls', 'crl', 'azure', 'ejbca', 'hsm', 'fileScan'];
            let count = 0;
            sources.forEach(source => {
                const checkbox = document.getElementById(`${source}Enabled`);
                if (checkbox && checkbox.checked) {
                    count++;
                }
            });
            const countEl = document.getElementById('enabledSourcesCount');
            if (countEl) {
                countEl.textContent = count;
            }
            return count;
        }

        // Update footer status text
        function updateConfigFooterStatus() {
            const count = updateEnabledSourcesCount();
            const statusEl = document.getElementById('configFooterStatus');
            if (statusEl) {
                if (count === 0) {
                    statusEl.textContent = 'Enable at least one scan source to continue';
                } else if (count === 1) {
                    statusEl.textContent = '1 scan source enabled';
                } else {
                    statusEl.textContent = `${count} scan sources enabled`;
                }
            }
        }

        // Reset config modal to initial state
        function resetConfigModal() {
            // Reset name
            document.getElementById('configName').value = '';

            // Reset all checkboxes and their UI
            const sources = ['tls', 'crl', 'azure', 'ejbca', 'hsm'];
            sources.forEach(source => {
                const checkbox = document.getElementById(`${source}Enabled`);
                if (checkbox) {
                    checkbox.checked = false;
                    updateConfigSourceUI(source, false);
                }
            });
            // Handle fileScan separately due to different naming
            const fileScanCheckbox = document.getElementById('fileScanEnabled');
            if (fileScanCheckbox) {
                fileScanCheckbox.checked = false;
                updateConfigSourceUI('filescan', false);
            }

            // Reset to first panel
            switchConfigPanel('tls-panel');

            // Clear form fields
            document.getElementById('tlsSubnets').value = '';
            document.getElementById('tlsHostnames').value = '';
            document.getElementById('tlsPorts').value = '443';
            document.getElementById('tlsTimeout').value = '10';
            document.getElementById('fileScanPaths').value = '';
            document.getElementById('fileScanExtensions').value = '.pem,.crt,.cer,.p12,.pfx,.key,.pub,.der,.jks,.keystore';
            document.getElementById('fileScanRegex').value = '';
            document.getElementById('fileScanMaxSize').value = '100';

            // Clear dynamic lists
            document.getElementById('azureTenanciesList').innerHTML = '';
            document.getElementById('ejbcaServersList').innerHTML = '';
            document.getElementById('hsmDevicesList').innerHTML = '';

            // Reset counters
            azureTenancyCount = 0;
            ejbcaServerCount = 0;
            hsmDeviceCount = 0;

            // Update count display
            updateEnabledSourcesCount();
            updateConfigFooterStatus();
        }

        // Modal functions
        function openNewScanModal() {
            const modal = document.getElementById('newScanModal');

            // Reset to default assessment type
            currentAssessmentType = 'pki_health_check';
            document.getElementById('scanAssessmentType').value = 'pki_health_check';
            document.querySelectorAll('.assessment-type-option').forEach(option => {
                option.classList.remove('selected');
            });
            document.querySelector('.assessment-type-option[data-type="pki_health_check"]').classList.add('selected');

            // Clear form fields
            document.getElementById('scanName').value = '';

            // Reset collector dropdown
            const collectorSelect = document.getElementById('scanCollector');
            if (collectorSelect) {
                collectorSelect.value = '';
                updateExecutionTargetInfo();
            }

            // Show engagement context if active
            const engagementContext = document.getElementById('scan-modal-engagement-context');
            const engagementNameEl = document.getElementById('scan-modal-engagement-name');
            if (activeEngagementId && activeEngagementName) {
                engagementNameEl.textContent = activeEngagementName;
                engagementContext.style.display = 'block';
            } else {
                engagementContext.style.display = 'none';
            }

            loadConfigsForDropdown();
            loadPoliciesForDropdown('pki_health_check');
            loadCollectorsForDropdown();  // Load available remote collectors
            modal.style.display = 'flex';
            modal.classList.add('active');
        }

        // Load collectors for scan modal dropdown
        async function loadCollectorsForDropdown() {
            const select = document.getElementById('scanCollector');
            if (!select) return;

            // Keep the local option
            select.innerHTML = '<option value="">This Server (Local)</option>';

            try {
                const response = await fetch('/api/remote/collectors?status=active');
                if (response.ok) {
                    const data = await response.json();
                    if (data.collectors && data.collectors.length > 0) {
                        // Add a separator
                        const separator = document.createElement('option');
                        separator.disabled = true;
                        separator.textContent = '─── Remote Collectors ───';
                        select.appendChild(separator);

                        // Add each collector
                        data.collectors.forEach(collector => {
                            const option = document.createElement('option');
                            option.value = collector.collector_id;
                            option.textContent = `${collector.collector_name} (${collector.location || collector.organization || 'Remote'})`;
                            option.dataset.location = collector.location || '';
                            option.dataset.organization = collector.organization || '';
                            option.dataset.transmissionMode = collector.transmission_mode || 'full';
                            select.appendChild(option);
                        });
                    }
                }
            } catch (error) {
                
                // Not critical - local execution still available
            }
        }

        // Update execution target info based on selection
        function updateExecutionTargetInfo() {
            const select = document.getElementById('scanCollector');
            const infoDiv = document.getElementById('executionTargetInfo');
            if (!select || !infoDiv) return;

            const selectedOption = select.options[select.selectedIndex];
            if (!select.value) {
                // Local execution
                infoDiv.innerHTML = 'Scan will run on this server using the ScanOrchestrator.';
                infoDiv.style.color = '#666';
            } else {
                // Remote collector
                const location = selectedOption.dataset.location;
                const org = selectedOption.dataset.organization;
                const mode = selectedOption.dataset.transmissionMode;
                let info = `Scan will be queued for remote execution.`;
                if (location) info += ` Location: ${location}.`;
                if (mode) info += ` Data mode: ${mode}.`;
                infoDiv.innerHTML = info;
                infoDiv.style.color = '#2563eb';
            }
        }

        function openNewConfigModal() {
            editingConfigId = null;
            document.getElementById('configModalTitle').textContent = 'Create New Configuration';
            const saveBtn = document.getElementById('configSaveBtn');
            saveBtn.textContent = 'Create Configuration';

            // Reset modal to initial state
            resetConfigModal();

            // Show engagement context if active
            const engagementContext = document.getElementById('config-modal-engagement-context');
            const engagementNameEl = document.getElementById('config-modal-engagement-name');
            if (activeEngagementId && activeEngagementName) {
                engagementNameEl.textContent = activeEngagementName;
                engagementContext.style.display = 'flex';
            } else {
                engagementContext.style.display = 'none';
            }

            document.getElementById('newConfigModal').classList.add('active');
        }

        function closeConfigModal() {
            editingConfigId = null;
            document.getElementById('newConfigModal').classList.remove('active');
            loadConfigurations();
        }

        async function openGenerateTokenModal() {
            const modal = document.getElementById('generateTokenModal');
            if (!modal) return;

            // Fetch available CAs and populate the dropdown
            try {
                const response = await fetch('/api/v1/ca/list');
                if (response.ok) {
                    const data = await response.json();
                    const cas = data.cas || [];
                    const dropdown = document.getElementById('tokenEngagementCA');

                    if (dropdown) {
                        // Keep the placeholder option
                        dropdown.innerHTML = '<option value="">-- Select a CA for certificate issuance --</option>';

                        // Add each CA
                        cas.forEach(ca => {
                            const option = document.createElement('option');
                            option.value = ca.engagement_id;
                            // Build display name from customer + project
                            const displayName = ca.customer_name && ca.project_name
                                ? `${ca.customer_name} - ${ca.project_name}`
                                : ca.engagement_id;
                            option.textContent = `${displayName} (${ca.engagement_id})`;
                            dropdown.appendChild(option);
                        });

                        // If only one CA, auto-select it
                        if (cas.length === 1) {
                            dropdown.value = cas[0].engagement_id;
                        }
                    }
                }
            } catch (error) {
                console.warn('Could not fetch CAs for dropdown:', error);
            }

            modal.classList.add('active');
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }
            // Clear form fields when closing generate token modal
            if (modalId === 'generateTokenModal') {
                document.getElementById('tokenCollectorName').value = '';
                document.getElementById('tokenOrganization').value = '';
                document.getElementById('tokenEngagementCA').value = '';
                document.getElementById('tokenLocation').value = '';
                document.getElementById('tokenEnvironment').value = 'production';
                document.getElementById('tokenTransmissionMode').value = 'selective';
                document.getElementById('tokenTTL').value = '24';
                document.getElementById('tokenMaxUses').value = '1';
                document.getElementById('tokenIPRestriction').value = '';
            }
            // Refresh the active tab's data
            if (modalId === 'newScanModal') loadScans();
            if (modalId === 'newConfigModal') loadConfigurations();
            if (modalId === 'newPolicyModal') loadPolicies();
            if (modalId === 'new-engagement-modal' || modalId === 'edit-engagement-modal') loadEngagements();
        }

        // Close modal when clicking outside
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === this) {
                    this.classList.remove('active');
                }
            });
        });

        // API Functions
        async function loadData() {
            loadScans();
            loadConfigurations();
            loadPoliciesV2();
            loadCompliancySelectors();
        }

        async function loadScans() {
            try {
                const params = getEngagementFilterParams();
                const url = params ? `/api/v1/scans?${params}` : '/api/v1/scans';

                const response = await fetch(url);

                if (!response.ok) throw new Error('Failed to load scans');

                const data = await response.json();
                scans = data.scans || [];
                renderScans();
            } catch (error) {
                showAlert('Error loading scans', 'error');
            }
        }

        async function loadConfigurations() {
            try {
                const params = getEngagementFilterParams();
                const url = params ? `/api/v1/scans/configurations?${params}` : '/api/v1/scans/configurations';
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to load configurations');
                const data = await response.json();
                configurations = data.configurations || [];
                renderConfigurations();
            } catch (error) {
                
                showAlert('Error loading configurations', 'error');
            }
        }


        async function loadConfigsForDropdown() {
            try {
                const response = await fetch('/api/v1/scans/configurations');
                if (!response.ok) throw new Error('Failed to load configurations');
                const configs = await response.json();
                const select = document.getElementById('scanConfig');
                select.innerHTML = '<option value="">Select a configuration...</option>';
                configurations.forEach(config => {
                    const option = document.createElement('option');
                    option.value = config.id;
                    option.textContent = config.name;
                    select.appendChild(option);
                });
            } catch (error) {
                
            }
        }

        async function loadPoliciesForDropdown(assessmentType = null) {
            try {
                // Use filtered endpoint if assessment type specified
                const endpoint = assessmentType 
                    ? `/api/v1/policies/by-assessment-type/${assessmentType}`
                    : '/api/v1/policies';
                
                const response = await fetch(endpoint);
                if (!response.ok) throw new Error('Failed to load policies');
                const data = await response.json();
                const policiesList = data.policies || [];
                const select = document.getElementById('scanPolicy');
                select.innerHTML = '<option value="">Select a policy...</option>';
                
                if (policiesList.length === 0) {
                    const option = document.createElement('option');
                    option.value = '';
                    option.textContent = `No ${assessmentType === 'pqc_assessment' ? 'PQC' : 'PKI'} policies available`;
                    option.disabled = true;
                    select.appendChild(option);
                } else {
                    policiesList.forEach(policy => {
                        const option = document.createElement('option');
                        option.value = policy.id;
                        option.textContent = policy.name;
                        select.appendChild(option);
                    });
                }
            } catch (error) {
                
                // Fallback to loading all policies
                try {
                    const response = await fetch('/api/v1/policies');
                    if (response.ok) {
                        const data = await response.json();
                        const policiesList = data.policies || [];
                        const select = document.getElementById('scanPolicy');
                        select.innerHTML = '<option value="">Select a policy...</option>';
                        policiesList.forEach(policy => {
                            const option = document.createElement('option');
                            option.value = policy.id;
                            option.textContent = policy.name;
                            select.appendChild(option);
                        });
                    }
                } catch (fallbackError) {
                    
                }
            }
        }

        async function uploadPolicyV2(policyFile) {
            const formData = new FormData();
            formData.append('file', policyFile);
            
            try {
                const response = await fetch('/api/v1/policies/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showNotification(`Policy uploaded: ${result.policy_name}`);
                    loadPolicies();
                } else {
                    showError('Failed to upload policy');
                }
            } catch (error) {
                
            }
        }

        async function createScan() {
            const name = document.getElementById('scanName').value.trim();
            const configId = document.getElementById('scanConfig').value;
            const policyId = document.getElementById('scanPolicy').value;
            const assessmentType = document.getElementById('scanAssessmentType').value || 'pki_health_check';
            const collectorId = document.getElementById('scanCollector')?.value || null;

            if (!name || !configId || !policyId) {
                showAlert('Please fill in all fields', 'error');
                return;
            }

            try {
                const payload = {
                    name: name,
                    config_id: parseInt(configId),
                    policy_id: parseInt(policyId),
                    assessment_type: assessmentType
                };

                // Include engagement if one is active
                if (activeEngagementId) {
                    payload.engagement_id = activeEngagementId;
                }

                // Include remote collector if selected
                if (collectorId) {
                    payload.collector_id = collectorId;
                }

                const response = await fetch('/api/v1/scans', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) throw new Error('Failed to create scan');

                closeModal('newScanModal');
                const typeInfo = getAssessmentTypeInfo(assessmentType);
                const engagementNote = activeEngagementId ? ` (in ${activeEngagementName})` : '';
                const collectorNote = collectorId ? ' (remote execution)' : '';
                showAlert(`${typeInfo.name} scan created successfully${engagementNote}${collectorNote}`, 'success');
                loadScans();
            } catch (error) {
                
                showAlert('Error creating scan: ' + error.message, 'error');
            }
        }

        /* BACKEND IMPLEMENTATION NOTES FOR SCAN EXECUTION:
        
        The /api/v1/scans/{scanId}/run endpoint must:
        
        1. Retrieve the scan configuration and policy from database
        2. Import the PKIHealthCheck class from pki_health_check_46.py:
           from pki_health_check_46 import PKIHealthCheck
        
        3. Execute scan by:
           - Creating PKIHealthCheck instance with config and policy
           - Calling health_check.run()
           - Capturing all print() output (console logging)
        
        4. Report generation should:
           - Save JSON report to: ./reports/scan_{scanId}.json
           - Save text report to: ./reports/scan_{scanId}.txt
           - Save PDF report to: ./reports/scan_{scanId}.pdf (if enabled)
           - Return report paths in response
        
        5. Update scan record in database:
           - Set status to 'successful' when complete
           - Set last_run timestamp
           - Store report location paths
        
        6. Response should include:
           {
               "status": "success",
               "output": "captured console output from PKI script",
               "report_path": "./reports/scan_{scanId}.json",
               "duration_seconds": 45
           }
        */

        async function saveConfigurationChanges() {
            const name = document.getElementById('configName').value.trim();

            if (!name) {
                showAlert('Please enter a configuration name', 'error');
                return;
            }

            const config = {
                version: `Config_${Date.now()}`,
                tls_scan: {
                    enabled: document.getElementById('tlsEnabled').checked,
                    subnets: document.getElementById('tlsSubnets').value.split('\n').filter(s => s.trim()),
                    hostnames: document.getElementById('tlsHostnames').value.split('\n').filter(h => h.trim()),
                    ports: document.getElementById('tlsPorts').value.split(',').map(p => parseInt(p.trim())),
                    timeout: parseInt(document.getElementById('tlsTimeout').value),
                    metadata_enrichment: {
                        enabled: document.getElementById('metadataEnrichmentEnabled').checked,
                        capture_environment: document.getElementById('captureEnvironmentEnabled').checked,
                        capture_security_analysis: document.getElementById('captureSecurityAnalysisEnabled').checked,
                        check_revocation: document.getElementById('checkRevocationEnabled').checked
                    }
                },
                crl_check: {
                    enabled: document.getElementById('crlEnabled').checked
                },
                azure_keyvault: {
                    enabled: document.getElementById('azureEnabled').checked,
                    tenancies: Array.from(document.querySelectorAll('[data-azure-tenancy]')).map(el => ({
                        name: el.querySelector('[data-azure-tenancy-name]').value,
                        service_principals: Array.from(el.querySelectorAll('[data-azure-sp]')).map((sp, spIdx) => {
                            // Extract credential field using helper (hybrid plaintext + reference format)
                            const clientSecretWrapper = sp.querySelector('.credential-field-wrapper');
                            const credValue = clientSecretWrapper
                                ? CredentialFieldHelper.extractCredentialValue(clientSecretWrapper)
                                : { plaintext_value: null, secret_reference: null };

                            

                            return {
                                name: sp.querySelector('[data-azure-sp-name]').value,
                                tenant_id: sp.querySelector('[data-azure-tenant-id]').value,
                                client_id: sp.querySelector('[data-azure-client-id]').value,
                                client_secret_plaintext: credValue.plaintext_value,
                                client_secret_reference: credValue.secret_reference,
                                vaults: Array.from(sp.querySelectorAll('[data-azure-vault]')).map(vault => ({
                                    url: vault.querySelector('[data-azure-vault-url]').value,
                                    key_names: vault.querySelector('[data-azure-key-names]').value.split(',').map(k => k.trim()).filter(k => k),
                                    certificate_names: vault.querySelector('[data-azure-cert-names]').value.split(',').map(c => c.trim()).filter(c => c)
                                }))
                            };
                        })
                    }))
                },
                ejbca: {
                    enabled: document.getElementById('ejbcaEnabled').checked,
                    servers: Array.from(document.querySelectorAll('[data-ejbca-server]')).map((el, idx) => {
                        // Extract credential field using helper (hybrid plaintext + reference format)
                        const p12PasswordWrapper = el.querySelector('.credential-field-wrapper');
                        const p12Input = p12PasswordWrapper ? p12PasswordWrapper.querySelector('.credential-input') : null;
                        const credValue = p12PasswordWrapper
                            ? CredentialFieldHelper.extractCredentialValue(p12PasswordWrapper)
                            : { plaintext_value: null, secret_reference: null };

                        const p12PathElement = el.querySelector('[data-ejbca-p12-path]');
                        const p12Path = p12PathElement ? p12PathElement.value.trim() : '';

                        // VALIDATION: Check if P12 path is required but missing
                        if (document.getElementById('ejbcaEnabled').checked && !p12Path) {
                            throw new Error(`EJBCA Server "${el.querySelector('[data-ejbca-name]').value}": P12 certificate path is required.`);
                        }

                        console.log('[Config Extract EJBCA Server ' + idx + ']', {
                            name: el.querySelector('[data-ejbca-name]').value,
                            url: el.querySelector('[data-ejbca-url]').value,
                            p12_path: p12Path,
                            hasCreds: !!credValue.plaintext_value || !!credValue.secret_reference
                        });

                        return {
                            name: el.querySelector('[data-ejbca-name]').value,
                            url: el.querySelector('[data-ejbca-url]').value,
                            p12_path: p12Path,
                            p12_password_plaintext: credValue.plaintext_value,
                            p12_password_reference: credValue.secret_reference
                        };
                    })
                },
                luna_hsm: {
                    enabled: document.getElementById('hsmEnabled').checked,
                    hsms: Array.from(document.querySelectorAll('[data-hsm-device]')).map(el => ({
                        name: el.querySelector('[data-hsm-name]').value,
                        pkcs11_module_path: el.querySelector('[data-hsm-pkcs11-path]').value,
                        partitions: Array.from(el.querySelectorAll('[data-hsm-partition]')).map(part => {
                            // Extract credential field using helper (hybrid plaintext + reference format)
                            const passwordWrapper = part.querySelector('.credential-field-wrapper');
                            const credValue = passwordWrapper
                                ? CredentialFieldHelper.extractCredentialValue(passwordWrapper)
                                : { plaintext_value: null, secret_reference: null };

                            return {
                                name: part.querySelector('[data-hsm-partition-name]').value,
                                slot_index: parseInt(part.querySelector('[data-hsm-slot-index]').value),
                                partition_password_plaintext: credValue.plaintext_value,
                                partition_password_reference: credValue.secret_reference
                            };
                        })
                    }))
                },
                file_scan: {
                    enabled: document.getElementById('fileScanEnabled').checked,
                    paths: document.getElementById('fileScanPaths').value.split('\n').filter(p => p.trim()),
                    crypto_extensions: document.getElementById('fileScanExtensions').value.split(',').map(e => e.trim()).filter(e => e),
                    regex_patterns: document.getElementById('fileScanRegex').value.split('\n').filter(r => r.trim()),
                    max_file_size_mb: parseInt(document.getElementById('fileScanMaxSize').value) || 100
                },
                output: {
                    report: `config_${Date.now()}.json`,
                    generate_pdf: true
                }
            };

            try {
                if (editingConfigId) {
                    // Update existing configuration
                    const response = await fetch(`/api/v1/scans/configurations/${editingConfigId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: name,
                            config: config
                        })
                    });

                    if (!response.ok) throw new Error('Failed to update configuration');
                    
                    closeConfigModal();
                    showAlert('Configuration updated successfully', 'success');
                    loadConfigurations();
                } else {
                    // Create new configuration
                    const payload = {
                        name: name,
                        config: config
                    };
                    
                    // Include engagement if one is active
                    if (activeEngagementId) {
                        payload.engagement_id = activeEngagementId;
                    }
                    
                    const response = await fetch('/api/v1/scans/configurations', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    if (!response.ok) throw new Error('Failed to create configuration LOCAL');
                    
                    closeConfigModal();
                    const engagementNote = activeEngagementId ? ` (in ${activeEngagementName})` : '';
                    showAlert(`Configuration created successfully${engagementNote}`, 'success');
                    loadConfigurations();
                }
            } catch (error) {
                
                showAlert('Error saving configuration: ' + error.message, 'error');
            }
        }

       

        // Render Functions
        function renderScans() {
            const tbody = document.getElementById('scans-table-body');
            
            // Preserve state for running scans before clearing
            const runningScansState = {};
            scans.forEach(scan => {
                if (scan.status === 'Running') {
                    const runtimeEl = document.getElementById(`runtime${scan.id}`);
                    const logEl = document.getElementById(`latestLog${scan.id}`);
                    runningScansState[scan.id] = {
                        runtimeText: runtimeEl ? runtimeEl.textContent : '',
                        logText: logEl ? logEl.textContent : 'Waiting for logs...'
                    };
                }
            });
            
            // Force clear the entire table body
            tbody.innerHTML = '';
            
            if (scans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No scans configured. Create one to get started.</td></tr>';
                return;
            }

            tbody.innerHTML = scans.map(scan => {
                const isRunning = scan.status === 'Running';
                const isQueued = scan.status === 'Queued';
                const scanStartTimeAttr = scan.scanStartTime || '';

                const assessmentTypeInfo = getAssessmentTypeInfo(scan.assessment_type || 'pki_health_check');

                const engagementDisplay = scan.engagement_id
                    ? `<span class="engagement-badge">${escapeHtml(scan.engagement_id)}</span>`
                    : '<span class="text-muted">—</span>';

                // Show collector or local execution indicator
                const executionTarget = scan.collector_id
                    ? `<span class="collector-badge" title="Remote: ${scan.collector_name || scan.collector_id}" style="background: #dbeafe; color: #1e40af; padding: 2px 6px; border-radius: 4px; font-size: 11px;">${scan.collector_name || 'Remote'}</span>`
                    : '<span class="text-muted" style="font-size: 11px;">Local</span>';

                return `
                <tr id="scanRow${scan.id}" class="${isRunning || isQueued ? 'scan-row-running' : ''}">
                    <td>
                        <div>${scan.name}</div>
                        <div style="margin-top: 4px; display: flex; gap: 6px; align-items: center;">
                            ${renderAssessmentTypeBadge(scan.assessment_type || 'pki_health_check')}
                            ${executionTarget}
                        </div>
                    </td>
                    <td>${engagementDisplay}</td>
                    <td>${scan.config_name || '-'}</td>
                    <td>${scan.policy_name || '-'}</td>
                    <td>
                        <div>
                            <span class="status-badge status-${scan.status.toLowerCase().replace(' ', '-')}" id="status${scan.id}">
                                ${scan.status}
                            </span>
                            ${isRunning ? `<span class="status-runtime" id="runtime${scan.id}">${runningScansState[scan.id]?.runtimeText || ''}</span>` : ''}
                            ${isQueued ? `<span class="status-runtime" id="runtime${scan.id}">Queued...</span>` : ''}
                        </div>
                        ${!isRunning && !isQueued ? renderCollectorBadges(scan.collector_results) : ''}
                    </td>
                    <td>${scan.last_run ? new Date(scan.last_run).toLocaleString() : 'Never'}</td>
                    <td>
                        <div class="action-buttons">
                            ${isRunning || isQueued ? `
                                <button class="btn-warning" id="scanCancelBtn${scan.id}" onclick="event.stopPropagation(); cancelScan(${scan.id})">Cancel</button>
                            ` : `
                                <button class="btn-success" id="scanBtn${scan.id}" onclick="event.stopPropagation(); runScan(${scan.id})">Run</button>
                                <button class="btn-secondary" id="scanHistoryBtn${scan.id}" onclick="event.stopPropagation(); viewScanHistory(${scan.id}, '${scan.name}')">History</button>
                                <button class="btn-secondary" id="scanReportBtn${scan.id}" onclick="event.stopPropagation(); viewReport(${scan.id})">Report</button>
                                <button class="btn-danger" id="scanDeleteBtn${scan.id}" onclick="event.stopPropagation(); deleteScan(${scan.id})">Delete</button>
                            `}
                        </div>
                    </td>
                </tr>
                ${isRunning ? `
                <tr id="scanRowExpanded${scan.id}" class="scan-row-expanded">
                    <td colspan="7">
                        <div class="scan-latest-log-container">
                            <div class="scan-latest-log-label">Latest Log:</div>
                            <div class="scan-latest-log-line" id="latestLog${scan.id}">${runningScansState[scan.id]?.logText || 'Waiting for logs...'}</div>
                        </div>
                    </td>
                </tr>
                ` : ''}
                ${isQueued ? `
                <tr id="scanRowExpanded${scan.id}" class="scan-row-expanded">
                    <td colspan="7">
                        <div class="scan-latest-log-container">
                            <div class="scan-latest-log-label">Status:</div>
                            <div class="scan-latest-log-line">Waiting for remote collector to pick up job...</div>
                        </div>
                    </td>
                </tr>
                ` : ''}
            `;
            }).join('');
            
            // Start runtime updates for running and queued scans
            scans.forEach(scan => {
                if (scan.status === 'Running' || scan.status === 'Queued') {
                    startScanRuntimeUpdate(scan.id);
                }
            });
        }

        function renderConfigurations() {
            const tbody = document.getElementById('configs-table-body');
            
            if (configurations.length === 0) {
                tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No configurations created yet.</td></tr>';
                return;
            }

            tbody.innerHTML = configurations.map(config => {
                const engagementDisplay = config.engagement_id 
                    ? `<span class="engagement-badge">${escapeHtml(config.engagement_id)}</span>`
                    : '<span class="text-muted">—</span>';
                
                return `
                <tr>
                    <td>${config.name}</td>
                    <td>${engagementDisplay}</td>
                    <td>${config.config_json.tls_scan?.enabled ? '✅' : '-'}</td>
                    <td>${config.config_json.crl_check?.enabled ? '✅' : '-'}</td>
                    <td>${config.config_json.azure_keyvault?.enabled ? '✅' : '-'}</td>
                    <td>${config.config_json.ejbca?.enabled ? '✅' : '-'}</td>
                    <td>${config.config_json.luna_hsm?.enabled ? '✅' : '-'}</td>
                    <td>${config.config_json.file_scan?.enabled ? '✅' : '-'}</td>
                    <td>${new Date(config.created_at).toLocaleDateString()}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn-secondary" onclick="editConfig(${config.id})">Edit</button>
                            <button class="btn-secondary" onclick="exportConfiguration(${config.id})">Export</button>
                            <button class="btn-danger" onclick="deleteConfig(${config.id})">Delete</button>
                        </div>
                    </td>
                </tr>
            `}).join('');
        }

        function renderPolicies() {
            const tbody = document.getElementById('policies-table-body');
            
            if (policies.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No policies created yet.</td></tr>';
                return;
            }
            
            tbody.innerHTML = policies.map(policy => `
                // Extract assessment type from policy JSON
                    let assessmentType = 'pki_health_check';
                    try {
                        const policyData = typeof policy.policy_json === 'string' 
                            ? JSON.parse(policy.policy_json) 
                            : policy.policy_json;
                        assessmentType = policyData?.metadata?.assessment_type || 'pki_health_check';
                    } catch (e) {}
                    
                    // In the table row HTML:
                    <td>
                        <strong>${escapeHtml(policy.name)}</strong>
                        <div style="margin-top: 4px;">${renderAssessmentTypeBadge(assessmentType)}</div>
                    </td>
                <tr>
                    <td>${policy.name}</td>
                    <td>${new Date(policy.created_at).toLocaleDateString()}</td>
                    <td>
                        <div class="action-buttons">
                            <button type="button" class="btn-secondary" onclick="editPolicy(${policy.id})">Edit</button>
                            <button type="button" class="btn-danger" onclick="deletePolicy(${policy.id})">Delete</button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        // Action Functions
        let scanStartTime = null;
        
        // Edit mode tracking
        let editingPolicyId = null;
        let editingConfigId = null;

        function formatRuntime(startTime) {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const hours = Math.floor(elapsed / 3600);
            const minutes = Math.floor((elapsed % 3600) / 60);
            const seconds = elapsed % 60;
            
            if (hours > 0) {
                return `${hours}h ${minutes}m ${seconds}s`;
            } else if (minutes > 0) {
                return `${minutes}m ${seconds}s`;
            } else {
                return `${seconds}s`;
            }
        }

        async function runScan(scanId) {
            const scan = scans.find(s => s.id === scanId);
            if (!scan) {
                showAlert('Scan not found', 'error');
                return;
            }

            currentScanId = scanId;
            scanInProgress = true;
            scanStartTime = Date.now();
            scan.scanStartTime = scanStartTime;

            // Set status to Running immediately so expanded row appears
            scan.status = 'Running';
            renderScans();

            // Background polling will handle status updates and table refresh

            try {
                const response = await fetch(`/api/v1/scans/${scanId}/run`, {
                    method: 'POST'
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || 'Failed to run scan');
                }

                const result = await response.json();

            } catch (error) {
                showAlert('Scan error: ' + error.message, 'error');
            } finally {
                scanInProgress = false;
            }
        }

        async function cancelScan(scanId) {
            if (!confirm('Are you sure you want to cancel this scan?')) {
                return;
            }
            
            try {
                const response = await fetch(`/api/v1/scans/${scanId}/cancel`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                
                if (response.ok) {
                    // Stop polling immediately
                    stopScanRuntimeUpdate(scanId);
                    
                    // Refresh the table
                    await forceRefreshScansTable();
                    
                    showToast('Scan cancelled', 'warning');
                } else {
                    const error = await response.json();
                    showToast(`Failed to cancel scan: ${error.error}`, 'danger');
                }
            } catch (error) {
                
                showToast('Error cancelling scan', 'danger');
            }
        }

        function toggleRunView(scanId, currentStatus) {
            if (currentStatus === 'Running') {
                // Show logs for running scan
                viewScanLogs(scanId);
            } else {
                // Start new scan
                runScan(scanId);
            }
        }

        let activeViewScanId = null;
        let logViewPollingInterval = null;

        async function viewScanLogs(scanId, scanName = null) {
            try {
                activeViewScanId = scanId;
                
                // Get scan details if name not provided
                if (!scanName) {
                    const scan = scans.find(s => s.id === scanId);
                    scanName = scan ? scan.name : 'Scan';
                }

                // Fetch current status
                const statusResponse = await fetch(`/api/v1/scans/${scanId}/status`);
                const statusData = await statusResponse.ok ? await statusResponse.json() : { status: 'Unknown' };

                // Open modal with logs
                const logsModal = document.getElementById('scanProgressModal');
                document.getElementById('scanProgressTitle').textContent = scanName + ' - Logs';
                document.getElementById('scanProgressStatus').textContent = 'Status: ' + statusData.status;
                document.getElementById('scanProgressCancelBtn').style.display = 'none';
                document.getElementById('scanProgressCloseBtn').style.display = 'block';

                const outputDiv = document.getElementById('scanProgressOutput');
                outputDiv.innerHTML = '<div id="logContent"></div>';
                
                // Load logs
                await loadLogsForRun(scanId, '');
                
                logsModal.classList.add('active');

                // Start polling for live updates if scan is running
                if (statusData.status === 'Running') {
                    if (logViewPollingInterval) clearInterval(logViewPollingInterval);
                    logViewPollingInterval = setInterval(async () => {
                        await loadLogsForRun(scanId, '');
                        
                        // Also update status
                        const newStatusResponse = await fetch(`/api/v1/scans/${scanId}/status`);
                        if (newStatusResponse.ok) {
                            const newStatusData = await newStatusResponse.json();
                            document.getElementById('scanProgressStatus').textContent = 'Status: ' + newStatusData.status;
                        }
                    }, 1000);  // Update every 1 second for live logs
                }

            } catch (error) {
                
                showAlert('Error fetching logs: ' + error.message, 'error');
            }
        }

        function viewRunReport(scanId) {
            const runSelector = document.getElementById('runSelector');
            if (!runSelector) {
                showAlert('Please select a run first', 'error');
                return;
            }
            
            const selectedRun = runSelector.value;
            if (!selectedRun) {
                // If no specific run selected, just open the latest report
                window.open(`/api/v1/reports/scans/${scanId}/view`, '_blank');
            } else {
                // For now, open the latest report (the system stores the most recent report)
                // If you need run-specific reports, the report filename would need to include run_number
                window.open(`/api/v1/reports/scans/${scanId}/view`, '_blank');
            }
        }

        async function openEmbedDashboardModal(reportType, reportId) {
            try {
                const configResponse = await fetch('/api/v1/reports/embed/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: reportType, id: reportId })
                });

                if (!configResponse.ok) {
                    throw new Error('Failed to load report configuration');
                }

                const config = await configResponse.json();
                showEmbedModal(reportType, reportId, config);

            } catch (error) {
                showAlert(`❌ Failed to open embed modal: ${error.message}`, 'error');
            }
        }

        function showEmbedModal(reportType, reportId, config) {
            const modal = document.getElementById('embedDashboardModal');

            document.getElementById('embedReportName').textContent = config.report_name;
            document.getElementById('embedEngagementId').textContent = config.engagement_id || 'N/A';

            const membersList = document.getElementById('embedMembersList');
            membersList.innerHTML = '';

            if (config.members.length === 0) {
                membersList.innerHTML = '<div style="color: #666; padding: 10px;">No engagement members found</div>';
            } else {
                config.members.forEach(member => {
                    const label = document.createElement('label');
                    label.style.display = 'flex';
                    label.style.alignItems = 'center';
                    label.style.gap = '8px';
                    label.style.padding = '8px';
                    label.style.cursor = 'pointer';

                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.value = member.user_id;
                    checkbox.checked = true;
                    checkbox.className = 'embed-recipient-checkbox';

                    const text = document.createElement('span');
                    // Display username (full_name may not be available in all cases)
                    text.textContent = member.full_name ? `${member.full_name} (${member.username})` : member.username;
                    text.style.fontSize = '13px';

                    label.appendChild(checkbox);
                    label.appendChild(text);
                    membersList.appendChild(label);
                });
            }

            const validitySelect = document.getElementById('embedValidityDays');
            validitySelect.innerHTML = '';
            config.validity_options.forEach(days => {
                const option = document.createElement('option');
                option.value = days;
                option.textContent = `${days} days`;
                if (days === config.default_validity) {
                    option.selected = true;
                }
                validitySelect.appendChild(option);
            });

            modal.dataset.reportType = reportType;
            modal.dataset.reportId = reportId;
            modal.dataset.engagementId = config.engagement_id;

            modal.style.display = 'block';
        }

        async function submitEmbedDashboard() {
            try {
                const modal = document.getElementById('embedDashboardModal');
                const reportType = modal.dataset.reportType;
                const reportId = modal.dataset.reportId;
                const validityDays = parseInt(document.getElementById('embedValidityDays').value);

                const checkboxes = document.querySelectorAll('.embed-recipient-checkbox:checked');
                const recipientUserIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

                if (recipientUserIds.length === 0) {
                    showAlert('❌ Please select at least one recipient', 'error');
                    return;
                }

                showAlert('Generating encrypted report...', 'info');

                const response = await fetch('/api/v1/reports/embed', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        type: reportType,
                        id: reportId,
                        recipient_user_ids: recipientUserIds,
                        validity_days: validityDays
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || 'Failed to generate report');
                }

                const result = await response.json();

                // Download HTML file locally
                if (result.html_content && result.html_filename) {
                    const blob = new Blob([result.html_content], { type: 'text/html' });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = result.html_filename;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    URL.revokeObjectURL(url);
                }

                // Show P12 passwords to admin
                if (result.p12_info && Object.keys(result.p12_info).length > 0) {
                    showP12PasswordsModal(result.p12_info, result.html_filename);
                } else {
                    showAlert(`✅ Report generated: ${result.html_filename}`, 'success');
                }

                modal.style.display = 'none';

            } catch (error) {
                showAlert(`❌ Error: ${error.message}`, 'error');
            }
        }

        function showP12PasswordsModal(p12Info, htmlFilename) {
            // Create modal overlay
            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999;';

            // Create modal
            const modal = document.createElement('div');
            modal.style.cssText = 'background:white;border-radius:8px;padding:24px;max-width:500px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 4px 6px rgba(0,0,0,0.1);';

            let content = '<h3 style="margin-top:0;color:#1f2937;">✅ Report Encrypted Successfully</h3>';
            content += `<p style="color:#374151;margin-bottom:12px;">Report: <strong>${htmlFilename}</strong></p>`;
            content += '<p style="color:#6b7280;font-size:13px;">P12 files are being downloaded. Share passwords with recipients via separate secure channels.</p>';
            content += '<hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0;">';

            // List recipients with passwords (P12s download automatically)
            Object.entries(p12Info).forEach(([userId, info]) => {
                content += `
                    <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:12px;margin-bottom:12px;">
                        <div style="font-weight:600;color:#1f2937;font-size:14px;margin-bottom:8px;">${info.username}</div>
                        <div style="background:white;border:1px dashed #d1d5db;border-radius:4px;padding:8px;margin-bottom:8px;font-family:monospace;font-size:12px;word-break:break-all;color:#374151;">
                            ${info.p12_password}
                        </div>
                        <div style="display:flex;gap:8px;">
                            <button onclick="navigator.clipboard.writeText('${info.p12_password}').then(() => showAlert('✅ Password copied', 'success'))" style="flex:1;padding:6px 12px;background:#3b82f6;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;">Copy Password</button>
                        </div>
                        <div style="font-size:11px;color:#6b7280;margin-top:8px;">Expires: ${new Date(info.expires_at).toLocaleDateString()}</div>
                    </div>
                `;
            });

            content += '<hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0;">';
            content += '<div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:6px;padding:12px;margin-bottom:16px;font-size:12px;color:#92400e;">';
            content += '<strong>⚠️ Important:</strong> Passwords are shown here only. Do not include them in email with the HTML file. Use a separate secure channel (encrypted email, Slack, call, etc).';
            content += '</div>';

            content += '<div style="text-align:right;"><button onclick="this.closest(\'div\').parentElement.parentElement.style.display=\'none\'" style="padding:8px 16px;background:#6b7280;color:white;border:none;border-radius:6px;cursor:pointer;">Close</button></div>';

            modal.innerHTML = content;
            overlay.appendChild(modal);
            overlay.onclick = (e) => e.target === overlay && (overlay.style.display = 'none');
            document.body.appendChild(overlay);

            // Automatically download each P12 file
            Object.entries(p12Info).forEach(([userId, info]) => {
                if (info.p12_b64) {
                    // Decode base64 to binary
                    const binaryString = atob(info.p12_b64);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }

                    // Create Blob and download
                    const blob = new Blob([bytes], { type: 'application/x-pkcs12' });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = `${info.username}_cert_${new Date().toISOString().split('T')[0]}.p12`;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    URL.revokeObjectURL(url);
                }
            });
        }

        async function generateEmbedDashboard(scanId) {
            openEmbedDashboardModal('scan', scanId);
        }

        async function viewScanHistory(scanId, scanName) {
            try {
                // Fetch scan runs
                const runsResponse = await fetch(`/api/v1/scans/${scanId}/runs`);
                const runsData = await runsResponse.ok ? await runsResponse.json() : { runs: [] };

                // Fetch current status
                const statusResponse = await fetch(`/api/v1/scans/${scanId}/status`);
                const statusData = await statusResponse.ok ? await statusResponse.json() : { status: 'Unknown' };

                // Open modal
                const modal = document.getElementById('scanHistoryModal');
                document.getElementById('scanHistoryTitle').textContent = `${scanName} - Run History`;

                let content = '';

                if (!runsData.runs || runsData.runs.length === 0) {
                    content = '<div style="text-align: center; padding: 40px; color: #666;">No previous runs found</div>';
                } else {
                    content = '<div style="display: flex; flex-direction: column; gap: 15px;">';
                    runsData.runs.forEach(run => {
                        const startTime = new Date(run.start_time).toLocaleString();
                        const logCount = run.log_count || 0;
                        const runStatus = run.status || 'Unknown';
                        const runtime = run.runtime || 'N/A';
                        const statusClass = `status-${runStatus.toLowerCase()}`;
                        
                        content += `
                        <div style="border: 1px solid #ddd; border-radius: 6px; padding: 15px; background: #fafafa;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <div style="font-weight: 600; margin-bottom: 5px;">Run ${run.run_number}</div>
                                    <div style="font-size: 13px; color: #666; margin-bottom: 3px;">Started: ${startTime}</div>
                                    <div style="font-size: 13px; color: #666; margin-bottom: 3px;">Runtime: ${runtime}</div>
                                    <div style="font-size: 13px; color: #666; margin-bottom: 3px;">Logs: ${logCount}</div>
                                    <div style="font-size: 13px; margin-top: 5px;">
                                        <span class="status-badge ${statusClass}">${runStatus}</span>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 8px;">
                                    <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="viewHistoryRunLogs(${scanId}, ${run.run_number}, '${scanName}')">View Logs</button>
                                    <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="viewHistoricReport(${scanId}, ${run.run_number})">View Report</button>
                                    <button class="btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="generateEmbedDashboard(${scanId})">Embed Dashboard</button>
                                </div>
                            </div>
                        </div>
                        `;
                    });
                    content += '</div>';
                }

                document.getElementById('scanHistoryContent').innerHTML = content;
                modal.style.display = 'flex';

            } catch (error) {
                
                showAlert('Error fetching scan history: ' + error.message, 'error');
            }
        }

        function viewHistoricReport(scanId, runNumber) {
            // Open through the report/view endpoint with run_number parameter
            window.open(`/api/v1/reports/scans/${scanId}/view?run_number=${runNumber}`, '_blank');
        }

        function closeScanHistoryModal() {
            document.getElementById('scanHistoryModal').style.display = 'none';
        }

        async function viewHistoryRunLogs(scanId, runNumber, scanName) {
            // Close the history modal
            closeScanHistoryModal();
            
            // Open the logs modal for this run
            try {
                activeViewScanId = scanId;
                
                // Fetch scan runs
                const runsResponse = await fetch(`/api/v1/scans/${scanId}/runs`);
                const runsData = await runsResponse.ok ? await runsResponse.json() : { runs: [] };

                // Fetch current status
                const statusResponse = await fetch(`/api/v1/scans/${scanId}/status`);
                const statusData = await statusResponse.ok ? await statusResponse.json() : { status: 'Unknown' };

                // Open modal with logs
                const logsModal = document.getElementById('scanProgressModal');
                document.getElementById('scanProgressTitle').textContent = scanName + ' - Logs (Run ' + runNumber + ')';
                document.getElementById('scanProgressStatus').textContent = 'Status: ' + statusData.status;
                document.getElementById('scanProgressCancelBtn').style.display = 'none';
                document.getElementById('scanProgressCloseBtn').style.display = 'block';

                const outputDiv = document.getElementById('scanProgressOutput');
                outputDiv.innerHTML = '<div id="logContent"></div>';
                
                // Load logs for specific run
                await loadLogsForRun(scanId, runNumber);
                
                logsModal.classList.add('active');

            } catch (error) {
                
                showAlert('Error fetching logs: ' + error.message, 'error');
            }
        }

        async function loadLogsForRun(scanId, runNumber) {
            try {
                let url = `/api/v1/scans/${scanId}/logs`;
                if (runNumber) {
                    url += `?run=${runNumber}`;
                }

                const logsResponse = await fetch(url);
                if (!logsResponse.ok) {
                    throw new Error('Failed to fetch logs');
                }
                const logsData = await logsResponse.json();

                const logContent = document.getElementById('logContent');
                logContent.innerHTML = '';

                if (logsData.logs && logsData.logs.length > 0) {
                    logsData.logs.forEach(log => {
                        const line = document.createElement('div');
                        line.className = 'scan-progress-line';
                        line.textContent = `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.log_entry}`;
                        logContent.appendChild(line);
                    });
                } else {
                    const line = document.createElement('div');
                    line.className = 'scan-progress-line';
                    line.textContent = 'No logs available for this run';
                    logContent.appendChild(line);
                }

                logContent.scrollTop = logContent.scrollHeight;
            } catch (error) {
                
                const logContent = document.getElementById('logContent');
                logContent.innerHTML = '<div class="scan-progress-line" style="color: red;">Error loading logs</div>';
            }
        }


        function addProgressLine(text) {
            const output = document.getElementById('scanProgressOutput');
            const line = document.createElement('div');
            line.className = 'scan-progress-line';
            line.textContent = text;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }

        function closeScanProgress() {
            document.getElementById('scanProgressModal').classList.remove('active');
            currentScanId = null;
            activeViewScanId = null;
            if (logViewPollingInterval) {
                clearInterval(logViewPollingInterval);
                logViewPollingInterval = null;
            }
            // Also clear the current scan run polling interval
            if (window.currentLogPollingInterval) {
                clearInterval(window.currentLogPollingInterval);
                window.currentLogPollingInterval = null;
            }
        }

        async function deleteScan(scanId) {
            if (!confirm('Are you sure you want to delete this scan?')) return;

            try {
                const response = await fetch(`/api/v1/scans/${scanId}`, {
                    method: 'DELETE'
                });

                if (!response.ok) throw new Error('Failed to delete scan');
                
                showAlert('Scan deleted successfully', 'success');
                await loadScans();
            } catch (error) {
                
                showAlert('Error deleting scan: ' + error.message, 'error');
            }
        }

        async function deleteConfig(configId) {
            if (!confirm('Are you sure you want to delete this configuration?')) return;

            try {
                const response = await fetch(`/api/v1/scans/configurations/${configId}`, {
                    method: 'DELETE'
                });

                if (!response.ok) throw new Error('Failed to delete configuration');
                
                showAlert('Configuration deleted successfully', 'success');
                await loadConfigurations();
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
            }
        }



        function editScan(scanId) {
            const scan = scans.find(s => s.id === scanId);
            if (!scan) return;
            
            document.getElementById('scanName').value = scan.name;
            document.getElementById('scanConfig').value = scan.config_id;
            document.getElementById('scanPolicy').value = scan.policy_id;
            document.getElementById('newScanModal').classList.add('active');
        }

        function editConfig(configId) {
            editingConfigId = configId;
            document.getElementById('configModalTitle').textContent = 'Edit Configuration';
            const saveBtn = document.getElementById('configSaveBtn');
            saveBtn.textContent = 'Update Configuration';

            // Reset modal first to clear any previous state
            resetConfigModal();

            // Remove old event listeners and set new one
            const newBtn = saveBtn.cloneNode(true);
            saveBtn.parentNode.replaceChild(newBtn, saveBtn);
            newBtn.addEventListener('click', function(e) {
                e.preventDefault();
                saveConfigurationChanges();
            });

            const config = configurations.find(c => c.id === configId);
            if (!config) return;

            document.getElementById('configName').value = config.name;

            // TLS Scan
            const tlsCfg = config.config_json.tls_scan;
            const tlsEnabled = tlsCfg?.enabled || false;
            document.getElementById('tlsEnabled').checked = tlsEnabled;
            document.getElementById('tlsSubnets').value = (tlsCfg?.subnets || []).join('\n');
            document.getElementById('tlsHostnames').value = (tlsCfg?.hostnames || []).join('\n');
            document.getElementById('tlsPorts').value = (tlsCfg?.ports || [443]).join(', ');
            document.getElementById('tlsTimeout').value = tlsCfg?.timeout || 10;

            // Metadata Enrichment
            const enrichmentCfg = tlsCfg?.metadata_enrichment;
            document.getElementById('metadataEnrichmentEnabled').checked = enrichmentCfg?.enabled || false;
            document.getElementById('captureEnvironmentEnabled').checked = enrichmentCfg?.capture_environment || false;
            document.getElementById('captureSecurityAnalysisEnabled').checked = enrichmentCfg?.capture_security_analysis || false;
            document.getElementById('checkRevocationEnabled').checked = enrichmentCfg?.check_revocation || false;

            updateConfigSourceUI('tls', tlsEnabled);

            // CRL Check
            const crlEnabled = config.config_json.crl_check?.enabled || false;
            document.getElementById('crlEnabled').checked = crlEnabled;
            updateConfigSourceUI('crl', crlEnabled);

            // Azure Key Vault
            const azureEnabled = config.config_json.azure_keyvault?.enabled || false;
            document.getElementById('azureEnabled').checked = azureEnabled;
            document.getElementById('azureTenanciesList').innerHTML = '';
            azureTenancyCount = 0;
            (config.config_json.azure_keyvault?.tenancies || []).forEach(tenancy => {
                addAzureTenancyForm();
                const tenancyEl = document.querySelector('[data-azure-tenancy]:last-of-type');
                tenancyEl.querySelector('[data-azure-tenancy-name]').value = tenancy.name;
                tenancy.service_principals?.forEach(sp => {
                    addAzureServicePrincipalForm(tenancyEl.getAttribute('data-azure-tenancy'));
                    const spEl = tenancyEl.querySelector('[data-azure-sp]:last-of-type');
                    spEl.querySelector('[data-azure-sp-name]').value = sp.name;
                    spEl.querySelector('[data-azure-tenant-id]').value = sp.tenant_id;
                    spEl.querySelector('[data-azure-client-id]').value = sp.client_id;

                    // Populate credential field with either plaintext or reference (hybrid format)
                    const clientSecretWrapper = spEl.querySelector('.credential-field-wrapper');
                    if (clientSecretWrapper) {
                        const credentialData = {
                            plaintext_value: sp.client_secret_plaintext || sp.client_secret || null,
                            secret_reference: sp.client_secret_reference || null
                        };
                        CredentialFieldHelper.populateCredentialField(clientSecretWrapper, credentialData);
                    }

                    sp.vaults?.forEach(vault => {
                        addAzureVaultForm(spEl.getAttribute('data-azure-sp'));
                        const vaultEl = spEl.querySelector('[data-azure-vault]:last-of-type');
                        vaultEl.querySelector('[data-azure-vault-url]').value = vault.url;
                        vaultEl.querySelector('[data-azure-key-names]').value = (vault.key_names || []).join(', ');
                        vaultEl.querySelector('[data-azure-cert-names]').value = (vault.certificate_names || []).join(', ');
                    });
                });
            });
            updateConfigSourceUI('azure', azureEnabled);

            // EJBCA
            const ejbcaEnabled = config.config_json.ejbca?.enabled || false;
            document.getElementById('ejbcaEnabled').checked = ejbcaEnabled;
            document.getElementById('ejbcaServersList').innerHTML = '';
            ejbcaServerCount = 0;
            (config.config_json.ejbca?.servers || []).forEach(server => {
                addEJBCAServerForm();
                const serverEl = document.querySelector('[data-ejbca-server]:last-of-type');
                serverEl.querySelector('[data-ejbca-name]').value = server.name;
                serverEl.querySelector('[data-ejbca-url]').value = server.url;

                // Populate P12 path if exists
                if (server.p12_path) {
                    const pathInput = serverEl.querySelector('[data-ejbca-p12-path]');
                    if (pathInput) {
                        pathInput.value = server.p12_path;
                    }
                }

                // Populate credential field with either plaintext or reference (hybrid format)
                const p12PasswordWrapper = serverEl.querySelector('.credential-field-wrapper');
                if (p12PasswordWrapper) {
                    const credentialData = {
                        plaintext_value: server.p12_password_plaintext || server.p12_password || null,
                        secret_reference: server.p12_password_reference || null
                    };
                    CredentialFieldHelper.populateCredentialField(p12PasswordWrapper, credentialData);
                }
            });
            updateConfigSourceUI('ejbca', ejbcaEnabled);

            // Luna HSM
            const hsmEnabled = config.config_json.luna_hsm?.enabled || false;
            document.getElementById('hsmEnabled').checked = hsmEnabled;
            document.getElementById('hsmDevicesList').innerHTML = '';
            hsmDeviceCount = 0;
            (config.config_json.luna_hsm?.hsms || []).forEach(hsm => {
                addHSMDeviceForm();
                const hsmEl = document.querySelector('[data-hsm-device]:last-of-type');
                hsmEl.querySelector('[data-hsm-name]').value = hsm.name;
                hsmEl.querySelector('[data-hsm-pkcs11-path]').value = hsm.pkcs11_module_path;
                hsm.partitions?.forEach(partition => {
                    addHSMPartitionForm(hsmEl.getAttribute('data-hsm-device'));
                    const partEl = hsmEl.querySelector('[data-hsm-partition]:last-of-type');
                    partEl.querySelector('[data-hsm-partition-name]').value = partition.name;
                    partEl.querySelector('[data-hsm-slot-index]').value = partition.slot_index;

                    // Populate credential field with either plaintext or reference (hybrid format)
                    const passwordWrapper = partEl.querySelector('.credential-field-wrapper');
                    if (passwordWrapper) {
                        const credentialData = {
                            plaintext_value: partition.partition_password_plaintext || partition.partition_password || null,
                            secret_reference: partition.partition_password_reference || null
                        };
                        CredentialFieldHelper.populateCredentialField(passwordWrapper, credentialData);
                    }
                });
            });
            updateConfigSourceUI('hsm', hsmEnabled);

            // File Scan
            const fileScanEnabled = config.config_json.file_scan?.enabled || false;
            document.getElementById('fileScanEnabled').checked = fileScanEnabled;
            document.getElementById('fileScanPaths').value = (config.config_json.file_scan?.paths || []).join('\n');
            document.getElementById('fileScanExtensions').value = (config.config_json.file_scan?.crypto_extensions || []).join(', ');
            document.getElementById('fileScanRegex').value = (config.config_json.file_scan?.regex_patterns || []).join('\n');
            document.getElementById('fileScanMaxSize').value = config.config_json.file_scan?.max_file_size_mb || 100;
            updateConfigSourceUI('filescan', fileScanEnabled);

            // Update counts
            updateEnabledSourcesCount();
            updateConfigFooterStatus();

            // Switch to first panel
            switchConfigPanel('tls-panel');

            document.getElementById('newConfigModal').classList.add('active');
        }

        function editPolicy(policyId) {
            editingPolicyId = policyId;
            document.getElementById('policyModalTitle').textContent = 'Edit Policy';
            const saveBtn = document.getElementById('policySaveBtn');
            saveBtn.textContent = 'Update Policy';
            
            // Remove old event listeners and set new one
            const newBtn = saveBtn.cloneNode(true);
            saveBtn.parentNode.replaceChild(newBtn, saveBtn);
            newBtn.addEventListener('click', function(e) {
                e.preventDefault();
                savePolicyChanges();
            });
            
            const policy = policies.find(p => p.id === policyId);
            if (!policy) return;
            
            const policyData = policy.policy_json.policy;
            const assessmentRules = policy.policy_json.assessment_rules;
            
            document.getElementById('policyName').value = policy.name;
            document.getElementById('rsaMinSize').value = policyData?.cryptographic_algorithms?.approved_signature_algorithms?.RSA?.min_key_size || 2048;
            document.getElementById('ecdsaMinSize').value = policyData?.cryptographic_algorithms?.approved_signature_algorithms?.ECDSA?.min_key_size || 256;
            
            document.getElementById('maxDaysTLS').value = policyData?.certificate_requirements?.validity_period?.max_days_tls || 398;
            document.getElementById('maxDaysCodeSigning').value = policyData?.certificate_requirements?.validity_period?.max_days_code_signing || 398;
            document.getElementById('maxDaysClientAuth').value = policyData?.certificate_requirements?.validity_period?.max_days_client_auth || 1095;
            document.getElementById('maxDaysRootCA').value = policyData?.certificate_requirements?.validity_period?.max_days_root_ca || 7300;
            
            document.getElementById('expiryHigh').value = policyData?.certificate_requirements?.expiry?.high?.days || 7;
            document.getElementById('expiryMedium').value = policyData?.certificate_requirements?.expiry?.medium?.days || 20;
            document.getElementById('expiryLow').value = policyData?.certificate_requirements?.expiry?.low?.days || 60;
            
            document.getElementById('requiredCiphers').value = (policyData?.tls_configuration?.cipher_suites?.required || []).join('\n');
            
            document.getElementById('crlMaxValidity').value = policyData?.crl_requirements?.max_validity_hours || 168;
            document.getElementById('crlMaxRevoked').value = policyData?.crl_requirements?.max_revoked_certificates || 10000;
            
            // Certificate Rules
            const certChecks = assessmentRules?.certificate_checks || {};
            document.getElementById('certWeakRsaEnabled').checked = certChecks.weak_rsa_key_size?.enabled ?? true;
            document.getElementById('certWeakRsaSeverity').value = certChecks.weak_rsa_key_size?.severity || 'high';
            document.getElementById('certWeakRsaRisk').value = certChecks.weak_rsa_key_size?.risk_score || 8.0;
            
            document.getElementById('certWeakEccEnabled').checked = certChecks.weak_ecc_key_size?.enabled ?? true;
            document.getElementById('certWeakEccSeverity').value = certChecks.weak_ecc_key_size?.severity || 'high';
            document.getElementById('certWeakEccRisk').value = certChecks.weak_ecc_key_size?.risk_score || 8.0;
            
            document.getElementById('certValidityEnabled').checked = certChecks.validity_period?.enabled ?? true;
            document.getElementById('certValiditySeverity').value = certChecks.validity_period?.severity || 'medium';
            document.getElementById('certValidityRisk').value = certChecks.validity_period?.risk_score || 6.0;
            
            document.getElementById('certExpiredEnabled').checked = certChecks.certificate_expired?.enabled ?? true;
            document.getElementById('certExpiredSeverity').value = certChecks.certificate_expired?.severity || 'critical';
            document.getElementById('certExpiredRisk').value = certChecks.certificate_expired?.risk_score || 10.0;
            
            document.getElementById('certExpiringHighEnabled').checked = certChecks.certificate_expiring_high?.enabled ?? true;
            document.getElementById('certExpiringHighDays').value = certChecks.certificate_expiring_high?.threshold_days || 7;
            
            document.getElementById('certExpiringMedEnabled').checked = certChecks.certificate_expiring_med?.enabled ?? true;
            document.getElementById('certExpiringMedDays').value = certChecks.certificate_expiring_med?.threshold_days || 20;
            
            document.getElementById('certExpiringLowEnabled').checked = certChecks.certificate_expiring_low?.enabled ?? true;
            document.getElementById('certExpiringLowDays').value = certChecks.certificate_expiring_low?.threshold_days || 60;
            
            document.getElementById('certWeakHashEnabled').checked = certChecks.weak_hash_algorithm?.enabled ?? true;
            document.getElementById('certWeakHashSeverity').value = certChecks.weak_hash_algorithm?.severity || 'critical';
            document.getElementById('certWeakHashRisk').value = certChecks.weak_hash_algorithm?.risk_score || 9.5;
            
            document.getElementById('certTransparencyEnabled').checked = certChecks.transparency_logs?.enabled ?? true;
            document.getElementById('certTransparencySeverity').value = certChecks.transparency_logs?.severity || 'medium';
            document.getElementById('certTransparencyRisk').value = certChecks.transparency_logs?.risk_score || 4.0;
            
            document.getElementById('certWildcardEnabled').checked = certChecks.wildcard?.enabled ?? true;
            document.getElementById('certWildcardSeverity').value = certChecks.wildcard?.severity || 'medium';
            document.getElementById('certWildcardRisk').value = certChecks.wildcard?.risk_score || 5.0;
            
            // TLS Rules
            const tlsChecks = assessmentRules?.tls_checks || {};
            document.getElementById('tlsProhibitedEnabled').checked = tlsChecks.prohibited_protocol?.enabled ?? true;
            document.getElementById('tlsProhibitedSeverity').value = tlsChecks.prohibited_protocol?.severity || 'critical';
            document.getElementById('tlsProhibitedRisk').value = tlsChecks.prohibited_protocol?.risk_score || 9.0;
            
            document.getElementById('tlsProhibitedCipherEnabled').checked = tlsChecks.prohibited_cipher?.enabled ?? true;
            document.getElementById('tlsProhibitedCipherSeverity').value = tlsChecks.prohibited_cipher?.severity || 'critical';
            document.getElementById('tlsProhibitedCipherRisk').value = tlsChecks.prohibited_cipher?.risk_score || 8.0;
            
            // CRL Rules
            const crlChecks = assessmentRules?.crl_checks || {};
            document.getElementById('crlStaleEnabled').checked = crlChecks.stale_crl?.enabled ?? true;
            document.getElementById('crlStaleBase').value = crlChecks.stale_crl?.risk_score_base || 7.0;
            document.getElementById('crlStalePerDay').value = crlChecks.stale_crl?.risk_score_per_day || 0.1;
            document.getElementById('crlStaleMax').value = crlChecks.stale_crl?.risk_score_max || 9.0;
            
            document.getElementById('crlLongValidityEnabled').checked = crlChecks.long_validity_period?.enabled ?? true;
            document.getElementById('crlLongValiditySeverity').value = crlChecks.long_validity_period?.severity || 'medium';
            document.getElementById('crlLongValidityRisk').value = crlChecks.long_validity_period?.risk_score || 4.0;
            
            document.getElementById('crlLargeEnabled').checked = crlChecks.large_crl?.enabled ?? true;
            document.getElementById('crlLargeSeverity').value = crlChecks.large_crl?.severity || 'low';
            document.getElementById('crlLargeRisk').value = crlChecks.large_crl?.risk_score || 3.0;
            document.getElementById('crlLargeThreshold').value = crlChecks.large_crl?.threshold || 1000;
            
            document.getElementById('crlRevokedEnabled').checked = crlChecks.certificate_revoked?.enabled ?? true;
            document.getElementById('crlRevokedSeverity').value = crlChecks.certificate_revoked?.severity || 'critical';
            document.getElementById('crlRevokedRisk').value = crlChecks.certificate_revoked?.risk_score || 10.0;
            
            // Key Rules
            const keyRules = assessmentRules?.key_assessment_rules?.key_checks || {};
            document.getElementById('keyRsaMinEnabled').checked = keyRules.rsa_key_min_size?.enabled ?? true;
            document.getElementById('keyRsaMinSize').value = keyRules.rsa_key_min_size?.min_size || 3072;
            document.getElementById('keyRsaMinSeverity').value = keyRules.rsa_key_min_size?.severity || 'high';
            document.getElementById('keyRsaMinRisk').value = keyRules.rsa_key_min_size?.risk_score || 8.0;
            
            document.getElementById('keyEcCurveEnabled').checked = keyRules.ec_curve_check?.enabled ?? true;
            document.getElementById('keyEcCurves').value = (keyRules.ec_curve_check?.allowed_curves || []).join(', ');
            document.getElementById('keyEcCurveSeverity').value = keyRules.ec_curve_check?.severity || 'medium';
            document.getElementById('keyEcCurveRisk').value = keyRules.ec_curve_check?.risk_score || 5.0;
            
            document.getElementById('newPolicyModal').classList.add('active');
        }

        function viewReport(scanId) {
            const scan = scans.find(s => s.id === scanId);
            if (!scan) {
                showAlert('Scan not found', 'error');
                return;
            }
            
            // Open the report view endpoint which renders pki_report.html with embedded data
            window.open(`/api/v1/reports/scans/${scanId}/view`, '_blank');
        }

        function addAzureTenancyForm() {
            const container = document.getElementById('azureTenanciesList');
            const id = 'azure-tenancy-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-azure-tenancy', id);
            form.innerHTML = `
                <h4>Azure Tenancy</h4>
                <div class="form-group">
                    <label>Tenancy Name</label>
                    <input type="text" data-azure-tenancy-name placeholder="e.g., Production Tenant" required>
                </div>
                <div id="service-principals-${id}"></div>
                <button type="button" class="add-btn" onclick="addAzureServicePrincipalForm('${id}')">+ Add Service Principal</button>
                <button type="button" class="remove-btn" onclick="this.closest('[data-azure-tenancy]').remove()">Remove Tenancy</button>
            `;
            container.appendChild(form);
            return form;
        }

        function addAzureServicePrincipalForm(tenancyId) {
            const container = document.querySelector(`#service-principals-${tenancyId}`);
            const id = 'azure-sp-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-azure-sp', id);
            form.style.marginLeft = '20px';
            const clientSecretFieldId = 'azure-client-secret-' + Date.now();
            form.innerHTML = `
                <h4>Service Principal</h4>
                <div class="form-group">
                    <label>SP Name</label>
                    <input type="text" data-azure-sp-name placeholder="e.g., sp-name" required>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>Tenant ID</label>
                        <input type="text" data-azure-tenant-id placeholder="UUID" required>
                    </div>
                    <div class="form-group">
                        <label>Client ID</label>
                        <input type="text" data-azure-client-id placeholder="UUID" required>
                    </div>
                </div>
                <div class="form-group">
                    ${CredentialFieldHelper.createCredentialFieldHTML({
                        fieldId: clientSecretFieldId,
                        fieldName: 'client_secret',
                        label: 'Client Secret',
                        placeholder: 'Enter secret or select from secret store',
                        fieldType: 'password',
                        required: true
                    })}
                </div>
                <div id="vaults-${id}"></div>
                <button type="button" class="add-btn" onclick="addAzureVaultForm('${id}')">+ Add Vault</button>
                <button type="button" class="remove-btn" onclick="this.closest('[data-azure-sp]').remove()">Remove SP</button>
            `;
            container.appendChild(form);
            return form;
        }

        function addAzureVaultForm(spId) {
            const container = document.querySelector(`#vaults-${spId}`);
            const id = 'azure-vault-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-azure-vault', id);
            form.style.marginLeft = '40px';
            form.innerHTML = `
                <h4>Vault</h4>
                <div class="form-group">
                    <label>Vault URL</label>
                    <input type="text" data-azure-vault-url placeholder="https://vault.azure.net/" required>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>Key Names (comma-separated)</label>
                        <input type="text" data-azure-key-names placeholder="key1, key2">
                    </div>
                    <div class="form-group">
                        <label>Certificate Names (comma-separated)</label>
                        <input type="text" data-azure-cert-names placeholder="cert1, cert2">
                    </div>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-azure-vault]').remove()">Remove Vault</button>
            `;
            container.appendChild(form);
            return form;
        }

        function addEJBCAServerForm() {
            const container = document.getElementById('ejbcaServersList');
            const id = 'ejbca-server-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-ejbca-server', id);
            const p12PasswordFieldId = 'ejbca-p12-password-' + Date.now();
            form.innerHTML = `
                <h4>EJBCA Server Configuration</h4>
                <div class="form-group">
                    <label>Server Name</label>
                    <input type="text" data-ejbca-name placeholder="e.g., Production EJBCA" required>
                </div>
                <div class="form-group">
                    <label>URL</label>
                    <input type="text" data-ejbca-url placeholder="https://ejbca.example.com" required>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>P12 Certificate Path</label>
                        <input type="text" data-ejbca-p12-path placeholder="C:\\path\\to\\cert.p12" required>
                    </div>
                    <div class="form-group">
                        ${CredentialFieldHelper.createCredentialFieldHTML({
                            fieldId: p12PasswordFieldId,
                            fieldName: 'p12_password',
                            label: 'P12 Password',
                            placeholder: 'Enter password or select from secret store',
                            fieldType: 'password',
                            required: true
                        })}
                    </div>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-ejbca-server]').remove()">Remove Server</button>
            `;
            container.appendChild(form);


            return form;
        }

        function addCLMEJBCAServerForm() {
            const container = document.getElementById('clmEjbcaServersList');
            const id = 'clm-ejbca-server-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-ejbca-server', id);
            const p12PasswordFieldId = 'clm-ejbca-p12-password-' + Date.now();
            form.innerHTML = `
                <h4>EJBCA Server Configuration</h4>
                <div class="form-group">
                    <label>Server Name</label>
                    <input type="text" data-clm-ejbca-name placeholder="e.g., Production EJBCA" required>
                </div>
                <div class="form-group">
                    <label>URL</label>
                    <input type="text" data-clm-ejbca-url placeholder="https://ejbca.example.com" required>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>P12 Certificate Path</label>
                        <input type="text" data-clm-ejbca-p12-path placeholder="C:\\path\\to\\cert.p12" required>
                    </div>
                    <div class="form-group">
                        ${CredentialFieldHelper.createCredentialFieldHTML({
                            fieldId: p12PasswordFieldId,
                            fieldName: 'p12_password',
                            label: 'P12 Password',
                            placeholder: 'Enter password or select from secret store',
                            fieldType: 'password',
                            required: true
                        })}
                    </div>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-ejbca-server]').remove()">Remove Server</button>
            `;
            container.appendChild(form);
        }

         function addCLMAzureKeyVaultServerForm() {
            const container = document.getElementById('clmAzureKeyVaultServersList');
            const id = 'clm-azure-keyvault-server-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-azure-keyvault-server', id);
            const clientSecretFieldId = 'clm-azure-client-secret-' + Date.now();
            form.innerHTML = `
                <h4>Azure Key Vault Configuration</h4>
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" data-clm-azure-keyvault-name placeholder="e.g., Production Vault" required>
                </div>
                <div class="form-group">
                    <label>Vault URL</label>
                    <input type="text" data-clm-azure-keyvault-url placeholder="https://myvault.vault.azure.net" required>
                </div>
                <div class="form-group">
                    <label>Tenant ID</label>
                    <input type="text" data-clm-azure-keyvault-tenant-id placeholder="Azure Tenant ID" required>
                </div>
                <div class="form-group">
                    <label>Client ID</label>
                    <input type="text" data-clm-azure-keyvault-client-id placeholder="Azure App Registration Client ID" required>
                </div>
                <div class="form-group">
                    ${CredentialFieldHelper.createCredentialFieldHTML({
                        fieldId: clientSecretFieldId,
                        fieldName: 'client_secret',
                        label: 'Client Secret',
                        placeholder: 'Enter secret or select from secret store',
                        fieldType: 'password',
                        required: true
                    })}
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-azure-keyvault-server]').remove()">Remove Vault</button>
            `;
            container.appendChild(form);
        }

        function addHSMDeviceForm() {
            const container = document.getElementById('hsmDevicesList');
            const id = 'hsm-device-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-hsm-device', id);
            form.innerHTML = `
                <h4>HSM Device</h4>
                <div class="form-group">
                    <label>Device Name</label>
                    <input type="text" data-hsm-name placeholder="e.g., HSM-01" required>
                </div>
                <div class="form-group">
                    <label>PKCS#11 Module Path</label>
                    <input type="text" data-hsm-pkcs11-path placeholder="C:\\path\\to\\cryptoki.dll" required>
                </div>
                <div id="partitions-${id}"></div>
                <button type="button" class="add-btn" onclick="addHSMPartitionForm('${id}')">+ Add Partition</button>
                <button type="button" class="remove-btn" onclick="this.closest('[data-hsm-device]').remove()">Remove Device</button>
            `;
            container.appendChild(form);
            return form;
        }

        function addHSMPartitionForm(deviceId) {
            const container = document.querySelector(`#partitions-${deviceId}`);
            const id = 'hsm-partition-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-hsm-partition', id);
            form.style.marginLeft = '20px';
            const partitionPasswordFieldId = 'hsm-partition-password-' + Date.now();
            form.innerHTML = `
                <h4>Partition</h4>
                <div class="form-group">
                    <label>Partition Name</label>
                    <input type="text" data-hsm-partition-name placeholder="e.g., Partition-01" required>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>Slot Index</label>
                        <input type="number" data-hsm-slot-index value="0" min="0" required>
                    </div>
                    <div class="form-group">
                        ${CredentialFieldHelper.createCredentialFieldHTML({
                            fieldId: partitionPasswordFieldId,
                            fieldName: 'partition_password',
                            label: 'Partition Password',
                            placeholder: 'Enter password or select from secret store',
                            fieldType: 'password',
                            required: true
                        })}
                    </div>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-hsm-partition]').remove()">Remove Partition</button>
            `;
            container.appendChild(form);
            return form;
        }

        function clearReports() {
            if (confirm('Are you sure you want to clear old reports?')) {
                showAlert('Reports cleared', 'success');
            }
        }

        function exportData() {
            showAlert('Export functionality coming soon', 'info');
        }

        function importConfigFromFile() {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = '.json';
            input.onchange = async (e) => {
                try {
                    const file = e.target.files[0];
                    const text = await file.text();
                    const data = JSON.parse(text);
                    console.log('[Config Import] Loaded config:', data);

                    const configNameEl = document.getElementById('configName');
                    if (configNameEl) configNameEl.value = data.version || 'Imported Config';

                    const tlsEnabledEl = document.getElementById('tlsEnabled');
                    if (tlsEnabledEl) tlsEnabledEl.checked = data.tls_scan?.enabled || false;

                    const tlsSubnetsEl = document.getElementById('tlsSubnets');
                    if (tlsSubnetsEl) tlsSubnetsEl.value = (data.tls_scan?.subnets || []).join('\n');

                    const tlsHostnamesEl = document.getElementById('tlsHostnames');
                    if (tlsHostnamesEl) tlsHostnamesEl.value = (data.tls_scan?.hostnames || []).join('\n');

                    const tlsPortsEl = document.getElementById('tlsPorts');
                    if (tlsPortsEl) tlsPortsEl.value = (data.tls_scan?.ports || [443]).join(', ');

                    const tlsTimeoutEl = document.getElementById('tlsTimeout');
                    if (tlsTimeoutEl) tlsTimeoutEl.value = data.tls_scan?.timeout || 10;

                    const tlsOptionsEl = document.getElementById('tlsOptions');
                    if (tlsOptionsEl) tlsOptionsEl.style.display = tlsEnabledEl?.checked ? 'block' : 'none';

                    const crlEnabledEl = document.getElementById('crlEnabled');
                    if (crlEnabledEl) crlEnabledEl.checked = data.crl_check?.enabled || false;

                    // Azure Key Vault
                    const azureEnabledEl = document.getElementById('azureEnabled');
                    if (azureEnabledEl) azureEnabledEl.checked = data.azure_keyvault?.enabled || false;

                    const azureTenanciesListEl = document.getElementById('azureTenanciesList');
                    if (azureTenanciesListEl) azureTenanciesListEl.innerHTML = '';

                    (data.azure_keyvault?.tenancies || []).forEach(tenancy => {
                        const tenancyEl = addAzureTenancyForm();
                        if (tenancyEl) {
                            const tenancyNameEl = tenancyEl.querySelector('[data-azure-tenancy-name]');
                            if (tenancyNameEl) tenancyNameEl.value = tenancy.name;

                            tenancy.service_principals?.forEach(sp => {
                                const spEl = addAzureServicePrincipalForm(tenancyEl.getAttribute('data-azure-tenancy'));
                                if (spEl) {
                                    const spNameEl = spEl.querySelector('[data-azure-sp-name]');
                                    const tenantIdEl = spEl.querySelector('[data-azure-tenant-id]');
                                    const clientIdEl = spEl.querySelector('[data-azure-client-id]');

                                    if (spNameEl) spNameEl.value = sp.name;
                                    if (tenantIdEl) tenantIdEl.value = sp.tenant_id;
                                    if (clientIdEl) clientIdEl.value = sp.client_id;

                                    // Populate credential field with either plaintext or reference (hybrid format)
                                    // Multiple wrapper divs may exist, select the first one for client secret
                                    const clientSecretWrappers = spEl.querySelectorAll('.credential-field-wrapper');
                                    if (clientSecretWrappers.length > 0) {
                                        const clientSecretWrapper = clientSecretWrappers[0];
                                        const credentialData = {
                                            plaintext_value: sp.client_secret_plaintext || sp.client_secret || null,
                                            secret_reference: sp.client_secret_reference || null
                                        };
                                        try {
                                            CredentialFieldHelper.populateCredentialField(clientSecretWrapper, credentialData);
                                        } catch (e) {
                                            console.error('[Config Import] Error populating client secret:', e);
                                        }
                                    }

                                    sp.vaults?.forEach(vault => {
                                        const vaultEl = addAzureVaultForm(spEl.getAttribute('data-azure-sp'));
                                        if (vaultEl) {
                                            const vaultUrlEl = vaultEl.querySelector('[data-azure-vault-url]');
                                            const keyNamesEl = vaultEl.querySelector('[data-azure-key-names]');
                                            const certNamesEl = vaultEl.querySelector('[data-azure-cert-names]');

                                            if (vaultUrlEl) vaultUrlEl.value = vault.url;
                                            if (keyNamesEl) keyNamesEl.value = (vault.key_names || []).join(', ');
                                            if (certNamesEl) certNamesEl.value = (vault.certificate_names || []).join(', ');
                                        }
                                    });
                                }
                            });
                        }
                    });
                    const azureOptionsEl = document.getElementById('azureOptions');
                    if (azureOptionsEl) azureOptionsEl.style.display = azureEnabledEl?.checked ? 'block' : 'none';

                    // EJBCA
                    const ejbcaEnabledEl = document.getElementById('ejbcaEnabled');
                    if (ejbcaEnabledEl) ejbcaEnabledEl.checked = data.ejbca?.enabled || false;

                    const ejbcaServersListEl = document.getElementById('ejbcaServersList');
                    if (ejbcaServersListEl) ejbcaServersListEl.innerHTML = '';
                    (data.ejbca?.servers || []).forEach(server => {
                        const serverEl = addEJBCAServerForm();
                        if (serverEl) {
                            const nameEl = serverEl.querySelector('[data-ejbca-name]');
                            const urlEl = serverEl.querySelector('[data-ejbca-url]');
                            const p12PathEl = serverEl.querySelector('[data-ejbca-p12-path]');

                            if (nameEl) nameEl.value = server.name;
                            if (urlEl) urlEl.value = server.url;
                            if (p12PathEl) p12PathEl.value = server.p12_path;

                            // Handle credential field for p12_password
                            // Multiple wrapper divs may exist, select the last one (p12_password is the last credential field)
                            const p12PasswordWrappers = serverEl.querySelectorAll('.credential-field-wrapper');
                            if (p12PasswordWrappers.length > 0) {
                                const p12PasswordWrapper = p12PasswordWrappers[p12PasswordWrappers.length - 1];
                                const credentialData = {
                                    plaintext_value: server.p12_password_plaintext || server.p12_password || null,
                                    secret_reference: server.p12_password_reference || null
                                };
                                try {
                                    CredentialFieldHelper.populateCredentialField(p12PasswordWrapper, credentialData);
                                } catch (e) {
                                    console.error('[Config Import] Error populating p12_password:', e);
                                }
                            }
                        }
                    });
                    const ejbcaOptionsEl = document.getElementById('ejbcaOptions');
                    if (ejbcaOptionsEl) ejbcaOptionsEl.style.display = ejbcaEnabledEl?.checked ? 'block' : 'none';

                    // Luna HSM
                    const hsmEnabledEl = document.getElementById('hsmEnabled');
                    if (hsmEnabledEl) hsmEnabledEl.checked = data.luna_hsm?.enabled || false;

                    const hsmDevicesListEl = document.getElementById('hsmDevicesList');
                    if (hsmDevicesListEl) hsmDevicesListEl.innerHTML = '';
                    (data.luna_hsm?.hsms || []).forEach(hsm => {
                        const hsmEl = addHSMDeviceForm();
                        if (hsmEl) {
                            const hsmNameEl = hsmEl.querySelector('[data-hsm-name]');
                            const pkcs11PathEl = hsmEl.querySelector('[data-hsm-pkcs11-path]');

                            if (hsmNameEl) hsmNameEl.value = hsm.name;
                            if (pkcs11PathEl) pkcs11PathEl.value = hsm.pkcs11_module_path;

                            hsm.partitions?.forEach(partition => {
                                const partEl = addHSMPartitionForm(hsmEl.getAttribute('data-hsm-device'));
                                if (partEl) {
                                    const partNameEl = partEl.querySelector('[data-hsm-partition-name]');
                                    const slotIndexEl = partEl.querySelector('[data-hsm-slot-index]');

                                    if (partNameEl) partNameEl.value = partition.name;
                                    if (slotIndexEl) slotIndexEl.value = partition.slot_index;

                                    // Handle credential field for partition_password
                                    // Multiple wrapper divs may exist, select the last one (partition_password is the last credential field)
                                    const partPasswordWrappers = partEl.querySelectorAll('.credential-field-wrapper');
                                    if (partPasswordWrappers.length > 0) {
                                        const partPasswordWrapper = partPasswordWrappers[partPasswordWrappers.length - 1];
                                        const credentialData = {
                                            plaintext_value: partition.partition_password_plaintext || partition.partition_password || null,
                                            secret_reference: partition.partition_password_reference || null
                                        };
                                        try {
                                            CredentialFieldHelper.populateCredentialField(partPasswordWrapper, credentialData);
                                        } catch (e) {
                                            console.error('[Config Import] Error populating partition_password:', e);
                                        }
                                    }
                                }
                            });
                        }
                    });
                    const hsmOptionsEl = document.getElementById('hsmOptions');
                    if (hsmOptionsEl) hsmOptionsEl.style.display = hsmEnabledEl?.checked ? 'block' : 'none';

                    const newConfigModalEl = document.getElementById('newConfigModal');
                    if (newConfigModalEl) newConfigModalEl.classList.add('active');
                    showAlert('Configuration imported successfully', 'success');
                } catch (error) {
                    console.error('[Config Import] Error:', error);
                    console.error('[Config Import] Stack:', error.stack);
                    showAlert('Error importing configuration: ' + error.message, 'error');
                }
            };
            input.click();
        }

        async function exportConfiguration(configId) {
            try {
                const response = await fetch(`/api/v1/scans/configurations/${configId}/export`);
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Export failed');
                }

                const blob = await response.blob();
                const contentDisposition = response.headers.get('Content-Disposition');
                let filename = `config_${configId}.json`;
                if (contentDisposition) {
                    const matches = contentDisposition.match(/filename="([^"]+)"/);
                    if (matches && matches[1]) {
                        filename = matches[1];
                    }
                }

                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                showAlert('Configuration exported successfully', 'success');
            } catch (error) {
                showAlert(`Failed to export configuration: ${error.message}`, 'error');
            }
        }

        function importPolicyFromFile() {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = '.json';
            input.onchange = async (e) => {
                try {
                    const file = e.target.files[0];
                    const text = await file.text();
                    const data = JSON.parse(text);
                    
                    // Validate policy v2.0 structure
                    if (!data.version || data.version !== '2.0') {
                        showAlert('Policy must be version 2.0', 'error');
                        return;
                    }
                    
                    // Extract policy components
                    const metadata = data.metadata || {};
                    const parameters = data.parameters || {};
                    const rules = data.rules || [];
                    
                    // Reset modal to create new policy mode
                    currentPolicyV2 = null;
                    currentPolicyRules = [];
                    editingRuleIndex = null;
                    
                    // Populate metadata fields
                    document.getElementById('policyV2Name').value = metadata.name || 'Imported Policy';
                    document.getElementById('policyV2Category').value = metadata.category || 'custom';
                    document.getElementById('policyV2Description').value = metadata.description || '';
                    
                    // Set assessment type from imported policy
                    const importedAssessmentType = metadata.assessment_type || 'pki_health_check';
                    selectPolicyAssessmentType(importedAssessmentType);
                    const radioToCheck = document.querySelector(`input[name="policyAssessmentType"][value="${importedAssessmentType}"]`);
                    if (radioToCheck) radioToCheck.checked = true;
                    
                    // Populate parameters fields
                    document.getElementById('policyV2OrgName').value = parameters.organization_name?.value || '';
                    document.getElementById('policyV2ComplianceLevel').value = parameters.compliance_level?.value || 'high';
                    
                    // Load imported rules
                    if (rules.length > 0) {
                        currentPolicyRules = rules;
                        showAlert(`Imported ${rules.length} rules from policy file`, 'success');
                    } else {
                        showAlert('Policy file contains no rules. Add rules manually or use Load Template Rules.', 'warning');
                    }
                    
                    // Render the rules and parameters
                    renderPolicyRules();
                    renderGlobalParameters();
                    
                    // Open modal to allow editing/saving
                    document.getElementById('policyV2ModalTitle').textContent = 'Edit Imported Policy';
                    document.getElementById('newPolicyV2Modal').classList.add('active');
                    showAlert('Policy imported successfully. Review and save to create.', 'success');
                } catch (error) {
                    
                    showAlert('Error importing policy: ' + error.message, 'error');
                }
            };
            input.click();
        }


        // Alert function
        function showAlert(message, type = 'info') {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            alertDiv.textContent = message;
            alertDiv.style.position = 'fixed';
            alertDiv.style.top = '20px';
            alertDiv.style.right = '20px';
            alertDiv.style.zIndex = '10000';
            alertDiv.style.minWidth = '300px';
            alertDiv.style.maxWidth = '500px';
            document.body.appendChild(alertDiv);

            setTimeout(() => alertDiv.remove(), 5000);
        }

        // Close scan history modal when clicking outside
        document.getElementById('scanHistoryModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeScanHistoryModal();
            }
        });

        // ==================== USER MANAGEMENT ====================

        // Setup user dropdown
        function setupUserDropdown() {
            const userMenuBtn = document.getElementById('userMenuBtn');
            const userDropdown = document.getElementById('userDropdown');
            
            userMenuBtn.addEventListener('click', () => {
                userDropdown.style.display = userDropdown.style.display === 'none' ? 'block' : 'none';
            });
            
            document.addEventListener('click', (e) => {
                if (!userMenuBtn.contains(e.target) && !userDropdown.contains(e.target)) {
                    userDropdown.style.display = 'none';
                }
            });
        }

        // Setup main tab listeners
        function setupMainTabListeners() {
            // Main tabs (Scanning, CLM, KMS)
            document.querySelectorAll('.main-tabs .tab-button').forEach(btn => {
                btn.addEventListener('click', function() {
                    const mainTab = this.dataset.mainTab;
                    
                    document.querySelectorAll('.main-tabs .tab-button').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.main-tab-content').forEach(t => t.classList.remove('active'));
                    
                    this.classList.add('active');
                    document.getElementById(mainTab).classList.add('active');
                    
                    // Load default tabs and data for each module
                    if (mainTab === 'scanning') {
                        // Scanning module: Load Scans tab
                        const scansBtn = document.querySelector('[data-main-tab="scanning"]').closest('.tabs:not(.main-tabs)');
                        loadScans();
                    } else if (mainTab === 'clm') {
                        // CLM module: Load Certificates tab
                        startCLMCertificateRefresh();
                    } else if (mainTab === 'kms') {
                        // KMS module: Load Keys tab (placeholder for future)
                        stopCLMCertificateRefresh();
                    }
                });
            });

            // Sub-tabs (within each main tab)
            document.querySelectorAll('.tabs:not(.main-tabs) .tab-button').forEach(btn => {
                btn.addEventListener('click', function() {
                    const tab = this.dataset.tab;
                    const parentContainer = this.closest('.main-tab-content');
                    
                    // Find all buttons and content within the same parent
                    parentContainer.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                    parentContainer.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                    
                    this.classList.add('active');
                    const tabElement = parentContainer.querySelector(`#${tab}`);
                    if (tabElement) {
                        tabElement.classList.add('active');
                    }
                    
                    // Load users when users tab is clicked
                    if (tab === 'users') {
                        loadUsers();
                    }
                    
                    // Load CLM integrations when CLM integrations tab is clicked
                    if (tab === 'clm-integrations') {
                        loadCLMIntegrations();
                    }
                    
                    // Load CLM certificates when certificates tab is clicked
                    if (tab === 'clm-certificates') {
                        loadCollectorCertificates();
                    }

                    // Load Assets tab data
                    if (tab === 'assets-dashboard') {
                        loadAssetsDashboard();
                    }
                    if (tab === 'assets-certificates') {
                        loadAssetsCertificates();
                    }
                    if (tab === 'assets-keys') {
                        loadAssetsKeys();
                    }

                    // Load Lifecycle tab data
                    if (tab === 'lifecycle-overview') {
                        loadLifecycleOverview();
                    }
                    if (tab === 'lifecycle-certificates') {
                        loadLifecycleCertificates();
                    }
                    if (tab === 'lifecycle-keys') {
                        loadLifecycleKeys();
                    }
                    if (tab === 'lifecycle-policies') {
                        loadLifecyclePolicies();
                    }
                });
            });
        }

        // Load all users
        async function loadUsers() {
            try {
                // Load users
                const usersResponse = await fetch('/api/v1/users');
                if (!usersResponse.ok) {
                    const error = await usersResponse.json();
                    throw new Error(error.error || 'Failed to load users');
                }
                
                const usersData = await usersResponse.json();
                const tbody = document.getElementById('users-table-body');
                
                if (usersData.users.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No users found.</td></tr>';
                } else {
                    tbody.innerHTML = usersData.users.map(user => {
                        // Determine role badge color
                        let roleColor = '#3b82f6'; // default blue
                        if (user.role === 'admin') roleColor = '#ef4444'; // red
                        else if (user.role === 'clm-user') roleColor = '#10b981'; // green
                        else if (user.role === 'kms-user') roleColor = '#f59e0b'; // orange
                        else if (user.role === 'scan-user') roleColor = '#3b82f6'; // blue
                        else if (user.role === 'report-user') roleColor = '#8b5cf6'; // purple

                        // Determine enabled status
                        const enabled = user.enabled !== undefined ? user.enabled : 1;
                        const statusBadge = enabled ?
                            '<span style="background: #51cf66; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">Active</span>' :
                            '<span style="background: #ff6b6b; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">Disabled</span>';

                        // Auth provider badge - show provider name or "Local" if none
                        let authProviderBadge;
                        if (user.auth_provider_name && user.auth_provider_name.trim() !== '') {
                            authProviderBadge = `<span style="background: #4c6ef5; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">${user.auth_provider_name}</span>`;
                        } else {
                            authProviderBadge = '<span style="background: #868e96; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">Local</span>';
                        }

                        return `
                        <tr style="${!enabled ? 'opacity: 0.6;' : ''}">
                            <td><strong>${user.username}</strong></td>
                            <td><span style="background: ${roleColor}; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">${user.role}</span></td>
                            <td>${authProviderBadge}</td>
                            <td>${statusBadge}</td>
                            <td>${new Date(user.created_at).toLocaleDateString()}</td>
                            <td style="text-align: right;">
                                <button onclick="editUser(${user.id})" style="background: #3b82f6; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600; margin-right: 4px;">Edit</button>
                                <button onclick="deleteUser(${user.id})" style="background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600;">Delete</button>
                            </td>
                        </tr>
                        `;
                    }).join('');
                }

                // Removed - RBAC table no longer in Users tab (moved to Settings > Roles & Permissions)
                // // Load RBAC roles
                // const rbacResponse = await fetch('/api/v1/rbac/roles');
                // if (rbacResponse.ok) {
                //     const rbacData = await rbacResponse.json();
                //     const rbacTbody = document.getElementById('rbac-table-body');
                //
                //     if (rbacData && rbacData.roles && Array.isArray(rbacData.roles)) {
                //         rbacTbody.innerHTML = rbacData.roles.map(role => `
                //             <tr>
                //                 <td><strong>${role.name || 'N/A'}</strong></td>
                //                 <td>${role.display_name || 'N/A'}</td>
                //                 <td>
                //                     <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                //                         ${role.permissions && Array.isArray(role.permissions) ? role.permissions.map(perm => `
                //                             <span style="background: #667eea; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">${perm}</span>
                //                         `).join('') : '<span style="color: #999;">No permissions</span>'}
                //                     </div>
                //                 </td>
                //             </tr>
                //         `).join('');
                //     } else {
                //         rbacTbody.innerHTML = '<tr><td colspan="3" class="empty-state">No roles data available</td></tr>';
                //     }
                // } else {
                //     const rbacTbody = document.getElementById('rbac-table-body');
                //     rbacTbody.innerHTML = '<tr><td colspan="3" class="empty-state">Failed to load roles.</td></tr>';
                // }
            } catch (error) {
                
                showAlert('Failed to load users: ' + error.message, 'error');
                const tbody = document.getElementById('users-table-body');
                tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Error: ${error.message}</td></tr>`;
            }
        }

        // Open new user modal - REMOVED: This old prompt-based implementation has been replaced
        // by the modal-based version in settings_management.js
        // The openNewUserModal() function is now defined in settings_management.js

        // function openNewUserModal() {
        //     const username = prompt('Enter username:');
        //     if (!username) return;
        //
        //     const password = prompt('Enter password:');
        //     if (!password) return;
        //
        //     const role = prompt('Enter role (admin/scan-user/report-user/clm-user/kms-user):', 'scan-user');
        //     if (!role) return;
        //
        //     // Validate role
        //     const validRoles = ['admin', 'scan-user', 'report-user', 'clm-user', 'kms-user'];
        //     if (!validRoles.includes(role)) {
        //         showAlert('Invalid role. Must be one of: ' + validRoles.join(', '), 'error');
        //         return;
        //     }
        //
        //     createUser(username, password, role);
        // }

        // Create new user
        async function createUser(username, password, role) {
            try {
                const response = await fetch('/api/v1/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        role: role
                    })
                });
                
                if (response.ok) {
                    showAlert('User created successfully', 'success');
                    loadUsers();
                } else {
                    const error = await response.json();
                    showAlert('Failed to create user: ' + error.error, 'error');
                }
            } catch (error) {
                
                showAlert('Failed to create user', 'error');
            }
        }

        // Delete user
        async function deleteUser(userId) {
            if (!confirm('Are you sure you want to delete this user?')) return;
            
            try {
                const response = await fetch(`/api/v1/users/${userId}`, {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    showAlert('User deleted successfully', 'success');
                    loadUsers();
                } else {
                    const error = await response.json();
                    showAlert('Failed to delete user: ' + error.error, 'error');
                }
            } catch (error) {
                
                showAlert('Failed to delete user', 'error');
            }
        }

        // ==================== CLM FUNCTIONS ====================
        
        // Helper function to extract CN from structured subject/issuer objects
        function extractCommonName(subjectOrIssuer) {
            if (!subjectOrIssuer) return 'N/A';
            
            // If it's a structured object with commonName property
            if (typeof subjectOrIssuer === 'object' && subjectOrIssuer.commonName) {
                return subjectOrIssuer.commonName;
            }
            
            // If it's a string, try to extract CN using regex
            if (typeof subjectOrIssuer === 'string') {
                const cnMatch = subjectOrIssuer.match(/CN=([^,]+)/);
                if (cnMatch) return cnMatch[1];
            }
            
            return 'N/A';
        }
        
        // CLM Integration Modal
        function openNewCLMIntegrationModal() {
            resetCLMIntegrationModal();
            
            // Clear previous forms
            document.getElementById('clmEjbcaServersList').innerHTML = '';
            document.getElementById('clmIntegrationName').value = '';
            document.getElementById('clmIntegrationTypeDropdown').value = '';
            document.getElementById('clmCertificateStoreTypeDropdown').value = '';
            document.getElementById('clmKeyStoreTypeDropdown').value = '';
            
            // Reset visibility
            document.getElementById('clmCertificateStoreSection').style.display = 'none';
            document.getElementById('clmKeyStoreSection').style.display = 'none';
            //document.getElementById('clmWorkflowSection').style.display = 'none';
            document.getElementById('clmEjbcaConfigSection').style.display = 'none';
            document.getElementById('clmAdcsConfigSection').style.display = 'none';
            document.getElementById('clmKeyStoreLunaConfigSection').style.display = 'none';
            document.getElementById('clmKeyStoreAzureConfigSection').style.display = 'none';
            document.getElementById('clmKeyStoreLunaDevicesList').innerHTML = 'none';
            document.getElementById('clmKeyStoreAzureServersList').innerHTML = 'none';
            
            // Show modal
            const modal = document.getElementById('newCLMIntegrationModal');

            modal.style.display = 'flex';
            modal.classList.add('active');
            // Add scrollable content to modal if it's too large
            var modalContent = modal.querySelector('.modal-content');
            if (modalContent) {
                modalContent.style.maxHeight = '85vh';
                modalContent.style.overflowY = 'auto';
            }
        }

        // Update CLM integration display based on integration type selection
        function updateClmIntegrationDisplay() {
            const integrationType = document.getElementById('clmIntegrationTypeDropdown').value;
            
            var certSection = document.getElementById('clmCertificateStoreSection');
            var keySection = document.getElementById('clmKeyStoreSection');
            var workflowSection = document.getElementById('clmWorkflowSection');
            
            if (certSection) certSection.style.display = integrationType === 'certificate-store' ? 'block' : 'none';
            if (keySection) keySection.style.display = integrationType === 'key-store' ? 'block' : 'none';
            if (workflowSection) workflowSection.style.display = integrationType === 'workflow' ? 'block' : 'none';
            
            // Reset certificate store type when switching types
            var certStoreDropdown = document.getElementById('clmCertificateStoreTypeDropdown');
            var ejbcaConfig = document.getElementById('clmEjbcaConfigSection');
            var adcsConfig = document.getElementById('clmAdcsConfigSection');
            var azureConfig = document.getElementById('clmAzureKeyVaultConfigSection');
            
            if (certStoreDropdown) certStoreDropdown.value = '';
            if (ejbcaConfig) ejbcaConfig.style.display = 'none';
            if (adcsConfig) adcsConfig.style.display = 'none';
            if (azureConfig) azureConfig.style.display = 'none';
            
            // Reset key store type when switching types
            var keyStoreDropdown = document.getElementById('clmKeyStoreTypeDropdown');
            var lunaConfig = document.getElementById('clmKeyStoreLunaConfigSection');
            var keyStoreAzureConfig = document.getElementById('clmKeyStoreAzureConfigSection');
            
            if (keyStoreDropdown) keyStoreDropdown.value = '';
            if (lunaConfig) lunaConfig.style.display = 'none';
            if (keyStoreAzureConfig) keyStoreAzureConfig.style.display = 'none';
        }

        function updateClmCertificateStoreDisplay() {
            const storeType = document.getElementById('clmCertificateStoreTypeDropdown').value;
            document.getElementById('clmEjbcaConfigSection').style.display = 
                storeType === 'ejbca' ? 'block' : 'none';
            document.getElementById('clmAzureKeyVaultConfigSection').style.display = 
                storeType === 'azure-keyvault' ? 'block' : 'none';
            document.getElementById('clmAdcsConfigSection').style.display = 
                storeType === 'adcs' ? 'block' : 'none';
            
            // Initialize EJBCA servers list if showing EJBCA
            if (storeType === 'ejbca' && document.getElementById('clmEjbcaServersList').innerHTML === '') {
                addCLMEJBCAServerForm();
            }
            
            // Initialize Azure Key Vault servers list if showing Azure Key Vault
            if (storeType === 'azure-keyvault' && document.getElementById('clmAzureKeyVaultServersList').innerHTML === '') {
                addCLMAzureKeyVaultServerForm();
            }
        }

        // Update Key Store display based on key store type selection
        function updateClmKeyStoreDisplay() {
            const storeType = document.getElementById('clmKeyStoreTypeDropdown').value;
            document.getElementById('clmKeyStoreLunaConfigSection').style.display = 
                storeType === 'luna-hsm' ? 'block' : 'none';
            document.getElementById('clmKeyStoreAzureConfigSection').style.display = 
                storeType === 'azure-keyvault' ? 'block' : 'none';
            
            // Initialize Luna HSM devices list if showing Luna HSM
            if (storeType === 'luna-hsm' && document.getElementById('clmKeyStoreLunaDevicesList').innerHTML === '') {
                addCLMKeyStoreLunaForm();
            }
            
            // Initialize Azure Key Vault servers list if showing Azure Key Vault
            if (storeType === 'azure-keyvault' && document.getElementById('clmKeyStoreAzureServersList').innerHTML === '') {
                addCLMKeyStoreAzureForm();
            }
        }

        // Add Luna HSM form for Key Store integration
        function addCLMKeyStoreLunaForm() {
            const container = document.getElementById('clmKeyStoreLunaDevicesList');
            const id = 'clm-keystore-luna-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-keystore-luna', id);
            form.style.cssText = 'border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; background: #fafafa; margin-bottom: 15px;';
            form.innerHTML = `
                <h4 style="margin-top: 0; color: #333; margin-bottom: 20px;">Luna HSM Configuration</h4>
                <div class="form-group">
                    <label>Device Name</label>
                    <input type="text" data-clm-keystore-luna-name placeholder="e.g., HSM-Production-01" required>
                </div>
                <div class="form-group">
                    <label>PKCS#11 Module Path</label>
                    <input type="text" data-clm-keystore-luna-pkcs11-path placeholder="C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll" required>
                </div>
                <div id="clm-keystore-luna-partitions-${id}"></div>
                <button type="button" class="add-btn" onclick="addCLMKeyStoreLunaPartitionForm('${id}')">+ Add Partition</button>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-keystore-luna]').remove()">Remove Device</button>
            `;
            container.appendChild(form);
        }

        // Add Luna HSM Partition form for Key Store integration
        function addCLMKeyStoreLunaPartitionForm(deviceId) {
            const container = document.querySelector(`#clm-keystore-luna-partitions-${deviceId}`);
            const id = 'clm-keystore-luna-partition-' + Date.now();
            const partitionPasswordFieldId = 'clm-luna-partition-password-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-keystore-luna-partition', id);
            form.style.cssText = 'margin-left: 20px; border: 1px solid #d0d0d0; border-radius: 6px; padding: 15px; background: #f5f5f5; margin-bottom: 10px;';
            form.innerHTML = `
                <h5 style="margin-top: 0; color: #555;">Partition</h5>
                <div class="form-group">
                    <label>Partition Name</label>
                    <input type="text" data-clm-keystore-luna-partition-name placeholder="e.g., Partition-01" required>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div class="form-group">
                        <label>Slot Index</label>
                        <input type="number" data-clm-keystore-luna-slot-index value="0" min="0" required>
                    </div>
                    <div class="form-group">
                        ${CredentialFieldHelper.createCredentialFieldHTML({
                            fieldId: partitionPasswordFieldId,
                            fieldName: 'partition_password',
                            label: 'Partition Password',
                            placeholder: 'Enter password or select from secret store',
                            fieldType: 'password',
                            required: true
                        })}
                    </div>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-keystore-luna-partition]').remove()">Remove Partition</button>
            `;
            container.appendChild(form);
        }

        // Add Azure Key Vault form for Key Store integration
        function addCLMKeyStoreAzureForm() {
            const container = document.getElementById('clmKeyStoreAzureServersList');
            const id = 'clm-keystore-azure-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-keystore-azure', id);
            form.style.cssText = 'border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; background: #fafafa; margin-bottom: 15px;';
            form.innerHTML = `
                <h4 style="margin-top: 0; color: #333; margin-bottom: 20px;">Azure Key Vault Configuration</h4>
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" data-clm-keystore-azure-name placeholder="e.g., Production Key Vault" required>
                </div>
                <div class="form-group">
                    <label>Vault URL</label>
                    <input type="text" data-clm-keystore-azure-url placeholder="https://myvault.vault.azure.net" required>
                </div>
                <div class="form-group">
                    <label>Tenant ID</label>
                    <input type="text" data-clm-keystore-azure-tenant-id placeholder="Azure Tenant ID" required>
                </div>
                <div class="form-group">
                    <label>Client ID</label>
                    <input type="text" data-clm-keystore-azure-client-id placeholder="Azure App Registration Client ID" required>
                </div>
                <div class="form-group">
                    <label>Client Secret</label>
                    <input type="password" data-clm-keystore-azure-client-secret placeholder="Azure App Registration Client Secret" required>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-keystore-azure]').remove()">Remove Vault</button>
            `;
            container.appendChild(form);
        }

        // Add Luna HSM form for Key Store integration
        function addCLMKeyStoreLunaForm() {
            const container = document.getElementById('clmKeyStoreLunaDevicesList');
            const id = 'clm-keystore-luna-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-keystore-luna', id);
            form.style.cssText = 'border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; background: #fafafa; margin-bottom: 15px;';
            form.innerHTML = `
                <h4 style="margin-top: 0; color: #333; margin-bottom: 20px;">Luna HSM Configuration</h4>
                <div class="form-group">
                    <label>Device Name</label>
                    <input type="text" data-clm-keystore-luna-name placeholder="e.g., HSM-Production-01" required>
                </div>
                <div class="form-group">
                    <label>PKCS#11 Module Path</label>
                    <input type="text" data-clm-keystore-luna-pkcs11-path placeholder="C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll" required>
                </div>
                <div id="clm-keystore-luna-partitions-${id}"></div>
                <button type="button" class="add-btn" onclick="addCLMKeyStoreLunaPartitionForm('${id}')">+ Add Partition</button>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-keystore-luna]').remove()">Remove Device</button>
            `;
            container.appendChild(form);
        }

        // Add Luna HSM Partition form for Key Store integration
        function addCLMKeyStoreLunaPartitionForm(deviceId) {
            const container = document.querySelector(`#clm-keystore-luna-partitions-${deviceId}`);
            const id = 'clm-keystore-luna-partition-' + Date.now();
            const partitionPasswordFieldId = 'clm-luna-partition-password-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-keystore-luna-partition', id);
            form.style.cssText = 'margin-left: 20px; border: 1px solid #d0d0d0; border-radius: 6px; padding: 15px; background: #f5f5f5; margin-bottom: 10px;';
            form.innerHTML = `
                <h5 style="margin-top: 0; color: #555;">Partition</h5>
                <div class="form-group">
                    <label>Partition Name</label>
                    <input type="text" data-clm-keystore-luna-partition-name placeholder="e.g., Partition-01" required>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div class="form-group">
                        <label>Slot Index</label>
                        <input type="number" data-clm-keystore-luna-slot-index value="0" min="0" required>
                    </div>
                    <div class="form-group">
                        ${CredentialFieldHelper.createCredentialFieldHTML({
                            fieldId: partitionPasswordFieldId,
                            fieldName: 'partition_password',
                            label: 'Partition Password',
                            placeholder: 'Enter password or select from secret store',
                            fieldType: 'password',
                            required: true
                        })}
                    </div>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-keystore-luna-partition]').remove()">Remove Partition</button>
            `;
            container.appendChild(form);
        }

        // Add Azure Key Vault form for Key Store integration
        function addCLMKeyStoreAzureForm() {
            const container = document.getElementById('clmKeyStoreAzureServersList');
            const id = 'clm-keystore-azure-' + Date.now();
            const form = document.createElement('div');
            form.className = 'nested-form';
            form.setAttribute('data-clm-keystore-azure', id);
            form.style.cssText = 'border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; background: #fafafa; margin-bottom: 15px;';
            form.innerHTML = `
                <h4 style="margin-top: 0; color: #333; margin-bottom: 20px;">Azure Key Vault Configuration</h4>
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" data-clm-keystore-azure-name placeholder="e.g., Production Key Vault" required>
                </div>
                <div class="form-group">
                    <label>Vault URL</label>
                    <input type="text" data-clm-keystore-azure-url placeholder="https://myvault.vault.azure.net" required>
                </div>
                <div class="form-group">
                    <label>Tenant ID</label>
                    <input type="text" data-clm-keystore-azure-tenant-id placeholder="Azure Tenant ID" required>
                </div>
                <div class="form-group">
                    <label>Client ID</label>
                    <input type="text" data-clm-keystore-azure-client-id placeholder="Azure App Registration Client ID" required>
                </div>
                <div class="form-group">
                    <label>Client Secret</label>
                    <input type="password" data-clm-keystore-azure-client-secret placeholder="Azure App Registration Client Secret" required>
                </div>
                <button type="button" class="remove-btn" onclick="this.closest('[data-clm-keystore-azure]').remove()">Remove Vault</button>
            `;
            container.appendChild(form);
        }
        

        async function saveCLMIntegration() {
            
            const integrationName = document.getElementById('clmIntegrationName').value;
            const integrationType = document.getElementById('clmIntegrationTypeDropdown').value;
            const isEditMode = editingIntegrationId !== null;
            
            
            
            
            
            
            if (!integrationName) {
                
                showAlert('Please enter an integration name', 'error');
                return;
            }
            
            if (!integrationType) {
                
                showAlert('Please select an integration type', 'error');
                return;
            }
            
            if (integrationType === 'certificate-store') {
                const storeType = document.getElementById('clmCertificateStoreTypeDropdown').value;
                
                if (!storeType) {
                    
                    showAlert('Please select a certificate store type', 'error');
                    return;
                }
                
                if (storeType === 'ejbca') {
                    const serverElements = document.querySelectorAll('[data-clm-ejbca-server]');
                    

                    const servers = Array.from(serverElements).map(el => {
                        const nameEl = el.querySelector('[data-clm-ejbca-name]');
                        const urlEl = el.querySelector('[data-clm-ejbca-url]');
                        const pathEl = el.querySelector('[data-clm-ejbca-p12-path]');

                        // Find the credential field wrapper for password
                        const credentialWrapper = el.querySelector('.credential-field-wrapper');
                        let p12_password_plaintext = null;
                        let p12_password_reference = null;

                        if (credentialWrapper) {
                            // Use CredentialFieldHelper to extract the credential value in hybrid format
                            const credentialValue = CredentialFieldHelper.extractCredentialValue(credentialWrapper);
                            
                            
                            
                            
                            p12_password_plaintext = credentialValue.plaintext_value;
                            p12_password_reference = credentialValue.secret_reference;
                        }

                        if (!nameEl || !urlEl || !pathEl) {
                            
                            return null;
                        }

                        return {
                            name: nameEl.value,
                            url: urlEl.value,
                            p12_path: pathEl.value,
                            p12_password_plaintext: p12_password_plaintext,
                            p12_password_reference: p12_password_reference
                        };
                    }).filter(server => server !== null);

                    

                    if (servers.length === 0) {
                        
                        showAlert('No EJBCA server configuration found. Please add a server.', 'error');
                        return;
                    }

                    const primaryServer = servers[0];
                    if (!primaryServer.name || !primaryServer.url || !primaryServer.p12_path || (!primaryServer.p12_password_plaintext && !primaryServer.p12_password_reference)) {
                        
                        
                        showAlert('Please fill in all required fields for the EJBCA server', 'error');
                        return;
                    }
                    
                    
                    
                    try {
                        const url = isEditMode ? '/api/v1/inventory/integrations/' + editingIntegrationId : '/api/v1/inventory/integrations';
                        const method = isEditMode ? 'PUT' : 'POST';
                        const response = await fetch(url, {
                            method: method,
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                name: integrationName,
                                type: 'EJBCA',
                                config: {
                                    ejbca: {
                                        servers: servers  // Include all servers with proper credential format
                                    }
                                }
                            })
                        });
                        
                        
                        
                        if (response.ok) {
                            const data = await response.json();

                            showAlert('Integration created successfully', 'success');
                            closeModal('newCLMIntegrationModal');
                            editingIntegrationId = null;
                            loadCLMIntegrations();
                            loadCollectorCertificates();
                        } else {
                            try {
                                const error = await response.json();
                                showAlert('Failed to create integration: ' + (error.error || error.message || 'Unknown error'), 'error');
                            } catch (e) {
                                showAlert('Failed to create integration: HTTP ' + response.status, 'error');
                            }
                        }
                    } catch (error) {

                        showAlert('Error: ' + error.message, 'error');
                    }
                } else if (storeType === 'azure-keyvault') {
                    const serverElements = document.querySelectorAll('[data-clm-azure-keyvault-server]');
                    

                    const servers = Array.from(serverElements).map(el => {
                        const nameEl = el.querySelector('[data-clm-azure-keyvault-name]');
                        const urlEl = el.querySelector('[data-clm-azure-keyvault-url]');
                        const tenantEl = el.querySelector('[data-clm-azure-keyvault-tenant-id]');
                        const clientIdEl = el.querySelector('[data-clm-azure-keyvault-client-id]');

                        // Find the credential field wrapper for client secret
                        const credentialWrapper = el.querySelector('.credential-field-wrapper');
                        let client_secret_plaintext = null;
                        let client_secret_reference = null;

                        if (credentialWrapper) {
                            // Use CredentialFieldHelper to extract the credential value in hybrid format
                            const credentialValue = CredentialFieldHelper.extractCredentialValue(credentialWrapper);
                            client_secret_plaintext = credentialValue.plaintext_value;
                            client_secret_reference = credentialValue.secret_reference;
                        }

                        if (!nameEl || !urlEl || !tenantEl || !clientIdEl) {
                            
                            return null;
                        }

                        return {
                            name: nameEl.value,
                            vault_url: urlEl.value,
                            tenant_id: tenantEl.value,
                            client_id: clientIdEl.value,
                            client_secret_plaintext: client_secret_plaintext,
                            client_secret_reference: client_secret_reference
                        };
                    }).filter(server => server !== null);

                    

                    if (servers.length === 0) {
                        
                        showAlert('No Azure Key Vault configuration found. Please add a vault.', 'error');
                        return;
                    }

                    const primaryServer = servers[0];
                    if (!primaryServer.name || !primaryServer.vault_url || !primaryServer.tenant_id || !primaryServer.client_id || (!primaryServer.client_secret_plaintext && !primaryServer.client_secret_reference)) {
                        
                        
                        showAlert('Please fill in all required fields for the Azure Key Vault', 'error');
                        return;
                    }

                    

                    try {
                        const url = isEditMode ? '/api/v1/inventory/integrations/' + editingIntegrationId : '/api/v1/inventory/integrations';
                        const method = isEditMode ? 'PUT' : 'POST';
                        const response = await fetch(url, {
                            method: method,
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                name: integrationName,
                                type: 'Azure Key Vault',
                                config: {
                                    azure_keyvault: {
                                        tenancies: [{
                                            service_principals: servers
                                        }]
                                    }
                                }
                            })
                        });
                        
                        
                        
                        if (response.ok) {
                            const data = await response.json();
                            
                            showAlert(isEditMode ? 'Integration updated successfully' : 'Integration created successfully', 'success');
                            closeModal('newCLMIntegrationModal');
                            editingIntegrationId = null;
                            loadCLMIntegrations();
                            loadCollectorCertificates();
                        } else {
                            const error = await response.json();
                            
                            showAlert('Failed to create integration: ' + (error.error || 'Unknown error'), 'error');
                        }
                    } catch (error) {
                        
                        showAlert('Error: ' + error.message, 'error');
                    }
                } else if (storeType === 'adcs') {
                    const serverAddress = document.getElementById('clmAdcsServerAddress').value;
                    const ca = document.getElementById('clmAdcsCertificateAuthority').value;
                    const templateName = document.getElementById('clmAdcsTemplateName').value;
                    const authMethod = document.getElementById('clmAdcsAuthMethod').value;
                    const username = document.getElementById('clmAdcsUsername').value;
                    const password = document.getElementById('clmAdcsPassword').value;
                    
                    if (!serverAddress || !ca || !templateName || !authMethod) {
                        
                        showAlert('Please fill in all required ADCS fields', 'error');
                        return;
                    }
                    
                    
                    
                    try {
                        const response = await fetch('/api/v1/inventory/integrations', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                name: integrationName,
                                type: 'ADCS',
                                config: {
                                    server_address: serverAddress,
                                    certificate_authority: ca,
                                    template_name: templateName,
                                    auth_method: authMethod,
                                    username: username || null,
                                    password: password || null
                                }
                            })
                        });
                        
                        
                        
                        if (response.ok) {
                            const data = await response.json();

                            showAlert('Integration created successfully', 'success');
                            closeModal('newCLMIntegrationModal');
                            editingIntegrationId = null;
                            loadCLMIntegrations();
                            loadCollectorCertificates();
                        } else {
                            try {
                                const error = await response.json();
                                showAlert('Failed to create integration: ' + (error.error || error.message || 'Unknown error'), 'error');
                            } catch (e) {
                                showAlert('Failed to create integration: HTTP ' + response.status, 'error');
                            }
                        }
                    } catch (error) {

                        showAlert('Error: ' + error.message, 'error');
                    }
                }
            } else if (integrationType === 'key-store') {
                const storeType = document.getElementById('clmKeyStoreTypeDropdown').value;
                
                if (!storeType) {
                    
                    showAlert('Please select a key store type', 'error');
                    return;
                }
                
                if (storeType === 'luna-hsm') {
                    const deviceElements = document.querySelectorAll('[data-clm-keystore-luna]');
                    
                    
                    const devices = Array.from(deviceElements).map(el => {
                        // Get device-level fields
                        const name = el.querySelector('[data-clm-keystore-luna-name]')?.value || '';
                        const pkcs11Path = el.querySelector('[data-clm-keystore-luna-pkcs11-path]')?.value || '';
                        
                        // Get partitions for this device
                        const partitionElements = el.querySelectorAll('[data-clm-keystore-luna-partition]');
                        const partitions = Array.from(partitionElements).map(partEl => {
                            // Extract credential field using helper (hybrid plaintext + reference format)
                            const passwordWrapper = partEl.querySelector('.credential-field-wrapper');
                            const credValue = passwordWrapper
                                ? CredentialFieldHelper.extractCredentialValue(passwordWrapper)
                                : { plaintext_value: null, secret_reference: null };

                            return {
                                name: partEl.querySelector('[data-clm-keystore-luna-partition-name]')?.value || '',
                                slot: partEl.querySelector('[data-clm-keystore-luna-slot-index]')?.value || '0',
                                password_plaintext: credValue.plaintext_value,
                                password_reference: credValue.secret_reference
                            };
                        });
                        
                        return {
                            name: name,
                            library_path: pkcs11Path,
                            partitions: partitions
                        };
                    });
                    
                    
                    
                    if (devices.length === 0) {
                        
                        showAlert('No Luna HSM configuration found. Please add a device.', 'error');
                        return;
                    }
                    
                    const primaryDevice = devices[0];
                    if (!primaryDevice.name || !primaryDevice.library_path) {
                        
                        
                        showAlert('Please fill in the Device Name and PKCS#11 Module Path', 'error');
                        return;
                    }
                    
                    if (primaryDevice.partitions.length === 0) {
                        
                        showAlert('Please add at least one partition to the Luna HSM', 'error');
                        return;
                    }
                    
                    const primaryPartition = primaryDevice.partitions[0];
                    if (!primaryPartition.name || (!primaryPartition.password_plaintext && !primaryPartition.password_reference)) {


                        showAlert('Please fill in all required fields for the partition', 'error');
                        return;
                    }
                    
                    
                    
                    try {
                        const response = await fetch('/api/v1/inventory/integrations', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                name: integrationName,
                                type: 'Luna HSM',
                                config: {
                                    library_path: primaryDevice.library_path,
                                    slot: parseInt(primaryPartition.slot) || 0,
                                    pin_plaintext: primaryPartition.password_plaintext,
                                    pin_reference: primaryPartition.password_reference,
                                    device_name: primaryDevice.name,
                                    partition_name: primaryPartition.name
                                }
                            })
                        });
                        
                        
                        
                        if (response.ok) {
                            const data = await response.json();
                            
                            showAlert('Integration created successfully', 'success');
                            closeModal('newCLMIntegrationModal');
                            editingIntegrationId = null;
                            loadCLMIntegrations();
                        } else {
                            const error = await response.json();
                            
                            showAlert('Failed to create integration: ' + (error.error || 'Unknown error'), 'error');
                        }
                    } catch (error) {
                        
                        showAlert('Error: ' + error.message, 'error');
                    }
                } else if (storeType === 'azure-keyvault') {
                    const serverElements = document.querySelectorAll('[data-clm-keystore-azure]');
                    
                    
                    const servers = Array.from(serverElements).map(el => ({
                        name: el.querySelector('[data-clm-keystore-azure-name]').value,
                        vault_url: el.querySelector('[data-clm-keystore-azure-url]').value,
                        tenant_id: el.querySelector('[data-clm-keystore-azure-tenant-id]').value,
                        client_id: el.querySelector('[data-clm-keystore-azure-client-id]').value,
                        client_secret: el.querySelector('[data-clm-keystore-azure-client-secret]').value
                    }));
                    
                    
                    
                    if (servers.length === 0) {
                        
                        showAlert('No Azure Key Vault configuration found. Please add a vault.', 'error');
                        return;
                    }
                    
                    const primaryServer = servers[0];
                    if (!primaryServer.name || !primaryServer.vault_url || !primaryServer.tenant_id || !primaryServer.client_id || !primaryServer.client_secret) {
                        
                        
                        showAlert('Please fill in all required fields for the Azure Key Vault', 'error');
                        return;
                    }
                    
                    
                    
                    try {
                        const response = await fetch('/api/v1/inventory/integrations', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                name: integrationName,
                                type: 'Azure Key Vault (Keys)',
                                config: {
                                    vault_url: primaryServer.vault_url,
                                    tenant_id: primaryServer.tenant_id,
                                    client_id: primaryServer.client_id,
                                    client_secret: primaryServer.client_secret
                                }
                            })
                        });
                        
                        
                        
                        if (response.ok) {
                            const data = await response.json();
                            
                            showAlert('Integration created successfully', 'success');
                            closeModal('newCLMIntegrationModal');
                            editingIntegrationId = null;
                            loadCLMIntegrations();
                        } else {
                            const error = await response.json();
                            
                            showAlert('Failed to create integration: ' + (error.error || 'Unknown error'), 'error');
                        }
                    } catch (error) {
                        
                        showAlert('Error: ' + error.message, 'error');
                    }
                }
            } else if (integrationType === 'workflow') {
                
                showAlert('Workflow integration coming soon', 'info');
            }
        }

        async function loadConnectorsWithBanner() {
            // Show loading banner
            const loadingBanner = document.getElementById('connectorsLoadingStatus');
            const statusText = document.getElementById('connectorsStatusText');
            
            if (loadingBanner) {
                loadingBanner.style.display = 'block';
                statusText.textContent = 'Loading connectors...';
            }
            
            try {
                await loadCLMIntegrations();
                
                if (statusText) {
                    statusText.textContent = 'Connectors loaded successfully';
                }
                
                // Hide banner after short delay
                setTimeout(() => {
                    if (loadingBanner) {
                        loadingBanner.style.display = 'none';
                    }
                }, 800);
                
            } catch (error) {
                
                if (statusText) {
                    statusText.textContent = 'Failed to load connectors';
                }
                // Hide banner after showing error
                setTimeout(() => {
                    if (loadingBanner) {
                        loadingBanner.style.display = 'none';
                    }
                }, 2000);
            }
        }

        async function loadCLMIntegrations() {
            try {
                // Fetch integrations and sync status in parallel
                const [integrationsResponse, syncStatusResponse] = await Promise.all([
                    fetch('/api/v1/inventory/integrations'),
                    fetch('/api/v1/inventory/sync-status').catch(() => ({ ok: false }))
                ]);
                
                if (!integrationsResponse.ok) {
                    throw new Error('Failed to load integrations');
                }
                
                const data = await integrationsResponse.json();
                const tbody = document.getElementById('clm-integrations-body');
                
                // Parse sync status if available
                inventorySyncStatus = {};
                if (syncStatusResponse.ok) {
                    const syncData = await syncStatusResponse.json();
                    (syncData.connectors || []).forEach(s => {
                        inventorySyncStatus[s.connector_id] = s;
                    });
                }
                
                // Update stats
                const totalConnectors = data.integrations.length;
                const healthyConnectors = data.integrations.filter(i => i.status === 'Healthy').length;
                const activeConnectors = data.integrations.filter(i => i.enabled).length;
                let totalItems = 0;
                data.integrations.forEach(i => {
                    const syncStatus = inventorySyncStatus[i.id] || {};
                    totalItems += syncStatus.items_total || 0;
                });
                
                const statsTotal = document.getElementById('connectors-total');
                const statsHealthy = document.getElementById('connectors-healthy');
                const statsActive = document.getElementById('connectors-active');
                const statsItems = document.getElementById('connectors-items');
                
                if (statsTotal) statsTotal.textContent = totalConnectors;
                if (statsHealthy) statsHealthy.textContent = healthyConnectors;
                if (statsActive) statsActive.textContent = activeConnectors;
                if (statsItems) statsItems.textContent = totalItems;
                
                const grid = document.getElementById('clm-integrations-grid');
                const emptyState = document.getElementById('connectors-empty-state');
                
                if (data.integrations.length === 0) {
                    if (grid) grid.style.display = 'none';
                    if (emptyState) emptyState.style.display = 'block';
                    if (tbody) tbody.innerHTML = '';
                } else {
                    if (grid) {
                        grid.style.display = 'grid';
                        grid.innerHTML = data.integrations.map(integration => {
                            const syncStatus = inventorySyncStatus[integration.id] || {};
                            const inventoryCount = syncStatus.items_total || 0;
                            const certCount = syncStatus.certificates_total || 0;
                            const keyCount = syncStatus.keys_total || 0;
                            const lastInventorySync = syncStatus.last_sync_completed;
                            const syncState = syncStatus.last_sync_status || 'pending';

                            const lastSyncDisplay = lastInventorySync
                                ? formatRelativeTime(lastInventorySync)
                                : (integration.last_sync ? new Date(integration.last_sync).toLocaleDateString() : 'Never');

                            const icon = getConnectorIcon(integration.type);

                            // Extract status word (first word before colon, if present)
                            const statusText = integration.status ? integration.status.split(':')[0].trim() : 'Unknown';

                            // Status colors for health badge
                            const statusInfo = statusText === 'Healthy'
                                ? { bg: 'rgba(16, 185, 129, 0.1)', border: '#10b981', text: '#10b981', icon: '✓' }
                                : statusText === 'Unhealthy'
                                ? { bg: 'rgba(239, 68, 68, 0.1)', border: '#ef4444', text: '#ef4444', icon: '✕' }
                                : { bg: 'rgba(107, 114, 128, 0.1)', border: '#6b7280', text: '#6b7280', icon: '?' };

                            const syncStateBadges = {
                                'success': { bg: '#dcfce7', color: '#166534', label: 'Synced' },
                                'failed': { bg: '#fee2e2', color: '#991b1b', label: 'Failed' },
                                'in_progress': { bg: '#dbeafe', color: '#1e40af', label: 'Syncing...' },
                                'pending': { bg: '#f1f5f9', color: '#475569', label: 'Pending' }
                            };
                            const syncStateBadge = syncStateBadges[syncState] || syncStateBadges.pending;

                            return `
                                <div style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05);" id="connectorCard${integration.id}">
                                    <!-- Header with gradient -->
                                    <div style="padding: 20px 24px; background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; cursor: pointer;" onclick="toggleConnectorDetails(${integration.id})">
                                        <div style="flex: 1;">
                                            <div style="font-size: 18px; font-weight: 700; color: #1f2937; margin-bottom: 4px;">${icon} ${escapeHtml(integration.name)}</div>
                                            <div style="font-size: 13px; color: #6b7280;">${integration.type === 'promoted' ? 'Virtual Service Connector' : escapeHtml(integration.type)}</div>
                                        </div>
                                        <div style="background: ${statusInfo.bg}; border: 1.5px solid ${statusInfo.border}; border-radius: 8px; padding: 8px 16px; text-align: center; flex-shrink: 0;">
                                            <div style="font-size: 12px; font-weight: 600; color: ${statusInfo.text};">${statusInfo.icon} ${statusText}</div>
                                        </div>
                                    </div>

                                    <!-- Details Grid -->
                                    <div style="padding: 20px 24px; border-bottom: 1px solid #e5e7eb;">
                                        <div style="display: grid; grid-template-columns: auto 1fr; gap: 16px 24px; font-size: 14px;">
                                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Total Items</div>
                                            <div style="color: #1f2937; font-weight: 500;">${inventoryCount}</div>

                                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Certificates</div>
                                            <div style="color: #1f2937; font-weight: 500;">${certCount}</div>

                                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Keys</div>
                                            <div style="color: #1f2937; font-weight: 500;">${keyCount}</div>

                                            ${integration.type !== 'promoted' ? `
                                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Last Sync</div>
                                            <div style="color: #1f2937; font-weight: 500;">🕐 ${lastSyncDisplay}</div>

                                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Sync State</div>
                                            <div style="display: inline-block; padding: 4px 12px; border-radius: 4px; background: ${syncStateBadge.bg}; color: ${syncStateBadge.color}; font-size: 12px; font-weight: 600;">${syncStateBadge.label}</div>
                                            ` : ''}

                                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Status</div>
                                            <div style="color: #1f2937; font-weight: 500;">${integration.enabled ? '✅ Enabled' : '❌ Disabled'}</div>
                                        </div>
                                    </div>

                                    <!-- Action Buttons -->
                                    <div style="padding: 16px 24px; background: #f9fafb; border-top: 1px solid #e5e7eb; display: flex; gap: 8px; flex-wrap: wrap;">
                                        ${integration.type !== 'promoted' ? `
                                        <button onclick="editCLMIntegration(${integration.id}); event.stopPropagation();"
                                            style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                                            ✏️ Edit
                                        </button>
                                        <button onclick="syncCLMIntegration(${integration.id}); event.stopPropagation();" ${!integration.enabled ? 'disabled' : ''}
                                            style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500; ${!integration.enabled ? 'opacity: 0.5;' : ''}">
                                            ⚡ Sync
                                        </button>
                                        ` : ''}
                                        <button onclick="toggleCLMIntegration(${integration.id}, ${!integration.enabled}); event.stopPropagation();"
                                            style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                                            ${integration.enabled ? '🔴 Disable' : '🟢 Enable'}
                                        </button>
                                        ${integration.type !== 'promoted' ? `
                                        <button onclick="deleteCLMIntegration(${integration.id}); event.stopPropagation();"
                                            style="padding: 6px 12px; background: white; color: #dc2626; border: 1px solid #fecaca; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                                            🗑️ Delete
                                        </button>
                                        ` : ''}
                                    </div>
                                </div>
                            `;
                        }).join('');
                    }
                    if (emptyState) emptyState.style.display = 'none';
                    
                    // Also update hidden tbody for backwards compatibility
                    if (tbody) {
                        tbody.innerHTML = data.integrations.map(integration => {
                            return '<tr id="integrationDetails' + integration.id + '" style="display: none;"><td colspan="6"><div id="detailsContent' + integration.id + '"></div></td></tr>';
                        }).join('');
                    }
                }
            } catch (error) {
                
                showAlert('Failed to load integrations', 'error');
            }
        }

        async function syncAllConnectors() {
            showAlert('Starting sync for all connectors...', 'info');
            
            try {
                const response = await fetch('/api/v1/inventory/sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                
                if (!response.ok) throw new Error('Sync request failed');
                
                const data = await response.json();
                const results = data.results || {};
                
                let successes = 0, failures = 0, totalItems = 0;
                Object.values(results).forEach(r => {
                    if (r.success) {
                        successes++;
                        totalItems += (r.certificates_total || 0) + (r.keys_total || 0);
                    } else {
                        failures++;
                    }
                });
                
                if (failures > 0) {
                    showAlert(`Sync: ${successes} succeeded, ${failures} failed (${totalItems} items)`, 'warning');
                } else {
                    showAlert(`Sync completed: ${successes} connectors, ${totalItems} items`, 'success');
                }
                
                await loadCLMIntegrations();
                
            } catch (error) {
                
                showAlert('Sync failed: ' + error.message, 'error');
            }
        }

        function formatRelativeTime(dateString) {
            if (!dateString) return 'Unknown';
            const date = new Date(dateString);
            const now = new Date();
            const diffMs = now - date;
            const diffMins = Math.floor(diffMs / (1000 * 60));
            const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            
            if (diffMins < 1) return 'Just now';
            if (diffMins < 60) return `${diffMins}m ago`;
            if (diffHours < 24) return `${diffHours}h ago`;
            if (diffDays < 7) return `${diffDays}d ago`;
            return date.toLocaleDateString();
        }

        async function toggleIntegrationDetails(integrationId) {
            const detailsRow = document.getElementById(`integrationDetails${integrationId}`);
            const arrow = document.getElementById(`arrow${integrationId}`);
            const isVisible = detailsRow.style.display !== 'none';
            
            if (isVisible) {
                // Hide the details and rotate arrow back
                detailsRow.style.display = 'none';
                if (arrow) arrow.style.transform = 'rotate(0deg)';
            } else {
                // Show and load details, rotate arrow
                detailsRow.style.display = 'table-row';
                if (arrow) arrow.style.transform = 'rotate(90deg)';
                await loadIntegrationDetails(integrationId);
            }
        }

        async function loadIntegrationDetails(integrationId) {
            try {
                const detailsContent = document.getElementById(`detailsContent${integrationId}`);
                
                // Get integration data
                const response = await fetch('/api/v1/inventory/integrations');
                const data = await response.json();
                const integration = data.integrations.find(i => i.id === integrationId);
                
                if (!integration) return;
                
                let html = `
                    <div style="margin-bottom: 20px;">
                        <h4 style="margin-top: 0; color: #333;">Integration Configuration</h4>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr style="border-bottom: 1px solid #ddd;">
                                <td style="padding: 10px; font-weight: 600; width: 30%;">Name:</td>
                                <td style="padding: 10px;">${integration.name}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #ddd;">
                                <td style="padding: 10px; font-weight: 600;">Type:</td>
                                <td style="padding: 10px;">${integration.type}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #ddd;">
                                <td style="padding: 10px; font-weight: 600;">Status:</td>
                                <td style="padding: 10px;">
                                    <span class="status-badge" style="background: ${integration.status === 'Healthy' ? '#d4edda' : integration.status === 'Unhealthy' ? '#f8d7da' : '#fff3cd'}; color: ${integration.status === 'Healthy' ? '#155724' : integration.status === 'Unhealthy' ? '#721c24' : '#856404'};">
                                        ${integration.status}
                                    </span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 10px; font-weight: 600;">Last Sync:</td>
                                <td style="padding: 10px;">${integration.last_sync ? new Date(integration.last_sync).toLocaleString() : 'Never'}</td>
                            </tr>
                        </table>
                    </div>
                `;
                
                // If EJBCA, load CA information
                if (integration.type === 'EJBCA') {
                    try {
                        const casResponse = await fetch(`/api/v1/inventory/integrations/${integrationId}/cas`);
                        if (casResponse.ok) {
                            const casData = await casResponse.json();
                            const cas = casData.cas || [];

                            html += `
                                <div style="margin-bottom: 20px;">
                                    <h4 style="margin-top: 0; color: #333;">Certificate Authorities</h4>
                            `;

                            if (cas.length === 0) {
                                html += '<p style="color: #999;">No certificate authorities available.</p>';
                            } else {
                                html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px;">';
                                cas.forEach(ca => {
                                    // If integration is disabled, show CA as disabled
                                    const isDisabled = !integration.enabled;
                                    const displayStatus = isDisabled ? 'Disabled' : ca.status;
                                    const statusBg = isDisabled ? '#f1f5f9' : (ca.status === 'Active' ? '#dcfce7' : '#fee2e2');
                                    const statusColor = isDisabled ? '#64748b' : (ca.status === 'Active' ? '#166534' : '#991b1b');

                                    // Always display subject DN if available
                                    let subjectDnHtml = '';
                                    if (ca.subject_dn) {
                                        subjectDnHtml = `
                                            <div style="font-size: 11px; color: #64748b; margin-top: 6px; font-family: monospace; word-break: break-all;">
                                                <span style="font-weight: 600;">Subject:</span> ${escapeHtml(ca.subject_dn)}
                                            </div>
                                        `;
                                    }

                                    // Always display issuer DN if available
                                    let issuerDnHtml = '';
                                    if (ca.issuer_dn) {
                                        issuerDnHtml = `
                                            <div style="font-size: 11px; color: #64748b; margin-top: 4px; font-family: monospace; word-break: break-all;">
                                                <span style="font-weight: 600;">Issuer:</span> ${escapeHtml(ca.issuer_dn)}
                                            </div>
                                        `;
                                    }

                                    // Always display expiration info if available
                                    let expirationHtml = '';
                                    if (ca.expiration_date) {
                                        const expDate = new Date(ca.expiration_date);
                                        const now = new Date();
                                        const daysUntilExpiry = Math.floor((expDate - now) / (1000 * 60 * 60 * 24));

                                        let expColor = '#10b981'; // green
                                        let expText = `Expires: ${expDate.toLocaleDateString()}`;

                                        if (daysUntilExpiry < 0) {
                                            expColor = '#ef4444'; // red
                                            expText = `⚠️ EXPIRED: ${expDate.toLocaleDateString()}`;
                                        } else if (daysUntilExpiry < 180) {
                                            expColor = '#f59e0b'; // orange
                                            expText = `⚠️ Expires in ${daysUntilExpiry} days`;
                                        }

                                        expirationHtml = `
                                            <div style="margin-top: 8px; font-size: 12px; color: ${expColor}; font-weight: 500;">
                                                ${expText}
                                            </div>
                                        `;
                                    }

                                    // Always display key algorithm info if available
                                    let keyAlgoHtml = '';
                                    if (ca.key_algorithm) {
                                        const keySpec = ca.key_spec ? ` ${ca.key_spec}` : '';
                                        keyAlgoHtml = `
                                            <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                                                <span style="font-weight: 500;">Key:</span> ${escapeHtml(ca.key_algorithm)}${keySpec}
                                            </div>
                                        `;
                                    }

                                    // Always display CRL period info if available
                                    let crlHtml = '';
                                    if (ca.crl_period) {
                                        const crlHours = parseInt(ca.crl_period);
                                        const crlText = crlHours < 24
                                            ? `${crlHours} hours`
                                            : `${Math.round(crlHours / 24)} days`;
                                        crlHtml = `
                                            <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                                                <span style="font-weight: 500;">CRL:</span> ${crlText}
                                            </div>
                                        `;
                                    }

                                    // Test badges to show which fields are available
                                    let testBadges = '<div style="margin-bottom: 8px; display: flex; flex-wrap: wrap; gap: 4px;">';
                                    if (ca.subject_dn) testBadges += '<span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: 600;">✓ Subject</span>';
                                    if (ca.issuer_dn) testBadges += '<span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: 600;">✓ Issuer</span>';
                                    if (ca.expiration_date) testBadges += '<span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: 600;">✓ Expiry</span>';
                                    if (ca.key_algorithm && ca.key_algorithm !== 'Unknown') testBadges += '<span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: 600;">✓ Key</span>';
                                    if (ca.crl_period) testBadges += '<span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: 600;">✓ CRL</span>';
                                    testBadges += '</div>';

                                    html += `
                                        <div style="background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e5e7eb; opacity: ${isDisabled ? '0.6' : '1'};">
                                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                                                <div style="font-weight: 600; color: #374151; flex: 1; word-break: break-word;">${escapeHtml(ca.name)}</div>
                                                <span style="padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; background: ${statusBg}; color: ${statusColor}; white-space: nowrap; margin-left: 8px;">
                                                    ${displayStatus}
                                                </span>
                                            </div>
                                            ${testBadges}
                                            <div style="font-size: 12px; color: #64748b; margin-bottom: 8px; word-break: break-all;">
                                                ${escapeHtml(ca.subject)}
                                            </div>
                                            ${subjectDnHtml}
                                            ${issuerDnHtml}
                                            <div style="font-size: 13px; color: #374151; font-weight: 500; margin-top: 8px;">
                                                📜 ${ca.certificate_count} certificate${ca.certificate_count !== 1 ? 's' : ''}
                                            </div>
                                            ${keyAlgoHtml}
                                            ${crlHtml}
                                            ${expirationHtml}
                                        </div>
                                    `;
                                });
                                html += '</div>';
                            }

                            html += '</div>';
                        }
                    } catch (error) {

                        html += '<p style="color: #d32f2f;">Error loading certificate authorities</p>';
                    }
                }
                
                detailsContent.innerHTML = html;
            } catch (error) {
                
                const detailsContent = document.getElementById(`detailsContent${integrationId}`);
                detailsContent.innerHTML = '<p style="color: #d32f2f;">Error loading details</p>';
            }
        }

        async function toggleCLMIntegration(integrationId, enabled) {
            try {
                const response = await fetch(`/api/v1/inventory/integrations/${integrationId}/toggle`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ enabled: enabled })
                });
                
                if (response.ok) {
                    showAlert(enabled ? 'Integration enabled' : 'Integration disabled', 'success');
                    loadCLMIntegrations();
                    loadCollectorCertificates();
                } else {
                    const error = await response.json();
                    showAlert('Failed to toggle integration: ' + (error.error || 'Unknown error'), 'error');
                    loadCLMIntegrations(); // Reload to reflect actual state
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
                loadCLMIntegrations(); // Reload to reflect actual state
            }
        }

        async function syncCLMIntegration(integrationId) {
            try {
                const response = await fetch(`/api/v1/inventory/sync/${integrationId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                    
                if (response.ok) {
                    showAlert('Sync started', 'success');
                    setTimeout(() => loadCLMIntegrations(), 1000);
                } else {
                    const error = await response.json();
                    showAlert('Sync failed: ' + (error.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
            }
        }

        async function deleteCLMIntegration(integrationId) {
            if (!confirm('Are you sure you want to delete this integration?')) return;
            
            try {
                const response = await fetch(`/api/v1/inventory/integrations/${integrationId}`, {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    showAlert('Integration deleted', 'success');
                    loadCLMIntegrations();
                } else {
                    const error = await response.json();
                    showAlert('Failed to delete: ' + (error.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
            }
        }

        async function syncCLMCertificates() {
            await loadCollectorCertificates();
            showAlert('Certificates synced', 'success');
        }






        // Global state
        let currentPolicyV2 = null;
        let editingRuleIndex = null;
        let currentPolicyRules = [];

        // ============== POLICY LIST MANAGEMENT ==============

        async function loadPoliciesV2() {
            try {
                const response = await fetch('/api/v1/policies');
                if (!response.ok) throw new Error('Failed to load policies');
                
                const data = await response.json();
                policies = data.policies || [];
                
                const pkiContainer = document.getElementById('pki-policies-grid');
                const pqcContainer = document.getElementById('pqc-policies-grid');
                const pkiCountEl = document.getElementById('pki-policy-count');
                const pqcCountEl = document.getElementById('pqc-policy-count');
                
                // Separate policies by assessment type
                const pkiPolicies = [];
                const pqcPolicies = [];
                
                policies.forEach(policy => {
                    const policyData = typeof policy.policy_json === 'string' 
                        ? JSON.parse(policy.policy_json) 
                        : policy.policy_json;
                    const assessmentType = policyData?.metadata?.assessment_type || 'pki_health_check';
                    
                    if (assessmentType === 'pqc_assessment') {
                        pqcPolicies.push(policy);
                    } else {
                        pkiPolicies.push(policy);
                    }
                });
                
                // Update counts
                if (pkiCountEl) pkiCountEl.textContent = `${pkiPolicies.length} ${pkiPolicies.length === 1 ? 'policy' : 'policies'}`;
                if (pqcCountEl) pqcCountEl.textContent = `${pqcPolicies.length} ${pqcPolicies.length === 1 ? 'policy' : 'policies'}`;
                
                // Render PKI policies
                if (pkiContainer) {
                    if (pkiPolicies.length === 0) {
                        pkiContainer.innerHTML = `
                            <div class="empty-state" style="grid-column: 1/-1; padding: 40px; text-align: center; color: var(--text-muted);">
                                No PKI health check policies created yet.
                            </div>`;
                    } else {
                        pkiContainer.innerHTML = pkiPolicies.map(policy => renderPolicyCard(policy, 'pki')).join('');
                    }
                }
                
                // Render PQC policies
                if (pqcContainer) {
                    if (pqcPolicies.length === 0) {
                        pqcContainer.innerHTML = `
                            <div class="empty-state" style="grid-column: 1/-1; padding: 40px; text-align: center; color: var(--text-muted);">
                                No PQC migration policies created yet.
                            </div>`;
                    } else {
                        pqcContainer.innerHTML = pqcPolicies.map(policy => renderPolicyCard(policy, 'pqc')).join('');
                    }
                }
                
            } catch (error) {
                
                showAlert('Failed to load policies: ' + error.message, 'error');
            }
        }
        
        function renderPolicyCard(policy, type) {
            const policyData = typeof policy.policy_json === 'string' 
                ? JSON.parse(policy.policy_json) 
                : policy.policy_json;
            
            const metadata = policyData.metadata || {};
            const rules = policyData.rules || [];
            const rulesCount = rules.length;
            const createdDate = new Date(policy.created_at).toLocaleDateString();
            const category = metadata.category || 'Custom';
            const description = metadata.description || policyData.description || 'No description provided';
            const frameworks = metadata.frameworks || metadata.compliance_frameworks || [];
            const frameworkList = Array.isArray(frameworks) ? frameworks.join(', ') : '';
            
            const enabledRules = rules.filter(r => r.enabled !== false).length;
            
            const severities = rules.reduce((acc, rule) => {
                const sev = (rule.findings?.if_triggered?.severity || 'medium').toLowerCase();
                acc[sev] = (acc[sev] || 0) + 1;
                return acc;
            }, {});
            
            let severityBadges = '';
            if (severities.critical) severityBadges += `<span class="policy-rule-severity critical">${severities.critical} Critical</span> `;
            if (severities.high) severityBadges += `<span class="policy-rule-severity high">${severities.high} High</span> `;
            if (severities.medium) severityBadges += `<span class="policy-rule-severity medium">${severities.medium} Medium</span> `;
            if (severities.low) severityBadges += `<span class="policy-rule-severity low">${severities.low} Low</span> `;

            // Generate framework badges
            let frameworkBadges = '';
            if (Array.isArray(frameworks) && frameworks.length > 0) {
                frameworkBadges = frameworks.map(fw => {
                    const fwName = fw.replace(/\s*[-–]\s*.*/, '').trim(); // Extract name before dash
                    const fwEmoji = {
                        'NCSC': '🇬🇧',
                        'GCHQ': '🔐',
                        'PCI': '💳',
                        'ISO': '⚙️',
                        'NIST': '📊',
                        'FIPS': '🛡️',
                        'DORA': '⚡',
                        'UK': '🇬🇧',
                        'Data Protection': '🔒'
                    };
                    const emoji = Object.keys(fwEmoji).find(key => fwName.includes(key))
                        ? fwEmoji[Object.keys(fwEmoji).find(key => fwName.includes(key))]
                        : '🔗';
                    return `<span class="policy-framework-badge" title="${escapeHtml(fw)}">${emoji} ${escapeHtml(fwName)}</span>`;
                }).join('');
            }

            const borderColor = type === 'pqc' ? '#7c3aed' : '#0ea5e9';

            return `
                <div class="policy-card" style="border-top: 3px solid ${borderColor};">
                    <div class="policy-card-header">
                        <h4 class="policy-card-title">${escapeHtml(policy.name)}</h4>
                        <span class="policy-card-version">v${policyData.version || '1.0'}</span>
                    </div>
                    <p class="policy-card-description">${escapeHtml(description.substring(0, 120))}${description.length > 120 ? '...' : ''}</p>
                    <div class="policy-card-meta">
                        <span class="policy-card-meta-item">📋 ${rulesCount} rules (${enabledRules} enabled)</span>
                        <span class="policy-card-meta-item">🏷️ ${escapeHtml(category)}</span>
                        <span class="policy-card-meta-item">📅 ${createdDate}</span>
                    </div>
                    ${severityBadges ? `<div style="margin-bottom: 14px;">${severityBadges}</div>` : ''}
                    ${frameworkBadges ? `<div class="policy-card-frameworks-badges" style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px;">${frameworkBadges}</div>` : ''}
                    <div class="policy-card-actions">
                        <button class="btn-tiny" onclick="viewPolicyV2(${policy.id})">👁️ View</button>
                        <button class="btn-tiny" onclick="editPolicyV2(${policy.id})">✏️ Edit</button>
                        <button class="btn-tiny" onclick="deletePolicyV2(${policy.id})">🗑️ Delete</button>
                    </div>
                </div>
            `;
        }

        

        // ============== MODAL MANAGEMENT ==============

        function openNewPolicyModal() {
            // Reset assessment type to default
            currentPolicyAssessmentType = 'pki_health_check';
            document.querySelectorAll('.policy-type-radio').forEach(radio => {
                radio.classList.remove('selected');
            });
            document.querySelector('.policy-type-radio[data-type="pki_health_check"]').classList.add('selected');
            const pkiRadio = document.querySelector('input[name="policyAssessmentType"][value="pki_health_check"]');
            if (pkiRadio) pkiRadio.checked = true;

            currentPolicyV2 = null;
            editingRuleIndex = null;
            currentPolicyRules = [];
            
            document.getElementById('policyV2ModalTitle').textContent = 'Create New Policy v2.0';
            document.getElementById('policyV2Name').value = '';
            document.getElementById('policyV2Category').value = 'custom';
            document.getElementById('policyV2Description').value = '';
            document.getElementById('policyV2OrgName').value = '';
            document.getElementById('policyV2ComplianceLevel').value = 'high';
            
            renderPolicyRules();
            renderGlobalParameters();
            
            document.getElementById('newPolicyV2Modal').classList.add('active');
        }

        function closePolicyV2Modal() {
            document.getElementById('newPolicyV2Modal').classList.remove('active');
            currentPolicyV2 = null;
        }

        async function editPolicyV2(policyId) {
            try {
                const response = await fetch(`/api/v1/policies/${policyId}`);
                if (!response.ok) throw new Error('Failed to load policy');
                
                const data = await response.json();
                const policy = data.policy;
                const policyData = typeof policy.policy_json === 'string' 
                    ? JSON.parse(policy.policy_json) 
                    : policy.policy_json;
                
                currentPolicyV2 = { id: policyId, name: policy.name, ...policyData };
                currentPolicyRules = policyData.rules || [];
                editingRuleIndex = null;
                
                document.getElementById('policyV2ModalTitle').textContent = 'Edit Policy v2.0';
                document.getElementById('policyV2Name').value = policy.name;
                document.getElementById('policyV2Category').value = policyData.metadata?.category || 'custom';
                document.getElementById('policyV2Description').value = policyData.metadata?.description || '';
                document.getElementById('policyV2OrgName').value = 
                    policyData.parameters?.organization_name?.value || '';
                document.getElementById('policyV2ComplianceLevel').value = 
                    policyData.parameters?.compliance_level?.value || 'high';
                
                renderPolicyRules();
                renderGlobalParameters();
                
                document.getElementById('newPolicyV2Modal').classList.add('active');
                
            } catch (error) {
                
                showAlert('Failed to load policy: ' + error.message, 'error');
            }
        }

        let deletingPolicyId = null;
        
        async function deletePolicyV2(policyId, confirmDelete = false) {
            // Prevent double-click
            if (deletingPolicyId === policyId) return;

            deletingPolicyId = policyId;

            // Disable the delete button visually
            const deleteBtn = document.querySelector(`button[onclick="deletePolicyV2(${policyId})"]`);
            if (deleteBtn) {
                deleteBtn.disabled = true;
                deleteBtn.textContent = '⏳ Checking...';
            }

            try {
                // First request - check for related records
                let url = `/api/v1/policies/${policyId}`;
                if (confirmDelete) {
                    url += '?confirm=true';
                }

                const response = await fetch(url, {
                    method: 'DELETE'
                });

                const data = await response.json();

                // If warning with related records, show confirmation dialog
                if (data.requires_confirmation && !confirmDelete) {
                    deletingPolicyId = null;
                    if (deleteBtn) {
                        deleteBtn.disabled = false;
                        deleteBtn.textContent = '🗑️ Delete';
                    }

                    // Build message showing related records
                    let message = `<strong>Policy "${data.policy_name}" has related records:</strong><br><br>`;

                    if (data.related_records.scans?.length > 0) {
                        message += `<strong>Scans (${data.related_records.scans.length}):</strong><br>`;
                        data.related_records.scans.forEach(scan => {
                            message += `• ${scan.name} (${scan.status})<br>`;
                        });
                        message += '<br>';
                    }

                    if (data.related_records.reassessments?.length > 0) {
                        message += `<strong>Reassessments (${data.related_records.reassessments.length}):</strong><br>`;
                        message += '• ' + data.related_records.reassessments.length + ' reassessment(s)<br><br>';
                    }

                    message += '<strong>Deleting this policy will remove all related records. Continue?</strong>';

                    // Show custom confirmation modal
                    showConfirmationModal(message, () => {
                        deletePolicyV2(policyId, true);
                    });
                    return;
                }

                if (!response.ok) {
                    throw new Error(data.error || 'Failed to delete policy');
                }

                // Success
                const summary = data.deleted_summary;
                let successMsg = `Policy "${summary.policy_name}" deleted successfully.`;
                if (summary.scans_deleted > 0 || summary.reassessments_deleted > 0) {
                    successMsg += ` (Removed: ${summary.scans_deleted} scan(s), ${summary.reassessments_deleted} reassessment(s))`;
                }

                showAlert(successMsg, 'success');
                loadPoliciesV2();
            } catch (error) {
                showAlert('Failed to delete policy: ' + error.message, 'error');
            } finally {
                deletingPolicyId = null;
                if (deleteBtn) {
                    deleteBtn.disabled = false;
                    deleteBtn.textContent = '🗑️ Delete';
                }
            }
        }

        // Helper function to show confirmation modal
        function showConfirmationModal(message, onConfirm) {
            const modalId = 'confirmation_modal_' + Date.now();
            const modal = document.createElement('div');
            modal.id = modalId;
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
            `;

            modal.innerHTML = `
                <div style="background: white; padding: 20px; border-radius: 8px; max-width: 500px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <div style="margin-bottom: 20px; font-size: 14px; line-height: 1.6;">
                        ${message}
                    </div>
                    <div style="text-align: right; gap: 10px; display: flex; justify-content: flex-end;">
                        <button type="button" class="btn-secondary" onclick="document.getElementById('${modalId}').remove();">Cancel</button>
                        <button type="button" class="btn-danger" onclick="document.getElementById('${modalId}').remove(); onConfirm();">Delete All</button>
                    </div>
                </div>
            `;

            // Make onConfirm available in window scope temporarily
            window.onConfirm = onConfirm;
            document.body.appendChild(modal);
        }

        // ============== POLICY SAVE ==============

        async function savePolicyV2() {
            const name = document.getElementById('policyV2Name').value.trim();
            
            if (!name) {
                showAlert('Please enter a policy name', 'error');
                return;
            }
            
            if (currentPolicyRules.length === 0) {
                showAlert('Please add at least one rule to the policy', 'error');
                return;
            }
            
            try {
                // Get selected assessment type from radio buttons
                const assessmentTypeRadio = document.querySelector('input[name="policyAssessmentType"]:checked');
                const assessmentType = assessmentTypeRadio ? assessmentTypeRadio.value : 'pki_health_check';
                
                const policyObject = {
                    version: '2.0',
                    metadata: {
                        name: name,
                        description: document.getElementById('policyV2Description').value,
                        category: document.getElementById('policyV2Category').value,
                        assessment_type: assessmentType,
                        created_at: currentPolicyV2?.created_at || new Date().toISOString(),
                        last_modified: new Date().toISOString(),
                        author: 'dashboard'
                    },
                    parameters: {
                        organization_name: {
                            type: 'string',
                            value: document.getElementById('policyV2OrgName').value,
                            editable: true
                        },
                        compliance_level: {
                            type: 'enum',
                            value: document.getElementById('policyV2ComplianceLevel').value,
                            editable: true
                        }
                    },
                    rules: currentPolicyRules
                };
                
                const method = currentPolicyV2?.id ? 'PUT' : 'POST';
                const url = currentPolicyV2?.id 
                    ? `/api/v1/policies/${currentPolicyV2.id}`
                    : '/api/v1/policies';
                
                const response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: name,
                        policy: policyObject
                    })
                });
                
                if (!response.ok) throw new Error('Failed to save policy');
                
                showAlert('Policy saved successfully', 'success');
                closePolicyV2Modal();
                loadPoliciesV2();
                
            } catch (error) {
                
                showAlert('Failed to save policy: ' + error.message, 'error');
            }
        }

        // ============== RULES MANAGEMENT ==============

        function renderPolicyRules() {
            const container = document.getElementById('policyRulesContainer');
            
            if (currentPolicyRules.length === 0) {
                container.innerHTML = `
                    <div style="padding: 20px; text-align: center; color: #999;">
                        No rules added yet. Click "Add Rule" or "Load Template Rules" to get started.
                    </div>
                `;
                return;
            }
            
            container.innerHTML = `
                <div style="padding: 0;">
                    ${currentPolicyRules.map((rule, index) => `
                        <div style="padding: 12px; border-bottom: 1px solid #e0e0e0; display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-weight: 600; color: #333;">${escapeHtml(rule.metadata?.name || rule.rule_id)}</div>
                                <div style="font-size: 12px; color: #666; margin-top: 4px;">
                                    ${escapeHtml(rule.metadata?.description || '')}
                                </div>
                                <div style="font-size: 11px; color: #999; margin-top: 3px;">
                                    Severity: <strong>${rule.findings?.if_triggered?.severity || 'N/A'}</strong> | 
                                    Risk: <strong>${rule.findings?.if_triggered?.risk_score || 0}</strong>
                                </div>
                            </div>
                            <div style="display: flex; gap: 5px;">
                                <button class="btn-tiny" onclick="editRuleInPolicy(${index})">✏️ Edit</button>
                                <button class="btn-tiny" onclick="deleteRuleFromPolicy(${index})">🗑️ Remove</button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        function addRuleToPolicy() {
            editingRuleIndex = null;
            openRuleEditor();
        }

        function editRuleInPolicy(index) {
            editingRuleIndex = index;
            const rule = currentPolicyRules[index];
            populateRuleEditor(rule);
            openRuleEditor();
        }

        function deleteRuleFromPolicy(index) {
            if (confirm('Remove this rule from the policy?')) {
                currentPolicyRules.splice(index, 1);
                renderPolicyRules();
            }
        }

        function openRuleEditor() {
            document.getElementById('ruleEditorModal').classList.add('active');
        }

        function closeRuleEditor() {
            document.getElementById('ruleEditorModal').classList.remove('active');
        }

        function populateRuleEditor(rule) {
            document.getElementById('ruleEditorId').value = rule.rule_id || `rule-${Date.now()}`;
            document.getElementById('ruleEditorName').value = rule.metadata?.name || '';
            document.getElementById('ruleEditorDescription').value = rule.metadata?.description || '';
            document.getElementById('ruleEditorSeverity').value = 
                rule.findings?.if_triggered?.severity || 'high';
            document.getElementById('ruleEditorRiskScore').value = 
                rule.findings?.if_triggered?.risk_score || 8.0;
            document.getElementById('ruleEditorEnabled').checked = rule.enabled !== false;
            
            const condition = rule.condition || {};
            document.getElementById('ruleEditorConditionType').value = condition.type || 'simple';
            updateConditionFields();
            
            if (condition.type === 'simple') {
                document.getElementById('ruleEditorAssetField').value = condition.asset_field || '';
                document.getElementById('ruleEditorOperator').value = condition.operator || 'equals';
                document.getElementById('ruleEditorValues').value = 
                    (condition.values || []).join('\n');
            } else if (condition.type === 'expression') {
                document.getElementById('ruleEditorExpression').value = condition.expression || '';
            } else if (condition.type === 'temporal') {
                document.getElementById('ruleEditorDateField').value = condition.date_field || '';
                document.getElementById('ruleEditorTemporalOperator').value = condition.operator || 'expires_within_days';
                document.getElementById('ruleEditorDays').value = condition.days || '';
            }
            
            const findings = rule.findings?.if_triggered || {};
            document.getElementById('ruleEditorFindingTitle').value = findings.title || '';
            document.getElementById('ruleEditorFindingDescription').value = findings.description || '';
            document.getElementById('ruleEditorFindingRemediation').value = findings.remediation || '';
            
            renderRuleParameters(rule.parameters || {});
        }

        function updateConditionFields() {
            const type = document.getElementById('ruleEditorConditionType').value;
            document.getElementById('simpleConditionFields').style.display = 
                type === 'simple' ? 'block' : 'none';
            document.getElementById('expressionConditionFields').style.display = 
                type === 'expression' ? 'block' : 'none';
            document.getElementById('temporalConditionFields').style.display = 
                type === 'temporal' ? 'block' : 'none';
        }

        function renderRuleParameters(parameters) {
            const container = document.getElementById('ruleParametersContainer');
            const paramEntries = Object.entries(parameters);
            
            if (paramEntries.length === 0) {
                container.innerHTML = '<div style="color: #999; text-align: center; padding: 20px;">No parameters defined yet.</div>';
                return;
            }
            
            container.innerHTML = paramEntries.map(([key, param], index) => `
                <div style="padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: 600; font-size: 12px;">${escapeHtml(key)}</div>
                        <div style="font-size: 11px; color: #666; margin-top: 3px;">
                            Type: ${param.type} | Value: ${JSON.stringify(param.value)}
                        </div>
                    </div>
                    <button class="btn-tiny" onclick="deleteRuleParameter('${escapeHtml(key)}')">🗑️</button>
                </div>
            `).join('');
        }

        function addRuleParameter() {
            const key = prompt('Parameter name (e.g., minimum_key_size):', '');
            if (!key) return;
            
            const type = prompt('Parameter type (string/integer/list/boolean):', 'string');
            const value = prompt('Default value:', '');
            
            // Store in a temporary way - would need UI expansion for full functionality
            showAlert('Parameter feature requires expanded UI. For now, edit the JSON directly in the policy file.', 'info');
        }

        function deleteRuleParameter(key) {
            showAlert('Parameter editing requires expanded UI. Edit the JSON directly in the policy file.', 'info');
        }

        function saveRuleToPolicy() {
            const rule = buildRuleFromEditor();
            
            if (!rule.rule_id || !rule.metadata?.name) {
                showAlert('Rule ID and Name are required', 'error');
                return;
            }
            
            if (editingRuleIndex !== null) {
                currentPolicyRules[editingRuleIndex] = rule;
            } else {
                currentPolicyRules.push(rule);
            }
            
            renderPolicyRules();
            closeRuleEditor();
        }

        function buildRuleFromEditor() {
            const conditionType = document.getElementById('ruleEditorConditionType').value;
            let condition = { type: conditionType };
            
            if (conditionType === 'simple') {
                condition.asset_field = document.getElementById('ruleEditorAssetField').value;
                condition.operator = document.getElementById('ruleEditorOperator').value;
                const values = document.getElementById('ruleEditorValues').value
                    .split('\n')
                    .map(v => v.trim())
                    .filter(v => v);
                condition.values = values.length === 1 ? values[0] : values;
            } else if (conditionType === 'expression') {
                condition.expression = document.getElementById('ruleEditorExpression').value;
            } else if (conditionType === 'temporal') {
                condition.date_field = document.getElementById('ruleEditorDateField').value;
                condition.operator = document.getElementById('ruleEditorTemporalOperator').value;
                condition.days = parseInt(document.getElementById('ruleEditorDays').value) || 0;
            }
            
            return {
                rule_id: document.getElementById('ruleEditorId').value,
                version: '1.0.0',
                enabled: document.getElementById('ruleEditorEnabled').checked,
                type: 'assessment',
                metadata: {
                    name: document.getElementById('ruleEditorName').value,
                    description: document.getElementById('ruleEditorDescription').value,
                    category: 'custom'
                },
                scope: {
                    collector_types: ['tls', 'azure', 'ejbca', 'luna_hsm', 'crl', 'file_scan'],
                    asset_types: ['certificate', 'key', 'tls_endpoint', 'crl']
                },
                parameters: {},
                condition: condition,
                findings: {
                    if_triggered: {
                        severity: document.getElementById('ruleEditorSeverity').value,
                        risk_score: parseFloat(document.getElementById('ruleEditorRiskScore').value),
                        title: document.getElementById('ruleEditorFindingTitle').value,
                        description: document.getElementById('ruleEditorFindingDescription').value,
                        remediation: document.getElementById('ruleEditorFindingRemediation').value
                    }
                },
                dashboard_config: {
                    category: 'Custom Rules',
                    display_order: 999,
                    form_fields: []
                }
            };
        }

        // ============== GLOBAL PARAMETERS ==============

        function renderGlobalParameters() {
            const container = document.getElementById('policyGlobalParametersContainer');
            
            container.innerHTML = `
                <div class="form-group">
                    <label>Organization Name</label>
                    <input type="text" id="policyGlobalOrgName" placeholder="Your Organization">
                </div>
                <div class="form-group">
                    <label>Email Contact</label>
                    <input type="email" id="policyGlobalEmail" placeholder="contact@organization.com">
                </div>
            `;
        }

        // ============== TEMPLATE & IMPORT ==============

        function importRulesFromTemplate() {
            showAlert('Loading template rules...', 'info');
            
            // Load the comprehensive template
            fetch('/policies/nist-sp800-52-v2.0.json')
                .then(r => r.json())
                .then(data => {
                    const rules = data.rules || [];
                    currentPolicyRules = rules.slice(0, 5); // Load first 5 rules as example
                    renderPolicyRules();
                    showAlert(`Loaded ${currentPolicyRules.length} template rules. Edit as needed.`, 'success');
                })
                .catch(() => {
                    showAlert('Template file not found. Create rules manually.', 'error');
                });
        }

        function importPolicyFile() {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = '.json';
            input.onchange = async (e) => {
                try {
                    const file = e.target.files[0];
                    const text = await file.text();
                    const policy = JSON.parse(text);
                    
                    if (policy.version !== '2.0') {
                        showAlert('Policy must be version 2.0', 'error');
                        return;
                    }
                    
                    // Save the imported policy
                    const response = await fetch('/api/v1/policies', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: policy.metadata?.name || 'Imported Policy',
                            policy: policy
                        })
                    });
                    
                    if (!response.ok) throw new Error('Failed to import');
                    
                    showAlert('Policy imported successfully', 'success');
                    loadPoliciesV2();
                    
                } catch (error) {
                    showAlert('Failed to import policy: ' + error.message, 'error');
                }
            };
            input.click();
        }

        function downloadPolicyTemplate() {
            fetch('/policies/nist-sp800-52-v2.0.json')
                .then(r => r.blob())
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'policy-template-v2.0.json';
                    a.click();
                })
                .catch(() => {
                    showAlert('Template file not found', 'error');
                });
        }

        // ============== INITIALIZATION ==============

        // Load policies when dashboard loads
        document.addEventListener('DOMContentLoaded', () => {
            loadPoliciesV2();
        });










        // Certificate refresh interval
        let clmCertificateRefreshInterval = null;
        let allCLMCertificates = []; // Store all certificates for filtering

        async function loadCollectorCertificates() {
            const dashboardLoading = document.getElementById('clmDashboardLoadingStatus');
            const certsLoading = document.getElementById('clmCertificatesLoadingStatus');
            if (dashboardLoading) dashboardLoading.style.display = 'block';
            if (certsLoading) certsLoading.style.display = 'block';
            
            try {
                const integrationsResponse = await fetch('/api/v1/inventory/integrations');
                if (!integrationsResponse.ok) throw new Error('Failed to fetch integrations');
                const integrationsData = await integrationsResponse.json();
                const allIntegrations = integrationsData.integrations || [];

                // Log raw response
                console.log('[CLM Dashboard] Raw API response:', integrationsData);
                console.log(`[CLM Dashboard] allIntegrations array length: ${allIntegrations.length}`);
                console.log('[CLM Dashboard] All integrations:', allIntegrations.map(i => ({id: i.id, name: i.name, type: i.type, enabled: i.enabled})));

                const enabledIntegrations = allIntegrations.filter(i => i.enabled === true || i.enabled === 1);

                // Log for debugging
                console.log(`[CLM Dashboard] Found ${allIntegrations.length} total integrations, ${enabledIntegrations.length} enabled:`,
                    enabledIntegrations.map(i => `${i.name} (type: ${i.type}, enabled: ${i.enabled})`));
                
                if (allIntegrations.length === 0) {
                    const tbody = document.getElementById('clm-certificates-body');
                    tbody.innerHTML = '<tr><td colspan="11" class="empty-state">No certificate sources configured. Go to Connectors to add an integration.</td></tr>';
                    document.getElementById('clmCertCount').textContent = '0 / 0 certificates';
                    if (dashboardLoading) dashboardLoading.style.display = 'none';
                    if (certsLoading) certsLoading.style.display = 'none';
                    return;
                }
                
                if (enabledIntegrations.length === 0) {
                    const tbody = document.getElementById('clm-certificates-body');
                    tbody.innerHTML = '<tr><td colspan="11" class="empty-state">No enabled integrations. Go to Connectors to enable an integration.</td></tr>';
                    document.getElementById('clmCertCount').textContent = '0 / 0 certificates';
                    if (dashboardLoading) dashboardLoading.style.display = 'none';
                    if (certsLoading) certsLoading.style.display = 'none';
                    return;
                }
                
                // Fetch from inventory integrations only (not TLS scans)
                const response = await fetch('/api/v1/inventory/certificates');
                if (!response.ok) throw new Error(`HTTP ${response.status}`);

                const data = await response.json();
                allCLMCertificates = data.certificates || [];
                
                if (allCLMCertificates.length === 0) {
                    const tbody = document.getElementById('clm-certificates-body');
                    tbody.innerHTML = '<tr><td colspan="11" class="empty-state">Inventory is empty. Go to Connectors and click "Sync" to populate.</td></tr>';
                    document.getElementById('clmCertCount').textContent = '0 / 0 certificates';
                    if (dashboardLoading) dashboardLoading.style.display = 'none';
                    if (certsLoading) certsLoading.style.display = 'none';
                    return;
                }
                
                document.getElementById('clmLastSyncTime').textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
                
                const sourceFilter = document.getElementById('clmCertSourceFilter');
                const uniqueSources = [...new Set(allCLMCertificates.map(c => c.source_integration || c.source || 'Unknown'))];
                sourceFilter.innerHTML = '<option value="">All Sources</option>' + 
                    uniqueSources.map(source => `<option value="${escapeHtml(source)}">${escapeHtml(source)}</option>`).join('');
                
                filterCLMCertificates();
                updateCLMDashboard(allCLMCertificates, [], allIntegrations);
                
                if (dashboardLoading) dashboardLoading.style.display = 'none';
                if (certsLoading) certsLoading.style.display = 'none';
                
            } catch (error) {
                
                const tbody = document.getElementById('clm-certificates-body');
                tbody.innerHTML = `<tr><td colspan="11" class="empty-state">Error: ${escapeHtml(error.message)}</td></tr>`;
                if (dashboardLoading) dashboardLoading.style.display = 'none';
                if (certsLoading) certsLoading.style.display = 'none';
            }
        }

        function filterCLMCertificates() {
            const searchTerm = document.getElementById('clmCertSearch').value.toLowerCase();
            const sourceFilter = document.getElementById('clmCertSourceFilter').value;
            const statusFilter = document.getElementById('clmCertStatusFilter').value;
            const environmentFilter = document.getElementById('assetsCertEnvironmentFilter').value;

            const filteredCerts = allCLMCertificates.filter(cert => {
                // Helper to convert cert subject/issuer to searchable string
                const getSearchableString = (value) => {
                    if (typeof value === 'object' && value) {
                        return Object.values(value).join(' ').toLowerCase();
                    }
                    return String(value || '').toLowerCase();
                };

                // Search filter - check all fields including table display values
                const subjectSearch = getSearchableString(cert.subject);
                const issuerSearch = getSearchableString(cert.issuer);
                const serialSearch = String(cert.serial_number || '').toLowerCase();
                const fingerprintSearch = String(cert.fingerprint_sha256 || '').toLowerCase();
                const sourceSearch = String(cert.source_integration || '').toLowerCase();
                const notBeforeSearch = String(cert.not_before || '').toLowerCase();
                const notAfterSearch = String(cert.not_after || '').toLowerCase();

                const searchMatch = !searchTerm ||
                    subjectSearch.includes(searchTerm) ||
                    issuerSearch.includes(searchTerm) ||
                    serialSearch.includes(searchTerm) ||
                    fingerprintSearch.includes(searchTerm) ||
                    sourceSearch.includes(searchTerm) ||
                    notBeforeSearch.includes(searchTerm) ||
                    notAfterSearch.includes(searchTerm);

                // Source filter
                const sourceMatch = !sourceFilter || cert.source_integration === sourceFilter;

                // Environment filter
                const environmentMatch = !environmentFilter || cert.inferred_environment_type === environmentFilter;

                // Status filter
                let statusMatch = true;
                if (statusFilter) {
                    const expiryDate = new Date(cert.not_after);
                    const today = new Date();
                    const daysToExpiry = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));

                    if (statusFilter === 'expired') {
                        statusMatch = daysToExpiry < 0;
                    } else if (statusFilter === 'expiring') {
                        statusMatch = daysToExpiry >= 0 && daysToExpiry < 60;
                    } else if (statusFilter === 'valid') {
                        statusMatch = daysToExpiry >= 60;
                    }
                }

                return searchMatch && sourceMatch && statusMatch && environmentMatch;
            });
            
            // Update count display
            document.getElementById('clmCertCount').textContent = filteredCerts.length + ' / ' + allCLMCertificates.length + ' certificates';
            
            // Populate table
            const tbody = document.getElementById('clm-certificates-body');
            
            if (filteredCerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="11" class="empty-state">No certificates match the current filters.</td></tr>';
            } else {
                tbody.innerHTML = filteredCerts.map(cert => {
                    const expiryDate = new Date(cert.not_after);
                    const today = new Date();
                    const daysToExpiry = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
                    
                    let statusClass = 'status-badge';
                    let status = 'Valid';
                    if (daysToExpiry < 0) {
                        statusClass += ' status-failed';
                        status = 'Expired';
                    } else if (daysToExpiry < 30) {
                        statusClass += ' status-partial';
                        status = 'Expiring Soon';
                    } else {
                        statusClass += ' status-successful';
                    }
                    
                    const subjectCN = extractCommonName(cert.subject);
                    const issuerCN = extractCommonName(cert.issuer);

                    // Determine certificate type
                    const certType = cert.is_ca ? 'CA' : (cert.is_self_signed ? 'Self-Signed' : 'End Entity');
                    const keyType = cert.public_key_algorithm ? cert.public_key_algorithm.replace('_', '') : 'Unknown';
                    const keySize = cert.public_key_size || 'N/A';

                    // Determine environment badge
                    let envBadgeClass = 'badge-secondary';
                    let envText = 'Unknown';
                    if (cert.inferred_environment_type) {
                        envText = cert.inferred_environment_type.charAt(0).toUpperCase() + cert.inferred_environment_type.slice(1);
                        const envLower = cert.inferred_environment_type.toLowerCase();
                        if (envLower === 'production') envBadgeClass = 'badge-danger';
                        else if (envLower === 'staging') envBadgeClass = 'badge-warning';
                        else if (envLower === 'development') envBadgeClass = 'badge-info';
                        else if (envLower === 'testing') envBadgeClass = 'badge-primary';
                    }
                    const confidencePct = cert.inferred_discovery_confidence ? (cert.inferred_discovery_confidence * 100).toFixed(0) : '0';

                    return `
                        <tr>
                            <td>${subjectCN}</td>
                            <td>${issuerCN}</td>
                            <td>${cert.not_before ? new Date(cert.not_before).toLocaleDateString() : 'N/A'}</td>
                            <td>${cert.not_after ? new Date(cert.not_after).toLocaleDateString() : 'N/A'}</td>
                            <td>${daysToExpiry >= 0 ? daysToExpiry : 'Expired'}</td>
                            <td><span class="badge badge-info">${keyType}</span></td>
                            <td>${keySize}</td>
                            <td><span class="badge badge-info">${certType}</span></td>
                            <td><strong>${cert.source_integration || 'Unknown'}</strong></td>
                            <td><span class="badge ${envBadgeClass}" title="Confidence: ${confidencePct}%">${envText}</span></td>
                            <td><span class="${statusClass}">${status}</span></td>
                            <td style="text-align: right;">
                                <button class="btn-secondary" onclick="viewCLMCertificateDetails(this)" data-cert="${btoa(JSON.stringify(cert))}">View</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            }
        }

        function clearCLMFilters() {
            document.getElementById('clmCertSearch').value = '';
            document.getElementById('clmCertSourceFilter').value = '';
            document.getElementById('clmCertStatusFilter').value = '';
            filterCLMCertificates();
        }

        function viewCLMCertificateDetails(buttonElement) {
            try {
                // Get certificate data from data attribute
                const certData = buttonElement.getAttribute('data-cert');
                const cert = JSON.parse(atob(certData));
                
                const notAfter = new Date(cert.not_after);
                const notBefore = new Date(cert.not_before);
                
                let html = '';
                
                // Basic Information
                html += '<div class="modal-section"><h3>Basic Information</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">Common Name</span><span class="field-value">' + (cert.subject && cert.subject.commonName ? cert.subject.commonName : 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Serial Number</span><span class="field-value">' + (cert.serial_number || 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Fingerprint (SHA-256)</span><span class="field-value">' + (cert.fingerprint_sha256 || 'N/A') + '</span></div>';
                html += '</div></div>';
                
                // Validity Period
                html += '<div class="modal-section"><h3>Validity Period</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">Valid From</span><span class="field-value">' + notBefore.toLocaleString() + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Valid Until</span><span class="field-value">' + notAfter.toLocaleString() + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Days Until Expiration</span><span class="field-value">' + Math.ceil((notAfter - new Date()) / (1000 * 60 * 60 * 24)) + ' days</span></div>';
                html += '</div></div>';
                
                // Subject Information
                if (cert.subject) {
                    html += '<div class="modal-section"><h3>Subject Information</h3><div class="modal-section-content">';
                    if (typeof cert.subject === 'string') {
                        // Tokenized subject (anonymized mode)
                        html += '<div class="field-row"><span class="field-label">Subject (Tokenized)</span><span class="field-value">' + cert.subject + '</span></div>';
                    } else if (typeof cert.subject === 'object') {
                        // Full subject details (full/selective modes)
                        for (const [key, value] of Object.entries(cert.subject)) {
                            const label = key.replace(/([A-Z])/g, ' $1');
                            html += '<div class="field-row"><span class="field-label">' + label + '</span><span class="field-value">' + (value || 'N/A') + '</span></div>';
                        }
                    }
                    html += '</div></div>';
                }

                // Issuer Information
                if (cert.issuer) {
                    html += '<div class="modal-section"><h3>Issuer Information</h3><div class="modal-section-content">';
                    if (typeof cert.issuer === 'string') {
                        // Tokenized issuer (anonymized mode)
                        html += '<div class="field-row"><span class="field-label">Issuer (Tokenized)</span><span class="field-value">' + cert.issuer + '</span></div>';
                    } else if (typeof cert.issuer === 'object') {
                        // Full issuer details (full/selective modes)
                        for (const [key, value] of Object.entries(cert.issuer)) {
                            const label = key.replace(/([A-Z])/g, ' $1');
                            html += '<div class="field-row"><span class="field-label">' + label + '</span><span class="field-value">' + (value || 'N/A') + '</span></div>';
                        }
                    }
                    html += '</div></div>';
                }
                
                // Public Key Information
                html += '<div class="modal-section"><h3>Public Key Information</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">Algorithm</span><span class="field-value">' + (cert.public_key_algorithm || 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Key Size</span><span class="field-value">' + (cert.public_key_size || 'N/A') + ' bits</span></div>';
                if (cert.signature_algorithm) {
                    html += '<div class="field-row"><span class="field-label">Signature Algorithm</span><span class="field-value">' + cert.signature_algorithm + '</span></div>';
                }
                html += '</div></div>';
                
                // Key Usage
                if (cert.key_usage && cert.key_usage.length > 0) {
                    html += '<div class="modal-section"><h3>Key Usage</h3><div class="array-list">';
                    for (const usage of cert.key_usage) {
                        html += '<span class="array-item">' + usage + '</span>';
                    }
                    html += '</div></div>';
                }
                
                // Extended Key Usage
                if (cert.extended_key_usage && cert.extended_key_usage.length > 0) {
                    html += '<div class="modal-section"><h3>Extended Key Usage</h3><div class="array-list">';
                    for (const eku of cert.extended_key_usage) {
                        html += '<span class="array-item">' + eku + '</span>';
                    }
                    html += '</div></div>';
                }
                
                // Subject Alternative Names
                if (cert.san && cert.san.length > 0) {
                    html += '<div class="modal-section"><h3>Subject Alternative Names (SANs)</h3><div class="array-list">';
                    for (const san of cert.san) {
                        html += '<span class="array-item">' + san.replace(/[<>]/g, '') + '</span>';
                    }
                    html += '</div></div>';
}
                
                // Basic Constraints
                if (cert.basic_constraints) {
                    html += '<div class="modal-section"><h3>Basic Constraints</h3><div class="modal-section-content">';
                    html += '<div class="field-row"><span class="field-label">Is CA</span><span class="field-value">' + (cert.basic_constraints.ca ? 'Yes' : 'No') + '</span></div>';
                    html += '<div class="field-row"><span class="field-label">Path Length</span><span class="field-value">' + (cert.basic_constraints.path_length || 'N/A') + '</span></div>';
                    html += '</div></div>';
                }
                
                // Distribution Points
                html += '<div class="modal-section"><h3>Distribution Points</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">CRL Distribution Points</span>';
                if (cert.crl_distribution_points && cert.crl_distribution_points.length > 0) {
                    html += '<div class="array-list">';
                    for (const cdp of cert.crl_distribution_points) {
                        html += '<span class="array-item">' + cdp + '</span>';
                    }
                    html += '</div>';
                } else {
                    html += '<span class="field-value">N/A</span>';
                }
                html += '</div>';
                html += '<div class="field-row"><span class="field-label">OCSP Responders</span>';
                if (cert.ocsp_responders && cert.ocsp_responders.length > 0) {
                    html += '<div class="array-list">';
                    for (const ocsp of cert.ocsp_responders) {
                        html += '<span class="array-item">' + ocsp + '</span>';
                    }
                    html += '</div>';
                } else {
                    html += '<span class="field-value">N/A</span>';
                }
                html += '</div>';
                html += '</div></div>';
                
                // Certificate Transparency
                html += '<div class="modal-section"><h3>Certificate Transparency</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">SCTs Present</span><span class="field-value">' + ((cert.certificate_transparency_scts && cert.certificate_transparency_scts.length > 0) ? 'Yes' : 'No') + '</span></div>';
                html += '</div></div>';
                
                // TLS Library Information
                html += '<div class="modal-section"><h3>TLS Configuration</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">TLS Library</span><span class="field-value">' + (cert.tls_library || 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">TLS Version</span><span class="field-value">' + (cert.tls_version || 'N/A') + '</span></div>';
                html += '</div></div>';
                
                // Certificate Chain
                if (cert.certificate_chain && cert.certificate_chain.length > 0) {
                    html += '<div class="modal-section"><h3>Certificate Chain</h3><div class="modal-section-content">';
                    html += '<div class="field-row"><span class="field-label">Chain Depth</span><span class="field-value">' + cert.certificate_chain.length + ' certificate(s)</span></div>';
                    
                    // Create table for chain display
                    html += '<table style="width: 100%; border-collapse: collapse; margin-top: 15px;">';
                    html += '<thead style="background: #f0f0f0; border-bottom: 2px solid #0078d4;">';
                    html += '<tr>';
                    html += '<th style="padding: 10px; text-align: left; font-weight: bold;">Position</th>';
                    html += '<th style="padding: 10px; text-align: left; font-weight: bold;">Subject</th>';
                    html += '<th style="padding: 10px; text-align: left; font-weight: bold;">Issuer</th>';
                    html += '<th style="padding: 10px; text-align: left; font-weight: bold;">Type</th>';
                    html += '</tr>';
                    html += '</thead>';
                    html += '<tbody>';
                    
                    for (let i = 0; i < cert.certificate_chain.length; i++) {
                        const chainCert = cert.certificate_chain[i];
                        const chainSubject = chainCert.subject && chainCert.subject.commonName ? chainCert.subject.commonName : 'Unknown';
                        const chainIssuer = chainCert.issuer && chainCert.issuer.commonName ? chainCert.issuer.commonName : 'Unknown';
                        let certType = 'Intermediate';
                        if (i === 0) certType = 'Leaf';
                        if (chainCert.is_self_signed) certType = 'Root';
                        
                        const rowColor = i % 2 === 0 ? '#ffffff' : '#f9f9f9';
                        html += '<tr style="background: ' + rowColor + '; border-bottom: 1px solid #e0e0e0;">';
                        html += '<td style="padding: 10px; vertical-align: top; font-weight: bold; color: #0078d4;">Cert ' + (i + 1) + '</td>';
                        html += '<td style="padding: 10px; vertical-align: top; word-break: break-all;">' + chainSubject + '</td>';
                        html += '<td style="padding: 10px; vertical-align: top; word-break: break-all;">' + chainIssuer + '</td>';
                        html += '<td style="padding: 10px; vertical-align: top;">' + certType + '</td>';
                        html += '</tr>';
                        
                        // Details row (collapsible-like, always expanded)
                        html += '<tr style="background: #fafafa; border-bottom: 1px solid #e0e0e0;">';
                        html += '<td colspan="4" style="padding: 10px;">';
                        html += '<div style="font-size: 0.9em; line-height: 1.6;">';
                        html += '<div><strong>Serial:</strong> ' + (chainCert.serial_number || 'N/A') + '</div>';
                        html += '<div><strong>Valid Until:</strong> ' + (new Date(chainCert.not_after).toLocaleString()) + '</div>';
                        html += '<div><strong>Self-Signed:</strong> ' + (chainCert.is_self_signed ? 'Yes' : 'No') + '</div>';
                        html += '<div style="margin-top: 8px; word-break: break-all;"><strong>Fingerprint:</strong><br><span style="font-family: monospace; font-size: 0.85em;">' + (chainCert.fingerprint_sha256 || 'N/A') + '</span></div>';
                        html += '</div></td></tr>';
                    }
                    
                    html += '</tbody>';
                    html += '</table>';
                    html += '</div></div>';
                }
                
                // Certificate Details
                html += '<div class="modal-section"><h3>Certificate Details</h3><div class="modal-section-content">';
                html += '<div class="field-row"><span class="field-label">Is Self-Signed</span><span class="field-value">' + (cert.is_self_signed ? 'Yes' : 'No') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Is CA</span><span class="field-value">' + (cert.is_ca ? 'Yes' : 'No') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Found At</span><span class="field-value">' + (cert.found_at_destination || 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Port</span><span class="field-value">' + (cert.found_on_port || 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Source</span><span class="field-value">' + (cert.source_integration || 'N/A') + '</span></div>';
                html += '<div class="field-row"><span class="field-label">Unique ID</span><span class="field-value">' + (cert.unique_id || 'N/A') + '</span></div>';
                html += '</div></div>';
                
                // Update modal header with badges
                const subjectCN = cert.subject && cert.subject.commonName ? cert.subject.commonName : 'Unknown';

                // Generate badge HTML
                let badgesHtml = '<div class="cert-header-badges">';

                // Cert Type Badge
                const certType = cert.is_ca ? 'Root/Intermediate CA' : 'End Entity';
                const typeIcon = cert.is_ca ? '🔐' : '📝';
                const typeClass = cert.is_ca ? 'type-ca' : 'type-entity';
                badgesHtml += `<div class="cert-badge ${typeClass}"><span class="cert-badge-icon">${typeIcon}</span>${certType}</div>`;

                // Algorithm Badge
                const algo = cert.public_key_algorithm || 'N/A';
                let algoClass = 'algo-other';
                let algoIcon = '🔑';
                if (algo.includes('RSA')) {
                    algoClass = 'algo-rsa';
                    algoIcon = '🔴';
                } else if (algo.includes('ECDSA') || algo.includes('EC')) {
                    algoClass = 'algo-ecdsa';
                    algoIcon = '🟣';
                }
                const keySize = cert.public_key_size ? ` (${cert.public_key_size}b)` : '';
                badgesHtml += `<div class="cert-badge ${algoClass}"><span class="cert-badge-icon">${algoIcon}</span>${algo}${keySize}</div>`;

                // Expiry Badge
                const daysUntilExpiry = Math.ceil((notAfter - new Date()) / (1000 * 60 * 60 * 24));
                let expiryClass = 'expiry-valid';
                let expiryIcon = '✓';
                let expiryText = `${daysUntilExpiry}d`;
                if (daysUntilExpiry < 0) {
                    expiryClass = 'expiry-expired';
                    expiryIcon = '✕';
                    expiryText = 'Expired';
                } else if (daysUntilExpiry < 30) {
                    expiryClass = 'expiry-warning';
                    expiryIcon = '⚠';
                    expiryText = `${daysUntilExpiry}d left`;
                }
                badgesHtml += `<div class="cert-badge ${expiryClass}"><span class="cert-badge-icon">${expiryIcon}</span>${expiryText}</div>`;

                badgesHtml += '</div>';

                // Update header structure
                const modalHeader = document.querySelector('#certificateDetailsModal .modal-header');
                modalHeader.innerHTML = `
                    <div class="cert-header-title">
                        <h2>Certificate: ${subjectCN}</h2>
                        <button class="cert-header-close" onclick="closeModal('certificateDetailsModal')">&times;</button>
                    </div>
                    ${badgesHtml}
                `;

                document.getElementById('certificateDetailsContent').innerHTML = html;
                document.getElementById('certificateDetailsModal').classList.add('active');
                
            } catch (error) {
                
                showAlert('Error displaying certificate details: ' + error.message, 'error');
            }
        }

        // Chart instances
        let statusPieChart = null;
        let integrationBarChart = null;
        let algorithmDoughnutChart = null;
        let expiryTimelineChart = null;
        let keySizeChart = null;
        let keyUsageChart = null;

        function updateCLMDashboard(allCertificates, allKeys, integrations) {
            // Calculate metrics
            const totalCerts = allCertificates.length;
            let expiringCount = 0;
            let expiredCount = 0;
            const today = new Date();
            const statusBreakdown = { 'Valid': 0, 'Expiring Soon (<60 days)': 0, 'Expired': 0 };
            const integrationStats = {};
            const algorithmStats = {};
            const keySizeStats = {};
            const keyUsageStats = {};
            const expiryTimeline = { '0-30 days': 0, '31-90 days': 0, '91-180 days': 0, '181-365 days': 0, '1+ years': 0 };

            // Build integration name mapping from integrations array
            const integrationNameMap = {};
            const integrationIdMap = {}; // Map connector_id to integration name
            integrations.forEach(integration => {
                integrationNameMap[integration.id] = integration.name;
                integrationNameMap[integration.name] = integration.name; // Also map by name directly
                integrationIdMap[integration.id] = integration.name;
                // Also map by type for legacy source_integration values
                integrationNameMap[integration.type.toLowerCase()] = integration.name;
                // Initialize stats for this integration
                integrationStats[integration.name] = {
                    valid: 0,
                    expiring: 0,
                    expired: 0,
                    cert_count: 0,
                    key_count: 0
                };
            });

            // Count active integrations - count ALL enabled integrations passed in
            const activeIntegrations = integrations.filter(i => i.enabled === true || i.enabled === 1).length;

            allCertificates.forEach(cert => {
                const expiryDate = new Date(cert.not_after);
                const daysToExpiry = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));

                // Count by status
                let status = 'Valid';
                if (daysToExpiry < 0) {
                    status = 'Expired';
                    expiredCount++;
                } else if (daysToExpiry < 60) {
                    status = 'Expiring Soon';
                    expiringCount++;
                }
                statusBreakdown[status]++;

                // Expiry timeline
                if (daysToExpiry < 0) {
                    // Already counted in expired
                } else if (daysToExpiry <= 30) {
                    expiryTimeline['0-30 days']++;
                } else if (daysToExpiry <= 90) {
                    expiryTimeline['31-90 days']++;
                } else if (daysToExpiry <= 180) {
                    expiryTimeline['91-180 days']++;
                } else if (daysToExpiry <= 365) {
                    expiryTimeline['181-365 days']++;
                } else {
                    expiryTimeline['1+ years']++;
                }

                // Count by integration - try multiple fields (connector_id, source_integration, source)
                let displayName = 'Unknown';
                if (cert.connector_id && integrationIdMap[cert.connector_id]) {
                    displayName = integrationIdMap[cert.connector_id];
                } else if (cert.source_integration) {
                    displayName = integrationNameMap[cert.source_integration] || cert.source_integration;
                } else if (cert.source) {
                    displayName = integrationNameMap[cert.source] || cert.source;
                }
                if (!integrationStats[displayName]) {
                    integrationStats[displayName] = { valid: 0, expiring: 0, expired: 0, cert_count: 0, key_count: 0 };
                }
                integrationStats[displayName].cert_count++;
                if (status === 'Valid') integrationStats[displayName].valid++;
                else if (status === 'Expiring Soon') integrationStats[displayName].expiring++;
                else integrationStats[displayName].expired++;

                // Count by algorithm
                const algo = cert.public_key_algorithm || 'Unknown';
                algorithmStats[algo] = (algorithmStats[algo] || 0) + 1;

                // Count by key size
                const keySize = cert.public_key_size || 'Unknown';
                keySizeStats[keySize] = (keySizeStats[keySize] || 0) + 1;

                // Count by key usage (case-insensitive, deduplicated)
                if (cert.key_usage && Array.isArray(cert.key_usage)) {
                    cert.key_usage.forEach(usage => {
                        const normalizedUsage = usage.toLowerCase();
                        keyUsageStats[normalizedUsage] = (keyUsageStats[normalizedUsage] || 0) + 1;
                    });
                }
            });

            // Count keys per integration
            if (allKeys && allKeys.length > 0) {
                allKeys.forEach(key => {
                    let displayName = 'Unknown';
                    if (key.connector_id && integrationIdMap[key.connector_id]) {
                        displayName = integrationIdMap[key.connector_id];
                    } else if (key.source_integration) {
                        displayName = integrationNameMap[key.source_integration] || key.source_integration;
                    } else if (key.source) {
                        displayName = integrationNameMap[key.source] || key.source;
                    }
                    if (!integrationStats[displayName]) {
                        integrationStats[displayName] = { valid: 0, expiring: 0, expired: 0, cert_count: 0, key_count: 0 };
                    }
                    integrationStats[displayName].key_count++;
                });
            }

            // Update metric cards
            document.getElementById('metric-total-certs').textContent = totalCerts;
            document.getElementById('metric-expiring-soon').textContent = expiringCount;
            document.getElementById('metric-expired').textContent = expiredCount;
            document.getElementById('metric-active-integrations').textContent = activeIntegrations;

            // Update integration breakdown table to show all enabled integrations
            const integrationTbody = document.getElementById('clm-integration-breakdown');
            const tableRows = [];

            // First add integrations with certificates or keys
            Object.entries(integrationStats).forEach(([integration, stats]) => {
                const totalItems = stats.cert_count + stats.key_count;
                tableRows.push({
                    name: integration,
                    cert_count: stats.cert_count,
                    key_count: stats.key_count,
                    total_items: totalItems,
                    valid: stats.valid,
                    expiring: stats.expiring,
                    expired: stats.expired,
                    hasData: totalItems > 0
                });
            });

            // Then add enabled integrations that don't have certificates or keys
            integrations.filter(i => i.enabled).forEach(integration => {
                if (!tableRows.some(r => r.name === integration.name)) {
                    tableRows.push({
                        name: integration.name,
                        cert_count: 0,
                        key_count: 0,
                        total_items: 0,
                        valid: 0,
                        expiring: 0,
                        expired: 0,
                        hasData: false
                    });
                }
            });

            // Sort: with-data first, then by name
            tableRows.sort((a, b) => {
                if (a.hasData !== b.hasData) return b.hasData - a.hasData;
                return a.name.localeCompare(b.name);
            });

            if (tableRows.length > 0) {
                integrationTbody.innerHTML = tableRows.map(row => `
                    <tr>
                        <td><strong>${escapeHtml(row.name)}</strong></td>
                        <td>${row.cert_count}</td>
                        <td>${row.key_count}</td>
                        <td>${row.total_items}</td>
                        <td>${row.valid}</td>
                        <td>${row.expiring}</td>
                        <td>${row.expired}</td>
                    </tr>
                `).join('');
            }

            // Render Charts
            renderCLMCharts(statusBreakdown, integrationStats, algorithmStats, expiryTimeline, keySizeStats, keyUsageStats);
        }

        function renderCLMCharts(statusBreakdown, integrationStats, algorithmStats, expiryTimeline, keySizeStats, keyUsageStats) {
            // Status Pie Chart
            if (statusPieChart) statusPieChart.destroy();
            const statusCtx = document.getElementById('statusPieChart');
            if (statusCtx) {
                statusPieChart = new Chart(statusCtx, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(statusBreakdown),
                        datasets: [{
                            data: Object.values(statusBreakdown),
                            backgroundColor: ['#51cf66', '#ffc107', '#dc3545'],
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { position: 'bottom', labels: { padding: 15, font: { size: 12 } } },
                            tooltip: { callbacks: { label: (context) => `${context.label}: ${context.parsed}` } }
                        }
                    }
                });
            }

            // Integration Bar Chart
            if (integrationBarChart) integrationBarChart.destroy();
            const integrationCtx = document.getElementById('integrationBarChart');
            if (integrationCtx) {
                const integrationLabels = Object.keys(integrationStats);
                const validData = integrationLabels.map(k => integrationStats[k].valid);
                const expiringData = integrationLabels.map(k => integrationStats[k].expiring);
                const expiredData = integrationLabels.map(k => integrationStats[k].expired);

                integrationBarChart = new Chart(integrationCtx, {
                    type: 'bar',
                    data: {
                        labels: integrationLabels,
                        datasets: [
                            { label: 'Valid', data: validData, backgroundColor: '#51cf66', borderWidth: 0 },
                            { label: 'Expiring Soon (<60 days)', data: expiringData, backgroundColor: '#ffc107', borderWidth: 0 },
                            { label: 'Expired', data: expiredData, backgroundColor: '#dc3545', borderWidth: 0 }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { position: 'bottom', labels: { padding: 15, font: { size: 12 } } }
                        },
                        scales: {
                            x: { stacked: true, grid: { display: false } },
                            y: { stacked: true, beginAtZero: true, ticks: { stepSize: 1 } }
                        }
                    }
                });
            }

            // Algorithm Doughnut Chart
            if (algorithmDoughnutChart) algorithmDoughnutChart.destroy();
            const algoCtx = document.getElementById('algorithmDoughnutChart');
            if (algoCtx) {
                const algoLabels = Object.keys(algorithmStats);
                const algoData = Object.values(algorithmStats);
                const colors = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a', '#fee140', '#30cfd0'];

                algorithmDoughnutChart = new Chart(algoCtx, {
                    type: 'doughnut',
                    data: {
                        labels: algoLabels,
                        datasets: [{
                            data: algoData,
                            backgroundColor: colors.slice(0, algoLabels.length),
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { position: 'bottom', labels: { padding: 15, font: { size: 12 } } }
                        }
                    }
                });
            }

            // Expiry Timeline Chart
            if (expiryTimelineChart) expiryTimelineChart.destroy();
            const expiryCtx = document.getElementById('expiryTimelineChart');
            if (expiryCtx) {
                expiryTimelineChart = new Chart(expiryCtx, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(expiryTimeline),
                        datasets: [{
                            label: 'Certificates',
                            data: Object.values(expiryTimeline),
                            backgroundColor: ['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#51cf66'],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true, ticks: { stepSize: 1 } },
                            x: { grid: { display: false } }
                        }
                    }
                });
            }

            // Key Size Chart
            if (keySizeChart) keySizeChart.destroy();
            const keySizeCtx = document.getElementById('keySizeChart');
            if (keySizeCtx) {
                const keySizeLabels = Object.keys(keySizeStats).sort((a, b) => {
                    // Sort numerically, with 'Unknown' at the end
                    if (a === 'Unknown') return 1;
                    if (b === 'Unknown') return -1;
                    return parseInt(a) - parseInt(b);
                });
                const keySizeData = keySizeLabels.map(size => keySizeStats[size]);
                const colors = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a', '#fee140', '#30cfd0'];

                keySizeChart = new Chart(keySizeCtx, {
                    type: 'bar',
                    data: {
                        labels: keySizeLabels,
                        datasets: [{
                            label: 'Certificates',
                            data: keySizeData,
                            backgroundColor: colors.slice(0, keySizeLabels.length),
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true, ticks: { stepSize: 1 } },
                            x: { grid: { display: false } }
                        }
                    }
                });
            }

            // Key Usage Chart
            if (keyUsageChart) keyUsageChart.destroy();
            const keyUsageCtx = document.getElementById('keyUsageChart');
            if (keyUsageCtx) {
                const sortedUsages = Object.entries(keyUsageStats)
                    .sort((a, b) => b[1] - a[1]);
                const keyUsageLabels = sortedUsages.map(u => u[0].replace(/_/g, ' '));
                const keyUsageData = sortedUsages.map(u => u[1]);

                keyUsageChart = new Chart(keyUsageCtx, {
                    type: 'bar',
                    data: {
                        labels: keyUsageLabels,
                        datasets: [{
                            label: 'Certificates',
                            data: keyUsageData,
                            backgroundColor: '#667eea',
                            borderColor: 'white',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: true,
                        scales: {
                            x: { beginAtZero: true }
                        },
                        plugins: {
                            legend: { display: false }
                        }
                    }
                });
            }
        }

        function toggleDetailSection(sectionId) {
            const section = document.getElementById(sectionId);
            const arrow = document.getElementById(sectionId + '-arrow');
            if (section.style.display === 'none') {
                section.style.display = 'block';
                arrow.textContent = '▼';
            } else {
                section.style.display = 'none';
                arrow.textContent = '▶';
            }
        }

        
        function startCLMCertificateRefresh() {
            // Load immediately
            loadCollectorCertificates();
            
            // Then refresh every 5 minutes (300000 milliseconds)
            if (clmCertificateRefreshInterval) {
                clearInterval(clmCertificateRefreshInterval);
            }
            
            clmCertificateRefreshInterval = setInterval(async () => {
                try {
                    await loadCollectorCertificates();
                } catch (error) {
                    
                }
            }, 300000); // 5 minutes
        }

        // Stop certificate refresh when leaving CLM tab
        function stopCLMCertificateRefresh() {
            if (clmCertificateRefreshInterval) {
                clearInterval(clmCertificateRefreshInterval);
                clmCertificateRefreshInterval = null;
            }
        }

        // ==================== KMS FUNCTIONS ====================
        function openNewKMSIntegrationModal() {
            showAlert('KMS integration creation coming soon', 'info');
        }

        async function syncKMSKeys() {
            showAlert('Syncing keys from Key Stores...', 'info');
            try {
                // Trigger actual sync from all connectors
                const response = await fetch('/api/v1/inventory/sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                
                if (!response.ok) {
                    throw new Error('Sync request failed');
                }
                
                const result = await response.json();
                showAlert(`Sync completed for ${Object.keys(result.results || {}).length} connectors`, 'success');
                
                // Reload the keys table after a short delay to allow sync to complete
                setTimeout(() => loadCollectorKeys(), 2000);
                
            } catch (error) {
                
                showAlert('Failed to trigger sync: ' + error.message, 'error');
            }
        }
        
        
        function viewKeyDetails(buttonElement) {
            try {
                // Get key data from data attribute
                const keyData = buttonElement.getAttribute('data-key');
                const key = JSON.parse(atob(keyData));
                
                // Helper to format boolean values with color coding
                const formatBool = (val, trueIsGood = true) => {
                    if (val === null || val === undefined) return '<span style="color: #6b7280;">N/A</span>';
                    const isTrue = val === true;
                    const color = (isTrue === trueIsGood) ? '#10b981' : '#ef4444';
                    return `<span style="color: ${color}; font-weight: 600;">${isTrue ? 'Yes' : 'No'}</span>`;
                };
                
                // Helper for security attributes (sensitive=good, extractable=bad)
                const formatSecurityBool = (val, sensitiveType = true) => {
                    if (val === null || val === undefined) return '<span style="color: #6b7280;">N/A</span>';
                    const isTrue = val === true;
                    const isGood = sensitiveType ? isTrue : !isTrue;
                    const color = isGood ? '#10b981' : '#f59e0b';
                    return `<span style="color: ${color}; font-weight: 600;">${isTrue ? 'Yes' : 'No'}</span>`;
                };
                
                let html = `
                    <!-- Basic Information -->
                    <div class="key-modal-section">
                        <h3>Basic Information</h3>
                        <div class="key-section-content">
                            <div class="key-field-row">
                                <span class="key-field-label">Key Label</span>
                                <span class="key-field-value">${escapeHtml(key.name || key.label || 'N/A')}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Key Type</span>
                                <span class="key-field-value">${escapeHtml(key.key_type || 'N/A')}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Key Size</span>
                                <span class="key-field-value">${key.key_size ? key.key_size + ' bits' : 'N/A'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Key Class</span>
                                <span class="key-field-value">${escapeHtml(key.key_class || 'N/A')}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Security Attributes -->
                    <div class="key-modal-section">
                        <h3>🔐 Security Attributes</h3>
                        <div class="key-section-content">
                            <div class="key-field-row">
                                <span class="key-field-label">Sensitive</span>
                                <span class="key-field-value">${formatSecurityBool(key.is_sensitive, true)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Extractable</span>
                                <span class="key-field-value">${formatSecurityBool(key.is_extractable, false)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Modifiable</span>
                                <span class="key-field-value">${formatSecurityBool(key.is_modifiable, false)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Always Sensitive</span>
                                <span class="key-field-value">${formatSecurityBool(key.is_always_sensitive, true)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Never Extractable</span>
                                <span class="key-field-value">${formatSecurityBool(key.is_never_extractable, true)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Local (Generated on HSM)</span>
                                <span class="key-field-value">${formatSecurityBool(key.is_local, true)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Permitted Operations -->
                    <div class="key-modal-section">
                        <h3>⚙️ Permitted Operations</h3>
                        <div class="key-ops-grid">
                            <div class="key-field-row">
                                <span class="key-field-label">Encrypt</span>
                                <span class="key-field-value">${formatBool(key.can_encrypt)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Decrypt</span>
                                <span class="key-field-value">${formatBool(key.can_decrypt)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Sign</span>
                                <span class="key-field-value">${formatBool(key.can_sign)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Verify</span>
                                <span class="key-field-value">${formatBool(key.can_verify)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Wrap</span>
                                <span class="key-field-value">${formatBool(key.can_wrap)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Unwrap</span>
                                <span class="key-field-value">${formatBool(key.can_unwrap)}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Derive</span>
                                <span class="key-field-value">${formatBool(key.can_derive)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Key Properties -->
                    <div class="key-modal-section">
                        <h3>Key Properties</h3>
                        <div class="key-section-content">
                            <div class="key-field-row">
                                <span class="key-field-label">Private Key</span>
                                <span class="key-field-value">${key.private ? 'Yes' : 'No'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Token Object</span>
                                <span class="key-field-value">${key.token ? 'Yes' : 'No'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">HSM Backed</span>
                                <span class="key-field-value">${key.is_hardware_protected || key.hsm_backed || (key.source && key.source.includes('Luna')) ? 'Yes' : 'No'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Source</span>
                                <span class="key-field-value">${escapeHtml(key.source || key.source_integration || 'N/A')}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Lifecycle -->
                    <div class="key-modal-section">
                        <h3>📅 Lifecycle</h3>
                        <div class="key-section-content">
                            <div class="key-field-row">
                                <span class="key-field-label">Start Date</span>
                                <span class="key-field-value">${key.not_before || key.start_date || 'Not Set'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">End Date</span>
                                <span class="key-field-value">${key.expires_on || key.end_date || 'Not Set'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Created</span>
                                <span class="key-field-value">${key.created_on ? new Date(key.created_on).toLocaleString() : 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                `;
                
                // Associated Certificate (if available)
                if (key.associated_certificate) {
                    const cert = key.associated_certificate;
                    html += `
                    <div class="key-modal-section">
                        <h3>Associated Certificate</h3>
                        <div class="key-section-content">
                            <div class="key-field-row">
                                <span class="key-field-label">Subject</span>
                                <span class="key-field-value">${escapeHtml(cert.subject?.commonName || cert.subject?.CN || 'N/A')}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Issuer</span>
                                <span class="key-field-value">${escapeHtml(cert.issuer?.commonName || cert.issuer?.CN || 'N/A')}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Valid Until</span>
                                <span class="key-field-value">${cert.not_after ? new Date(cert.not_after).toLocaleString() : 'N/A'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Fingerprint</span>
                                <span class="key-field-value" style="font-size: 11px;">${escapeHtml(cert.fingerprint_sha256 || 'N/A')}</span>
                            </div>
                        </div>
                    </div>`;
                }
                
                // PQC Analysis (if available)
                if (key.pqc_analysis) {
                    const pqc = key.pqc_analysis;
                    // Use existing fields from PQCAnalysis.to_dict()
                    const vulnLevel = (pqc.vulnerability_level || '').toLowerCase();
                    const vulnColor = vulnLevel === 'critical' ? '#ef4444' : 
                                      vulnLevel === 'high' ? '#f97316' : 
                                      vulnLevel === 'medium' ? '#f59e0b' : 
                                      vulnLevel === 'low' ? '#10b981' : '#6b7280';
                    const vulnDisplay = vulnLevel ? vulnLevel.charAt(0).toUpperCase() + vulnLevel.slice(1) : 'Unknown';
                    // Quantum safe = PQC ready or is_pqc or is_hybrid
                    const isQuantumSafe = pqc.is_pqc || pqc.migration_status === 'pqc_ready';
                    const migrationDisplay = (pqc.migration_status || '').replace(/_/g, ' ');
                    
                    html += `
                    <div class="key-modal-section">
                        <h3>🔮 PQC Analysis</h3>
                        <div class="key-section-content">
                            <div class="key-field-row">
                                <span class="key-field-label">Quantum Safe</span>
                                <span class="key-field-value">${isQuantumSafe ? '<span style="color: #10b981; font-weight: 600;">Yes</span>' : '<span style="color: #ef4444; font-weight: 600;">No</span>'}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Vulnerability Level</span>
                                <span class="key-field-value"><span style="color: ${vulnColor}; font-weight: 600;">${escapeHtml(vulnDisplay)}</span></span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Algorithm Class</span>
                                <span class="key-field-value">${escapeHtml(pqc.algorithm_class || 'Unknown')}</span>
                            </div>
                            <div class="key-field-row">
                                <span class="key-field-label">Migration Status</span>
                                <span class="key-field-value">${escapeHtml(migrationDisplay || 'Unknown')}</span>
                            </div>
                            ${pqc.classical_algorithm ? `<div class="key-field-row">
                                <span class="key-field-label">Classical Algorithm</span>
                                <span class="key-field-value">${escapeHtml(pqc.classical_algorithm)}</span>
                            </div>` : ''}
                            ${pqc.pqc_algorithm ? `<div class="key-field-row">
                                <span class="key-field-label">PQC Algorithm</span>
                                <span class="key-field-value">${escapeHtml(pqc.pqc_algorithm)}</span>
                            </div>` : ''}
                        </div>
                    </div>`;
                }
                
                // Object Information
                html += `
                    <div class="key-modal-section">
                        <h3>Object Information</h3>
                        <div class="key-field-row">
                            <span class="key-field-label">Object ID</span>
                            <span class="key-field-value" style="font-size: 11px;">${escapeHtml(key.object_id || key.key_id || 'N/A')}</span>
                        </div>
                    </div>
                `;
                
                // Update modal header and content
                const titleEl = document.getElementById('keyDetailsTitle') || document.querySelector('#keyDetailsModal .modal-header h2');
                if (titleEl) titleEl.textContent = 'Key: ' + escapeHtml(key.name || key.label || 'Unknown');
                document.getElementById('keyDetailsContent').innerHTML = html;
                const modal = document.getElementById('keyDetailsModal');
                modal.style.display = '';  // Clear inline display style
                modal.classList.add('active');
                
            } catch (error) {
                
                showAlert('Error displaying key details: ' + error.message, 'error');
            }
        }
        
        // Cache for KMS keys data
        let kmsKeysCache = [];
        
        async function loadCollectorKeys() {
            const tbody = document.getElementById('kms-keys-body');
            kmsKeysCache = []; // Reset cache
            
            try {
                const response = await fetch('/api/v1/inventory/keys');
                if (!response.ok) {
                    throw new Error('Failed to load keys');
                }
                
                const data = await response.json();
                const keys = data.keys || [];
                
                if (keys.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No keys found. Add a Luna HSM integration to get started.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = keys.map(key => {
                    const keyType = key.key_type || 'Unknown';
                    const keySize = key.key_size || '-';
                    const source = key.source_integration || key.source || 'Unknown';
                    const status = key.enabled !== false ? 'Active' : 'Disabled';
                    const statusColor = key.enabled !== false ? '#d4edda' : '#f8d7da';
                    const statusTextColor = key.enabled !== false ? '#155724' : '#721c24';
                    const created = key.created_on ? new Date(key.created_on).toLocaleDateString() : '-';
                    
                    return `
                        <tr>
                            <td><strong>${escapeHtml(key.name || key.label || 'Unnamed')}</strong></td>
                            <td>${escapeHtml(keyType)}</td>
                            <td>${keySize}</td>
                            <td>${escapeHtml(source)}</td>
                            <td>
                                <span class="status-badge" style="background: ${statusColor}; color: ${statusTextColor};">
                                    ${status}
                                </span>
                            </td>
                            <td>${created}</td>
                            <td>
                                <button class="btn-secondary" data-key="${btoa(JSON.stringify(key))}" onclick="viewKeyDetails(this)">Details</button>
                            </td>
                        </tr>
                    `;
                }).join('');
                
                showAlert(`Loaded ${keys.length} keys`, 'success');
                
            } catch (error) {
                
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Error loading keys. Check console for details.</td></tr>';
                showAlert('Failed to load keys: ' + error.message, 'error');
            }
        }
        
        //function viewKeyDetails(keyId) {
        //    showAlert('Key details view coming soon', 'info');
        //}

        // ==================== RE-ASSESSMENT FUNCTIONS ====================
        
        let reassessments = [];
        let uploadedReportData = null;
        
        async function loadReassessments() {
            try {
                const params = getEngagementFilterParams();
                const url = params ? `/api/v1/reports/reassessments?${params}` : '/api/v1/reports/reassessments';
                const response = await fetch(url);
                const data = await response.ok ? await response.json() : { reassessments: [] };
                reassessments = data.reassessments || [];
                renderReassessmentsTable();
            } catch (error) {
                
                showAlert('Failed to load reassessments', 'error');
            }
        }
        
        function renderReassessmentsTable() {
            const tbody = document.getElementById('reassessmentsTableBody');
            
            if (reassessments.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No re-assessments yet. Create one to get started.</td></tr>';
                return;
            }
            
            tbody.innerHTML = reassessments.map(ra => {
                const createdDate = new Date(ra.created_at).toLocaleString();
                const statusClass = `status-${ra.status.toLowerCase()}`;
                const engagementDisplay = ra.engagement_id 
                    ? `<span class="engagement-badge">${escapeHtml(ra.engagement_id)}</span>`
                    : '<span class="text-muted">—</span>';
                
                return `
                <tr>
                    <td><strong>${escapeHtml(ra.name)}</strong></td>
                    <td>${engagementDisplay}</td>
                    <td>${escapeHtml(ra.original_report_filename)}</td>
                    <td>${escapeHtml(ra.policy_name)}</td>
                    <td>${createdDate}</td>
                    <td><span class="status-badge ${statusClass}">${ra.status}</span></td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn-secondary" onclick="viewReassessmentReport(${ra.id})">Report</button>
                            <button class="btn-secondary" onclick="generateReassessmentEmbed(${ra.id})">Embed</button>
                        </div>
                    </td>
                </tr>
                `;
            }).join('');
        }
        
        async function openReassessModal() {
            // Load policies into dropdown
            try {
                const response = await fetch('/api/v1/policies');
                if (!response.ok) throw new Error('Failed to load policies');
                const data = await response.json();
                const policyList = data.policies || [];
                
                const policySelect = document.getElementById('reassessPolicySelect');
                policySelect.innerHTML = '<option value="">-- Select a Policy --</option>';
                
                policyList.forEach(policy => {
                    const option = document.createElement('option');
                    option.value = policy.id;
                    option.textContent = policy.name;
                    policySelect.appendChild(option);
                });
            } catch (error) {
                
                showAlert('Failed to load policies', 'error');
                return;
            }
            
            // Reset form
            document.getElementById('reassessForm').reset();
            document.getElementById('reportPreviewContainer').style.display = 'none';
            uploadedReportData = null;
            
            // Open modal
            document.getElementById('reassessModal').classList.add('active');
        }
        
        function handleReassessReportUpload(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            if (!file.name.endsWith('.json')) {
                showAlert('Please select a JSON file', 'error');
                return;
            }
            
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    uploadedReportData = JSON.parse(e.target.result);
                    
                    // Show preview
                    document.getElementById('previewCertCount').textContent = uploadedReportData.certificates?.length || 0;
                    document.getElementById('previewKeyCount').textContent = uploadedReportData.keys?.length || 0;
                    document.getElementById('previewFindingCount').textContent = uploadedReportData.findings?.length || 0;
                    document.getElementById('reportPreviewContainer').style.display = 'block';
                    
                } catch (error) {
                    showAlert('Error parsing JSON file: ' + error.message, 'error');
                    uploadedReportData = null;
                    document.getElementById('reportPreviewContainer').style.display = 'none';
                }
            };
            reader.readAsText(file);
        }
        
        async function submitReassessment(event) {
            event.preventDefault();
            
            const name = document.getElementById('reassessName').value;
            const policyId = document.getElementById('reassessPolicySelect').value;
            const fileInput = document.getElementById('reassessReportFile');
            
            if (!name || !policyId) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }
            
            if (!uploadedReportData) {
                showAlert('Please upload a valid JSON report file', 'error');
                return;
            }
            
            try {
                showAlert('Running re-assessment...', 'info');
                
                const response = await fetch('/api/v1/reports/reassessments', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: name,
                        policy_id: parseInt(policyId),
                        report_data: uploadedReportData,
                        original_filename: fileInput.files[0].name,
                        engagement_id: activeEngagementId || null
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showAlert(`Re-assessment completed! Found ${result.findings_count} findings.`, 'success');
                    closeModal('reassessModal');
                    await loadReassessments();
                } else {
                    const error = await response.json();
                    showAlert('Failed to create re-assessment: ' + (error.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
            }
        }
        
        function viewReassessmentReport(reassessmentId) {
            window.open(`/api/v1/reports/reassessments/${reassessmentId}/report/view`, '_blank');
        }
        
        async function generateReassessmentEmbed(reassessmentId) {
            try {
                showAlert('Generating embedded dashboard...', 'info');
                
                const response = await fetch('/api/v1/reports/embed', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ type: 'reassessment', id: reassessmentId })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showAlert('Embedded dashboard generated successfully!', 'success');
                } else {
                    const error = await response.json();
                    showAlert('Failed to generate dashboard: ' + (error.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
            }
        }

         // ==================== REPORT AGGREGATION FUNCTIONS ====================
        
        let aggregationReportFiles = [null, null];
        
        async function openAggregationModal() {
            // Load policies into dropdown
            try {
                const response = await fetch('/api/v1/policies');
                if (!response.ok) throw new Error('Failed to load policies');
                const data = await response.json();
                const policyList = data.policies || [];
                
                const policySelect = document.getElementById('aggregationPolicySelect');
                policySelect.innerHTML = '<option value="">-- Select a Policy --</option>';
                
                policyList.forEach(policy => {
                    const option = document.createElement('option');
                    option.value = policy.id;
                    option.textContent = policy.name;
                    policySelect.appendChild(option);
                });
            } catch (error) {
                
                showAlert('Failed to load policies', 'error');
                return;
            }
            
            // Reset form
            document.getElementById('aggregationForm').reset();
            document.getElementById('additionalReports').innerHTML = '';
            aggregationReportFiles = [null, null];
            updateAddReportButton();
            
            // Open modal
            document.getElementById('aggregationModal').classList.add('active');
        }
        
        function addReportField() {
            const additionalReports = document.getElementById('additionalReports');
            const currentCount = document.querySelectorAll('.report-selector').length;
            
            if (currentCount >= 5) {
                showAlert('Maximum 5 reports allowed', 'error');
                return;
            }
            
            const div = document.createElement('div');
            div.className = 'report-selector';
            div.style.marginBottom = '10px';
            div.style.display = 'flex';
            div.style.gap = '10px';
            div.style.alignItems = 'flex-start';
            
            div.innerHTML = `
                <div style="flex: 1;">
                    <input type="file" class="report-file-input" accept=".json" style="margin-bottom: 5px;">
                    <small style="color: #666;">Report ${currentCount + 1}</small>
                </div>
                <button type="button" class="btn-danger" onclick="this.parentElement.remove(); updateAddReportButton();" style="margin-top: 0; padding: 5px 10px; font-size: 12px;">Remove</button>
            `;
            
            additionalReports.appendChild(div);
            updateAddReportButton();
        }
        
        function updateAddReportButton() {
            const currentCount = document.querySelectorAll('.report-selector').length;
            const btn = document.getElementById('addReportBtn');
            btn.disabled = currentCount >= 5;
            btn.style.opacity = currentCount >= 5 ? '0.5' : '1';
        }
        
        function handleAggregationFileInput(input) {
            const file = input.files[0];
            if (!file) return;
            
            if (!file.name.endsWith('.json')) {
                showAlert('Please select a JSON file', 'error');
                input.value = '';
                return;
            }
            
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    JSON.parse(e.target.result);
                    const selector = input.closest('.report-selector');
                    const small = selector.querySelector('small');
                    small.style.color = 'green';
                    small.textContent += ' ✓ Loaded';
                } catch (error) {
                    showAlert('Error parsing JSON file: ' + error.message, 'error');
                    input.value = '';
                }
            };
            reader.readAsText(file);
        }
        
        async function submitAggregation(event) {
            event.preventDefault();
            
            const name = document.getElementById('aggregationName').value;
            const mergeStrategy = document.getElementById('mergeStrategy').value;
            const policyId = document.getElementById('aggregationPolicySelect').value;
            const fileInputs = document.querySelectorAll('.report-file-input');
            
            if (!name || !mergeStrategy || !policyId) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }
            
            // Collect reports
            const reports = [];
            for (const input of fileInputs) {
                if (!input.files[0]) {
                    showAlert('All report file inputs must have a file selected', 'error');
                    return;
                }
                
                // We need to read the files
                const file = input.files[0];
                const fileContent = await new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = (e) => {
                        try {
                            resolve(JSON.parse(e.target.result));
                        } catch (err) {
                            reject(err);
                        }
                    };
                    reader.onerror = reject;
                    reader.readAsText(file);
                });
                
                reports.push({
                    filename: file.name,
                    data: fileContent
                });
            }
            
            if (reports.length < 2) {
                showAlert('Please select at least 2 reports', 'error');
                return;
            }
            
            try {
                showAlert('Creating aggregation and running assessment...', 'info');
                
                const response = await fetch('/api/v1/reports/aggregations', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: name,
                        merge_strategy: mergeStrategy,
                        policy_id: parseInt(policyId),
                        reports: reports,
                        engagement_id: activeEngagementId || null
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showAlert(`Aggregation completed! ${result.certificates_count} certificates, ${result.keys_count} keys, ${result.findings_count} findings.`, 'success');
                    closeModal('aggregationModal');
                    await loadAggregations();
                } else {
                    const error = await response.json();
                    showAlert('Failed to create aggregation: ' + (error.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
            }
        }
        
        async function loadAggregations() {
            try {
                const params = getEngagementFilterParams();
                const url = params ? `/api/v1/reports/aggregations?${params}` : '/api/v1/reports/aggregations';
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to load aggregations');
                
                const aggregations = await response.json();
                const tbody = document.getElementById('aggregationsTableBody');
                
                if (aggregations.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No aggregations created yet. Create one to get started.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = aggregations.map(agg => {
                    const engagementDisplay = agg.engagement_id 
                        ? `<span class="engagement-badge">${escapeHtml(agg.engagement_id)}</span>`
                        : '<span class="text-muted">—</span>';
                    
                    return `
                    <tr>
                        <td>${escapeHtml(agg.name)}</td>
                        <td>${engagementDisplay}</td>
                        <td><span style="background: #e3f2fd; padding: 2px 8px; border-radius: 3px; font-size: 12px;">${escapeHtml(agg.merge_strategy.replace('_', ' '))}</span></td>
                        <td><small>${(() => { try { return JSON.parse(agg.source_reports || '[]').length; } catch(e) { return 0; } })()} reports</small></td>
                        <td>${escapeHtml(agg.policy_name)}</td>
                        <td><small>${new Date(agg.created_at).toLocaleDateString()}</small></td>
                        <td><span style="background: #c8e6c9; padding: 2px 8px; border-radius: 3px; font-size: 12px;">Completed</span></td>
                        <td>
                            <button class="btn-small" onclick="viewAggregationReport(${agg.id})">Report</button>
                            <button class="btn-small" onclick="embedAggregationDashboard(${agg.id})">Embed</button>
                        </td>
                    </tr>
                `}).join('');
            } catch (error) {
                
            }
        }
        
        function viewAggregationReport(aggregationId) {
            window.open(`/api/v1/reports/aggregations/${aggregationId}/report/view`, '_blank');
        }
        
        async function embedAggregationDashboard(aggregationId) {
            try {
                showAlert('Generating embedded dashboard...', 'info');
                const response = await fetch('/api/v1/reports/embed', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ type: 'aggregation', id: aggregationId })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showAlert(`Embedded dashboard generated: ${result.filename}`, 'success');
                } else {
                    const error = await response.json();
                    showAlert('Failed to generate embedded dashboard: ' + (error.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                
                showAlert('Error: ' + error.message, 'error');
             }
        }

        // ==================== REPORTS TAB FUNCTIONS ====================
        
        /**
         * Load all reports into the Crypto Asset Scans tab tables
         */
        async function loadCryptoAssetReports() {
            await Promise.all([
                loadScansForReportsTab(),
                loadReassessmentsForReportsTab(),
                loadAggregationsForReportsTab()
            ]);
        }
        
        // Alias for backward compatibility
        async function loadAllReportsForReportsTab() {
            await loadCryptoAssetReports();
        }
        
        /**
         * Refresh crypto asset reports tables
         */
        async function refreshCryptoAssetReports() {
            showAlert('Refreshing crypto asset reports...', 'info');
            await loadCryptoAssetReports();
            showAlert('Reports refreshed', 'success');
        }
        
        // Alias for backward compatibility
        async function refreshAllReports() {
            await refreshCryptoAssetReports();
        }

        // ==================== DOCUMENT SCANS TAB FUNCTIONS ====================
        
        /**
         * Load document assessments into the Document Scans tab
         */
        async function loadDocumentScanReports() {
            const tbody = document.getElementById('reports-doc-scans-table-body');
            try {
                const response = await fetch('/api/v1/document-assessment/assessments');
                if (!response.ok) throw new Error('Failed to load document assessments');
                
                const data = await response.json();
                const assessments = data.assessments || [];
                
                // Update summary cards
                document.getElementById('reports-doc-total').textContent = assessments.length;
                
                if (assessments.length > 0) {
                    // Calculate average coverage
                    const avgCoverage = assessments.reduce((sum, a) => {
                        const coverage = a.summary?.coverage_score || a.coverage_score || 0;
                        return sum + coverage;
                    }, 0) / assessments.length;
                    document.getElementById('reports-doc-avg-coverage').textContent = avgCoverage.toFixed(0) + '%';
                    
                    // Most recent grade
                    const recentGrade = assessments[0]?.summary?.assessment_grade || assessments[0]?.grade || '-';
                    document.getElementById('reports-doc-recent-grade').textContent = recentGrade;
                    
                    // Unique document types
                    const uniqueTypes = new Set(assessments.map(a => a.document_type)).size;
                    document.getElementById('reports-doc-types').textContent = uniqueTypes;
                } else {
                    document.getElementById('reports-doc-avg-coverage').textContent = '0%';
                    document.getElementById('reports-doc-recent-grade').textContent = '-';
                    document.getElementById('reports-doc-types').textContent = '0';
                }
                
                if (assessments.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No document assessments available.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = assessments.map(assessment => {
                    const grade = assessment.summary?.assessment_grade || assessment.grade || 'N/A';
                    const coverage = assessment.summary?.coverage_score || assessment.coverage_score || 0;
                    const findingsCount = assessment.findings?.length || assessment.findings_count || 0;
                    const assessedDate = new Date(assessment.assessed_at || assessment.created_at).toLocaleDateString();
                    
                    const gradeColors = {
                        'A': '#10b981', 'B': '#10b981', 'C': '#f59e0b', 'D': '#f59e0b', 'F': '#ef4444'
                    };
                    const gradeColor = gradeColors[grade] || '#64748b';
                    
                    return `
                    <tr>
                        <td><strong>${escapeHtml(assessment.filename || 'Unknown')}</strong></td>
                        <td><span style="background: #e0f2fe; padding: 2px 8px; border-radius: 3px; font-size: 12px;">${escapeHtml(assessment.document_type || 'Unknown')}</span></td>
                        <td><span style="color: ${gradeColor}; font-weight: 700; font-size: 18px;">${grade}</span></td>
                        <td>${coverage.toFixed(0)}%</td>
                        <td>${findingsCount}</td>
                        <td><small>${assessedDate}</small></td>
                        <td style="text-align: right;">
                            <div class="action-buttons" style="justify-content: flex-end;">
                                <button class="btn-small" onclick="viewDocumentReport('${assessment.assessment_id}', 'html')">View</button>
                                <button class="btn-primary" style="padding: 4px 10px; font-size: 12px;" onclick="viewDocumentReport('${assessment.assessment_id}', 'pdf')">
                                    📄 PDF
                                </button>
                            </div>
                        </td>
                    </tr>
                    `;
                }).join('');
            } catch (error) {
                
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Error loading document assessments.</td></tr>';
            }
        }
        
        /**
         * View document assessment report
         */
        function viewDocumentReport(assessmentId, format) {
            window.open(`/api/v1/document-assessment/assessments/${assessmentId}/report?format=${format}`, '_blank');
        }

        // ==================== SCAN REPORTING TAB FUNCTIONS ====================
        
        /**
         * Load selectors for combined report generation
         */
        async function loadScanReportingSelectors() {
            // Load crypto asset scans/reassessments/aggregations
            const cryptoSelect = document.getElementById('combined-crypto-scan-select');
            cryptoSelect.innerHTML = '<option value="">-- Select a scan/reassessment/aggregation --</option>';
            
            try {
                // Load scans
                const scansResponse = await fetch('/api/v1/scans');
                if (scansResponse.ok) {
                    const scansData = await scansResponse.json();
                    const completedScans = (scansData.scans || []).filter(s => s.status === 'Successful' || s.last_run);
                    
                    if (completedScans.length > 0) {
                        const scanOptgroup = document.createElement('optgroup');
                        scanOptgroup.label = '🔍 Scans';
                        completedScans.forEach(scan => {
                            const option = document.createElement('option');
                            option.value = `scan:${scan.id}`;
                            option.textContent = scan.name;
                            scanOptgroup.appendChild(option);
                        });
                        cryptoSelect.appendChild(scanOptgroup);
                    }
                }
                
                // Load reassessments
                const reassessResponse = await fetch('/api/v1/reports/reassessments');
                if (reassessResponse.ok) {
                    const reassessData = await reassessResponse.json();
                    const completedReassess = (reassessData.reassessments || []).filter(r => r.status === 'Completed');
                    
                    if (completedReassess.length > 0) {
                        const reassessOptgroup = document.createElement('optgroup');
                        reassessOptgroup.label = '🔄 Re-Assessments';
                        completedReassess.forEach(ra => {
                            const option = document.createElement('option');
                            option.value = `reassessment:${ra.id}`;
                            option.textContent = ra.name;
                            reassessOptgroup.appendChild(option);
                        });
                        cryptoSelect.appendChild(reassessOptgroup);
                    }
                }
                
                // Load aggregations
                const aggResponse = await fetch('/api/v1/reports/aggregations');
                if (aggResponse.ok) {
                    const aggregations = await aggResponse.json();
                    
                    if (aggregations.length > 0) {
                        const aggOptgroup = document.createElement('optgroup');
                        aggOptgroup.label = '📒 Aggregations';
                        aggregations.forEach(agg => {
                            const option = document.createElement('option');
                            option.value = `aggregation:${agg.id}`;
                            option.textContent = agg.name;
                            aggOptgroup.appendChild(option);
                        });
                        cryptoSelect.appendChild(aggOptgroup);
                    }
                }
            } catch (error) {
                
            }
            
            // Load document assessments
            const docSelect = document.getElementById('combined-doc-scan-select');
            docSelect.innerHTML = '<option value="">-- Select a document assessment (optional) --</option>';
            
            try {
                const docResponse = await fetch('/api/v1/document-assessment/assessments');
                if (docResponse.ok) {
                    const docData = await docResponse.json();
                    const assessments = docData.assessments || [];
                    
                    assessments.forEach(assessment => {
                        const option = document.createElement('option');
                        option.value = assessment.assessment_id;
                        option.textContent = `${assessment.filename} (${assessment.document_type || 'Unknown'})`;
                        docSelect.appendChild(option);
                    });
                }
            } catch (error) {
                
            }
        }
        
        /**
         * Generate combined report based on selections
         */
        async function generateCombinedReport() {
            const cryptoSelect = document.getElementById('combined-crypto-scan-select');
            const docSelect = document.getElementById('combined-doc-scan-select');
            const reportName = document.getElementById('combined-report-name').value;
            
            const generateExecSummary = document.getElementById('generate-exec-summary').checked;
            const generateEmbed = document.getElementById('generate-embed-dashboard').checked;
            const generateDocPdf = document.getElementById('generate-doc-pdf').checked;
            
            if (!cryptoSelect.value) {
                showAlert('Please select a crypto asset scan report', 'error');
                return;
            }
            
            if (!generateExecSummary && !generateEmbed && !generateDocPdf) {
                showAlert('Please select at least one output option', 'error');
                return;
            }
            
            const [reportType, reportId] = cryptoSelect.value.split(':');
            const docAssessmentId = docSelect.value || null;
            
            // Show progress
            document.getElementById('combined-report-progress').style.display = 'block';
            document.getElementById('combined-report-results').style.display = 'none';
            
            const generatedReports = [];
            
            try {
                // Generate Executive Summary
                if (generateExecSummary) {
                    document.getElementById('combined-report-status').textContent = 'Generating executive summary...';
                    
                    const execResponse = await fetch('/api/v1/reports/executive-summary', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            type: reportType,
                            id: parseInt(reportId),
                            document_assessment_id: docAssessmentId,
                            report_name: reportName || null
                        })
                    });
                    
                    if (execResponse.ok) {
                        const result = await execResponse.json();
                        generatedReports.push({
                            type: 'Executive Summary',
                            filename: result.filename,
                            path: result.path
                        });
                    } else {
                        const errorData = await execResponse.json().catch(() => ({}));
                        throw new Error(errorData.error || 'Failed to generate executive summary');
                    }
                }
                
                // Generate Embedded Dashboard
                if (generateEmbed) {
                    document.getElementById('combined-report-status').textContent = 'Generating embedded dashboard...';
                    
                    let embedEndpoint = '';
                    if (reportType === 'scan') {
                        embedEndpoint = `/api/v1/reports/embed`;
                    } else if (reportType === 'reassessment') {
                        embedEndpoint = `/api/v1/reports/embed`;
                    } else if (reportType === 'aggregation') {
                        embedEndpoint = `/api/v1/reports/embed`;
                    }
                    
                    const embedResponse = await fetch(embedEndpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            type: reportType,
                            id: parseInt(reportId)
                        })
                    });
                    
                    if (embedResponse.ok) {
                        const result = await embedResponse.json();
                        generatedReports.push({
                            type: 'Embedded Dashboard',
                            filename: result.filename,
                            path: result.path
                        });
                    }
                }
                
                // Generate Document Assessment PDF
                if (generateDocPdf && docAssessmentId) {
                    document.getElementById('combined-report-status').textContent = 'Generating document assessment PDF...';
                    
                    const docPdfResponse = await fetch('/api/v1/document-assessment/assessments/' + docAssessmentId + '/report/save', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            format: 'pdf'
                        })
                    });
                    
                    if (docPdfResponse.ok) {
                        const result = await docPdfResponse.json();
                        generatedReports.push({
                            type: 'Document Assessment PDF',
                            filename: result.filename,
                            path: result.path
                        });
                    } else {
                        const errorData = await docPdfResponse.json().catch(() => ({}));
                        throw new Error(errorData.error || 'Failed to generate document assessment PDF');
                    }
                }
                
                // Show results
                document.getElementById('combined-report-progress').style.display = 'none';
                document.getElementById('combined-report-results').style.display = 'block';
                
                const resultsList = document.getElementById('combined-report-list');
                resultsList.innerHTML = generatedReports.map(report => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;">
                        <div>
                            <span style="font-weight: 600; color: #1e293b;">${report.type}</span>
                            <span style="color: #64748b; margin-left: 8px;">${report.filename}</span>
                        </div>
                        ${report.url ? 
                            `<a href="${report.url}" target="_blank" class="btn-small">Download</a>` :
                            `<span style="color: #10b981; font-size: 13px;">✓ Generated</span>`
                        }
                    </div>
                `).join('');
                
                showAlert(`Successfully generated ${generatedReports.length} report(s)`, 'success');
                
            } catch (error) {
                document.getElementById('combined-report-progress').style.display = 'none';
                
                showAlert(`Error: ${error.message}`, 'error');
            }
        }
        
        /**
         * Generate full report package (all outputs)
         */
        async function generateFullReportPackage() {
            document.getElementById('generate-exec-summary').checked = true;
            document.getElementById('generate-embed-dashboard').checked = true;
            
            const docSelect = document.getElementById('combined-doc-scan-select');
            if (docSelect.value) {
                document.getElementById('generate-doc-pdf').checked = true;
            }
            
            await generateCombinedReport();
        }

        // ==================== CLM REPORTING TAB FUNCTIONS ====================
        
        // Store CLM assessment data for report generation
        let clmReportAssessmentData = null;
        
        /**
         * Load selectors for CLM reporting
         */
        async function loadCLMReportingSelectors() {
            // Load integrations
            const sourceSelect = document.getElementById('clm-report-source-select');
            sourceSelect.innerHTML = '<option value="all">All Enabled Integrations</option>';
            
            try {
                const response = await fetch('/api/v1/inventory/integrations');
                if (response.ok) {
                    const data = await response.json();
                    const integrations = data.integrations || data || [];
                    
                    integrations.filter(i => i.enabled !== 0).forEach(integration => {
                        const option = document.createElement('option');
                        option.value = integration.id;
                        option.textContent = `${integration.name} (${integration.type})`;
                        sourceSelect.appendChild(option);
                    });
                }
            } catch (error) {
                
            }
            
            // Load policies
            const policySelect = document.getElementById('clm-report-policy-select');
            policySelect.innerHTML = '<option value="">-- Select Policy --</option>';
            
            try {
                const response = await fetch('/api/v1/policies');
                if (response.ok) {
                    const data = await response.json();
                    // Handle both array response and object with policies property
                    const policies = Array.isArray(data) ? data : (data.policies || []);
                    
                    policies.forEach(policy => {
                        const option = document.createElement('option');
                        option.value = policy.id;
                        option.textContent = policy.name;
                        policySelect.appendChild(option);
                    });
                    
                } else {
                    
                }
            } catch (error) {
                
            }
        }
        
        /**
         * Run CLM compliance assessment for reporting
         */
        async function runCLMReportAssessment() {
            const sourceSelect = document.getElementById('clm-report-source-select');
            const policySelect = document.getElementById('clm-report-policy-select');
            
            if (!policySelect.value) {
                showAlert('Please select an assessment policy', 'error');
                return;
            }
            
            // Show loading
            document.getElementById('clm-report-assessment-status').style.display = 'block';
            document.getElementById('clm-report-results').style.display = 'none';
            
            try {
                const response = await fetch('/api/v1/clm/compliancy/assess', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        source_id: sourceSelect.value === 'all' ? null : parseInt(sourceSelect.value),
                        policy_id: parseInt(policySelect.value)
                    })
                });
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || 'Assessment failed');
                }
                
                const data = await response.json();
                clmReportAssessmentData = data;
                
                // Hide loading, show results
                document.getElementById('clm-report-assessment-status').style.display = 'none';
                document.getElementById('clm-report-results').style.display = 'block';
                
                // Update summary metrics
                const summary = data.summary || {};
                const findings = data.findings || [];
                
                const certsAssessed = summary.certificates_assessed || 0;
                const nonCompliantCerts = new Set(findings.map(f => f.evidence?.asset_id || f.evidence?.subject_cn || 'unknown')).size;
                const compliantCerts = Math.max(0, certsAssessed - nonCompliantCerts);
                
                document.getElementById('clm-report-certs-assessed').textContent = certsAssessed;
                document.getElementById('clm-report-compliant').textContent = compliantCerts;
                document.getElementById('clm-report-noncompliant').textContent = nonCompliantCerts;
                document.getElementById('clm-report-findings').textContent = findings.length;
                
                // Count by severity
                const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
                findings.forEach(f => {
                    const sev = (f.severity || 'low').toLowerCase();
                    if (severityCounts.hasOwnProperty(sev)) {
                        severityCounts[sev]++;
                    }
                });
                
                document.getElementById('clm-report-critical').textContent = severityCounts.critical;
                document.getElementById('clm-report-high').textContent = severityCounts.high;
                document.getElementById('clm-report-medium').textContent = severityCounts.medium;
                document.getElementById('clm-report-low').textContent = severityCounts.low;
                
                // Populate findings table
                const tbody = document.getElementById('clm-report-findings-table');
                if (findings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No compliance findings - all certificates are compliant!</td></tr>';
                } else {
                    tbody.innerHTML = findings.slice(0, 100).map(finding => {
                        const severityColors = {
                            'critical': '#dc3545',
                            'high': '#ff6b6b',
                            'medium': '#f59e0b',
                            'low': '#17a2b8'
                        };
                        const sevColor = severityColors[(finding.severity || 'low').toLowerCase()] || '#64748b';
                        
                        return `
                        <tr>
                            <td>${escapeHtml(finding.evidence?.subject_cn || finding.evidence?.asset_id || 'Unknown')}</td>
                            <td>${escapeHtml(finding.rule_name || finding.rule_id || 'Unknown')}</td>
                            <td><span style="color: ${sevColor}; font-weight: 600; text-transform: uppercase;">${finding.severity || 'low'}</span></td>
                            <td style="font-size: 13px;">${escapeHtml(finding.message || '')}</td>
                            <td><small>${escapeHtml(finding.evidence?.source_integration || finding.source || '-')}</small></td>
                        </tr>
                        `;
                    }).join('');
                    
                    if (findings.length > 100) {
                        tbody.innerHTML += `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); font-style: italic;">Showing first 100 of ${findings.length} findings</td></tr>`;
                    }
                }
                
                // Enable report generation buttons
                document.getElementById('btn-clm-exec-summary').disabled = false;
                document.getElementById('btn-clm-embed').disabled = false;
                
                showAlert('CLM compliance assessment completed', 'success');
                
            } catch (error) {
                document.getElementById('clm-report-assessment-status').style.display = 'none';
                
                showAlert(`Assessment failed: ${error.message}`, 'error');
            }
        }
        
        /**
         * Generate CLM Executive Summary
         */
        async function generateCLMExecSummary() {
            if (!clmReportAssessmentData) {
                showAlert('Please run an assessment first', 'error');
                return;
            }
            
            const reportName = document.getElementById('clm-report-name').value || 'CLM Compliance Report';
            
            showAlert('Generating CLM executive summary...', 'info');
            
            try {
                const response = await fetch('/api/v1/reports/executive-summary', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        type: 'clm',
                        assessment_data: clmReportAssessmentData,
                        report_name: reportName
                    })
                });
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || 'Failed to generate executive summary');
                }
                
                const result = await response.json();
                showAlert(`Executive summary generated: ${result.filename}`, 'success');
                
            } catch (error) {
                
                showAlert(`Error: ${error.message}`, 'error');
            }
        }
        
        /**
         * Generate CLM Embedded Dashboard
         */
        async function generateCLMEmbedDashboard() {
            if (!clmReportAssessmentData) {
                showAlert('Please run an assessment first', 'error');
                return;
            }
            
            const reportName = document.getElementById('clm-report-name').value || 'CLM Compliance Dashboard';
            
            showAlert('Generating CLM embedded dashboard...', 'info');
            
            try {
                const response = await fetch('/api/v1/reports/embed', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        type: 'clm',
                        assessment_data: clmReportAssessmentData,
                        report_name: reportName
                    })
                });
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || 'Failed to generate embedded dashboard');
                }
                
                const result = await response.json();
                showAlert(`Embedded dashboard generated: ${result.filename}`, 'success');
                
            } catch (error) {
                
                showAlert(`Error: ${error.message}`, 'error');
            }
        }
        
        /**
         * Load scans into the Reports tab
         */
        async function loadScansForReportsTab() {
            const tbody = document.getElementById('reports-scans-table-body');
            try {
                const response = await fetch('/api/v1/scans');
                if (!response.ok) throw new Error('Failed to load scans');

                const data = await response.json();
                const scansList = data.scans || [];

                // Filter to only completed scans with reports
                const completedScans = scansList.filter(s =>
                s.status === 'Successful' || s.last_run
            );
                if (completedScans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No completed scan reports available.</td></tr>';
                    return;
                }

                tbody.innerHTML = completedScans.map(scan => {
                    const scanDate = scan.last_run ? new Date(scan.last_run).toLocaleDateString() : 'N/A';
                    const assessmentType = scan.assessment_type || 'pki_health_check';
                    return `
                    <tr>
                        <td>
                            <strong>${escapeHtml(scan.name)}</strong>
                            <div style="margin-top: 4px;">${renderAssessmentTypeBadge(assessmentType)}</div>
                        </td>
                        <td><span style="background: #e3f2fd; padding: 2px 8px; border-radius: 3px; font-size: 12px;">Scan</span></td>
                        <td>${escapeHtml(scan.policy_name || 'N/A')}</td>
                        <td><span class="status-badge status-completed">Successful</span></td>
                        <td><small>${scanDate}</small></td>
                        <td style="text-align: right;">
                            <div class="action-buttons" style="justify-content: flex-end;">
                                <button class="btn-small" onclick="viewScanReport(${scan.id})">View</button>
                                <button class="btn-small" onclick="generateEmbedDashboard(${scan.id})">Embed</button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('scan', ${scan.id}, '${escapeHtml(scan.name)}', 'pdf')">
                                    📄 PDF
                                </button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('scan', ${scan.id}, '${escapeHtml(scan.name)}', 'docx')">
                                    📝 DOCX
                                </button>
                            </div>
                        </td>
                    </tr>
                    `;
                }).join('');
            } catch (error) {

                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading scan reports.</td></tr>';
            }
        }

        // Current reports filter
        let currentReportsFilter = 'all';
        
        /**
         * Filter reports by assessment type
         */
        async function filterReportsByAssessmentType(filterType) {
            currentReportsFilter = filterType;
            
            // Update button states
            document.querySelectorAll('.assessment-filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`.assessment-filter-btn[data-filter="${filterType}"]`).classList.add('active');
            
            // Reload reports with filter
            await loadScansForReportsTab(filterType);
        }
        
        /**
         * Updated loadScansForReportsTab with filter support
         */
        async function loadScansForReportsTab(filterType = 'all') {
            const tbody = document.getElementById('reports-scans-table-body');
            try {
                const response = await fetch('/api/v1/scans');
                if (!response.ok) throw new Error('Failed to load scans');

                const data = await response.json();
                let scansList = data.scans || [];

                // Filter by assessment type if specified
                if (filterType && filterType !== 'all') {
                    scansList = scansList.filter(s =>
                        (s.assessment_type || 'pki_health_check') === filterType
                    );
                }

                // Filter to only completed scans with reports
                const completedScans = scansList.filter(s =>
                    s.status === 'Successful' || s.last_run
                );

                if (completedScans.length === 0) {
                    const typeLabel = filterType === 'pqc_assessment' ? 'PQC Assessment' :
                                      filterType === 'pki_health_check' ? 'PKI Health Check' : '';
                    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No completed ${typeLabel} scan reports available.</td></tr>`;
                    return;
                }

                tbody.innerHTML = completedScans.map(scan => {
                    const scanDate = scan.last_run ? new Date(scan.last_run).toLocaleDateString() : 'N/A';
                    const assessmentType = scan.assessment_type || 'pki_health_check';
                    return `
                    <tr>
                        <td>
                            <strong>${escapeHtml(scan.name)}</strong>
                            <div style="margin-top: 4px;">${renderAssessmentTypeBadge(assessmentType)}</div>
                        </td>
                        <td><span style="background: #e3f2fd; padding: 2px 8px; border-radius: 3px; font-size: 12px;">Scan</span></td>
                        <td>${escapeHtml(scan.policy_name || 'N/A')}</td>
                        <td><span class="status-badge status-completed">Successful</span></td>
                        <td><small>${scanDate}</small></td>
                        <td style="text-align: right;">
                            <div class="action-buttons" style="justify-content: flex-end;">
                                <button class="btn-small" onclick="viewScanReport(${scan.id})">View</button>
                                <button class="btn-small" onclick="generateEmbedDashboard(${scan.id})">Embed</button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('scan', ${scan.id}, '${escapeHtml(scan.name)}', 'pdf')">
                                    📄 PDF
                                </button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('scan', ${scan.id}, '${escapeHtml(scan.name)}', 'docx')">
                                    📝 DOCX
                                </button>
                            </div>
                        </td>
                    </tr>
                    `;
                }).join('');
            } catch (error) {

                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading scan reports.</td></tr>';
            }
        }
        
        /**
         * Load reassessments into the Reports tab
         */
        async function loadReassessmentsForReportsTab() {
            const tbody = document.getElementById('reports-reassess-table-body');
            try {
                const response = await fetch('/api/v1/reports/reassessments');
                const data = await response.ok ? await response.json() : { reassessments: [] };
                const reassessmentsList = data.reassessments || [];
                
                // Filter to only completed reassessments
                const completedReassessments = reassessmentsList.filter(r => 
                    r.status === 'Completed' && r.reassessed_report_path
                );
                
                if (completedReassessments.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No completed re-assessment reports available.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = completedReassessments.map(ra => {
                    const createdDate = new Date(ra.created_at).toLocaleDateString();
                    return `
                    <tr>
                        <td><strong>${escapeHtml(ra.name)}</strong></td>
                        <td><span style="background: #fff3e0; padding: 2px 8px; border-radius: 3px; font-size: 12px;">Re-Assessment</span></td>
                        <td>${escapeHtml(ra.policy_name)}</td>
                        <td><span class="status-badge status-completed">Successful</span></td>
                        <td><small>${createdDate}</small></td>
                        <td style="text-align: right;">
                            <div class="action-buttons" style="justify-content: flex-end;">
                                <button class="btn-small" onclick="viewReassessmentReport(${ra.id})">View</button>
                                <button class="btn-small" onclick="generateReassessmentEmbed(${ra.id})">Embed</button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('reassessment', ${ra.id}, '${escapeHtml(ra.name)}', 'pdf')">
                                    📄 PDF
                                </button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('reassessment', ${ra.id}, '${escapeHtml(ra.name)}', 'docx')">
                                    📝 DOCX
                                </button>
                            </div>
                        </td>
                    </tr>
                    `;
                }).join('');
            } catch (error) {
                
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading re-assessment reports.</td></tr>';
            }
        }
        
        /**
         * Load aggregations into the Reports tab
         */
        async function loadAggregationsForReportsTab() {
            const tbody = document.getElementById('reports-aggregation-table-body');
            try {
                const response = await fetch('/api/v1/reports/aggregations');
                if (!response.ok) throw new Error('Failed to load aggregations');
                
                const aggregations = await response.json();
                
                if (aggregations.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No aggregated reports available.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = aggregations.map(agg => {
                    const createdDate = new Date(agg.created_at).toLocaleDateString();
                    return `
                    <tr>
                        <td><strong>${escapeHtml(agg.name)}</strong></td>
                        <td><span style="background: #e8f5e9; padding: 2px 8px; border-radius: 3px; font-size: 12px;">Aggregation</span></td>
                        <td>${escapeHtml(agg.policy_name)}</td>
                        <td><span class="status-badge status-completed">Successful</span></td>
                        <td><small>${createdDate}</small></td>
                        <td style="text-align: right;">
                            <div class="action-buttons" style="justify-content: flex-end;">
                                <button class="btn-small" onclick="viewAggregationReport(${agg.id})">View</button>
                                <button class="btn-small" onclick="embedAggregationDashboard(${agg.id})">Embed</button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('aggregation', ${agg.id}, '${escapeHtml(agg.name)}', 'pdf')">
                                    📄 PDF
                                </button>
                                <button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="generateExecutiveSummary('aggregation', ${agg.id}, '${escapeHtml(agg.name)}', 'docx')">
                                    📝 DOCX
                                </button>
                            </div>
                        </td>
                    </tr>
                    `;
                }).join('');
            } catch (error) {
                
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading aggregated reports.</td></tr>';
            }
        }
        
        /**
         * Generate Executive Summary Report (PDF or DOCX)
         * @param {string} reportType - 'scan', 'reassessment', or 'aggregation'
         * @param {number} reportId - The ID of the report
         * @param {string} reportName - The name of the report (for display)
         * @param {string} format - 'pdf' or 'docx' (default: 'pdf')
         */
        async function generateExecutiveSummary(reportType, reportId, reportName, format = 'pdf') {
            try {
                const formatLabel = format.toUpperCase();
                showAlert(`Generating executive summary (${formatLabel}) for "${reportName}"...`, 'info');

                const response = await fetch('/api/v1/reports/executive-summary', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        type: reportType,
                        id: reportId,
                        format: format
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || `Failed to generate executive summary (${format})`);
                }

                const result = await response.json();

                // Success - show message with filename
                showAlert(`✅ Executive summary (${formatLabel}) generated: ${result.filename}`, 'success');

                // Optionally offer to download
                if (result.path) {

                }

            } catch (error) {
                showAlert(`❌ Failed to generate executive summary: ${error.message}`, 'error');
            }
        }
        
        /**
         * View scan report (helper for Reports tab)
         */
        function viewScanReport(scanId) {
            window.open(`/api/v1/reports/scans/${scanId}/view`, '_blank');
        }
        
        // ==================== END REPORTS TAB FUNCTIONS ====================
        
        // Load aggregations when tab is clicked
        document.addEventListener('DOMContentLoaded', function() {
            const aggregationTab = document.querySelector('[data-tab="aggregation"]');
            if (aggregationTab) {
                aggregationTab.addEventListener('click', loadAggregations);
            }
        });
        
        // Also setup file input handlers for aggregation modal
        const aggregationModalObserver = new MutationObserver(function() {
            const fileInputs = document.querySelectorAll('#aggregationModal .report-file-input');
            fileInputs.forEach(input => {
                if (!input.hasListener) {
                    input.addEventListener('change', function() {
                        handleAggregationFileInput(this);
                    });
                    input.hasListener = true;
                }
            });
        });
        
        const aggregationModal = document.getElementById('aggregationModal');
        if (aggregationModal) {
            aggregationModalObserver.observe(aggregationModal, { childList: true, subtree: true });
        }

        // ==================== COMPLIANCY TAB FUNCTIONS ====================
        
        // Chart instances for compliancy
        let compliancyStatusChart = null;
        let compliancySeverityChart = null;
        let compliancyRuleViolationsChart = null;
        let compliancySourceChart = null;
        
        // Store assessment results for filtering/pagination
        let compliancyAssessmentResults = null;
        let compliancyFilteredFindings = [];
        let compliancyFindingsCurrentPage = 0;
        const compliancyFindingsPageSize = 25;
        
        // Auto-refresh interval
        let compliancyRefreshIntervalId = null;
        let compliancyRefreshSeconds = 120; // Default 2 minutes
        let compliancySelectorsLoaded = false;
        
        async function loadCompliancySelectors() {
            if (compliancySelectorsLoaded) return;
            
            // Load integrations for source selector
            try {
                const intResponse = await fetch('/api/v1/inventory/integrations');
                if (intResponse.ok) {
                    const intData = await intResponse.json();
                    const integrations = intData.integrations || [];
                    const sourceSelect = document.getElementById('compliancySourceSelect');
                    sourceSelect.innerHTML = '<option value="all">All Enabled Integrations</option>';
                    integrations.filter(i => i.enabled).forEach(integration => {
                        sourceSelect.innerHTML += `<option value="${integration.id}">${escapeHtml(integration.name)} (${integration.type})</option>`;
                    });
                }
            } catch (error) {
                
            }
            
            // Load policies for policy selector
            try {
                const policyResponse = await fetch('/api/v1/policies');
                if (policyResponse.ok) {
                    const policyData = await policyResponse.json();
                    const policies = policyData.policies || [];
                    const policySelect = document.getElementById('compliancyPolicySelect');
                    policySelect.innerHTML = '<option value="">-- Select Policy --</option>';
                    policies.forEach(policy => {
                        policySelect.innerHTML += `<option value="${policy.id}">${escapeHtml(policy.name)}</option>`;
                    });
                    
                    // Auto-select first policy if available
                    if (policies.length > 0) {
                        policySelect.value = policies[0].id;
                    }
                }
            } catch (error) {
                
            }
            
            compliancySelectorsLoaded = true;
        }
        
        async function initCompliancyTab() {
            await loadCompliancySelectors();

            // Small delay to ensure DOM is updated
            await new Promise(resolve => setTimeout(resolve, 100));

            // Set defaults: All Integrations
            const sourceSelect = document.getElementById('compliancySourceSelect');
            const policySelect = document.getElementById('compliancyPolicySelect');

            if (sourceSelect) sourceSelect.value = 'all';

            // Get policy ID and run assessment
            const policyId = policySelect ? policySelect.value : '';
            console.log('[Compliance] Tab loaded, policy ID:', policyId);
            console.log('[Compliance] Available options:', policySelect ? policySelect.innerHTML : 'No select found');

            if (policyId && policyId !== '') {
                console.log('[Compliance] Running initial assessment...');
                await runCompliancyAssessment();
            } else {
                // If no policy available, show empty state
                console.log('[Compliance] No policy selected, showing empty state');
                const emptyState = document.getElementById('compliancyEmptyState');
                const summarySection = document.getElementById('compliancySummarySection');
                if (emptyState) emptyState.style.display = 'block';
                if (summarySection) summarySection.style.display = 'none';
            }

            // Start auto-refresh
            startCompliancyAutoRefresh();
        }
        
        function startCompliancyAutoRefresh() {
            // Clear any existing interval
            if (compliancyRefreshIntervalId) {
                clearInterval(compliancyRefreshIntervalId);
            }
            
            // Start new interval
            compliancyRefreshIntervalId = setInterval(() => {
                const policyId = document.getElementById('compliancyPolicySelect').value;
                if (policyId) {
                    runCompliancyAssessment(true); // true = silent refresh (no alerts)
                }
            }, compliancyRefreshSeconds * 1000);
            
            
        }
        
        function stopCompliancyAutoRefresh() {
            if (compliancyRefreshIntervalId) {
                clearInterval(compliancyRefreshIntervalId);
                compliancyRefreshIntervalId = null;
            }
        }
        
        function updateCompliancyRefreshInterval() {
            compliancyRefreshSeconds = parseInt(document.getElementById('compliancyRefreshInterval').value);
            startCompliancyAutoRefresh();
        }
        
        function onCompliancyFilterChange() {
            // When source or policy changes, run assessment immediately
            const policyId = document.getElementById('compliancyPolicySelect').value;
            if (policyId) {
                runCompliancyAssessment();
            }
        }
        
        async function runCompliancyAssessment(silent = false) {
            const sourceId = document.getElementById('compliancySourceSelect').value;
            const policyId = document.getElementById('compliancyPolicySelect').value;
            
            if (!policyId) {
                if (!silent) {
                    showAlert('Please select a policy for assessment', 'error');
                }
                document.getElementById('compliancyEmptyState').style.display = 'block';
                document.getElementById('compliancySummarySection').style.display = 'none';
                return;
            }
            
            // Show loading state
            document.getElementById('compliancyAssessmentStatus').style.display = 'block';
            document.getElementById('compliancyStatusText').textContent = 'Running compliance assessment...';
            
            try {
                const response = await fetch('/api/v1/clm/compliancy/assess', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        source_id: sourceId === 'all' ? null : parseInt(sourceId),
                        policy_id: parseInt(policyId)
                    })
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Assessment failed');
                }
                
                const results = await response.json();
                compliancyAssessmentResults = results;
                
                // Update UI
                updateCompliancyDashboard(results);
                
                // Update last updated timestamp
                const now = new Date();
                document.getElementById('compliancyLastUpdated').textContent = 
                    `Last updated: ${now.toLocaleTimeString()}`;
                
                document.getElementById('compliancySummarySection').style.display = 'block';
                document.getElementById('compliancyEmptyState').style.display = 'none';
                
                if (!silent) {
                    showAlert(`Assessment complete: ${results.summary.total_findings} findings across ${results.summary.certificates_assessed} certificates`, 'success');
                }
                
            } catch (error) {
                
                if (!silent) {
                    showAlert('Assessment failed: ' + error.message, 'error');
                }
                document.getElementById('compliancyEmptyState').style.display = 'block';
            } finally {
                document.getElementById('compliancyAssessmentStatus').style.display = 'none';
            }
        }
        
        function updateCompliancyDashboard(results) {
            const summary = results.summary;
            const findings = results.findings || [];
            const ruleStats = results.rule_statistics || {};
            const certsAssessed = summary.certificates_assessed || 0;
            
            // Calculate compliant vs non-compliant certificates
            const nonCompliantCerts = new Set(findings.map(f => f.evidence?.asset_id || f.evidence?.subject_cn || 'unknown')).size;
            const compliantCerts = Math.max(0, certsAssessed - nonCompliantCerts);
            const compliantPct = certsAssessed > 0 ? ((compliantCerts / certsAssessed) * 100).toFixed(1) : 0;
            const nonCompliantPct = certsAssessed > 0 ? ((nonCompliantCerts / certsAssessed) * 100).toFixed(1) : 0;
            
            // Update metric cards
            document.getElementById('compliancy-certs-assessed').textContent = certsAssessed;
            document.getElementById('compliancy-compliant-count').textContent = compliantCerts;
            document.getElementById('compliancy-compliant-pct').textContent = compliantPct + '%';
            document.getElementById('compliancy-noncompliant-count').textContent = nonCompliantCerts;
            document.getElementById('compliancy-noncompliant-pct').textContent = nonCompliantPct + '%';
            document.getElementById('compliancy-total-findings').textContent = findings.length;
            
            // Count findings by severity
            const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
            findings.forEach(f => {
                const sev = (f.severity || 'low').toLowerCase();
                if (severityCounts.hasOwnProperty(sev)) {
                    severityCounts[sev]++;
                }
            });
            
            document.getElementById('compliancy-critical-count').textContent = severityCounts.critical;
            document.getElementById('compliancy-high-count').textContent = severityCounts.high;
            document.getElementById('compliancy-medium-count').textContent = severityCounts.medium;
            document.getElementById('compliancy-low-count').textContent = severityCounts.low;
            
            // Render charts
            renderCompliancyCharts(compliantCerts, nonCompliantCerts, severityCounts, findings, ruleStats);
            
            // Update rule summary table
            updateCompliancyRulesTable(ruleStats, certsAssessed);
            
            // Populate rule filter dropdown
            populateCompliancyRuleFilter(findings);
            
            // Update findings table
            compliancyFilteredFindings = [...findings];
            compliancyFindingsCurrentPage = 0;
            renderCompliancyFindingsTable();
        }
        
        function renderCompliancyCharts(compliant, nonCompliant, severityCounts, findings, ruleStats) {
            // Compliance Status Pie Chart
            if (compliancyStatusChart) compliancyStatusChart.destroy();
            const statusCtx = document.getElementById('compliancyStatusChart');
            if (statusCtx) {
                compliancyStatusChart = new Chart(statusCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Compliant', 'Non-Compliant'],
                        datasets: [{
                            data: [compliant, nonCompliant],
                            backgroundColor: ['#51cf66', '#ff6b6b'],
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { position: 'bottom', labels: { padding: 15, font: { size: 12 } } }
                        }
                    }
                });
            }
            
            // Severity Distribution Chart
            if (compliancySeverityChart) compliancySeverityChart.destroy();
            const sevCtx = document.getElementById('compliancySeverityChart');
            if (sevCtx) {
                compliancySeverityChart = new Chart(sevCtx, {
                    type: 'bar',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{
                            label: 'Findings',
                            data: [severityCounts.critical, severityCounts.high, severityCounts.medium, severityCounts.low],
                            backgroundColor: ['#dc3545', '#ff6b6b', '#ffc107', '#17a2b8']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: { legend: { display: false } },
                        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }
                    }
                });
            }
            
            // Top Rule Violations Chart
            if (compliancyRuleViolationsChart) compliancyRuleViolationsChart.destroy();
            const ruleCtx = document.getElementById('compliancyRuleViolationsChart');
            if (ruleCtx) {
                // Count violations per rule
                const ruleCounts = {};
                findings.forEach(f => {
                    const ruleName = f.rule_name || f.rule_id || 'Unknown Rule';
                    ruleCounts[ruleName] = (ruleCounts[ruleName] || 0) + 1;
                });
                
                // Sort and take top 8
                const sortedRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
                
                compliancyRuleViolationsChart = new Chart(ruleCtx, {
                    type: 'bar',
                    data: {
                        labels: sortedRules.map(r => r[0].length > 25 ? r[0].substring(0, 22) + '...' : r[0]),
                        datasets: [{
                            label: 'Violations',
                            data: sortedRules.map(r => r[1]),
                            backgroundColor: '#667eea'
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: { legend: { display: false } },
                        scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } }
                    }
                });
            }
            
            // Findings by Source Chart
            if (compliancySourceChart) compliancySourceChart.destroy();
            const sourceCtx = document.getElementById('compliancySourceChart');
            if (sourceCtx) {
                const sourceCounts = {};
                findings.forEach(f => {
                    const source = f.evidence?.source_integration || f.evidence?.source || 'Unknown';
                    sourceCounts[source] = (sourceCounts[source] || 0) + 1;
                });
                
                const sourceLabels = Object.keys(sourceCounts);
                const sourceData = Object.values(sourceCounts);
                const sourceColors = sourceLabels.map((_, i) => 
                    ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#fa709a', '#fee140'][i % 8]
                );
                
                compliancySourceChart = new Chart(sourceCtx, {
                    type: 'pie',
                    data: {
                        labels: sourceLabels,
                        datasets: [{
                            data: sourceData,
                            backgroundColor: sourceColors,
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: { legend: { position: 'bottom', labels: { padding: 10, font: { size: 11 } } } }
                    }
                });
            }
        }
        
        function updateCompliancyRulesTable(ruleStats, totalCerts) {
            const tbody = document.getElementById('compliancy-rules-tbody');
            const rulesEvaluated = document.getElementById('compliancy-rules-evaluated');
            
            const rules = Object.entries(ruleStats);
            rulesEvaluated.textContent = `${rules.length} rules evaluated`;
            
            if (rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No rules evaluated</td></tr>';
                return;
            }
            
            // Sort: enabled rules first (by violations desc), then disabled rules
            rules.sort((a, b) => {
                const aEnabled = a[1].enabled !== false;
                const bEnabled = b[1].enabled !== false;
                if (aEnabled !== bEnabled) return bEnabled - aEnabled;
                return (b[1].violations || 0) - (a[1].violations || 0);
            });
            
            tbody.innerHTML = rules.map(([ruleId, stats]) => {
                const violations = stats.violations || 0;
                const isEnabled = stats.enabled !== false;
                const passRate = totalCerts > 0 ? (((totalCerts - violations) / totalCerts) * 100).toFixed(1) : 100;
                const severityClass = getSeverityClass(stats.severity || 'low');
                const category = stats.category || 'General';
                
                const rowStyle = isEnabled ? '' : 'opacity: 0.5; background: #f9f9f9;';
                const statusBadge = isEnabled ? '' : '<span style="background: #6c757d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin-left: 8px;">DISABLED</span>';
                
                return `
                    <tr style="${rowStyle}">
                        <td>
                            <strong style="font-size: 13px;">${escapeHtml(stats.name || ruleId)}${statusBadge}</strong>
                            <br><small style="color: #888;">${escapeHtml(ruleId)}</small>
                        </td>
                        <td><span style="background: #e3f2fd; padding: 3px 8px; border-radius: 4px; font-size: 11px;">${escapeHtml(category)}</span></td>
                        <td><span class="${severityClass}" style="padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">${escapeHtml((stats.severity || 'Low').toUpperCase())}</span></td>
                        <td style="text-align: center; font-weight: 600; color: ${isEnabled ? (violations > 0 ? '#dc3545' : '#51cf66') : '#999'};">${isEnabled ? violations : '-'}</td>
                        <td style="text-align: center;">
                            ${isEnabled ? `
                            <div style="display: flex; align-items: center; gap: 8px; justify-content: center;">
                                <div style="width: 80px; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden;">
                                    <div style="width: ${passRate}%; height: 100%; background: ${passRate >= 90 ? '#51cf66' : passRate >= 70 ? '#ffc107' : '#ff6b6b'};"></div>
                                </div>
                                <span style="font-size: 12px; font-weight: 600;">${passRate}%</span>
                            </div>
                            ` : '<span style="color: #999; font-size: 12px;">Not evaluated</span>'}
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function getSeverityClass(severity) {
            const sev = (severity || '').toLowerCase();
            switch (sev) {
                case 'critical': return 'severity-critical';
                case 'high': return 'severity-high';
                case 'medium': return 'severity-medium';
                case 'low': return 'severity-low';
                default: return 'severity-low';
            }
        }
        
        function populateCompliancyRuleFilter(findings) {
            const ruleFilter = document.getElementById('compliancyFindingsRuleFilter');
            const uniqueRules = [...new Set(findings.map(f => f.rule_name || f.rule_id))];
            ruleFilter.innerHTML = '<option value="">All Rules</option>';
            uniqueRules.forEach(rule => {
                ruleFilter.innerHTML += `<option value="${escapeHtml(rule)}">${escapeHtml(rule)}</option>`;
            });
        }
        
        function filterCompliancyFindings() {
            if (!compliancyAssessmentResults) return;
            
            const severityFilter = document.getElementById('compliancyFindingsSeverityFilter').value.toLowerCase();
            const ruleFilter = document.getElementById('compliancyFindingsRuleFilter').value;
            const searchText = document.getElementById('compliancyFindingsSearch').value.toLowerCase();
            
            compliancyFilteredFindings = (compliancyAssessmentResults.findings || []).filter(f => {
                if (severityFilter && (f.severity || '').toLowerCase() !== severityFilter) return false;
                if (ruleFilter && (f.rule_name || f.rule_id) !== ruleFilter) return false;
                if (searchText) {
                    const searchFields = [
                        f.evidence?.subject_cn || '',
                        f.evidence?.issuer_cn || '',
                        f.evidence?.asset_id || '',
                        f.rule_name || '',
                        f.description || ''
                    ].join(' ').toLowerCase();
                    if (!searchFields.includes(searchText)) return false;
                }
                return true;
            });
            
            compliancyFindingsCurrentPage = 0;
            renderCompliancyFindingsTable();
        }
        
        function renderCompliancyFindingsTable() {
            const tbody = document.getElementById('compliancy-findings-tbody');
            const countEl = document.getElementById('compliancy-findings-count');
            const pageInfo = document.getElementById('compliancy-page-info');
            const prevBtn = document.getElementById('compliancy-prev-btn');
            const nextBtn = document.getElementById('compliancy-next-btn');
            
            const total = compliancyFilteredFindings.length;
            const totalPages = Math.ceil(total / compliancyFindingsPageSize);
            const start = compliancyFindingsCurrentPage * compliancyFindingsPageSize;
            const end = Math.min(start + compliancyFindingsPageSize, total);
            const pageFindings = compliancyFilteredFindings.slice(start, end);
            
            countEl.textContent = `Showing ${start + 1}-${end} of ${total} findings`;
            pageInfo.textContent = `Page ${compliancyFindingsCurrentPage + 1} of ${totalPages || 1}`;
            prevBtn.disabled = compliancyFindingsCurrentPage === 0;
            nextBtn.disabled = compliancyFindingsCurrentPage >= totalPages - 1;
            
            if (pageFindings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No findings match the current filters</td></tr>';
                return;
            }
            
            tbody.innerHTML = pageFindings.map(f => {
                const subjectCn = f.evidence?.subject_cn || f.evidence?.asset_id || 'Unknown';
                const ruleName = f.rule_name || f.rule_id || 'Unknown Rule';
                const severity = (f.severity || 'low').toUpperCase();
                const severityClass = getSeverityClass(f.severity);
                const riskScore = f.risk_score !== undefined ? f.risk_score.toFixed(1) : 'N/A';
                const evidence = formatEvidenceDisplay(f.evidence || {});
                const remediation = f.remediation || 'No remediation guidance available';
                
                return `
                    <tr>
                        <td>
                            <strong style="font-size: 12px;">${escapeHtml(subjectCn.length > 40 ? subjectCn.substring(0, 37) + '...' : subjectCn)}</strong>
                            ${f.evidence?.source_integration ? `<br><small style="color: #888;">${escapeHtml(f.evidence.source_integration)}</small>` : ''}
                        </td>
                        <td><span style="font-size: 12px;">${escapeHtml(ruleName)}</span></td>
                        <td><span class="${severityClass}" style="padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">${severity}</span></td>
                        <td style="text-align: center; font-weight: 600;">${riskScore}</td>
                        <td style="font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(evidence)}">${escapeHtml(evidence.length > 80 ? evidence.substring(0, 77) + '...' : evidence)}</td>
                        <td style="font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(remediation)}">${escapeHtml(remediation.length > 80 ? remediation.substring(0, 77) + '...' : remediation)}</td>
                    </tr>
                `;
            }).join('');
        }
        
        function formatEvidenceDisplay(evidence) {
            const parts = [];
            if (evidence.signature_algorithm) parts.push(`Sig: ${evidence.signature_algorithm}`);
            if (evidence.public_key_algorithm) parts.push(`Key: ${evidence.public_key_algorithm}`);
            if (evidence.public_key_size) parts.push(`Size: ${evidence.public_key_size}`);
            if (evidence.days_until_expiration !== undefined) parts.push(`Days: ${evidence.days_until_expiration}`);
            if (evidence.actual_value !== undefined) parts.push(`Value: ${evidence.actual_value}`);
            return parts.length > 0 ? parts.join(', ') : 'See certificate details';
        }
        
        function compliancyFindingsPage(direction) {
            const totalPages = Math.ceil(compliancyFilteredFindings.length / compliancyFindingsPageSize);
            compliancyFindingsCurrentPage = Math.max(0, Math.min(totalPages - 1, compliancyFindingsCurrentPage + direction));
            renderCompliancyFindingsTable();
        }
        
        function exportCompliancyFindings() {
            if (!compliancyFilteredFindings || compliancyFilteredFindings.length === 0) {
                showAlert('No findings to export', 'error');
                return;
            }
            
            const headers = ['Certificate', 'Source', 'Rule ID', 'Rule Name', 'Severity', 'Risk Score', 'Description', 'Remediation'];
            const rows = compliancyFilteredFindings.map(f => [
                f.evidence?.subject_cn || f.evidence?.asset_id || 'Unknown',
                f.evidence?.source_integration || f.evidence?.source || 'Unknown',
                f.rule_id || '',
                f.rule_name || '',
                f.severity || 'low',
                f.risk_score !== undefined ? f.risk_score.toString() : '',
                (f.description || '').replace(/"/g, '""'),
                (f.remediation || '').replace(/"/g, '""')
            ]);
            
            const csvContent = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = `compliancy_findings_${new Date().toISOString().slice(0, 10)}.csv`;
            link.click();
            
            showAlert(`Exported ${compliancyFilteredFindings.length} findings to CSV`, 'success');
        }
        
        function populateCompliancyRuleFilter(findings) {
            const ruleFilter = document.getElementById('compliancyFindingsRuleFilter');
            const uniqueRules = [...new Set(findings.map(f => f.rule_name || f.rule_id))];
            ruleFilter.innerHTML = '<option value="">All Rules</option>';
            uniqueRules.forEach(rule => {
                ruleFilter.innerHTML += `<option value="${escapeHtml(rule)}">${escapeHtml(rule)}</option>`;
            });
        }
        
        function filterCompliancyFindings() {
            if (!compliancyAssessmentResults) return;
            
            const severityFilter = document.getElementById('compliancyFindingsSeverityFilter').value.toLowerCase();
            const ruleFilter = document.getElementById('compliancyFindingsRuleFilter').value;
            const searchText = document.getElementById('compliancyFindingsSearch').value.toLowerCase();
            
            compliancyFilteredFindings = (compliancyAssessmentResults.findings || []).filter(f => {
                if (severityFilter && (f.severity || '').toLowerCase() !== severityFilter) return false;
                if (ruleFilter && (f.rule_name || f.rule_id) !== ruleFilter) return false;
                if (searchText) {
                    const searchFields = [
                        f.evidence?.subject_cn || '',
                        f.evidence?.issuer_cn || '',
                        f.evidence?.asset_id || '',
                        f.rule_name || '',
                        f.description || ''
                    ].join(' ').toLowerCase();
                    if (!searchFields.includes(searchText)) return false;
                }
                return true;
            });
            
            compliancyFindingsCurrentPage = 0;
            renderCompliancyFindingsTable();
        }
        
        function renderCompliancyFindingsTable() {
            const tbody = document.getElementById('compliancy-findings-tbody');
            const countEl = document.getElementById('compliancy-findings-count');
            const pageInfo = document.getElementById('compliancy-page-info');
            const prevBtn = document.getElementById('compliancy-prev-btn');
            const nextBtn = document.getElementById('compliancy-next-btn');
            
            const total = compliancyFilteredFindings.length;
            const totalPages = Math.ceil(total / compliancyFindingsPageSize);
            const start = compliancyFindingsCurrentPage * compliancyFindingsPageSize;
            const end = Math.min(start + compliancyFindingsPageSize, total);
            const pageFindings = compliancyFilteredFindings.slice(start, end);
            
            countEl.textContent = `Showing ${start + 1}-${end} of ${total} findings`;
            pageInfo.textContent = `Page ${compliancyFindingsCurrentPage + 1} of ${totalPages || 1}`;
            prevBtn.disabled = compliancyFindingsCurrentPage === 0;
            nextBtn.disabled = compliancyFindingsCurrentPage >= totalPages - 1;
            
            if (pageFindings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No findings match the current filters</td></tr>';
                return;
            }
            
            tbody.innerHTML = pageFindings.map(f => {
                const subjectCn = f.evidence?.subject_cn || f.evidence?.asset_id || 'Unknown';
                const ruleName = f.rule_name || f.rule_id || 'Unknown Rule';
                const severity = (f.severity || 'low').toUpperCase();
                const severityClass = getSeverityClass(f.severity);
                const riskScore = f.risk_score !== undefined ? f.risk_score.toFixed(1) : 'N/A';
                const evidence = formatEvidenceDisplay(f.evidence || {});
                const remediation = f.remediation || 'No remediation guidance available';
                
                return `
                    <tr>
                        <td>
                            <strong style="font-size: 12px;">${escapeHtml(subjectCn.length > 40 ? subjectCn.substring(0, 37) + '...' : subjectCn)}</strong>
                            ${f.evidence?.source_integration ? `<br><small style="color: #888;">${escapeHtml(f.evidence.source_integration)}</small>` : ''}
                        </td>
                        <td><span style="font-size: 12px;">${escapeHtml(ruleName)}</span></td>
                        <td><span class="${severityClass}" style="padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">${severity}</span></td>
                        <td style="text-align: center; font-weight: 600;">${riskScore}</td>
                        <td style="font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(evidence)}">${escapeHtml(evidence.length > 80 ? evidence.substring(0, 77) + '...' : evidence)}</td>
                        <td style="font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(remediation)}">${escapeHtml(remediation.length > 80 ? remediation.substring(0, 77) + '...' : remediation)}</td>
                    </tr>
                `;
            }).join('');
        }
        
        function formatEvidenceDisplay(evidence) {
            const parts = [];
            if (evidence.signature_algorithm) parts.push(`Sig: ${evidence.signature_algorithm}`);
            if (evidence.public_key_algorithm) parts.push(`Key: ${evidence.public_key_algorithm}`);
            if (evidence.public_key_size) parts.push(`Size: ${evidence.public_key_size}`);
            if (evidence.days_until_expiration !== undefined) parts.push(`Days: ${evidence.days_until_expiration}`);
            if (evidence.actual_value !== undefined) parts.push(`Value: ${evidence.actual_value}`);
            return parts.length > 0 ? parts.join(', ') : 'See certificate details';
        }
        
        function compliancyFindingsPage(direction) {
            const totalPages = Math.ceil(compliancyFilteredFindings.length / compliancyFindingsPageSize);
            compliancyFindingsCurrentPage = Math.max(0, Math.min(totalPages - 1, compliancyFindingsCurrentPage + direction));
            renderCompliancyFindingsTable();
        }
        
        function exportCompliancyFindings() {
            if (!compliancyFilteredFindings || compliancyFilteredFindings.length === 0) {
                showAlert('No findings to export', 'error');
                return;
            }
            
            const headers = ['Certificate', 'Source', 'Rule ID', 'Rule Name', 'Severity', 'Risk Score', 'Description', 'Remediation'];
            const rows = compliancyFilteredFindings.map(f => [
                f.evidence?.subject_cn || f.evidence?.asset_id || 'Unknown',
                f.evidence?.source_integration || f.evidence?.source || 'Unknown',
                f.rule_id || '',
                f.rule_name || '',
                f.severity || 'low',
                f.risk_score !== undefined ? f.risk_score.toString() : '',
                (f.description || '').replace(/"/g, '""'),
                (f.remediation || '').replace(/"/g, '""')
            ]);
            
            const csvContent = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = `compliancy_findings_${new Date().toISOString().slice(0, 10)}.csv`;
            link.click();
            
            showAlert(`Exported ${compliancyFilteredFindings.length} findings to CSV`, 'success');
        }

    

        // Sidebar navigation
        function setupSidebarNavigation() {
            // Handle parent expand/collapse
            document.querySelectorAll('.sidebar-nav-parent[data-parent]').forEach(parent => {
                parent.addEventListener('click', function() {
                    const parentName = this.dataset.parent;
                    const children = document.querySelector(`[data-parent-children="${parentName}"]`);
                    
                    this.classList.toggle('expanded');
                    if (children) {
                        children.classList.toggle('expanded');
                    }
                });
            });
            
            // Handle child nav items (within expandable parents)
            document.querySelectorAll('.sidebar-nav-child[data-main-tab]').forEach(btn => {
                btn.addEventListener('click', function(e) {
                    e.stopPropagation(); // Prevent parent collapse
                    const mainTabName = this.dataset.mainTab;
                    const reportsTab = this.dataset.reportsTab;
                    const settingsTab = this.dataset.settingsTab;

                    // Update sidebar active state - clear all
                    document.querySelectorAll('.sidebar-nav-item').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.sidebar-nav-child').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');

                    // Also update hidden main tabs for compatibility
                    document.querySelectorAll('.main-tabs [data-main-tab]').forEach(b => b.classList.remove('active'));
                    const hiddenBtn = document.querySelector(`.main-tabs [data-main-tab="${mainTabName}"]`);
                    if (hiddenBtn) hiddenBtn.classList.add('active');

                    // Switch main tab content (with default sub-tab selection)
                    // Hide all main tabs
                    document.querySelectorAll('.main-tab-content').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    // Show selected main tab
                    document.getElementById(mainTabName).classList.add('active');

                    // Set default sub-tabs for Assets and Lifecycle
                    if (mainTabName === 'assets') {
                        setTimeout(() => {
                            switchTab('assets-dashboard');
                        }, 50);
                    } else if (mainTabName === 'lifecycle') {
                        setTimeout(() => {
                            switchTab('lifecycle-overview');
                        }, 50);
                    }

                    // If this is a Reports sub-tab, switch to the specific sub-tab
                    if (reportsTab) {
                        setTimeout(() => {
                            switchTab(reportsTab);
                        }, 50);
                    }

                    // If this is a Settings sub-tab, switch to the specific sub-tab
                    if (settingsTab) {
                        setTimeout(() => {
                            switchTab(settingsTab);
                            // Special handling for RBAC tab initialization
                            if (settingsTab === 'settings-rbac' && typeof initializeRBAC === 'function') {
                                initializeRBAC();
                            }
                        }, 50);
                    }
                });
            });
            
            // Handle regular nav items (not in expandable parents)
            document.querySelectorAll('.sidebar-nav-item[data-main-tab]').forEach(btn => {
                btn.addEventListener('click', function() {
                    const mainTabName = this.dataset.mainTab;
                    const settingsTab = this.dataset.settingsTab;

                    // Update sidebar active state - clear all including children
                    document.querySelectorAll('.sidebar-nav-item').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.sidebar-nav-child').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');

                    // Also update hidden main tabs for compatibility
                    document.querySelectorAll('.main-tabs [data-main-tab]').forEach(b => b.classList.remove('active'));
                    const hiddenBtn = document.querySelector(`.main-tabs [data-main-tab="${mainTabName}"]`);
                    if (hiddenBtn) hiddenBtn.classList.add('active');

                    // Switch main tab content
                    switchMainTab(mainTabName);

                    // If this is Settings with a specific sub-tab, switch to it
                    if (settingsTab) {
                        setTimeout(() => {
                            switchTab(settingsTab);
                        }, 50);
                    }
                });
            });
        }

        // Toggle user dropdown
        function toggleUserDropdown() {
            const dropdown = document.getElementById('userDropdown');
            dropdown.classList.toggle('show');
        }

        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const userMenu = document.getElementById('userMenuBtn');
            const dropdown = document.getElementById('userDropdown');
            if (userMenu && dropdown && !userMenu.contains(e.target)) {
                dropdown.classList.remove('show');
            }
        });

        // Update user avatar initial
        function updateUserAvatar() {
            const username = document.getElementById('currentUsername').textContent;
            const avatar = document.getElementById('userAvatarInitial');
            if (avatar && username) {
                avatar.textContent = username.charAt(0).toUpperCase();
            }
        }

        // Override setupUserDropdown to also update avatar
        const originalSetupUserDropdown = typeof setupUserDropdown === 'function' ? setupUserDropdown : null;
        setupUserDropdown = function() {
            if (originalSetupUserDropdown) originalSetupUserDropdown();
            updateUserAvatar();
        };

        // Initialize sidebar on load
        window.addEventListener('load', () => {
            setupSidebarNavigation();
            updateUserAvatar();
        });

        // ==================== DOCUMENT SCANNING FUNCTIONS ====================
        
        // Load document assessments list
        async function loadDocumentAssessments() {
            try {
                const params = getEngagementFilterParams();
                const url = params ? `/api/v1/document-assessment/assessments?${params}` : '/api/v1/document-assessment/assessments';
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to load assessments');
                
                const data = await response.json();
                const assessments = data.assessments || [];
                
                // Update summary cards
                updateDocumentSummaryCards(assessments);
                
                // Render table
                renderDocumentAssessmentsTable(assessments);
                
            } catch (error) {
                
                document.getElementById('doc-assessments-table-body').innerHTML = 
                    '<tr><td colspan="8" class="empty-state">Error loading assessments. Please try again.</td></tr>';
            }
        }
        
        // Update summary cards
        function updateDocumentSummaryCards(assessments) {
            document.getElementById('doc-total-assessments').textContent = assessments.length;
            
            if (assessments.length > 0) {
                // Calculate average coverage
                const avgCoverage = assessments.reduce((sum, a) => sum + (a.coverage_score || 0), 0) / assessments.length;
                document.getElementById('doc-avg-coverage').textContent = avgCoverage.toFixed(1) + '%';
                
                // Get most recent grade
                const sorted = [...assessments].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                const latestGrade = sorted[0]?.summary?.assessment_grade || '-';
                document.getElementById('doc-recent-grade').textContent = latestGrade;
                
                // Count unique document types
                const uniqueTypes = new Set(assessments.map(a => a.document_type)).size;
                document.getElementById('doc-types-assessed').textContent = uniqueTypes;
            } else {
                document.getElementById('doc-avg-coverage').textContent = '0%';
                document.getElementById('doc-recent-grade').textContent = '-';
                document.getElementById('doc-types-assessed').textContent = '0';
            }
        }
        
        // Render assessments table
        function renderDocumentAssessmentsTable(assessments) {
            const tbody = document.getElementById('doc-assessments-table-body');
            
            if (!assessments || assessments.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No document assessments yet. Upload a document to get started.</td></tr>';
                return;
            }
            
            // Map document type to friendly name
            const docTypeNames = {
                'certificate_practice_statement': 'CPS',
                'certificate_policy': 'CP',
                'pki_design': 'PKI Design',
                'key_management_plan': 'Key Mgmt',
                'pki_operational_process': 'PKI Ops',
                'business_continuity': 'BC/DR'
            };
            
            tbody.innerHTML = assessments.map(assessment => {
                const grade = assessment.summary?.assessment_grade || 'N/A';
                const gradeClass = getGradeClass(grade);
                const coverage = (assessment.coverage_score || 0).toFixed(1);
                const found = assessment.findings_found || 0;
                const partial = assessment.findings_partial || 0;
                const missing = assessment.findings_missing || 0;
                const createdAt = new Date(assessment.created_at).toLocaleString();
                const docType = docTypeNames[assessment.document_type] || assessment.document_type || 'Unknown';
                
                const engagementDisplay = assessment.engagement_id 
                    ? `<span class="engagement-badge">${escapeHtml(assessment.engagement_id)}</span>`
                    : '<span class="text-muted">—</span>';
                
                return `
                    <tr>
                        <td>
                            <div style="font-weight: 500;">${escapeHtml(assessment.filename)}</div>
                        </td>
                        <td>${engagementDisplay}</td>
                        <td>
                            <span class="badge badge-info">${escapeHtml(docType)}</span>
                        </td>
                        <td>
                            <span class="badge ${gradeClass}" style="font-size: 16px; font-weight: 700;">${grade}</span>
                        </td>
                        <td>${coverage}%</td>
                        <td>
                            <span style="color: var(--success);">${found} found</span> / 
                            <span style="color: var(--warning);">${partial} partial</span> / 
                            <span style="color: var(--danger);">${missing} missing</span>
                        </td>
                        <td>${createdAt}</td>
                        <td style="text-align: right;">
                            <button class="btn-secondary btn-sm" onclick="viewDocumentAssessment('${assessment.assessment_id}')" title="View Details">
                                👁️ View
                            </button>
                            <button class="btn-secondary btn-sm" onclick="downloadDocumentReport('${assessment.assessment_id}', 'pdf')" title="Download PDF">
                                📄 PDF
                            </button>
                            <button class="btn-danger btn-sm" onclick="deleteDocumentAssessment('${assessment.assessment_id}')" title="Delete">
                                🗑️
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        // Get CSS class for grade
        function getGradeClass(grade) {
            const gradeClasses = {
                'A': 'badge-success',
                'B': 'badge-success',
                'C': 'badge-warning',
                'D': 'badge-warning',
                'F': 'badge-danger'
            };
            return gradeClasses[grade] || 'badge-secondary';
        }
        
        // Load document types for dropdown
        async function loadDocumentTypes() {
            try {
                const response = await fetch('/api/v1/document-assessment/types');
                if (!response.ok) throw new Error('Failed to load document types');
                
                const data = await response.json();
                const types = data.document_types || [];
                
                const select = document.getElementById('doc-type-select');
                // Keep the auto-detect option
                select.innerHTML = '<option value="">Auto-detect (recommended)</option>';
                
                types.forEach(type => {
                    const option = document.createElement('option');
                    option.value = type.id;  // API returns 'id'
                    option.textContent = type.name;  // API returns 'name'
                    if (type.description) {
                        option.title = type.description;
                    }
                    select.appendChild(option);
                });
                
            } catch (error) {
                
            }
        }
        
        // Load templates
        async function loadDocumentTemplates() {
            try {
                const response = await fetch('/api/v1/document-assessment/templates');
                if (!response.ok) throw new Error('Failed to load templates');
                
                const data = await response.json();
                
                // Render built-in templates
                renderTemplatesGrid('doc-builtin-templates', data.builtin_templates || []);
                
                // Render custom templates
                renderTemplatesGrid('doc-custom-templates', data.custom_templates || [], true);
                
            } catch (error) {
                
                document.getElementById('doc-builtin-templates').innerHTML = 
                    '<div class="empty-state">Error loading templates.</div>';
            }
        }
        
        // Render templates grid
        function renderTemplatesGrid(containerId, templates, isCustom = false) {
            const container = document.getElementById(containerId);
            
            if (!templates || templates.length === 0) {
                container.innerHTML = `<div class="empty-state" style="padding: 40px; text-align: center; color: var(--text-muted);">
                    ${isCustom ? 'No custom templates defined.' : 'No templates available.'}
                </div>`;
                return;
            }
            
            // Map document type to friendly name
            const docTypeNames = {
                'certificate_practice_statement': 'Certificate Practice Statement (CPS)',
                'certificate_policy': 'Certificate Policy (CP)',
                'pki_design': 'PKI Design Document',
                'key_management_plan': 'Key Management Plan',
                'pki_operational_process': 'PKI Operational Process',
                'business_continuity': 'Business Continuity Document'
            };
            
            container.innerHTML = templates.map(template => {
                const docType = template.document_type || 'unknown';
                const docTypeName = docTypeNames[docType] || docType;
                const sectionCount = template.section_count || template.element_count || 0;
                const frameworkCount = Array.isArray(template.frameworks) ? template.frameworks.length : 0;
                const frameworkList = Array.isArray(template.frameworks) ? template.frameworks.join(', ') : '';
                
                return `
                <div class="card" style="padding: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                        <h4 style="margin: 0; font-size: 15px; color: var(--text-primary);">${escapeHtml(template.name || docTypeName)}</h4>
                        <span class="badge badge-info" style="font-size: 11px;">${escapeHtml(template.version || '1.0')}</span>
                    </div>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                        ${escapeHtml(template.description || docTypeName)}
                    </p>
                    <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
                        <span style="margin-right: 16px;">📋 ${sectionCount} sections</span>
                        <span>🏷️ ${frameworkCount} frameworks</span>
                    </div>
                    ${frameworkList ? `<div style="font-size: 11px; color: var(--accent);">${escapeHtml(frameworkList)}</div>` : ''}
                </div>
                `;
            }).join('');
        }
        
        // File upload handling
        document.addEventListener('DOMContentLoaded', function() {
            const dropzone = document.getElementById('doc-file-dropzone');
            const fileInput = document.getElementById('doc-file-input');
            
            if (dropzone && fileInput) {
                // Click to browse
                dropzone.addEventListener('click', () => fileInput.click());
                
                // Drag and drop
                dropzone.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    dropzone.style.borderColor = 'var(--accent)';
                    dropzone.style.background = 'var(--accent-light)';
                });
                
                dropzone.addEventListener('dragleave', () => {
                    dropzone.style.borderColor = 'var(--border-color)';
                    dropzone.style.background = 'transparent';
                });
                
                dropzone.addEventListener('drop', (e) => {
                    e.preventDefault();
                    dropzone.style.borderColor = 'var(--border-color)';
                    dropzone.style.background = 'transparent';
                    
                    if (e.dataTransfer.files.length) {
                        fileInput.files = e.dataTransfer.files;
                        handleDocumentFileSelect(fileInput.files[0]);
                    }
                });
                
                // File input change
                fileInput.addEventListener('change', (e) => {
                    if (e.target.files.length) {
                        handleDocumentFileSelect(e.target.files[0]);
                    }
                });
            }
        });
        
        // Handle file selection
        function handleDocumentFileSelect(file) {
            const allowedTypes = ['.pdf', '.docx', '.doc'];
            const ext = '.' + file.name.split('.').pop().toLowerCase();
            
            if (!allowedTypes.includes(ext)) {
                showAlert('Invalid file type. Please upload PDF or DOCX files.', 'error');
                return;
            }
            
            document.getElementById('doc-file-name').textContent = file.name;
            document.getElementById('doc-file-selected').style.display = 'block';
            document.getElementById('doc-file-dropzone').style.display = 'none';
        }
        
        // Clear selected file
        function clearDocumentFile() {
            document.getElementById('doc-file-input').value = '';
            document.getElementById('doc-file-selected').style.display = 'none';
            document.getElementById('doc-file-dropzone').style.display = 'block';
        }
        
        // Reset form
        function resetDocumentForm() {
            clearDocumentFile();
            document.getElementById('doc-type-select').value = '';
            document.getElementById('doc-save-result').checked = true;
            document.getElementById('doc-assessment-result').style.display = 'none';
        }
        
        // Submit document for assessment
        async function submitDocumentAssessment(event) {
            event.preventDefault();
            
            const fileInput = document.getElementById('doc-file-input');
            if (!fileInput.files.length) {
                showAlert('Please select a document to assess.', 'error');
                return;
            }
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            const docType = document.getElementById('doc-type-select').value;
            if (docType) {
                formData.append('document_type', docType);
            }
            
            formData.append('save_result', document.getElementById('doc-save-result').checked ? 'true' : 'false');
            
            // Include engagement if one is active
            if (activeEngagementId) {
                formData.append('engagement_id', activeEngagementId);
            }
            
            // Show progress
            document.getElementById('doc-assess-btn').disabled = true;
            document.getElementById('doc-assessment-progress').style.display = 'block';
            document.getElementById('doc-assessment-result').style.display = 'none';
            
            try {
                const response = await fetch('/api/v1/document-assessment/assess', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (!response.ok) {
                    throw new Error(result.error || 'Assessment failed');
                }
                
                // Show result
                displayAssessmentResult(result);
                showAlert('Document assessment completed successfully!', 'success');
                
                // Refresh assessments list
                loadDocumentAssessments();
                
            } catch (error) {
                
                showAlert('Assessment failed: ' + error.message, 'error');
            } finally {
                document.getElementById('doc-assess-btn').disabled = false;
                document.getElementById('doc-assessment-progress').style.display = 'none';
            }
        }
        
        // Display assessment result
        function displayAssessmentResult(result) {
            const container = document.getElementById('doc-result-content');
            const grade = result.summary?.assessment_grade || 'N/A';
            const gradeClass = getGradeClass(grade);
            const coverage = (result.coverage_score || 0).toFixed(1);
            
            const findings = result.findings || [];
            const found = findings.filter(f => f.status === 'found').length;
            const partial = findings.filter(f => f.status === 'partial').length;
            const missing = findings.filter(f => f.status === 'missing').length;
            
            container.innerHTML = `
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px;">
                    <div style="text-align: center; padding: 16px; background: var(--content-bg); border-radius: 8px;">
                        <div class="badge ${gradeClass}" style="font-size: 32px; padding: 8px 16px;">${grade}</div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Grade</div>
                    </div>
                    <div style="text-align: center; padding: 16px; background: var(--content-bg); border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: var(--accent);">${coverage}%</div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Coverage</div>
                    </div>
                    <div style="text-align: center; padding: 16px; background: var(--content-bg); border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: var(--success);">${found}</div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Found</div>
                    </div>
                    <div style="text-align: center; padding: 16px; background: var(--content-bg); border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: var(--danger);">${missing}</div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Missing</div>
                    </div>
                </div>
                
                <div style="margin-bottom: 16px;">
                    <strong>Document Type:</strong> ${escapeHtml(result.document_type || 'Unknown')}
                </div>
                
                ${result.summary?.executive_summary ? `
                    <div style="padding: 16px; background: #f0f9ff; border-radius: 8px; margin-bottom: 16px;">
                        <strong>Summary:</strong> ${escapeHtml(result.summary.executive_summary)}
                    </div>
                ` : ''}
                
                <div style="display: flex; gap: 12px; margin-top: 20px;">
                    <button class="btn-primary" onclick="viewDocumentAssessment('${result.assessment_id}')">
                        View Full Details
                    </button>
                    <button class="btn-secondary" onclick="downloadDocumentReport('${result.assessment_id}', 'pdf')">
                        Download PDF Report
                    </button>
                </div>
            `;
            
            document.getElementById('doc-assessment-result').style.display = 'block';
        }
        
        // View assessment details
        async function viewDocumentAssessment(assessmentId) {
            try {
                const response = await fetch(`/api/v1/document-assessment/assessments/${assessmentId}`);
                if (!response.ok) throw new Error('Failed to load assessment');
                
                const assessment = await response.json();
                
                // Open in modal or new tab
                const reportUrl = `/api/v1/document-assessment/assessments/${assessmentId}/report?format=html`;
                window.open(reportUrl, '_blank');
                
            } catch (error) {
                
                showAlert('Failed to load assessment details.', 'error');
            }
        }
        
        // Download report
        function downloadDocumentReport(assessmentId, format) {
            window.open(`/api/v1/document-assessment/assessments/${assessmentId}/report?format=${format}`, '_blank');
        }
        
        // Delete assessment
        async function deleteDocumentAssessment(assessmentId) {
            if (!confirm('Are you sure you want to delete this assessment? This cannot be undone.')) {
                return;
            }
            
            try {
                const response = await fetch(`/api/v1/document-assessment/assessments/${assessmentId}`, {
                    method: 'DELETE'
                });
                
                if (!response.ok) throw new Error('Failed to delete assessment');
                
                showAlert('Assessment deleted successfully.', 'success');
                loadDocumentAssessments();
                
            } catch (error) {
                
                showAlert('Failed to delete assessment.', 'error');
            }
        }
        
        // Escape HTML helper (if not already defined)
        if (typeof escapeHtml !== 'function') {
            function escapeHtml(text) {
                if (!text) return '';
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
        }

        // ==================== ENGAGEMENT FUNCTIONS ====================
        
        let engagementDebounceTimer = null;
        
        function debounceLoadEngagements() {
            clearTimeout(engagementDebounceTimer);
            engagementDebounceTimer = setTimeout(loadEngagements, 300);
        }
        
        async function loadEngagements() {
            try {
                const status = document.getElementById('engagement-filter-status')?.value || '';
                const customer = document.getElementById('engagement-filter-customer')?.value || '';
                
                let url = '/api/v1/engagements?';
                if (status) url += `status=${encodeURIComponent(status)}&`;
                if (customer) url += `customer=${encodeURIComponent(customer)}&`;
                
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to load engagements');
                
                const data = await response.json();
                const engagements = data.engagements || [];
                
                // Update summary cards
                document.getElementById('engagements-total').textContent = engagements.length;
                document.getElementById('engagements-active').textContent = engagements.filter(e => e.status === 'Active').length;
                document.getElementById('engagements-completed').textContent = engagements.filter(e => e.status === 'Completed').length;
                document.getElementById('engagements-reports-total').textContent = engagements.reduce((sum, e) => sum + (e.report_count || 0), 0);
                
                renderEngagementsTable(engagements);
                
            } catch (error) {
                
                showAlert('Failed to load engagements.', 'error');
            }
        }
        
        function renderEngagementsTable(engagements) {
            const tbody = document.getElementById('engagements-table-body');
            
            if (!engagements || engagements.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No engagements found. Create one to get started.</td></tr>';
                return;
            }
            
            tbody.innerHTML = engagements.map(eng => {
                const statusColor = eng.status === 'Active' ? '#10b981' : 
                                   eng.status === 'Completed' ? '#3b82f6' : '#6b7280';
                
                return `
                    <tr>
                        <td><code style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-weight: 600;">${escapeHtml(eng.engagement_id)}</code></td>
                        <td><strong>${escapeHtml(eng.customer_name)}</strong></td>
                        <td>${escapeHtml(eng.project_name)}</td>
                        <td><span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; background: ${statusColor}20; color: ${statusColor};">${eng.status}</span></td>
                        <td style="text-align: center;"><span style="background: #e0e7ff; color: #3730a3; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600;">${eng.report_count || 0}</span></td>
                        <td style="text-align: center;"><span style="background: #d1fae5; color: #065f46; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600;">${eng.summary_count || 0}</span></td>
                        <td>${formatDate(eng.created_at)}</td>
                        <td style="text-align: right;">
                            <div style="display: flex; gap: 6px; justify-content: flex-end;">
                                <button class="btn-small" onclick="viewEngagement('${eng.engagement_id}')" title="View/Manage">
                                    View
                                </button>
                                <button class="btn-small btn-secondary" onclick="editEngagement('${eng.engagement_id}')" title="Edit">
                                    Edit
                                </button>
                                <button class="btn-small" style="background: #ef4444; color: white;" onclick="deleteEngagement('${eng.engagement_id}')" title="Delete">
                                    Delete
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function openNewEngagementModal() {
            let modal = document.getElementById('new-engagement-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'new-engagement-modal';
                modal.className = 'modal';
                modal.innerHTML = `
                    <div class="modal-content" style="max-width: 600px; margin: auto;">
                        <div class="modal-header">
                            <h3>Create New Engagement</h3>
                            <button class="close-btn" onclick="closeModal('new-engagement-modal')">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="form-group">
                                <label>Customer Name *</label>
                                <input type="text" id="new-eng-customer" placeholder="e.g., Acme Corporation" style="width: 100%;">
                            </div>
                            <div class="form-group">
                                <label>Project Name *</label>
                                <input type="text" id="new-eng-project" placeholder="e.g., PKI Health Assessment Q4 2024" style="width: 100%;">
                            </div>
                            <div class="form-group">
                                <label>Description</label>
                                <textarea id="new-eng-description" rows="3" placeholder="Brief description of the engagement scope..." style="width: 100%;"></textarea>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                <div class="form-group">
                                    <label>Start Date</label>
                                    <input type="date" id="new-eng-start-date" style="width: 100%;">
                                </div>
                                <div class="form-group">
                                    <label>Lead Consultant</label>
                                    <input type="text" id="new-eng-consultant" placeholder="e.g., John Smith" style="width: 100%;">
                                </div>
                            </div>
                        </div>
                        <div id="engagement-deployment-section" style="display: none; padding: 20px; border-top: 1px solid var(--border-color); background: var(--content-bg); max-height: 400px; overflow-y: auto;">
                            <h4 style="margin-top: 0; margin-bottom: 16px;">Deployment Progress</h4>
                            <div id="deployment-steps-container" style="display: flex; flex-direction: column; gap: 8px;"></div>
                            <div style="margin-top: 16px; height: 3px; background: var(--border-color); border-radius: 2px; overflow: hidden;">
                                <div id="deployment-progress" style="width: 0%; height: 100%; background: var(--success); transition: width 0.3s ease;"></div>
                            </div>
                            <div id="deployment-summary" style="margin-top: 10px; font-size: 12px; color: var(--text-secondary); text-align: center; font-weight: 500;"></div>
                        </div>
                        <div class="modal-footer">
                            <button id="new-eng-cancel-btn" class="btn-secondary" onclick="closeModal('new-engagement-modal')">Cancel</button>
                            <button id="new-eng-create-btn" class="btn-primary" onclick="createEngagement()">Create Engagement</button>
                            <button id="new-eng-close-btn" class="btn-secondary" onclick="closeModal('new-engagement-modal')" style="display: none;">Close</button>
                        </div>
                    </div>
                `;
                document.body.appendChild(modal);
            }

            // Reset form and hide deployment section
            document.getElementById('new-eng-customer').value = '';
            document.getElementById('new-eng-project').value = '';
            document.getElementById('new-eng-description').value = '';
            document.getElementById('new-eng-start-date').value = new Date().toISOString().split('T')[0];
            document.getElementById('new-eng-consultant').value = '';
            document.getElementById('engagement-deployment-section').style.display = 'none';
            document.getElementById('new-eng-cancel-btn').style.display = 'block';
            document.getElementById('new-eng-create-btn').style.display = 'block';
            document.getElementById('new-eng-close-btn').style.display = 'none';
            document.getElementById('deployment-progress').style.width = '0%';
            document.getElementById('deployment-summary').textContent = '';

            modal.style.display = 'flex';
        }

        function renderDeploymentSteps() {
            const container = document.getElementById('deployment-steps-container');
            container.innerHTML = `
                <div class="workflow-step" data-step-id="engagement_record" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">1</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">Engagement Record</div>
                        <div class="workflow-step-desc" id="desc-engagement_record" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="ca_key_gen" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">2</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">CA Key Generation</div>
                        <div class="workflow-step-desc" id="desc-ca_key_gen" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="ca_cert_sign" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">3</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">CA Certificate Signing</div>
                        <div class="workflow-step-desc" id="desc-ca_cert_sign" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="ca_vault_store" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">4</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">CA Vault Storage</div>
                        <div class="workflow-step-desc" id="desc-ca_vault_store" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="ca_db_record" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">5</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">CA Database Record</div>
                        <div class="workflow-step-desc" id="desc-ca_db_record" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="signing_cert_create" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">6</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">Report Signing Cert</div>
                        <div class="workflow-step-desc" id="desc-signing_cert_create" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="signing_vault_store" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">7</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">Signing Key Vault Storage</div>
                        <div class="workflow-step-desc" id="desc-signing_vault_store" style="font-size: 12px;"></div>
                    </div>
                </div>
                <div class="workflow-step" data-step-id="signing_db_record" style="margin-bottom: 4px; padding: 12px 16px;">
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">8</div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">Signing Cert Database</div>
                        <div class="workflow-step-desc" id="desc-signing_db_record" style="font-size: 12px;"></div>
                    </div>
                </div>
            `;
        }

        function replayDeploymentSteps(steps, onComplete) {
            const stepElements = document.querySelectorAll('[data-step-id]');
            let completedCount = 0;
            const totalSteps = steps.length;

            steps.forEach((step, index) => {
                setTimeout(() => {
                    const stepEl = Array.from(stepElements).find(el => el.getAttribute('data-step-id') === step.id);
                    if (!stepEl) return;

                    // Remove pending state and add appropriate status class
                    stepEl.classList.remove('active');
                    stepEl.classList.add(step.status === 'success' ? 'completed' : step.status === 'failed' ? 'failed' : step.status === 'warning' ? 'warning' : 'skipped');

                    // Update step number circle with symbol
                    const numberEl = stepEl.querySelector('.workflow-step-number');
                    if (step.status === 'success') {
                        numberEl.innerHTML = '<svg style="width: 18px; height: 18px; fill: currentColor;" viewBox="0 0 20 20"><path d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"/></svg>';
                    } else if (step.status === 'failed') {
                        numberEl.textContent = '✗';
                    } else if (step.status === 'warning') {
                        numberEl.textContent = '⚠';
                    } else {
                        numberEl.textContent = '—';
                    }

                    // Update detail text
                    const descEl = stepEl.querySelector('.workflow-step-desc');
                    if (step.detail) {
                        descEl.textContent = step.detail;
                    } else if (step.error) {
                        descEl.textContent = `Error: ${step.error}`;
                    }

                    // Update progress bar
                    completedCount++;
                    const progress = (completedCount / totalSteps) * 100;
                    document.getElementById('deployment-progress').style.width = progress + '%';

                    // Update summary
                    const summary = `${completedCount} of ${totalSteps} steps completed`;
                    document.getElementById('deployment-summary').textContent = summary;

                    // After last step, call onComplete
                    if (index === steps.length - 1) {
                        const hasFailure = steps.some(s => s.status === 'failed');
                        document.getElementById('deployment-close-btn').disabled = false;
                        if (onComplete) {
                            onComplete(!hasFailure);
                        }
                    }
                }, 300 * (index + 1));
            });
        }

        async function createEngagement() {
            const customer = document.getElementById('new-eng-customer').value.trim();
            const project = document.getElementById('new-eng-project').value.trim();
            const description = document.getElementById('new-eng-description').value.trim();
            const startDate = document.getElementById('new-eng-start-date').value;
            const consultant = document.getElementById('new-eng-consultant').value.trim();

            if (!customer) {
                showAlert('Customer name is required.', 'error');
                return;
            }
            if (!project) {
                showAlert('Project name is required.', 'error');
                return;
            }

            // Transition modal to deployment view
            document.getElementById('engagement-deployment-section').style.display = 'block';
            document.getElementById('new-eng-cancel-btn').style.display = 'none';
            document.getElementById('new-eng-create-btn').style.display = 'none';
            document.getElementById('new-eng-close-btn').style.display = 'block';

            // Render deployment steps in the modal
            renderDeploymentSteps();

            try {
                const response = await fetch('/api/v1/engagements', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        customer_name: customer,
                        project_name: project,
                        description: description || null,
                        start_date: startDate || null,
                        lead_consultant: consultant || null
                    })
                });

                const result = await response.json();

                // Replay deployment steps from response
                const steps = result.steps || [];
                replayDeploymentSteps(steps, (success) => {
                    if (success) {
                        showAlert(`Engagement ${result.engagement_id} created successfully.`, 'success');
                        loadEngagements();
                        loadEngagementsForContext();  // Refresh the working engagement dropdown
                    } else {
                        showAlert(`Engagement creation failed: ${result.error || 'Unknown error'}`, 'error');
                    }
                });

            } catch (error) {
                showAlert(`Failed to create engagement: ${error.message}`, 'error');
            }
        }
        
        async function viewEngagement(engagementId) {
            try {
                // Fetch engagement details and associated items in parallel
                const [engagementRes, associatedRes] = await Promise.all([
                    fetch(`/api/v1/engagements/${engagementId}`),
                    fetch(`/api/v1/engagements/${engagementId}/associated-items`)
                ]);
                
                if (!engagementRes.ok) throw new Error('Failed to load engagement');
                
                const engagement = await engagementRes.json();
                const associatedItems = associatedRes.ok ? await associatedRes.json() : null;
                
                openEngagementDetailModal(engagement, associatedItems);
                
            } catch (error) {
                
                showAlert('Failed to load engagement details.', 'error');
            }
        }
        
        function openEngagementDetailModal(engagement, associatedItems = null) {
            let modal = document.getElementById('engagement-detail-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'engagement-detail-modal';
                modal.className = 'modal';
                document.body.appendChild(modal);
            }
            
            const reports = engagement.reports || {scans: [], reassessments: [], aggregations: [], document_assessments: []};
            const summaries = engagement.executive_summaries || [];
            
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 1200px; max-height: 90vh; overflow-y: auto; margin: auto;">
                    <div class="modal-header">
                        <h3 style="display: flex; align-items: center; gap: 12px;">
                            <span style="background: #7c3aed; color: white; padding: 4px 10px; border-radius: 6px; font-size: 14px;">${escapeHtml(engagement.engagement_id)}</span>
                            ${escapeHtml(engagement.project_name)}
                        </h3>
                        <button class="close-btn" onclick="closeModal('engagement-detail-modal')">&times;</button>
                    </div>
                    <div class="modal-body" style="padding: 0;">
                        <!-- Engagement Info Bar -->
                        <div class="engagement-info-bar">
                            <div>
                                <div class="engagement-info-item-label">Customer</div>
                                <div class="engagement-info-item-value">${escapeHtml(engagement.customer_name)}</div>
                            </div>
                            <div>
                                <div class="engagement-info-item-label">Status</div>
                                <div class="engagement-info-item-value">${engagement.status}</div>
                            </div>
                            <div>
                                <div class="engagement-info-item-label">Start Date</div>
                                <div class="engagement-info-item-value">${engagement.start_date || 'N/A'}</div>
                            </div>
                            ${engagement.lead_consultant ? `
                            <div>
                                <div class="engagement-info-item-label">Lead Consultant</div>
                                <div class="engagement-info-item-value">${escapeHtml(engagement.lead_consultant)}</div>
                            </div>
                            ` : ''}
                        </div>
                        
                        <!-- Tab Navigation -->
                        <div class="engagement-tab-nav">
                            <button class="eng-detail-tab active" data-tab="associated" onclick="switchEngagementTab('associated')">
                                📁 Associated Items (${associatedItems ? associatedItems.total_reports : 0})
                            </button>
                            <button class="eng-detail-tab" data-tab="reports" onclick="switchEngagementTab('reports')">
                                📎 Linked Reports (${(reports.scans?.length || 0) + (reports.reassessments?.length || 0) + (reports.aggregations?.length || 0) + (reports.document_assessments?.length || 0)})
                            </button>
                            <button class="eng-detail-tab" data-tab="assessment" onclick="switchEngagementTab('assessment')">
                                📋 PQC Business Context
                            </button>
                            <button class="eng-detail-tab" data-tab="summaries" onclick="switchEngagementTab('summaries')">
                                📊 Executive Summaries (${summaries.length})
                            </button>
                            <button class="eng-detail-tab" data-tab="exports" onclick="switchEngagementTab('exports')">
                                📤 Exports
                            </button>
                        </div>
                        
                        <!-- Tab Content: Associated Items -->
                        <div id="eng-tab-associated" class="eng-tab-content" style="display: block; padding: 20px;">
                            ${renderAssociatedItemsTab(associatedItems, engagement.engagement_id)}
                        </div>
                        
                        <!-- Tab Content: Reports -->
                        <div id="eng-tab-reports" class="eng-tab-content" style="display: none; padding: 20px;">
                            ${engagement.description ? `
                            <div class="engagement-description-box">
                                <div class="engagement-description-label">Description</div>
                                <div class="engagement-description-text">${escapeHtml(engagement.description)}</div>
                            </div>
                            ` : ''}

                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                                <h4 style="margin: 0; font-size: 16px;">Linked Reports</h4>
                                <button class="btn-small btn-primary" onclick="openAddReportModal('${engagement.engagement_id}')">+ Add Report</button>
                            </div>

                            ${(() => {
                                const totalReports = (reports.scans?.length || 0) + (reports.reassessments?.length || 0) +
                                                    (reports.aggregations?.length || 0) + (reports.document_assessments?.length || 0);

                                if (totalReports === 0) {
                                    return `
                                        <div class="assessment-empty-state">
                                            <div class="assessment-empty-state-icon">📄</div>
                                            No reports linked yet. Add crypto scans or document assessments to this engagement.
                                        </div>
                                    `;
                                }

                                let html = '';

                                // Summary cards
                                html += `
                                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px;">
                                        <div style="text-align: center; padding: 12px; background: #dbeafe; border-radius: 8px;">
                                            <div style="font-size: 20px; font-weight: 700; color: #1e40af;">${reports.scans?.length || 0}</div>
                                            <div style="font-size: 11px; color: #1e40af; font-weight: 600;">Scans</div>
                                        </div>
                                        <div style="text-align: center; padding: 12px; background: #fce7f3; border-radius: 8px;">
                                            <div style="font-size: 20px; font-weight: 700; color: #9d174d;">${reports.reassessments?.length || 0}</div>
                                            <div style="font-size: 11px; color: #9d174d; font-weight: 600;">Reassessments</div>
                                        </div>
                                        <div style="text-align: center; padding: 12px; background: #d1fae5; border-radius: 8px;">
                                            <div style="font-size: 20px; font-weight: 700; color: #065f46;">${reports.aggregations?.length || 0}</div>
                                            <div style="font-size: 11px; color: #065f46; font-weight: 600;">Aggregations</div>
                                        </div>
                                        <div style="text-align: center; padding: 12px; background: #fef3c7; border-radius: 8px;">
                                            <div style="font-size: 20px; font-weight: 700; color: #92400e;">${reports.document_assessments?.length || 0}</div>
                                            <div style="font-size: 11px; color: #92400e; font-weight: 600;">Doc Assessments</div>
                                        </div>
                                    </div>
                                `;

                                // Scans section
                                if (reports.scans && reports.scans.length > 0) {
                                    html += `
                                        <div style="margin-bottom: 20px;">
                                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #1e40af;">🔬 Scans</h4>
                                            <table style="margin: 0;">
                                                <thead>
                                                    <tr>
                                                        <th>Name</th>
                                                        <th>Status</th>
                                                        <th>Last Run</th>
                                                        <th>Runs Available</th>
                                                        <th style="text-align: right;">Actions</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    ${reports.scans.map(s => `
                                                        <tr>
                                                            <td><strong>${escapeHtml(s.name)}</strong></td>
                                                            <td><span class="status-badge status-${(s.status || 'unknown').toLowerCase().replace(' ', '-')}">${s.status || 'Unknown'}</span></td>
                                                            <td>${s.last_run ? new Date(s.last_run).toLocaleString() : 'Never'}</td>
                                                            <td>
                                                                ${s.runs && s.runs.length > 1 ? `
                                                                    <select class="scan-run-selector" data-scan-id="${s.scan_id}" style="width: 100%; padding: 4px; font-size: 12px;">
                                                                        ${s.runs.map((run, idx) => `
                                                                            <option value="${run.run_number}">
                                                                                Run ${run.run_number} (${run.timestamp ? new Date(run.timestamp).toLocaleDateString() : 'N/A'})
                                                                            </option>
                                                                        `).join('')}
                                                                    </select>
                                                                ` : `Latest run`}
                                                            </td>
                                                            <td style="text-align: right; white-space: nowrap;">
                                                                ${s.report_path ? `<button class="btn-small" style="margin-right: 4px;" onclick="viewReport(${s.scan_id})">View Report</button>` : ''}
                                                                <button class="btn-small" style="background: #7c3aed; color: white; margin-right: 4px;" onclick="openReportEnrichModal('${engagement.engagement_id}', 'scan', ${s.report_reference_id}, '${escapeHtml(s.name)}')" title="Import context enrichment">🏷️ Enrich</button>
                                                                <button class="btn-small" style="background: #ef4444; color: white;" onclick="removeReportFromEngagement('${engagement.engagement_id}', 'scan', ${s.report_reference_id})">Remove</button>
                                                            </td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    `;
                                }

                                // Reassessments section
                                if (reports.reassessments && reports.reassessments.length > 0) {
                                    html += `
                                        <div style="margin-bottom: 20px;">
                                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #9d174d;">📋 Reassessments</h4>
                                            <table style="margin: 0;">
                                                <thead>
                                                    <tr>
                                                        <th>Name</th>
                                                        <th>Status</th>
                                                        <th>Created</th>
                                                        <th style="text-align: right;">Actions</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    ${reports.reassessments.map(r => `
                                                        <tr>
                                                            <td><strong>${escapeHtml(r.name)}</strong></td>
                                                            <td><span class="status-badge status-${(r.status || 'unknown').toLowerCase().replace(' ', '-')}">${r.status || 'Unknown'}</span></td>
                                                            <td>${r.created_at ? new Date(r.created_at).toLocaleString() : 'N/A'}</td>
                                                            <td style="text-align: right; white-space: nowrap;">
                                                                ${r.report_path ? `<button class="btn-small" style="margin-right: 4px;" onclick="viewReassessmentReport(${r.reassessment_id})">View Report</button>` : ''}
                                                                <button class="btn-small" style="background: #ef4444; color: white;" onclick="removeReportFromEngagement('${engagement.engagement_id}', 'reassessment', ${r.report_reference_id})">Remove</button>
                                                            </td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    `;
                                }

                                // Aggregations section
                                if (reports.aggregations && reports.aggregations.length > 0) {
                                    html += `
                                        <div style="margin-bottom: 20px;">
                                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #065f46;">📊 Aggregations</h4>
                                            <table style="margin: 0;">
                                                <thead>
                                                    <tr>
                                                        <th>Name</th>
                                                        <th>Status</th>
                                                        <th>Created</th>
                                                        <th style="text-align: right;">Actions</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    ${reports.aggregations.map(a => `
                                                        <tr>
                                                            <td><strong>${escapeHtml(a.name)}</strong></td>
                                                            <td><span class="status-badge status-${(a.status || 'unknown').toLowerCase().replace(' ', '-')}">${a.status || 'Unknown'}</span></td>
                                                            <td>${a.created_at ? new Date(a.created_at).toLocaleString() : 'N/A'}</td>
                                                            <td style="text-align: right; white-space: nowrap;">
                                                                ${a.report_path ? `<button class="btn-small" style="margin-right: 4px;" onclick="viewAggregationReport(${a.aggregation_id})">View Report</button>` : ''}
                                                                <button class="btn-small" style="background: #ef4444; color: white;" onclick="removeReportFromEngagement('${engagement.engagement_id}', 'aggregation', ${a.report_reference_id})">Remove</button>
                                                            </td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    `;
                                }

                                // Document Assessments section
                                if (reports.document_assessments && reports.document_assessments.length > 0) {
                                    html += `
                                        <div style="margin-bottom: 20px;">
                                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #92400e;">📄 Document Assessments</h4>
                                            <table style="margin: 0;">
                                                <thead>
                                                    <tr>
                                                        <th>Filename</th>
                                                        <th>Type</th>
                                                        <th>Coverage</th>
                                                        <th>Created</th>
                                                        <th style="text-align: right;">Actions</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    ${reports.document_assessments.map(d => `
                                                        <tr>
                                                            <td><strong>${escapeHtml(d.filename)}</strong></td>
                                                            <td><span class="badge badge-info">${escapeHtml(d.document_type || 'Unknown')}</span></td>
                                                            <td>${(d.coverage_score || 0).toFixed(1)}%</td>
                                                            <td>${d.created_at ? new Date(d.created_at).toLocaleString() : 'N/A'}</td>
                                                            <td style="text-align: right; white-space: nowrap;">
                                                                <button class="btn-small" style="margin-right: 4px;" onclick="viewDocumentAssessment('${d.assessment_id}')">View</button>
                                                                <button class="btn-small" style="background: #ef4444; color: white;" onclick="removeReportFromEngagement('${engagement.engagement_id}', 'document_assessment', ${d.report_reference_id})">Remove</button>
                                                            </td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    `;
                                }

                                return html;
                            })()}
                        </div>
                        
                        <!-- Tab Content: Assessment -->
                        <div id="eng-tab-assessment" class="eng-tab-content" style="display: none; padding: 20px;">
                            <div id="assessment-loading" class="assessment-loading">
                                <div class="assessment-loading-icon">⏳</div>
                                Loading assessment data...
                            </div>
                            <div id="assessment-content" style="display: none;"></div>
                        </div>
                        
                        <!-- Tab Content: Executive Summaries -->
                        <div id="eng-tab-summaries" class="eng-tab-content" style="display: none; padding: 20px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                                <h4 style="margin: 0; font-size: 16px;">Executive Summaries</h4>
                                <button class="btn-small btn-primary" onclick="openReportSelectionModal('${engagement.engagement_id}')" ${reports.length === 0 ? 'disabled title="Add reports first"' : ''} style="padding: 8px 16px; font-size: 12px;">
                                    ➕ Create Executive Report
                                </button>
                            </div>
                            
                            ${summaries.length === 0 ? `
                                <div class="assessment-empty-state">
                                    <div class="assessment-empty-state-icon">📑</div>
                                    No executive summaries generated yet. Add reports and generate a summary.
                                </div>
                            ` : `
                                <table style="margin: 0;">
                                    <thead>
                                        <tr>
                                            <th>Version</th>
                                            <th>Name</th>
                                            <th>Reports Included</th>
                                            <th>Generated</th>
                                            <th style="text-align: right;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${summaries.map(s => `
                                            <tr>
                                                <td><span style="background: #7c3aed; color: white; padding: 2px 10px; border-radius: 10px; font-size: 12px; font-weight: 700;">v${s.version}</span></td>
                                                <td>${escapeHtml(s.report_name || 'Executive Summary')}</td>
                                                <td><span style="background: #e0e7ff; color: #3730a3; padding: 2px 8px; border-radius: 10px; font-size: 12px;">${(s.included_reports || []).length} reports</span></td>
                                                <td>${formatDate(s.generated_at)}</td>
                                                <td style="text-align: right;">
                                                    <button class="btn-small" onclick="downloadEngagementSummary('${engagement.engagement_id}', ${s.id}, 'pdf')" style="padding: 4px 8px; font-size: 11px;">📄 PDF</button>
                                                    <button class="btn-small" onclick="downloadEngagementSummary('${engagement.engagement_id}', ${s.id}, 'docx')" style="padding: 4px 8px; font-size: 11px;">📝 DOCX</button>
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            `}
                        </div>
                        
                        <!-- Tab Content: Exports -->
                        <div id="eng-tab-exports" class="eng-tab-content" style="display: none; padding: 20px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                                <h4 style="margin: 0; font-size: 16px;">Export Options</h4>
                            </div>
                            
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
                                <!-- CBOM Export Card -->
                                <div style="border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; background: #f9fafb;">
                                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
                                        <span style="font-size: 24px;">📋</span>
                                        <div>
                                            <div style="font-weight: 600; font-size: 14px;">CycloneDX CBOM</div>
                                            <div style="font-size: 12px; color: #6b7280;">Cryptographic Bill of Materials</div>
                                        </div>
                                    </div>
                                    <p style="font-size: 13px; color: #4b5563; margin: 0 0 12px 0;">
                                        Export all cryptographic assets (certificates, keys, algorithms) in CycloneDX 1.6 format for supply chain security tools.
                                    </p>
                                    <div style="display: flex; gap: 8px;">
                                        <button class="btn-primary" style="flex: 1; padding: 8px 12px; font-size: 13px;" 
                                            onclick="exportEngagementCBOM('${engagement.engagement_id}', 'download')"
                                            ${associatedItems && associatedItems.scan_count > 0 ? '' : 'disabled title="No scans associated"'}>
                                            ⬇️ Download JSON
                                        </button>
                                        <button class="btn-secondary" style="padding: 8px 12px; font-size: 13px;" 
                                            onclick="exportEngagementCBOM('${engagement.engagement_id}', 'preview')"
                                            ${associatedItems && associatedItems.scan_count > 0 ? '' : 'disabled'}>
                                            👁️ Preview
                                        </button>
                                    </div>
                                </div>
                                
                                <!-- Future: SPDX Export Card (placeholder) -->
                                <div style="border: 1px dashed #d1d5db; border-radius: 8px; padding: 16px; background: #f9fafb; opacity: 0.6;">
                                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
                                        <span style="font-size: 24px;">📦</span>
                                        <div>
                                            <div style="font-weight: 600; font-size: 14px;">SPDX Export</div>
                                            <div style="font-size: 12px; color: #6b7280;">Coming Soon</div>
                                        </div>
                                    </div>
                                    <p style="font-size: 13px; color: #9ca3af; margin: 0 0 12px 0;">
                                        Export in SPDX format for additional toolchain compatibility.
                                    </p>
                                    <button class="btn-secondary" style="width: 100%; padding: 8px 12px; font-size: 13px;" disabled>
                                        Not Available
                                    </button>
                                </div>
                            </div>
                            
                            ${associatedItems && associatedItems.scan_count === 0 ? `
                            <div style="margin-top: 16px; padding: 12px; background: #fef3c7; border-radius: 6px; font-size: 13px; color: #92400e;">
                                ⚠️ No crypto scans associated with this engagement. Add scans to enable CBOM export.
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn-danger" onclick="deleteEngagement('${engagement.engagement_id}')" style="margin-right: auto;">
                            🗑️ Delete Engagement
                        </button>
                        <button class="btn-secondary" onclick="generateEngagementPackage('${engagement.engagement_id}')" ${reports.length === 0 && summaries.length === 0 ? 'disabled' : ''}>
                            📦 Download Report Package (ZIP)
                        </button>
                        <button class="btn-primary" onclick="closeModal('engagement-detail-modal')">Close</button>
                    </div>
                </div>
            `;
            
            // Store engagement ID for assessment functions
            modal.dataset.engagementId = engagement.engagement_id;

            modal.style.display = 'flex';

            // Initialize report inclusion checkboxes (selective aggregation)
            setTimeout(() => initReportCheckboxListeners(), 100);
        }
        
        function renderAssociatedItemsTab(items, engagementId) {
            if (!items) {
                return `
                    <div class="assessment-empty-state">
                        <div class="assessment-empty-state-icon">⏳</div>
                        Loading associated items...
                    </div>
                `;
            }
            
            const totalItems = (items.scan_count || 0) + (items.configuration_count || 0) + 
                              (items.reassessment_count || 0) + (items.aggregation_count || 0) + 
                              (items.document_assessment_count || 0);
            
            if (totalItems === 0) {
                return `
                    <div class="assessment-empty-state">
                        <div class="assessment-empty-state-icon">📂</div>
                        <p>No items directly associated with this engagement yet.</p>
                        <p style="font-size: 13px; color: var(--text-muted);">
                            Create scans, configurations, or assessments while this engagement is selected in the context bar to automatically associate them.
                        </p>
                    </div>
                `;
            }
            
            let html = `
                <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px;">
                    <div style="text-align: center; padding: 12px; background: #dbeafe; border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: #1e40af;">${items.scan_count || 0}</div>
                        <div style="font-size: 11px; color: #1e40af;">Scans</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: #f3e8ff; border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: #7c3aed;">${items.configuration_count || 0}</div>
                        <div style="font-size: 11px; color: #7c3aed;">Configurations</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: #fce7f3; border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: #9d174d;">${items.reassessment_count || 0}</div>
                        <div style="font-size: 11px; color: #9d174d;">Reassessments</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: #d1fae5; border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: #065f46;">${items.aggregation_count || 0}</div>
                        <div style="font-size: 11px; color: #065f46;">Aggregations</div>
                    </div>
                    <div style="text-align: center; padding: 12px; background: #fef3c7; border-radius: 8px;">
                        <div style="font-size: 24px; font-weight: 700; color: #92400e;">${items.document_assessment_count || 0}</div>
                        <div style="font-size: 11px; color: #92400e;">Doc Assessments</div>
                    </div>
                </div>
            `;
            
            // Scans section
            if (items.scans && items.scans.length > 0) {
                html += `
                    <div style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #1e40af;">🔬 Scans</h4>
                        <table style="margin: 0;">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Status</th>
                                    <th>Last Run</th>
                                    <th style="text-align: right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${items.scans.map(s => `
                                    <tr>
                                        <td><strong>${escapeHtml(s.name)}</strong></td>
                                        <td><span class="status-badge status-${(s.status || 'never-run').toLowerCase().replace(' ', '-')}">${s.status || 'Never Run'}</span></td>
                                        <td>${s.last_run ? new Date(s.last_run).toLocaleString() : 'Never'}</td>
                                        <td style="text-align: right;">
                                            ${s.report_path ? `<button class="btn-small" onclick="viewReport(${s.id})">View Report</button>` : ''}
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            // Reassessments section
            if (items.reassessments && items.reassessments.length > 0) {
                html += `
                    <div style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #9d174d;">📋 Reassessments</h4>
                        <table style="margin: 0;">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th style="text-align: right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${items.reassessments.map(r => `
                                    <tr>
                                        <td><strong>${escapeHtml(r.name)}</strong></td>
                                        <td><span class="status-badge status-${(r.status || 'completed').toLowerCase()}">${r.status || 'Completed'}</span></td>
                                        <td>${new Date(r.created_at).toLocaleString()}</td>
                                        <td style="text-align: right;">
                                            <button class="btn-small" onclick="viewReassessmentReport(${r.id})">View Report</button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            // Aggregations section
            if (items.aggregations && items.aggregations.length > 0) {
                html += `
                    <div style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #065f46;">📊 Aggregations</h4>
                        <table style="margin: 0;">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th style="text-align: right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${items.aggregations.map(a => `
                                    <tr>
                                        <td><strong>${escapeHtml(a.name)}</strong></td>
                                        <td><span class="status-badge status-${(a.status || 'completed').toLowerCase()}">${a.status || 'Completed'}</span></td>
                                        <td>${new Date(a.created_at).toLocaleString()}</td>
                                        <td style="text-align: right;">
                                            <button class="btn-small" onclick="viewAggregationReport(${a.id})">View Report</button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            // Document Assessments section
            if (items.document_assessments && items.document_assessments.length > 0) {
                html += `
                    <div style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #92400e;">📄 Document Assessments</h4>
                        <table style="margin: 0;">
                            <thead>
                                <tr>
                                    <th>Filename</th>
                                    <th>Type</th>
                                    <th>Coverage</th>
                                    <th>Created</th>
                                    <th style="text-align: right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${items.document_assessments.map(d => `
                                    <tr>
                                        <td><strong>${escapeHtml(d.filename)}</strong></td>
                                        <td><span class="badge badge-info">${escapeHtml(d.document_type || 'Unknown')}</span></td>
                                        <td>${(d.coverage_score || 0).toFixed(1)}%</td>
                                        <td>${new Date(d.created_at).toLocaleString()}</td>
                                        <td style="text-align: right;">
                                            <button class="btn-small" onclick="viewDocumentAssessment('${d.assessment_id}')">View</button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            // Configurations section (collapsed by default as less important)
            if (items.configurations && items.configurations.length > 0) {
                html += `
                    <div style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #7c3aed;">⚙️ Configurations</h4>
                        <table style="margin: 0;">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Created</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${items.configurations.map(c => `
                                    <tr>
                                        <td><strong>${escapeHtml(c.name)}</strong></td>
                                        <td>${new Date(c.created_at).toLocaleString()}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            return html;
        }

        function switchEngagementTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.eng-detail-tab').forEach(tab => {
                tab.classList.toggle('active', tab.dataset.tab === tabName);
            });
            
            // Update tab content
            document.querySelectorAll('.eng-tab-content').forEach(content => {
                content.style.display = 'none';
            });
            document.getElementById(`eng-tab-${tabName}`).style.display = 'block';
            
            // Load assessment data if switching to assessment tab
            if (tabName === 'assessment') {
                const modal = document.getElementById('engagement-detail-modal');
                const engagementId = modal.dataset.engagementId;
                loadAssessmentTab(engagementId);
            }
        }
        
        async function loadAssessmentTab(engagementId) {
            const loadingEl = document.getElementById('assessment-loading');
            const contentEl = document.getElementById('assessment-content');
            
            loadingEl.style.display = 'block';
            contentEl.style.display = 'none';
            
            try {
                // Fetch schema and current data in parallel
                const [schemaRes, dataRes] = await Promise.all([
                    fetch('/api/v1/assessment/schema'),
                    fetch(`/api/v1/engagements/${engagementId}/assessment`)
                ]);
                
                if (!schemaRes.ok || !dataRes.ok) {
                    throw new Error('Failed to load assessment data');
                }
                
                const schema = await schemaRes.json();
                const assessment = await dataRes.json();
                
                // Store in window for form handlers
                window.currentAssessmentSchema = schema;
                window.currentAssessmentData = assessment.assessment_data || {};
                window.currentEngagementId = engagementId;
                
                // Render the assessment form
                renderAssessmentForm(schema, assessment);
                
                loadingEl.style.display = 'none';
                contentEl.style.display = 'block';
                
            } catch (error) {
                
                loadingEl.innerHTML = `
                    <div class="assessment-error">
                        <div class="assessment-error-icon">⚠️</div>
                        Failed to load assessment data. ${error.message}
                    </div>
                `;
            }
        }
        
        function renderAssessmentForm(schema, assessment) {
            const contentEl = document.getElementById('assessment-content');
            const data = assessment.assessment_data || {};
            const score = assessment.computed_score;
            const blockers = assessment.blockers || [];
            
            let html = `
                <!-- Score Panel -->
                <div class="assessment-score-panel">
                    <div class="assessment-score-title">ASSESSMENT SCORE MODIFIER</div>
                    <div class="assessment-score-value">${score ? (score.total_modifier >= 0 ? '+' : '') + score.total_modifier : '--'}</div>
                    ${score ? `
                    <div class="assessment-score-breakdown">
                        <div class="assessment-score-item">
                            <div class="assessment-score-item-label">Organisational</div>
                            <div class="assessment-score-item-value">${score.organisational_modifier >= 0 ? '+' : ''}${score.organisational_modifier}</div>
                        </div>
                        <div class="assessment-score-item">
                            <div class="assessment-score-item-label">Technology</div>
                            <div class="assessment-score-item-value">${score.technology_modifier >= 0 ? '+' : ''}${score.technology_modifier}</div>
                        </div>
                        <div class="assessment-score-item">
                            <div class="assessment-score-item-label">Vendor</div>
                            <div class="assessment-score-item-value">${score.vendor_modifier >= 0 ? '+' : ''}${score.vendor_modifier}</div>
                        </div>
                    </div>
                    ` : '<div style="font-size: 12px; opacity: 0.8; margin-top: 8px;">Complete assessment to calculate score</div>'}
                </div>
                
                <!-- Blockers -->
                ${blockers.length > 0 ? `
                <div style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 12px 0; color: #ef4444;">⚠️ ${blockers.length} Blocker${blockers.length > 1 ? 's' : ''} Detected</h4>
                    ${blockers.map(b => `
                        <div class="blocker-card ${b.severity}">
                            <div class="blocker-name">${escapeHtml(b.name)}</div>
                            <div class="blocker-message">${escapeHtml(b.message)}</div>
                            <div class="blocker-recommendation">💡 ${escapeHtml(b.recommendation)}</div>
                        </div>
                    `).join('')}
                </div>
                ` : ''}
                
                <!-- Assessment Form -->
                <form id="assessment-form" onsubmit="saveAssessment(event)">
            `;
            
            // Render each domain
            schema.domains.forEach(domain => {
                html += `
                    <div class="assessment-domain">
                        <div class="assessment-domain-header" onclick="toggleDomain('${domain.id}')">
                            <div>
                                <div class="assessment-domain-title">${escapeHtml(domain.name)}</div>
                                <div class="assessment-domain-desc">${escapeHtml(domain.description)}</div>
                            </div>
                            <span id="domain-toggle-${domain.id}">▼</span>
                        </div>
                        <div class="assessment-domain-body" id="domain-body-${domain.id}">
                `;
                
                domain.questions.forEach(q => {
                    html += renderAssessmentQuestion(q, data[q.id]);
                });
                
                html += `
                        </div>
                    </div>
                `;
            });
            
            html += `
                    <div style="display: flex; justify-content: space-between; margin-top: 20px;">
                        <button type="button" class="btn-secondary" onclick="previewAssessmentScore()">
                            🔄 Preview Score
                        </button>
                        <button type="submit" class="btn-primary">
                            💾 Save Assessment
                        </button>
                    </div>
                </form>
            `;
            
            // Score Audit Trail
            if (score && score.score_factors && Object.keys(score.score_factors).length > 0) {
                html += `
                    <div class="assessment-audit-trail">
                        <h4>📊 Score Audit Trail</h4>
                        <div class="assessment-audit-trail-items">
                            ${Object.entries(score.score_factors).map(([key, value]) => `
                                <div class="assessment-audit-trail-item">
                                    <strong>${key}:</strong> ${escapeHtml(String(value))}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            
            contentEl.innerHTML = html;
        }
        
        function renderAssessmentQuestion(question, currentValue) {
            let inputHtml = '';
            
            switch (question.response_type) {
                case 'select':
                    inputHtml = `
                        <select name="${question.id}" onchange="markAssessmentChanged()">
                            <option value="">-- Select --</option>
                            ${question.options.map(opt => `
                                <option value="${opt}" ${currentValue === opt ? 'selected' : ''}>${opt}</option>
                            `).join('')}
                        </select>
                    `;
                    break;
                    
                case 'number':
                    inputHtml = `
                        <input type="number" name="${question.id}" 
                               value="${currentValue || ''}" 
                               min="${question.min || 0}" 
                               max="${question.max || 9999}"
                               placeholder="${question.unit || ''}"
                               onchange="markAssessmentChanged()">
                        ${question.unit ? `<span style="margin-left: 8px; color: #64748b; font-size: 13px;">${question.unit}</span>` : ''}
                    `;
                    break;
                    
                case 'structured_list':
                    const listItems = Array.isArray(currentValue) ? currentValue : [];
                    inputHtml = `
                        <div class="structured-list-container" id="list-${question.id}">
                            ${listItems.map((item, idx) => renderStructuredListItem(question, item, idx)).join('')}
                            <button type="button" class="structured-list-add" onclick="addStructuredListItem('${question.id}')">
                                + Add Entry
                            </button>
                        </div>
                    `;
                    break;
                    
                case 'select_with_count':
                    const swcValue = typeof currentValue === 'object' ? currentValue : { answer: null, count: 0 };
                    inputHtml = `
                        <div style="display: flex; gap: 12px; align-items: center;">
                            <select name="${question.id}_answer" onchange="markAssessmentChanged()">
                                <option value="">-- Select --</option>
                                ${question.options.map(opt => `
                                    <option value="${opt}" ${swcValue.answer === opt ? 'selected' : ''}>${opt}</option>
                                `).join('')}
                            </select>
                            <div style="display: flex; align-items: center; gap: 6px;">
                                <label style="font-size: 13px; color: #64748b;">Count:</label>
                                <input type="number" name="${question.id}_count" 
                                       value="${swcValue.count || 0}" min="0" style="width: 80px;"
                                       onchange="markAssessmentChanged()">
                            </div>
                        </div>
                    `;
                    break;
                    
                case 'vendor_timeline':
                    const vtValue = typeof currentValue === 'object' ? currentValue : {};
                    inputHtml = `
                        <div class="vendor-timeline-fields">
                            <div>
                                <label>Vendor Name</label>
                                <input type="text" name="${question.id}_vendor" 
                                       value="${escapeHtml(vtValue.vendor_name || '')}"
                                       placeholder="e.g., DigiCert, Entrust"
                                       onchange="markAssessmentChanged()">
                            </div>
                            <div>
                                <label>PQC Ready Date</label>
                                <input type="date" name="${question.id}_date" 
                                       value="${vtValue.pqc_date || ''}"
                                       onchange="markAssessmentChanged()">
                            </div>
                            <div>
                                <label>Confidence</label>
                                <select name="${question.id}_confidence" onchange="markAssessmentChanged()">
                                    <option value="">-- Select --</option>
                                    ${question.confidence_options.map(opt => `
                                        <option value="${opt}" ${vtValue.confidence === opt ? 'selected' : ''}>${opt}</option>
                                    `).join('')}
                                </select>
                            </div>
                        </div>
                    `;
                    break;
                    
                case 'compliance_deadline':
                    const cdValue = typeof currentValue === 'object' ? currentValue : {};
                    inputHtml = `
                        <div style="display: flex; gap: 12px;">
                            <div style="flex: 1;">
                                <label style="font-size: 11px; color: #64748b; display: block; margin-bottom: 4px;">Regulation</label>
                                <select name="${question.id}_regulation" onchange="markAssessmentChanged()">
                                    <option value="">-- Select --</option>
                                    ${question.regulation_options.map(opt => `
                                        <option value="${opt}" ${cdValue.regulation === opt ? 'selected' : ''}>${opt}</option>
                                    `).join('')}
                                </select>
                            </div>
                            <div style="flex: 1;">
                                <label style="font-size: 11px; color: #64748b; display: block; margin-bottom: 4px;">Deadline</label>
                                <input type="date" name="${question.id}_deadline" 
                                       value="${cdValue.deadline_date || ''}"
                                       onchange="markAssessmentChanged()">
                            </div>
                        </div>
                    `;
                    break;
                    
                default:
                    inputHtml = `<input type="text" name="${question.id}" value="${escapeHtml(currentValue || '')}" onchange="markAssessmentChanged()">`;
            }
            
            return `
                <div class="assessment-question">
                    <div class="assessment-question-id">${question.id}</div>
                    <div class="assessment-question-text">${escapeHtml(question.question)}</div>
                    <div class="assessment-input">${inputHtml}</div>
                </div>
            `;
        }
        
        function renderStructuredListItem(question, item, index) {
            const fields = question.list_fields || ['value'];
            return `
                <div class="structured-list-item" data-index="${index}">
                    ${fields.map(f => `
                        <input type="text" name="${question.id}_${index}_${f}" 
                               value="${escapeHtml((item && item[f]) || '')}"
                               placeholder="${f.replace('_', ' ')}"
                               onchange="markAssessmentChanged()">
                    `).join('')}
                    <button type="button" class="structured-list-remove" onclick="removeStructuredListItem('${question.id}', ${index})">×</button>
                </div>
            `;
        }
        
        function addStructuredListItem(questionId) {
            const container = document.getElementById(`list-${questionId}`);
            const items = container.querySelectorAll('.structured-list-item');
            const newIndex = items.length;
            
            const question = findQuestionById(questionId);
            if (!question) return;
            
            const newItemHtml = renderStructuredListItem(question, {}, newIndex);
            const addBtn = container.querySelector('.structured-list-add');
            addBtn.insertAdjacentHTML('beforebegin', newItemHtml);
            markAssessmentChanged();
        }
        
        function removeStructuredListItem(questionId, index) {
            const container = document.getElementById(`list-${questionId}`);
            const item = container.querySelector(`.structured-list-item[data-index="${index}"]`);
            if (item) {
                item.remove();
                markAssessmentChanged();
            }
        }
        
        function findQuestionById(questionId) {
            if (!window.currentAssessmentSchema) return null;
            for (const domain of window.currentAssessmentSchema.domains) {
                const q = domain.questions.find(q => q.id === questionId);
                if (q) return q;
            }
            return null;
        }
        
        function toggleDomain(domainId) {
            const body = document.getElementById(`domain-body-${domainId}`);
            const toggle = document.getElementById(`domain-toggle-${domainId}`);
            
            if (body.style.display === 'none') {
                body.style.display = 'block';
                toggle.textContent = '▼';
            } else {
                body.style.display = 'none';
                toggle.textContent = '▶';
            }
        }
        
        function markAssessmentChanged() {
            window.assessmentChanged = true;
        }
        
        function collectAssessmentData() {
            const form = document.getElementById('assessment-form');
            const formData = new FormData(form);
            const data = {};
            
            // Get schema for type information
            const schema = window.currentAssessmentSchema;
            if (!schema) return data;
            
            schema.domains.forEach(domain => {
                domain.questions.forEach(q => {
                    switch (q.response_type) {
                        case 'select':
                        case 'number':
                            const val = formData.get(q.id);
                            if (val) data[q.id] = q.response_type === 'number' ? parseInt(val) : val;
                            break;
                            
                        case 'select_with_count':
                            const answer = formData.get(`${q.id}_answer`);
                            const count = formData.get(`${q.id}_count`);
                            if (answer) {
                                data[q.id] = { answer, count: parseInt(count) || 0 };
                            }
                            break;
                            
                        case 'vendor_timeline':
                            const vendor = formData.get(`${q.id}_vendor`);
                            const date = formData.get(`${q.id}_date`);
                            const confidence = formData.get(`${q.id}_confidence`);
                            if (vendor || date || confidence) {
                                data[q.id] = { vendor_name: vendor, pqc_date: date, confidence };
                            }
                            break;
                            
                        case 'compliance_deadline':
                            const regulation = formData.get(`${q.id}_regulation`);
                            const deadline = formData.get(`${q.id}_deadline`);
                            if (regulation) {
                                data[q.id] = { regulation, deadline_date: deadline };
                            }
                            break;
                            
                        case 'structured_list':
                            const items = [];
                            const container = document.getElementById(`list-${q.id}`);
                            if (container) {
                                container.querySelectorAll('.structured-list-item').forEach((itemEl, idx) => {
                                    const itemData = {};
                                    let hasData = false;
                                    q.list_fields.forEach(f => {
                                        const input = itemEl.querySelector(`input[name="${q.id}_${idx}_${f}"]`);
                                        if (input && input.value) {
                                            itemData[f] = input.value;
                                            hasData = true;
                                        }
                                    });
                                    if (hasData) items.push(itemData);
                                });
                            }
                            if (items.length > 0) data[q.id] = items;
                            break;
                    }
                });
            });
            
            return data;
        }
        
        async function saveAssessment(event) {
            event.preventDefault();
            
            const engagementId = window.currentEngagementId;
            if (!engagementId) {
                showAlert('No engagement selected', 'error');
                return;
            }
            
            const assessmentData = collectAssessmentData();
            
            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}/assessment`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ assessment_data: assessmentData })
                });
                
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to save assessment');
                }
                
                const result = await response.json();
                
                showAlert('Assessment saved successfully', 'success');
                window.assessmentChanged = false;
                
                // Reload to show updated score
                loadAssessmentTab(engagementId);
                
            } catch (error) {
                
                showAlert(`Failed to save: ${error.message}`, 'error');
            }
        }
        
        async function previewAssessmentScore() {
            const assessmentData = collectAssessmentData();
            
            try {
                const response = await fetch('/api/v1/assessment/preview-score', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ assessment_data: assessmentData })
                });
                
                if (!response.ok) {
                    throw new Error('Failed to preview score');
                }
                
                const result = await response.json();
                
                // Update score panel
                const scorePanel = document.querySelector('.assessment-score-panel');
                if (scorePanel && result.score) {
                    const s = result.score;
                    scorePanel.innerHTML = `
                        <div class="assessment-score-title">ASSESSMENT SCORE MODIFIER (Preview)</div>
                        <div class="assessment-score-value">${s.total_modifier >= 0 ? '+' : ''}${s.total_modifier}</div>
                        <div class="assessment-score-breakdown">
                            <div class="assessment-score-item">
                                <div class="assessment-score-item-label">Organisational</div>
                                <div class="assessment-score-item-value">${s.organisational_modifier >= 0 ? '+' : ''}${s.organisational_modifier}</div>
                            </div>
                            <div class="assessment-score-item">
                                <div class="assessment-score-item-label">Technology</div>
                                <div class="assessment-score-item-value">${s.technology_modifier >= 0 ? '+' : ''}${s.technology_modifier}</div>
                            </div>
                            <div class="assessment-score-item">
                                <div class="assessment-score-item-label">Vendor</div>
                                <div class="assessment-score-item-value">${s.vendor_modifier >= 0 ? '+' : ''}${s.vendor_modifier}</div>
                            </div>
                        </div>
                    `;
                }
                
                // Show blockers if any
                if (result.blockers && result.blockers.length > 0) {
                    showAlert(`Preview: ${result.blockers.length} blocker(s) detected`, 'warning');
                }
                
            } catch (error) {
                
                showAlert('Failed to preview score', 'error');
            }
        }
        
        async function openAddReportModal(engagementId) {
            try {
                const response = await fetch('/api/v1/engagements/available-reports');
                if (!response.ok) throw new Error('Failed to load available reports');
                
                const available = await response.json();
                
                let modal = document.getElementById('add-report-modal');
                if (!modal) {
                    modal = document.createElement('div');
                    modal.id = 'add-report-modal';
                    modal.className = 'modal';
                    document.body.appendChild(modal);
                }
                
                modal.innerHTML = `
                    <div class="modal-content" style="max-width: 650px; margin: auto;">
                        <div class="modal-header">
                            <h3>Add Report to Engagement</h3>
                            <button class="close-btn" onclick="closeModal('add-report-modal')">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="form-group">
                                <label>Report Type *</label>
                                <select id="add-report-type" onchange="updateAvailableReports()" style="width: 100%;">
                                    <option value="">-- Select Type --</option>
                                    <option value="scan">Crypto Asset Scan</option>
                                    <option value="reassessment">Re-Assessment</option>
                                    <option value="aggregation">Aggregation</option>
                                    <option value="document_assessment">Document Assessment</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Select Report *</label>
                                <select id="add-report-select" style="width: 100%;">
                                    <option value="">-- Select a report type first --</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                    <input type="checkbox" id="add-report-include-exec" checked style="width: 18px; height: 18px;">
                                    Include in Executive Summary generation
                                </label>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button class="btn-secondary" onclick="closeModal('add-report-modal')">Cancel</button>
                            <button class="btn-primary" onclick="addReportToEngagement('${engagementId}')">Add Report</button>
                        </div>
                    </div>
                `;
                
                window._availableReports = available;
                window._currentEngagementId = engagementId;
                modal.style.display = 'flex';
                modal.style.alignItems = 'center';
                modal.style.justifyContent = 'center';
                
            } catch (error) {
                
                showAlert('Failed to load available reports.', 'error');
            }
        }
        
        function updateAvailableReports() {
            const type = document.getElementById('add-report-type').value;
            const select = document.getElementById('add-report-select');
            const available = window._availableReports || {};
            
            let reports = [];
            if (type === 'scan') reports = available.scans || [];
            else if (type === 'reassessment') reports = available.reassessments || [];
            else if (type === 'aggregation') reports = available.aggregations || [];
            else if (type === 'document_assessment') reports = available.document_assessments || [];
            
            if (reports.length === 0) {
                select.innerHTML = '<option value="">-- No reports available of this type --</option>';
                return;
            }
            
            select.innerHTML = '<option value="">-- Select a report --</option>' +
                reports.map(r => {
                    const name = r.name || r.filename || `Report #${r.id}`;
                    const date = r.last_run || r.created_at || '';
                    return `<option value="${r.id}" data-name="${escapeHtml(name)}" data-path="${r.report_path || ''}">${escapeHtml(name)}${date ? ` (${formatDate(date)})` : ''}</option>`;
                }).join('');
        }
        
        async function addReportToEngagement(engagementId) {
            const type = document.getElementById('add-report-type').value;
            const select = document.getElementById('add-report-select');
            const reportId = select.value;
            const includeExec = document.getElementById('add-report-include-exec').checked;
            
            if (!type || !reportId) {
                showAlert('Please select a report type and report.', 'error');
                return;
            }
            
            const selectedOption = select.options[select.selectedIndex];
            const reportName = selectedOption.dataset.name || `Report #${reportId}`;
            const reportPath = selectedOption.dataset.path || null;
            
            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}/reports`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        report_type: type,
                        report_reference_id: parseInt(reportId),
                        report_name: reportName,
                        report_path: reportPath,
                        include_in_executive: includeExec
                    })
                });
                
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to add report');
                }
                
                showAlert('Report added to engagement.', 'success');
                closeModal('add-report-modal');
                viewEngagement(engagementId);
                
            } catch (error) {
                
                showAlert(`Failed to add report: ${error.message}`, 'error');
            }
        }
        
        async function removeReportFromEngagement(engagementId, reportType, reportRefId) {
            if (!confirm('Remove this report from the engagement?')) return;
            
            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}/reports/${reportType}/${reportRefId}`, {
                    method: 'DELETE'
                });
                
                if (!response.ok) throw new Error('Failed to remove report');
                
                showAlert('Report removed from engagement.', 'success');
                viewEngagement(engagementId);
                loadEngagements();
                
            } catch (error) {
                
                showAlert('Failed to remove report.', 'error');
            }
        }
        
        // Initialize report checkbox event listeners after DOM is ready
        function initReportCheckboxListeners() {
            document.querySelectorAll('.report-inclusion-checkbox').forEach(checkbox => {
                checkbox.addEventListener('change', async (e) => {
                    const reportId = parseInt(e.target.getAttribute('data-report-id'));
                    const engagementId = e.target.getAttribute('data-engagement-id');

                    // Disable checkbox during API call
                    e.target.disabled = true;
                    const originalState = e.target.checked;

                    try {
                        const response = await fetch(
                            `/api/v1/engagements/${engagementId}/reports/${reportId}/toggle-inclusion`,
                            { method: 'PUT', headers: { 'Content-Type': 'application/json' } }
                        );

                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}`);
                        }

                        const result = await response.json();

                        if (result.success) {
                            e.target.checked = result.include_in_executive === 1;
                            const action = result.include_in_executive === 1 ? 'included' : 'excluded';
                            showAlert(`Report ${action} in executive summary`, 'success');
                        } else {
                            throw new Error(result.error || 'Unknown error');
                        }

                    } catch (error) {
                        console.error('Error toggling report inclusion:', error);
                        e.target.checked = originalState;
                        showAlert(`Error updating report: ${error.message}`, 'error');

                    } finally {
                        e.target.disabled = false;
                    }
                });
            });
        }

        async function toggleReportInclusion(engagementId, reportType, reportRefId, include) {
            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}/reports/${reportType}/${reportRefId}/inclusion`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ include_in_executive: include })
                });

                if (!response.ok) throw new Error('Failed to update');

            } catch (error) {

                showAlert('Failed to update report inclusion.', 'error');
            }
        }
        
        /**
         * Open modal to select reports for executive summary
         * Allows selecting 1 scan/aggregation report + multiple document reports
         */
        async function openReportSelectionModal(engagementId) {
            try {
                // Fetch engagement with reports
                const engagementRes = await fetch(`/api/v1/engagements/${engagementId}`);
                if (!engagementRes.ok) throw new Error('Failed to load engagement');

                const engagement = await engagementRes.json();
                const linkedReports = engagement.reports || {scans: [], reassessments: [], aggregations: [], document_assessments: []};

                // Get scan IDs from linked reports
                const linkedScanIds = new Set(
                    (linkedReports.scans || [])
                        .map(r => r.report_reference_id)
                );
                const linkedAggregationIds = new Set(
                    (linkedReports.aggregations || [])
                        .map(r => r.report_reference_id)
                );

                // Fetch all available reports from the system (pass engagement_id to filter documents)
                let allReports = { scans: [], reassessments: [], aggregations: [], document_assessments: [] };

                try {
                    // Fetch reports linked to this engagement (documents filtered by engagement_id)
                    const availableRes = await fetch(`/api/v1/engagements/available-reports?engagement_id=${encodeURIComponent(engagementId)}`);
                    if (availableRes.ok) {
                        allReports = await availableRes.json();
                    } else {
                        throw new Error(`API returned status ${availableRes.status}`);
                    }
                } catch (e) {
                    console.warn('Could not fetch available reports:', e);
                    showAlert('⚠️ Could not load available reports. Some reports may not appear.', 'warning');
                }

                // Filter to only show linked scans with actual reports + show their runs
                const scanReports = allReports.scans
                    .filter(s => linkedScanIds.has(s.id) && s.report_path)
                    .map(s => ({
                        ...s,
                        report_name: s.name,
                        report_type: 'scan',
                        report_reference_id: s.id,
                        id: `scan_${s.id}`,
                        _data: s,
                        runs: s.runs || [] // Include run history
                    }));

                const aggregationReports = allReports.aggregations
                    .filter(a => linkedAggregationIds.has(a.id))
                    .map(a => ({
                        ...a,
                        report_name: a.name,
                        report_type: 'aggregation',
                        report_reference_id: a.id,
                        id: `aggregation_${a.id}`,
                        _data: a
                    }));

                // Get reassessment IDs from linked reports
                const linkedReassessmentIds = new Set(
                    (linkedReports.reassessments || [])
                        .map(r => r.report_reference_id)
                );

                const reassessmentReports = allReports.reassessments
                    .filter(r => linkedReassessmentIds.has(r.id))
                    .map(r => ({
                        ...r,
                        report_name: r.name,
                        report_type: 'reassessment',
                        report_reference_id: r.id,
                        id: `reassessment_${r.id}`,
                        _data: r
                    }));

                const allScanAggReports = [...scanReports, ...aggregationReports, ...reassessmentReports];

                // Document assessments - already filtered to only those linked to engagement
                const docReports = allReports.document_assessments
                    .map(d => ({
                        ...d,
                        report_name: d.filename || `Doc Assessment - ${d.assessment_id}`,
                        report_type: 'document_assessment',
                        report_reference_id: d.id,
                        id: `doc_${d.id}`,
                        _data: d
                    }));

                if (allScanAggReports.length === 0 && docReports.length === 0) {
                    showAlert('No reports available', 'error');
                    return;
                }

                // Create modal
                let modal = document.getElementById('report-selection-modal');
                if (!modal) {
                    modal = document.createElement('div');
                    modal.id = 'report-selection-modal';
                    modal.className = 'modal';
                    document.body.appendChild(modal);
                }

                modal.innerHTML = `
                    <div class="modal-content" style="max-width: 600px; max-height: 80vh; overflow-y: auto; margin: auto;">
                        <div class="modal-header">
                            <h3>Create Executive Report - Select Reports</h3>
                            <button class="close-btn" onclick="closeModal('report-selection-modal')">&times;</button>
                        </div>
                        <div class="modal-body" style="padding: 20px;">

                            <!-- Report Name Input -->
                            <div style="margin-bottom: 20px;">
                                <label style="display: block; font-weight: 600; margin-bottom: 8px;">Report Name (Optional)</label>
                                <input type="text" id="exec-report-name" placeholder="e.g., Executive Summary - Q1 2026"
                                       style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px;">
                            </div>

                            <!-- Select Format -->
                            <div style="margin-bottom: 20px;">
                                <label style="display: block; font-weight: 600; margin-bottom: 8px;">Export Format</label>
                                <div style="display: flex; gap: 10px;">
                                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                        <input type="radio" name="exec-format" value="pdf" checked>
                                        📄 PDF
                                    </label>
                                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                        <input type="radio" name="exec-format" value="docx">
                                        📝 DOCX
                                    </label>
                                </div>
                            </div>

                            <!-- Report Type Filter -->
                            <div style="margin-bottom: 20px;">
                                <label style="display: block; font-weight: 600; margin-bottom: 8px;">Report Type Filter</label>
                                <select id="report-type-filter" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; background-color: white;">
                                    <option value="all">All Types (Scan, Aggregation, Reassessment)</option>
                                    <option value="scan">Scans Only</option>
                                    <option value="aggregation">Aggregations Only</option>
                                    <option value="reassessment">Reassessments Only</option>
                                </select>
                            </div>

                            <!-- Crypto Asset Reports (Select One) -->
                            <div style="margin-bottom: 20px;">
                                <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #1e40af;">Select One Scan, Aggregation or Reassessment Report</label>
                                <div style="border: 1px solid #ddd; border-radius: 4px; padding: 12px; background: #f9f9f9;">
                                    ${allScanAggReports.length === 0 ? `
                                        <p style="color: #999; margin: 0;">No scan or aggregation reports available</p>
                                    ` : `
                                        ${allScanAggReports.map(r => `
                                            <div style="margin-bottom: 12px; padding: 8px; border: 1px solid #e0e0e0; border-radius: 4px; background: #fafafa;">
                                                <!-- Main radio button -->
                                                <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; margin-bottom: ${r.runs && r.runs.length > 0 ? '8px' : '0'};">
                                                    <input type="radio" name="scan-report" value="${r.id}" data-report-type="${r.report_type}" data-ref-id="${r.report_reference_id}">
                                                    <span style="flex: 1;">
                                                        <strong>${escapeHtml(r.report_name)}</strong>
                                                        <span style="color: #666; font-size: 12px; margin-left: 8px;">(${r.report_type})</span>
                                                        ${r._data?.status ? `<span style="color: #999; font-size: 11px; margin-left: 8px;">Status: ${r._data.status}</span>` : ''}
                                                    </span>
                                                </label>

                                                <!-- Dropdown for scan runs (if available) -->
                                                ${r.runs && r.runs.length > 1 ? `
                                                    <div style="margin-left: 28px; padding-top: 4px;">
                                                        <select class="scan-run-selector" data-scan-id="${r.id}" style="width: 100%; padding: 6px; font-size: 12px; border: 1px solid #ccc; border-radius: 3px; background: white;">
                                                            <option value="">-- Select a specific run --</option>
                                                            ${r.runs.map((run, idx) => `
                                                                <option value="${run.run_number}" ${idx === 0 ? 'selected' : ''}>
                                                                    Run ${run.run_number}${run.timestamp ? ' (' + new Date(run.timestamp).toLocaleDateString() + ')' : ''}
                                                                </option>
                                                            `).join('')}
                                                        </select>
                                                    </div>
                                                ` : ''}

                                                <!-- Last run date -->
                                                ${r._data?.last_run ? `
                                                    <div style="margin-left: 28px; color: #666; font-size: 11px; margin-top: 4px;">
                                                        Latest run: ${new Date(r._data.last_run).toLocaleDateString()}
                                                    </div>
                                                ` : ''}
                                            </div>
                                        `).join('')}
                                    `}
                                </div>
                            </div>

                            <!-- Document Assessment Reports (Select Multiple) -->
                            <div style="margin-bottom: 20px;">
                                <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #065f46;">Select Document Assessment Reports (Optional)</label>
                                <div style="border: 1px solid #ddd; border-radius: 4px; padding: 12px; background: #f9f9f9;">
                                    ${docReports.length === 0 ? `
                                        <p style="color: #999; margin: 0;">No document assessments available</p>
                                    ` : `
                                        ${docReports.map(r => `
                                            <label style="display: flex; align-items: center; gap: 10px; padding: 8px; cursor: pointer; border-radius: 4px; margin-bottom: 8px;">
                                                <input type="checkbox" name="doc-report" value="${r.id}" data-report-type="document_assessment" data-ref-id="${r.report_reference_id}">
                                                <span style="flex: 1;">
                                                    <strong>${escapeHtml(r.report_name)}</strong>
                                                    ${r._data?.created_at ? `<span style="color: #666; font-size: 12px; margin-left: 8px;"> - ${new Date(r._data.created_at).toLocaleDateString()}</span>` : ''}
                                                </span>
                                            </label>
                                        `).join('')}
                                    `}
                                </div>
                            </div>

                            <!-- Action Buttons -->
                            <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
                                <button class="btn-small btn-secondary" onclick="closeModal('report-selection-modal')" style="padding: 8px 16px;">
                                    Cancel
                                </button>
                                <button class="btn-small btn-primary" onclick="generateEngagementExecSummaryFromModal('${engagementId}')" style="padding: 8px 16px;">
                                    ✓ Generate Report
                                </button>
                            </div>

                        </div>
                    </div>
                `;

                modal.style.display = 'flex';

                // Add filter functionality
                const filterSelect = document.getElementById('report-type-filter');
                if (filterSelect) {
                    filterSelect.addEventListener('change', function() {
                        const selectedType = this.value;
                        const reportLabels = modal.querySelectorAll('input[name="scan-report"]');

                        reportLabels.forEach(radio => {
                            const reportType = radio.getAttribute('data-report-type');
                            const parentDiv = radio.closest('div[style*="margin-bottom: 12px"]');

                            if (selectedType === 'all' || reportType === selectedType) {
                                parentDiv.style.display = '';
                            } else {
                                parentDiv.style.display = 'none';
                            }
                        });
                    });
                }

            } catch (error) {
                console.error('Error opening report selection modal:', error);
                showAlert(`Error: ${error.message}`, 'error');
            }
        }

        /**
         * Generate executive summary from the report selection modal
         */
        async function generateEngagementExecSummaryFromModal(engagementId) {
            try {
                // Get values from modal
                const reportName = document.getElementById('exec-report-name').value || null;
                const format = document.querySelector('input[name="exec-format"]:checked').value || 'pdf';

                // Get selected scan/aggregation report
                const scanReportElement = document.querySelector('input[name="scan-report"]:checked');
                if (!scanReportElement) {
                    showAlert('❌ Please select at least one scan or aggregation report', 'error');
                    return;
                }

                const scanReportId = scanReportElement.value;
                const scanReportType = scanReportElement.getAttribute('data-report-type');
                const scanRefId = scanReportElement.getAttribute('data-ref-id');

                // Get selected document reports
                const docReportElements = document.querySelectorAll('input[name="doc-report"]:checked');
                const docReportIds = Array.from(docReportElements).map(input => ({
                    id: input.value,
                    report_type: input.getAttribute('data-report-type'),
                    report_reference_id: input.getAttribute('data-ref-id')
                }));

                // Close modal
                closeModal('report-selection-modal');

                // Show generating message
                const formatLabel = format.toUpperCase();
                showAlert(`Generating executive summary (${formatLabel})... This may take a moment.`, 'info');

                // Call API to generate
                const response = await fetch(`/api/v1/engagements/${engagementId}/executive-summary`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        report_name: reportName,
                        format: format,
                        selected_reports: {
                            scan_report: {
                                id: scanReportId,
                                report_type: scanReportType,
                                report_reference_id: scanRefId
                            },
                            doc_reports: docReportIds
                        }
                    })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to generate summary');
                }

                const result = await response.json();
                showAlert(`Executive summary v${result.version} (${formatLabel}) generated successfully!`, 'success');
                viewEngagement(engagementId);

            } catch (error) {
                console.error('Error generating executive summary:', error);
                showAlert(`Failed to generate summary: ${error.message}`, 'error');
            }
        }

        async function generateEngagementExecSummary(engagementId, format = 'pdf') {
            // Legacy function - now redirects to modal
            openReportSelectionModal(engagementId);
        }
        
        function downloadEngagementSummary(engagementId, summaryId, format = 'pdf') {
            window.open(`/api/v1/engagements/${engagementId}/executive-summaries/${summaryId}/download?format=${format}`, '_blank');
        }
        
        /**
         * Export engagement cryptographic assets as CycloneDX CBOM
         */
        async function exportEngagementCBOM(engagementId, mode = 'download') {
            try {
                if (mode === 'preview') {
                    showAlert('Loading CBOM preview...', 'info');
                    
                    const response = await fetch(`/api/v1/reports/cbom/engagement/${engagementId}?format=json`);
                    
                    if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.error || 'Failed to generate CBOM');
                    }
                    
                    const cbom = await response.json();
                    
                    // Show preview in a modal
                    showCBOMPreviewModal(cbom, engagementId);
                    
                } else {
                    // Direct download
                    showAlert('Generating CBOM...', 'info');
                    window.open(`/api/v1/reports/cbom/engagement/${engagementId}?format=download`, '_blank');
                    showAlert('CBOM download started', 'success');
                }
                
            } catch (error) {
                
                showAlert(`CBOM export failed: ${error.message}`, 'error');
            }
        }
        
        /**
         * Show CBOM preview in a modal
         */
        function showCBOMPreviewModal(cbom, engagementId) {
            // Calculate summary stats
            const components = cbom.components || [];
            const certCount = components.filter(c => c.cryptoProperties?.assetType === 'certificate').length;
            const keyCount = components.filter(c => c.cryptoProperties?.assetType === 'related-crypto-material').length;
            const algoCount = components.filter(c => c.cryptoProperties?.assetType === 'algorithm').length;
            const protoCount = components.filter(c => c.cryptoProperties?.assetType === 'protocol').length;
            
            const modalHtml = `
                <div id="cbom-preview-modal" class="modal" style="display: flex; justify-content: center; align-items: center;">
                    <div class="modal-content" style="max-width: 900px; max-height: 85vh; display: flex; flex-direction: column;">
                        <div class="modal-header">
                            <h3>📋 CycloneDX CBOM Preview</h3>
                            <span class="modal-close" onclick="closeModal('cbom-preview-modal')">&times;</span>
                        </div>
                        <div class="modal-body" style="flex: 1; overflow: hidden; display: flex; flex-direction: column;">
                            <!-- Summary Stats -->
                            <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
                                <div style="background: #dbeafe; padding: 8px 16px; border-radius: 6px; text-align: center;">
                                    <div style="font-size: 20px; font-weight: 700; color: #1e40af;">${certCount}</div>
                                    <div style="font-size: 11px; color: #1e40af;">Certificates</div>
                                </div>
                                <div style="background: #d1fae5; padding: 8px 16px; border-radius: 6px; text-align: center;">
                                    <div style="font-size: 20px; font-weight: 700; color: #065f46;">${keyCount}</div>
                                    <div style="font-size: 11px; color: #065f46;">Keys</div>
                                </div>
                                <div style="background: #fef3c7; padding: 8px 16px; border-radius: 6px; text-align: center;">
                                    <div style="font-size: 20px; font-weight: 700; color: #92400e;">${algoCount}</div>
                                    <div style="font-size: 11px; color: #92400e;">Algorithms</div>
                                </div>
                                <div style="background: #e0e7ff; padding: 8px 16px; border-radius: 6px; text-align: center;">
                                    <div style="font-size: 20px; font-weight: 700; color: #3730a3;">${protoCount}</div>
                                    <div style="font-size: 11px; color: #3730a3;">Protocols</div>
                                </div>
                                <div style="background: #f3f4f6; padding: 8px 16px; border-radius: 6px; text-align: center;">
                                    <div style="font-size: 20px; font-weight: 700; color: #374151;">${components.length}</div>
                                    <div style="font-size: 11px; color: #374151;">Total Components</div>
                                </div>
                            </div>
                            
                            <!-- Metadata -->
                            <div style="background: #f9fafb; padding: 10px; border-radius: 6px; margin-bottom: 12px; font-size: 12px;">
                                <strong>Format:</strong> ${cbom.bomFormat} ${cbom.specVersion} &nbsp;|&nbsp;
                                <strong>Serial:</strong> ${cbom.serialNumber?.split(':').pop()?.substring(0, 8)}... &nbsp;|&nbsp;
                                <strong>Generated:</strong> ${cbom.metadata?.timestamp ? new Date(cbom.metadata.timestamp).toLocaleString() : 'N/A'}
                            </div>
                            
                            <!-- JSON Preview -->
                            <div style="flex: 1; overflow: auto; background: #1f2937; border-radius: 6px; padding: 12px;">
                                <pre style="margin: 0; color: #e5e7eb; font-size: 12px; font-family: 'Consolas', 'Monaco', monospace; white-space: pre-wrap;">${escapeHtml(JSON.stringify(cbom, null, 2))}</pre>
                            </div>
                        </div>
                        <div class="modal-footer" style="display: flex; justify-content: space-between;">
                            <button class="btn-secondary" onclick="copyCBOMToClipboard()">
                                📋 Copy to Clipboard
                            </button>
                            <div style="display: flex; gap: 8px;">
                                <button class="btn-primary" onclick="exportEngagementCBOM('${engagementId}', 'download'); closeModal('cbom-preview-modal');">
                                    ⬇️ Download JSON
                                </button>
                                <button class="btn-secondary" onclick="closeModal('cbom-preview-modal')">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Store CBOM for clipboard copy
            window._currentCBOM = cbom;
            
            // Remove existing modal if present
            const existing = document.getElementById('cbom-preview-modal');
            if (existing) existing.remove();
            
            // Add to document
            document.body.insertAdjacentHTML('beforeend', modalHtml);
        }
        
        /**
         * Copy current CBOM to clipboard
         */
        function copyCBOMToClipboard() {
            if (window._currentCBOM) {
                navigator.clipboard.writeText(JSON.stringify(window._currentCBOM, null, 2))
                    .then(() => showAlert('CBOM copied to clipboard', 'success'))
                    .catch(() => showAlert('Failed to copy to clipboard', 'error'));
            }
        }
        
        async function generateEngagementPackage(engagementId) {
            try {
                showAlert('Generating report package...', 'info');
                
                const response = await fetch(`/api/v1/engagements/${engagementId}/package`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ include_individual_reports: true })
                });
                
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to generate package');
                }
                
                showAlert('Report package generated. Starting download...', 'success');
                window.open(`/api/v1/engagements/${engagementId}/package/download`, '_blank');
                
            } catch (error) {
                
                showAlert(`Failed to generate package: ${error.message}`, 'error');
            }
        }
        
        async function editEngagement(engagementId) {
            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}`);
                if (!response.ok) throw new Error('Failed to load engagement');
                
                const engagement = await response.json();
                
                let modal = document.getElementById('edit-engagement-modal');
                if (!modal) {
                    modal = document.createElement('div');
                    modal.id = 'edit-engagement-modal';
                    modal.className = 'modal';
                    document.body.appendChild(modal);
                }
                
                modal.innerHTML = `
                    <div class="modal-content" style="max-width: 600px;">
                        <div class="modal-header">
                            <h3>Edit Engagement - ${escapeHtml(engagement.engagement_id)}</h3>
                            <button class="close-btn" onclick="closeModal('edit-engagement-modal')">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="form-group">
                                <label>Customer Name *</label>
                                <input type="text" id="edit-eng-customer" value="${escapeHtml(engagement.customer_name)}" style="width: 100%;">
                            </div>
                            <div class="form-group">
                                <label>Project Name *</label>
                                <input type="text" id="edit-eng-project" value="${escapeHtml(engagement.project_name)}" style="width: 100%;">
                            </div>
                            <div class="form-group">
                                <label>Description</label>
                                <textarea id="edit-eng-description" rows="3" style="width: 100%;">${escapeHtml(engagement.description || '')}</textarea>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                <div class="form-group">
                                    <label>Status</label>
                                    <select id="edit-eng-status" style="width: 100%;">
                                        <option value="Active" ${engagement.status === 'Active' ? 'selected' : ''}>Active</option>
                                        <option value="Completed" ${engagement.status === 'Completed' ? 'selected' : ''}>Completed</option>
                                        <option value="Archived" ${engagement.status === 'Archived' ? 'selected' : ''}>Archived</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Lead Consultant</label>
                                    <input type="text" id="edit-eng-consultant" value="${escapeHtml(engagement.lead_consultant || '')}" style="width: 100%;">
                                </div>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                <div class="form-group">
                                    <label>Start Date</label>
                                    <input type="date" id="edit-eng-start" value="${engagement.start_date || ''}" style="width: 100%;">
                                </div>
                                <div class="form-group">
                                    <label>End Date</label>
                                    <input type="date" id="edit-eng-end" value="${engagement.end_date || ''}" style="width: 100%;">
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button class="btn-secondary" onclick="closeModal('edit-engagement-modal')">Cancel</button>
                            <button class="btn-primary" onclick="saveEngagement('${engagementId}')">Save Changes</button>
                        </div>
                    </div>
                `;
                
                modal.style.display = 'flex';
                modal.style.alignItems = 'center';
                modal.style.justifyContent = 'center';
                
            } catch (error) {
                
                showAlert('Failed to load engagement for editing.', 'error');
            }
        }
        
        async function saveEngagement(engagementId) {
            const data = {
                customer_name: document.getElementById('edit-eng-customer').value.trim(),
                project_name: document.getElementById('edit-eng-project').value.trim(),
                description: document.getElementById('edit-eng-description').value.trim() || null,
                status: document.getElementById('edit-eng-status').value,
                lead_consultant: document.getElementById('edit-eng-consultant').value.trim() || null,
                start_date: document.getElementById('edit-eng-start').value || null,
                end_date: document.getElementById('edit-eng-end').value || null
            };
            
            if (!data.customer_name || !data.project_name) {
                showAlert('Customer name and project name are required.', 'error');
                return;
            }
            
            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to save');
                }
                
                showAlert('Engagement updated successfully.', 'success');
                closeModal('edit-engagement-modal');
                loadEngagements();
                
            } catch (error) {
                
                showAlert(`Failed to save: ${error.message}`, 'error');
            }
        }
        
        async function deleteEngagement(engagementId) {
            try {
                // Fetch engagement details and deletion preview in parallel
                const [engagementRes, previewRes] = await Promise.all([
                    fetch(`/api/v1/engagements/${engagementId}`),
                    fetch(`/api/v1/engagements/${engagementId}/deletion-preview`)
                ]);

                if (!engagementRes.ok || !previewRes.ok) {
                    throw new Error('Failed to load engagement');
                }

                const engagement = await engagementRes.json();
                const preview = await previewRes.json();

                // Open deletion modal with confirmation screen
                openEngagementDeletionModal(engagementId, engagement.customer_name, preview.preview);

            } catch (error) {
                showAlert(`Failed to load engagement: ${error.message}`, 'error');
            }
        }

        function openEngagementDeletionModal(engagementId, customerName, preview) {
            // Always remove old modal to ensure fresh state for new engagement
            let oldModal = document.getElementById('engagement-deletion-modal');
            if (oldModal) {
                oldModal.remove();
            }

            let modal = document.createElement('div');
            modal.id = 'engagement-deletion-modal';
            modal.className = 'modal';

            const totalRecords = Object.values(preview).reduce((sum, count) => sum + (count || 0), 0);

            modal.innerHTML = `
                <div class="modal-content" style="max-width: 600px; margin: auto;">

                    <div class="modal-header">
                        <h3>Delete Engagement</h3>
                        <button class="close-btn" onclick="closeModal('engagement-deletion-modal')">&times;</button>
                    </div>

                    <div class="modal-body">

                        <div id="deletion-confirmation-section" style="display: block;">
                            <div style="margin-bottom: 16px;">
                                <strong>You are about to permanently delete:</strong><br>
                                Engagement: <strong>${escapeHtml(engagementId)}</strong> (${escapeHtml(customerName)})
                            </div>

                            <div style="background: var(--content-bg); padding: 16px; border-radius: var(--radius); margin-bottom: 16px; max-height: 200px; overflow-y: auto;">
                                <strong style="font-size: 14px; display: block; margin-bottom: 8px;">This will cascade-delete:</strong>
                                <ul style="font-size: 12px; margin: 0; padding-left: 20px; color: var(--text-secondary); list-style: none;">
                                    <li>Scan Logs: <strong>${preview.scan_logs || 0}</strong> records</li>
                                    <li>Scans: <strong>${preview.scans || 0}</strong> records</li>
                                    <li>Configurations: <strong>${preview.configurations || 0}</strong> records</li>
                                    <li>Reassessments: <strong>${preview.reassessments || 0}</strong> records</li>
                                    <li>Report Aggregations: <strong>${preview.report_aggregations || 0}</strong> records</li>
                                    <li>Document Assessments: <strong>${preview.document_assessments || 0}</strong> records</li>
                                    <li>Executive Summaries: <strong>${preview.engagement_executive_summaries || 0}</strong> records</li>
                                    <li>Engagement Reports: <strong>${preview.engagement_reports || 0}</strong> records</li>
                                    <li>CA Certificates: <strong>${preview.engagement_ca_certificates || 0}</strong> records</li>
                                    <li>Report Signing Certs: <strong>${preview.report_signing_certificates || 0}</strong> records</li>
                                    <li>Dashboard Certificates: <strong>${preview.engagement_dashboard_certificates || 0}</strong> records</li>
                                    <li>Collector Certificates: <strong>${preview.collector_certificates || 0}</strong> records</li>
                                    <li>Certificate Audit Log: <strong>${preview.certificate_audit_log || 0}</strong> records</li>
                                    <li>Registration Requests: <strong>${preview.certificate_registration_requests || 0}</strong> records</li>
                                    <li>Revocation List: <strong>${preview.certificate_revocation_list || 0}</strong> records</li>
                                    <li>User Digital Identities: <strong>${preview.user_digital_identities || 0}</strong> records</li>
                                    <li><strong>${preview.vault_keys || 0}</strong> vault keys (non-recoverable)</li>
                                </ul>
                                <div style="margin-top: 12px; font-size: 12px; color: var(--danger); font-weight: 600;">
                                    Total: ${totalRecords} records
                                </div>
                            </div>

                            <div style="margin-bottom: 16px;">
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; font-weight: 600;">
                                    To confirm, type engagement ID:
                                </label>
                                <input
                                    id="deletion-confirm-input"
                                    type="text"
                                    placeholder="${engagementId}"
                                    style="width: 100%; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: var(--radius); font-family: monospace; font-size: 13px;"
                                    oninput="updateDeletionConfirmation()"
                                />
                            </div>

                            <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
                                <input
                                    id="deletion-acknowledge-checkbox"
                                    type="checkbox"
                                    onchange="updateDeletionConfirmation()"
                                />
                                <span>I understand this cannot be undone</span>
                            </label>
                        </div>

                        <div id="deletion-progress-section" style="display: none; max-height: 400px; overflow-y: auto;">
                            <div id="deletion-steps-container" style="display: flex; flex-direction: column; gap: 8px;"></div>
                            <div style="margin-top: 16px; height: 3px; background: var(--border-color); border-radius: 2px; overflow: hidden;">
                                    <div id="deletion-progress" style="width: 0%; height: 100%; background: var(--danger); transition: width 0.3s ease;"></div>
                                </div>
                                <div id="deletion-summary" style="margin-top: 10px; font-size: 12px; color: var(--text-secondary); text-align: center; font-weight: 500;"></div>
                            </div>

                        </div>

                        <div class="modal-footer">
                            <button id="del-cancel-btn" class="btn-secondary" onclick="closeModal('engagement-deletion-modal')">Cancel</button>
                            <button id="del-execute-btn" class="btn-danger" onclick="executeDeletionWithProgress('${engagementId}')" disabled style="opacity: 0.5; cursor: not-allowed;">Delete</button>
                            <button id="del-close-btn" class="btn-secondary" onclick="closeModal('engagement-deletion-modal')" style="display: none;">Close</button>
                        </div>

                    </div>
                `;
            document.body.appendChild(modal);

            // Initialize form state
            document.getElementById('deletion-confirm-input').value = '';
            document.getElementById('deletion-acknowledge-checkbox').checked = false;
            document.getElementById('deletion-confirmation-section').style.display = 'block';
            document.getElementById('deletion-progress-section').style.display = 'none';
            document.getElementById('del-cancel-btn').style.display = 'block';
            document.getElementById('del-execute-btn').style.display = 'block';
            document.getElementById('del-close-btn').style.display = 'none';
            document.getElementById('deletion-progress').style.width = '0%';
            document.getElementById('deletion-summary').textContent = '';
            updateDeletionConfirmation();

            modal.style.display = 'flex';
        }

        function updateDeletionConfirmation() {
            const input = document.getElementById('deletion-confirm-input');
            const checkbox = document.getElementById('deletion-acknowledge-checkbox');
            const button = document.getElementById('del-execute-btn');

            const inputMatches = input && input.value.trim() === input.placeholder;
            const isAcknowledged = checkbox && checkbox.checked;
            const isEnabled = inputMatches && isAcknowledged;

            if (button) {
                button.disabled = !isEnabled;
                button.style.opacity = isEnabled ? '1' : '0.5';
                button.style.cursor = isEnabled ? 'pointer' : 'not-allowed';
            }
        }

        async function executeDeletionWithProgress(engagementId) {
            // Hide confirmation section, show progress section
            document.getElementById('deletion-confirmation-section').style.display = 'none';
            document.getElementById('deletion-progress-section').style.display = 'block';
            document.getElementById('del-cancel-btn').style.display = 'none';
            document.getElementById('del-execute-btn').style.display = 'none';
            document.getElementById('del-close-btn').disabled = true;

            try {
                const response = await fetch(`/api/v1/engagements/${engagementId}`, {
                    method: 'DELETE'
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Deletion failed');
                }

                const data = await response.json();

                // Replay deletion steps from response
                replayDeletionSteps(data.steps || [], (success) => {
                    if (success) {
                        showAlert('Engagement deleted successfully.', 'success');
                        loadEngagements();
                        loadEngagementsForContext();
                        if (activeEngagementId === engagementId) {
                            setEngagementContext(null);
                        }
                    }
                    document.getElementById('del-close-btn').disabled = false;
                    document.getElementById('del-close-btn').style.display = 'block';
                });

            } catch (error) {
                showAlert(`Deletion failed: ${error.message}`, 'error');
                document.getElementById('del-close-btn').disabled = false;
                document.getElementById('del-close-btn').style.display = 'block';
            }
        }

        function replayDeletionSteps(steps, onComplete) {
            const container = document.getElementById('deletion-steps-container');
            const progressBar = document.getElementById('deletion-progress');
            const summaryDiv = document.getElementById('deletion-summary');

            // Pre-render all step elements
            steps.forEach((step, index) => {
                const stepDiv = document.createElement('div');
                stepDiv.className = 'workflow-step';
                stepDiv.setAttribute('data-step-id', step.id);
                stepDiv.style.marginBottom = '4px';
                stepDiv.style.padding = '12px 16px';

                stepDiv.innerHTML = `
                    <div class="workflow-step-number" style="width: 32px; height: 32px; min-width: 32px; font-size: 13px;">
                        ${index + 1}
                    </div>
                    <div class="workflow-step-content">
                        <div class="workflow-step-title" style="margin-bottom: 2px; font-size: 14px;">
                            ${step.label}
                        </div>
                        <div class="workflow-step-desc" style="font-size: 12px;">
                            <!-- Will be updated during replay -->
                        </div>
                    </div>
                `;
                container.appendChild(stepDiv);
            });

            // Replay with staggered timing
            let completedCount = 0;
            const totalSteps = steps.length;

            steps.forEach((step, index) => {
                setTimeout(() => {
                    const stepEl = container.querySelector(`[data-step-id="${step.id}"]`);
                    if (!stepEl) return;

                    // Update step element with status class
                    stepEl.classList.remove('active');

                    if (step.status === 'success') {
                        stepEl.classList.add('completed');
                        const numberEl = stepEl.querySelector('.workflow-step-number');
                        numberEl.innerHTML = '<svg style="width: 18px; height: 18px; fill: currentColor;" viewBox="0 0 20 20"><path d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"/></svg>';
                    } else if (step.status === 'failed') {
                        stepEl.classList.add('failed');
                        stepEl.querySelector('.workflow-step-number').textContent = '✗';
                    } else if (step.status === 'warning') {
                        stepEl.classList.add('warning');
                        stepEl.querySelector('.workflow-step-number').textContent = '⚠';
                    } else {
                        stepEl.classList.add('skipped');
                        stepEl.querySelector('.workflow-step-number').textContent = '—';
                    }

                    // Update description with count or error
                    const descEl = stepEl.querySelector('.workflow-step-desc');
                    if (step.status === 'success') {
                        descEl.textContent = `Deleted ${step.count} records`;
                    } else if (step.status === 'warning') {
                        descEl.textContent = `Warning: ${step.error}`;
                    } else if (step.status === 'failed') {
                        descEl.textContent = `Error: ${step.error}`;
                    }

                    // Update progress bar
                    completedCount++;
                    const progress = (completedCount / totalSteps) * 100;
                    progressBar.style.width = progress + '%';
                    summaryDiv.textContent = `${completedCount} of ${totalSteps} steps completed`;

                    // Call callback on last step
                    if (index === steps.length - 1) {
                        const hasFailure = steps.some(s => s.status === 'failed');
                        if (onComplete) {
                            onComplete(!hasFailure);
                        }
                    }
                }, 300 * (index + 1));  // 300ms staggered delay
            });
        }

        function openReportEnrichModal(engagementId, reportType, reportRefId, reportName) {
            let modal = document.getElementById('report-enrich-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'report-enrich-modal';
                modal.className = 'modal';
                document.body.appendChild(modal);
            }
            
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 550px;">
                    <div class="modal-header">
                        <h3 style="display: flex; align-items: center; gap: 8px;">
                            <span>🏷️</span> Import Context Enrichment
                        </h3>
                        <button class="close-btn" onclick="closeModal('report-enrich-modal')">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div style="background: #f8fafc; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px;">
                            <div style="font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">Report</div>
                            <div style="font-weight: 600;">${reportName}</div>
                        </div>
                        
                        <p style="font-size: 13px; color: #475569; margin-bottom: 16px;">
                            Select the context enrichment JSON file exported from the PQC report's Context Enrichment tab. 
                            This will import business context for all assets in this report.
                        </p>
                        
                        <div class="form-group">
                            <label>Context Enrichment File (.json)</label>
                            <input type="file" id="report-enrich-file" accept=".json" style="width: 100%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 6px;">
                        </div>
                        
                        <div id="report-enrich-status" style="margin-top: 12px; font-size: 13px;"></div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn-secondary" onclick="closeModal('report-enrich-modal')">Cancel</button>
                        <button class="btn-primary" onclick="importReportContext('${engagementId}')">📥 Import</button>
                    </div>
                </div>
            `;
            
            modal.style.display = 'flex';
            modal.style.alignItems = 'center';
            modal.style.justifyContent = 'center';
        }
        
        async function importReportContext(engagementId) {
            const fileInput = document.getElementById('report-enrich-file');
            const statusDiv = document.getElementById('report-enrich-status');
            
            if (!fileInput.files || fileInput.files.length === 0) {
                statusDiv.innerHTML = '<span style="color: #dc2626;">Please select a file first.</span>';
                return;
            }
            
            const file = fileInput.files[0];
            statusDiv.innerHTML = '<span style="color: #2563eb;">Importing...</span>';
            
            try {
                const text = await file.text();
                const importData = JSON.parse(text);
                
                if (importData.export_type !== 'caip_context_enrichment') {
                    statusDiv.innerHTML = '<span style="color: #dc2626;">Invalid file format. Please select a CAIP context enrichment export.</span>';
                    return;
                }
                
                const response = await fetch(`/api/v1/engagements/${engagementId}/context/import`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(importData)
                });
                
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Import failed');
                }
                
                const result = await response.json();
                statusDiv.innerHTML = `<span style="color: #16a34a;">✓ Success! Imported ${result.imported} assets. ${result.skipped} skipped.</span>`;
                
                setTimeout(() => {
                    closeModal('report-enrich-modal');
                    showAlert(`Context imported: ${result.imported} assets enriched.`, 'success');
                }, 1500);
                
            } catch (error) {
                
                statusDiv.innerHTML = `<span style="color: #dc2626;">Error: ${error.message}</span>`;
            }
        }
        
        // Helper: format date (use existing if available)
        if (typeof formatDate !== 'function') {
            function formatDate(dateStr) {
                if (!dateStr) return 'N/A';
                try {
                    const date = new Date(dateStr);
                    return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
                } catch {
                    return dateStr;
                }
            }
        }


        // ============================================================================
// COMMAND CENTER MODULE
// ============================================================================

let ccCharts = {};
let ccRefreshInterval = null;
let ccAttentionItems = [];

function initCommandCenter() {
    loadCommandCenterData();
    // Start auto-refresh every 60 seconds
    if (ccRefreshInterval) clearInterval(ccRefreshInterval);
    ccRefreshInterval = setInterval(loadCommandCenterData, 60000);
}

function refreshCommandCenter() {
    const btn = document.getElementById('cc-refresh-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span style="margin-right: 6px;">⏳</span>Refreshing...';
    }
    loadCommandCenterData().finally(() => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<span style="margin-right: 6px;">🔄</span>Refresh';
        }
    });
}

async function loadCommandCenterData() {
    try {
        // Fetch all data in parallel
        const [summaryRes, certsRes, keysRes, changesRes] = await Promise.all([
            fetch('/api/v1/inventory/summary'),
            fetch('/api/v1/inventory/certificates'),
            fetch('/api/v1/inventory/keys'),
            fetch('/api/v1/activity/feed?limit=30&since_days=7')
        ]);

        const summary = await summaryRes.json();
        const certsData = await certsRes.json();
        const keysData = await keysRes.json();
        const changesData = await changesRes.json();

        const certs = certsData.certificates || [];
        const keys = keysData.keys || [];

        // Update timestamp
        document.getElementById('cc-last-refresh').textContent =
            `Last refresh: ${new Date().toLocaleTimeString()}`;

        // Update summary cards
        updateCCSummaryCards(summary, certs, keys);

        // Update charts
        updateCCCharts(summary, certs, keys);

        // Update attention items
        updateCCAttentionItems(certs, keys);

        // Update activity feed - use unified feed if available, otherwise fall back
        if (changesData.grouped) {
            renderActivityFeed(changesData.grouped);
        } else {
            updateCCRecentChanges(changesData.changes || []);
        }

    } catch (error) {
        
    }
}

function updateCCSummaryCards(summary, certs, keys) {
    document.getElementById('cc-total-certs').textContent = summary.total_certificates || 0;
    document.getElementById('cc-total-keys').textContent = summary.total_keys || 0;

    // Calculate critical issues (expired + weak algorithms)
    const expiry = summary.certificate_expiry || {};
    const expired = expiry.expired || 0;
    
    // Count weak algorithms (RSA < 2048, 3DES, etc.)
    let weakAlgos = 0;
    certs.forEach(cert => {
        const algo = cert.public_key_algorithm || '';
        const size = cert.public_key_size || 0;
        if (algo.includes('RSA') && size < 2048) weakAlgos++;
        if (algo.includes('3DES') || algo.includes('DES')) weakAlgos++;
        if (algo.includes('MD5') || algo.includes('SHA1')) weakAlgos++;
    });
    
    document.getElementById('cc-critical-issues').textContent = expired + weakAlgos;

    // Calculate PQC readiness
    const pqcStats = calculatePQCStats(certs, keys);
    const totalAssets = pqcStats.ready + pqcStats.hybrid + pqcStats.needsMigration + pqcStats.unknown;
    const readinessPercent = totalAssets > 0 
        ? Math.round(((pqcStats.ready + pqcStats.hybrid) / totalAssets) * 100) 
        : 0;
    
    document.getElementById('cc-pqc-readiness').textContent = `${readinessPercent}%`;
    document.getElementById('cc-pqc-summary').textContent = 
        `${pqcStats.ready + pqcStats.hybrid} of ${totalAssets} assets ready`;
    
    // Update PQC breakdown
    document.getElementById('cc-pqc-ready').textContent = pqcStats.ready;
    document.getElementById('cc-pqc-hybrid').textContent = pqcStats.hybrid;
    document.getElementById('cc-pqc-needs-migration').textContent = pqcStats.needsMigration;
    document.getElementById('cc-pqc-unknown').textContent = pqcStats.unknown;
}

function calculatePQCStats(certs, keys) {
    let ready = 0, hybrid = 0, needsMigration = 0, unknown = 0;

    certs.forEach(cert => {
        // Check both top-level and nested pqc_analysis fields
        const pqc = cert.pqc_analysis || {};
        const status = (cert.migration_status || pqc.migration_status || '').toLowerCase();
        const isPqc = cert.is_pqc || pqc.is_pqc;
        const isHybrid = cert.is_hybrid || pqc.is_hybrid;
        
        if (isPqc && !isHybrid) {
            ready++;
        } else if (isHybrid) {
            hybrid++;
        } else if (status === 'pqc_ready' || status === 'ready') {
            ready++;
        } else if (status === 'hybrid' || status === 'hybrid_transition') {
            hybrid++;
        } else if (status === 'needs_migration' || status === 'vulnerable') {
            needsMigration++;
        } else if (status === 'unknown' || status === '') {
            unknown++;
        } else {
            // Default to needs_migration for unrecognised statuses
            needsMigration++;
        }
    });

    keys.forEach(key => {
        // Check both top-level and nested pqc_analysis fields
        const pqc = key.pqc_analysis || {};
        const status = (key.migration_status || pqc.migration_status || '').toLowerCase();
        const isPqc = key.is_pqc || pqc.is_pqc;
        const isHybrid = key.is_hybrid || pqc.is_hybrid;
        const vulnLevel = (pqc.vulnerability_level || '').toLowerCase();
        const algoClass = (pqc.algorithm_class || '').toLowerCase();
        
        if (isPqc && !isHybrid) {
            ready++;
        } else if (isHybrid) {
            hybrid++;
        } else if (status === 'pqc_ready' || status === 'ready') {
            // This handles AES-256, AES-192, and other PQC-safe symmetric algorithms
            ready++;
        } else if (status === 'hybrid' || status === 'hybrid_transition') {
            hybrid++;
        } else if (status === 'needs_migration' || status === 'vulnerable') {
            needsMigration++;
        } else if (status === 'unknown' || status === '') {
            // For unknown status, check vulnerability level as fallback
            // Symmetric keys with 'none' or 'low' vulnerability are PQC-safe
            if (algoClass === 'symmetric' && (vulnLevel === 'none' || vulnLevel === 'low')) {
                ready++;
            } else if (algoClass === 'hash' && (vulnLevel === 'none' || vulnLevel === 'low')) {
                ready++;
            } else {
                unknown++;
            }
        } else {
            // Default to needs_migration for unrecognised statuses
            needsMigration++;
        }
    });

    return { ready, hybrid, needsMigration, unknown };
}

function updateCCCharts(summary, certs, keys) {
    // Certificate Health Donut
    const expiry = summary.certificate_expiry || {};
    const healthy = (expiry.expiring_90_days || 0) + (expiry.valid || 0);
    const expiringSoon = (expiry.expiring_7_days || 0) + (expiry.expiring_30_days || 0);
    const expired = expiry.expired || 0;

    createOrUpdateDonutChart('cc-cert-health-chart', 'ccCertHealth', 
        ['Healthy', 'Expiring Soon', 'Expired'],
        [healthy, expiringSoon, expired],
        ['#22c55e', '#f59e0b', '#ef4444']
    );

    // Key Health Donut
    let keysActive = 0, keysExpiring = 0, keysDisabled = 0;
    keys.forEach(key => {
        if (key.is_enabled === false) keysDisabled++;
        else if (key.days_until_expiration !== null && key.days_until_expiration <= 30) keysExpiring++;
        else keysActive++;
    });
    
    createOrUpdateDonutChart('cc-key-health-chart', 'ccKeyHealth',
        ['Active', 'Expiring', 'Disabled'],
        [keysActive, keysExpiring, keysDisabled],
        ['#22c55e', '#f59e0b', '#94a3b8']
    );

    // PQC Status Donut
    const pqcStats = calculatePQCStats(certs, keys);
    createOrUpdateDonutChart('cc-pqc-status-chart', 'ccPqcStatus',
        ['PQC Ready', 'Hybrid', 'Needs Migration', 'Unknown'],
        [pqcStats.ready, pqcStats.hybrid, pqcStats.needsMigration, pqcStats.unknown],
        ['#22c55e', '#6366f1', '#f59e0b', '#94a3b8']
    );

    // Source Distribution Donut
    const sourceMap = {};
    (summary.certificates_by_connector || []).forEach(s => {
        sourceMap[s.connector_name || 'Unknown'] = (sourceMap[s.connector_name] || 0) + s.certificate_count;
    });
    (summary.keys_by_connector || []).forEach(s => {
        sourceMap[s.connector_name || 'Unknown'] = (sourceMap[s.connector_name] || 0) + s.key_count;
    });
    
    const sourceLabels = Object.keys(sourceMap);
    const sourceData = Object.values(sourceMap);
    const sourceColors = generateColors(sourceLabels.length);
    
    createOrUpdateDonutChart('cc-source-chart', 'ccSource',
        sourceLabels.length > 0 ? sourceLabels : ['No Data'],
        sourceData.length > 0 ? sourceData : [1],
        sourceLabels.length > 0 ? sourceColors : ['#e2e8f0']
    );

    // Expiry Timeline Horizontal Bar
    updateCCExpiryTimeline(summary);

    // Algorithm Type Chart
    updateCCAlgorithmChart(certs, keys);

    // Key Size Chart
    updateCCKeySizeChart(certs, keys);

    // PQC Gauge (semi-circle)
    updateCCPQCGauge(pqcStats);
}

function createOrUpdateDonutChart(canvasId, chartKey, labels, data, colors) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    if (ccCharts[chartKey]) {
        ccCharts[chartKey].data.labels = labels;
        ccCharts[chartKey].data.datasets[0].data = data;
        ccCharts[chartKey].data.datasets[0].backgroundColor = colors;
        ccCharts[chartKey].update();
    } else {
        ccCharts[chartKey] = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { boxWidth: 12, padding: 8, font: { size: 10 } }
                    }
                }
            }
        });
    }
}

function updateCCExpiryTimeline(summary) {
    const ctx = document.getElementById('cc-expiry-timeline-chart');
    if (!ctx) return;

    const expiry = summary.certificate_expiry || {};
    const data = [
        expiry.expired || 0,
        expiry.expiring_7_days || 0,
        expiry.expiring_30_days || 0,
        expiry.expiring_90_days || 0,
        expiry.valid || 0
    ];

    if (ccCharts.expiryTimeline) {
        ccCharts.expiryTimeline.data.datasets[0].data = data;
        ccCharts.expiryTimeline.update();
    } else {
        ccCharts.expiryTimeline = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Expired', '< 7 days', '7-30 days', '30-90 days', '> 90 days'],
                datasets: [{
                    data: data,
                    backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#eab308', '#22c55e'],
                    borderRadius: 4,
                    barThickness: 40
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { font: { size: 11 } } },
                    y: { grid: { display: false }, ticks: { font: { size: 11 } } }
                }
            }
        });
    }
}

function updateCCAlgorithmChart(certs, keys) {
    const ctx = document.getElementById('cc-algo-type-chart');
    if (!ctx) return;

    const algoMap = {};
    certs.forEach(cert => {
        const algo = cert.public_key_algorithm || 'Unknown';
        algoMap[algo] = (algoMap[algo] || 0) + 1;
    });
    keys.forEach(key => {
        const algo = key.key_type || 'Unknown';
        algoMap[algo] = (algoMap[algo] || 0) + 1;
    });

    const labels = Object.keys(algoMap);
    const data = Object.values(algoMap);

    if (ccCharts.algoType) {
        ccCharts.algoType.data.labels = labels;
        ccCharts.algoType.data.datasets[0].data = data;
        ccCharts.algoType.update();
    } else {
        ccCharts.algoType = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: generateColors(labels.length),
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '55%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { boxWidth: 10, padding: 6, font: { size: 9 } }
                    }
                }
            }
        });
    }
}

function updateCCKeySizeChart(certs, keys) {
    const ctx = document.getElementById('cc-key-size-chart');
    if (!ctx) return;

    const sizeMap = {};
    certs.forEach(cert => {
        const size = cert.public_key_size || 'Unknown';
        sizeMap[size] = (sizeMap[size] || 0) + 1;
    });
    keys.forEach(key => {
        const size = key.key_size || 'Unknown';
        sizeMap[size] = (sizeMap[size] || 0) + 1;
    });

    // Sort by key size
    const sortedSizes = Object.keys(sizeMap).sort((a, b) => {
        const numA = parseInt(a) || 0;
        const numB = parseInt(b) || 0;
        return numA - numB;
    });

    const labels = sortedSizes;
    const data = sortedSizes.map(s => sizeMap[s]);
    
    // Color by strength
    const colors = labels.map(size => {
        const numSize = parseInt(size) || 0;
        if (numSize < 2048) return '#ef4444';
        if (numSize < 3072) return '#f59e0b';
        return '#22c55e';
    });

    if (ccCharts.keySize) {
        ccCharts.keySize.data.labels = labels;
        ccCharts.keySize.data.datasets[0].data = data;
        ccCharts.keySize.data.datasets[0].backgroundColor = colors;
        ccCharts.keySize.update();
    } else {
        ccCharts.keySize = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { font: { size: 9 } } },
                    y: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 9 } } }
                }
            }
        });
    }
}

function updateCCPQCGauge(pqcStats) {
    const ctx = document.getElementById('cc-pqc-gauge-chart');
    if (!ctx) return;

    const total = pqcStats.ready + pqcStats.hybrid + pqcStats.needsMigration + pqcStats.unknown;
    const readyPercent = total > 0 ? Math.round(((pqcStats.ready + pqcStats.hybrid) / total) * 100) : 0;

    // Destroy existing chart if it exists to avoid canvas reuse issues
    if (ccCharts.pqcGauge) {
        ccCharts.pqcGauge.destroy();
        ccCharts.pqcGauge = null;
    }

    ccCharts.pqcGauge = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Ready', 'Not Ready'],
            datasets: [{
                data: [readyPercent, 100 - readyPercent],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.9)',
                    'rgba(226, 232, 240, 0.9)'
                ],
                borderWidth: 0,
                circumference: 180,
                rotation: 270
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        },
        plugins: [{
            id: 'gaugeText',
            afterDraw: function(chart) {
                const { ctx, width, height } = chart;
                ctx.save();
                
                // Draw percentage in center
                const fontSize = Math.min(width, height) / 4;
                ctx.font = `bold ${fontSize}px sans-serif`;
                ctx.fillStyle = '#1e293b';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(`${readyPercent}%`, width / 2, height / 1.5);
                
                // Draw label below
                ctx.font = `${fontSize / 3}px sans-serif`;
                ctx.fillStyle = '#64748b';
                ctx.fillText('PQC Ready', width / 2, height / 1.5 + fontSize / 1.5);
                
                ctx.restore();
            }
        }]
    });
}

function updateCCAttentionItems(certs, keys) {
    ccAttentionItems = [];

    // Check certificates for issues
    certs.forEach(cert => {
        const days = cert.days_until_expiration;
        const name = cert.subject_cn || cert.subject?.commonName || 'Unknown';
        const source = cert.source || 'Unknown';

        if (days !== null && days < 0) {
            ccAttentionItems.push({
                type: 'certificate', icon: '📜', name, source,
                issue: 'Expired', issueType: 'expired', days,
                severity: 'critical'
            });
        } else if (days !== null && days <= 30) {
            ccAttentionItems.push({
                type: 'certificate', icon: '📜', name, source,
                issue: `Expiring in ${days} days`, issueType: 'expiring_soon', days,
                severity: days <= 7 ? 'high' : 'medium'
            });
        }

        // Check for weak algorithms
        const algo = cert.public_key_algorithm || '';
        const size = cert.public_key_size || 0;
        if (algo.includes('RSA') && size < 2048) {
            ccAttentionItems.push({
                type: 'certificate', icon: '📜', name, source,
                issue: `Weak key: RSA-${size}`, issueType: 'weak_algorithm', days,
                severity: 'high'
            });
        }

        // Check PQC migration status
        const migStatus = cert.migration_status || cert.pqc_analysis?.migration_status;
        if (migStatus === 'needs_migration' || migStatus === 'vulnerable') {
            ccAttentionItems.push({
                type: 'certificate', icon: '📜', name, source,
                issue: 'Needs PQC Migration', issueType: 'needs_migration', days,
                severity: 'medium'
            });
        }
    });

    // Check keys for issues
    keys.forEach(key => {
        const days = key.days_until_expiration;
        const name = key.name || key.key_id || 'Unknown';
        const source = key.source || 'Unknown';

        if (days !== null && days < 0) {
            ccAttentionItems.push({
                type: 'key', icon: '🔑', name, source,
                issue: 'Expired', issueType: 'expired', days,
                severity: 'critical'
            });
        } else if (days !== null && days <= 30) {
            ccAttentionItems.push({
                type: 'key', icon: '🔑', name, source,
                issue: `Expiring in ${days} days`, issueType: 'expiring_soon', days,
                severity: days <= 7 ? 'high' : 'medium'
            });
        }

        // Check PQC migration status
        const pqc = key.pqc_analysis || {};
        if (pqc.migration_status === 'needs_migration' || pqc.migration_status === 'vulnerable') {
            ccAttentionItems.push({
                type: 'key', icon: '🔑', name, source,
                issue: 'Needs PQC Migration', issueType: 'needs_migration', days,
                severity: 'medium'
            });
        }
    });

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    ccAttentionItems.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    // Update count badge
    document.getElementById('cc-attention-count').textContent = `${ccAttentionItems.length} items`;

    // Render filtered items
    filterCCAttentionItems();
}

function filterCCAttentionItems() {
    const typeFilter = document.getElementById('cc-attention-filter-type')?.value || '';
    const assetFilter = document.getElementById('cc-attention-filter-asset')?.value || '';
    const search = (document.getElementById('cc-attention-search')?.value || '').toLowerCase();

    const filtered = ccAttentionItems.filter(item => {
        if (typeFilter && item.issueType !== typeFilter) return false;
        if (assetFilter && item.type !== assetFilter) return false;
        if (search && !item.name.toLowerCase().includes(search) && !item.source.toLowerCase().includes(search)) return false;
        return true;
    });

    const tbody = document.getElementById('cc-attention-tbody');
    if (!tbody) return;

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No issues requiring attention</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.slice(0, 100).map(item => {
        const severityColor = {
            critical: '#ef4444',
            high: '#f97316',
            medium: '#f59e0b',
            low: '#22c55e'
        }[item.severity] || '#94a3b8';

        const daysDisplay = item.days !== null 
            ? (item.days < 0 ? `<span style="color: #ef4444; font-weight: 600;">${item.days}</span>` : item.days)
            : '-';

        return `
            <tr>
                <td style="text-align: center; font-size: 18px;">${item.icon}</td>
                <td style="font-weight: 500;">${escapeHtml(item.name)}</td>
                <td><span style="background: ${item.type === 'certificate' ? '#e0f2fe' : '#fef3c7'}; color: ${item.type === 'certificate' ? '#0369a1' : '#b45309'}; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-transform: uppercase;">${item.type}</span></td>
                <td><span style="color: ${severityColor}; font-weight: 500;">${escapeHtml(item.issue)}</span></td>
                <td style="color: #64748b; font-size: 12px;">${escapeHtml(item.source)}</td>
                <td style="text-align: center;">${daysDisplay}</td>
                <td style="text-align: right;">
                    <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="viewCCAssetDetails('${item.type}', '${escapeHtml(item.name)}')">View</button>
                </td>
            </tr>
        `;
    }).join('');
}

function toggleCCAttentionSection() {
    const content = document.getElementById('cc-attention-content');
    const arrow = document.getElementById('cc-attention-arrow');
    if (content && arrow) {
        const isHidden = content.style.display === 'none';
        content.style.display = isHidden ? 'block' : 'none';
        arrow.textContent = isHidden ? '▼' : '▶';
    }
}

function updateCCRecentChanges(changes) {
    const container = document.getElementById('cc-recent-changes');
    if (!container) return;

    if (!changes || changes.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: #94a3b8;">No recent changes recorded</div>';
        return;
    }

    container.innerHTML = changes.map(change => {
        const icon = change.entity_type === 'certificate' ? '📜' : '🔑';
        const changeIcon = {
            added: '➕',
            updated: '🔄',
            removed: '➖',
            reappeared: '↩️'
        }[change.change_type] || '•';
        
        const timeAgo = formatTimeAgo(change.detected_at);
        const details = change.change_details && typeof change.change_details === 'string'
            ? JSON.parse(change.change_details)
            : (change.change_details || {});
        const name = details.subject_cn || details.key_name || `${change.entity_type} #${change.entity_id}`;

        return `
            <div style="display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px solid #f1f5f9;">
                <span style="font-size: 16px;">${changeIcon}</span>
                <span style="font-size: 16px;">${icon}</span>
                <div style="flex: 1;">
                    <div style="font-weight: 500; color: #1e293b;">${escapeHtml(name)}</div>
                    <div style="font-size: 12px; color: #64748b;">${change.change_type} • ${timeAgo}</div>
                </div>
            </div>
        `;
    }).join('');
}

function loadCCRecentChanges() {
    fetch('/api/v1/activity/feed?limit=30&since_days=7')
        .then(res => res.json())
        .then(data => {
            if (data.grouped) {
                renderActivityFeed(data.grouped);
            } else {
                // fallback: old endpoint shape
                updateCCRecentChanges(data.changes || []);
            }
        })
        .catch(() => {
            fetch('/api/v1/inventory/changes?limit=20')
                .then(res => res.json())
                .then(data => updateCCRecentChanges(data.changes || []));
        });
}

function renderActivityFeed(grouped) {
    const container = document.getElementById('cc-recent-changes');
    if (!container) return;

    const sections = [
        { key: 'today',      label: 'Today' },
        { key: 'yesterday',  label: 'Yesterday' },
        { key: 'this_week',  label: 'This Week' },
        { key: 'earlier',    label: 'Earlier' }
    ];

    const html = sections
        .filter(s => grouped[s.key] && grouped[s.key].length > 0)
        .map(s => `
            <div style="margin-bottom: 4px;">
                <div style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase;
                            letter-spacing: 0.8px; padding: 10px 0 6px 0; border-bottom: 1px solid #f1f5f9;">
                    ${s.label} <span style="font-weight: 400;">(${grouped[s.key].length})</span>
                </div>
                ${grouped[s.key].map(ev => renderActivityEventRow(ev)).join('')}
            </div>
        `).join('');

    container.innerHTML = html || '<div style="text-align: center; padding: 40px; color: #94a3b8;">No recent activity</div>';
}

function renderActivityEventRow(ev) {
    const borderColors = {
        inventory_change: '#3b82f6',
        connector_sync:   '#10b981',
        expiry_alert:     '#f59e0b',
        scan_run:         '#8b5cf6'
    };
    const severityOverrides = {
        error:    '#ef4444',
        critical: '#ef4444',
        expired:  '#dc2626',
        warning:  '#f59e0b',
    };
    const borderColor = severityOverrides[ev.severity] || borderColors[ev.event_type] || '#94a3b8';

    // --- Icons per event type ---
    let leftIcon = '•';
    if (ev.event_type === 'inventory_change') {
        const changeIcons = { added: '➕', updated: '🔄', removed: '➖', reappeared: '↩️' };
        leftIcon = changeIcons[ev.change_type] || '📋';
    } else if (ev.event_type === 'connector_sync') {
        leftIcon = ev.severity === 'success' ? '✅' : '❌';
    } else if (ev.event_type === 'expiry_alert') {
        leftIcon = ev.days_until_expiry <= 0 ? '💀' : (ev.days_until_expiry <= 7 ? '🔴' : '⚠️');
    } else if (ev.event_type === 'scan_run') {
        leftIcon = ev.severity === 'success' ? '🔍' : '⚠️';
    }

    // --- Connector pill (shown for inventory + sync events) ---
    const connectorTypeLabels = {
        ejbca:          { label: 'EJBCA',    bg: '#dbeafe', color: '#1d4ed8' },
        azure_keyvault: { label: 'Azure KV', bg: '#ede9fe', color: '#6d28d9' },
        azure_key_vault:{ label: 'Azure KV', bg: '#ede9fe', color: '#6d28d9' },
        luna_hsm:       { label: 'Luna HSM', bg: '#fef3c7', color: '#92400e' },
        tls:            { label: 'TLS',      bg: '#dcfce7', color: '#166534' },
        file_share:     { label: 'File',     bg: '#f1f5f9', color: '#475569' },
    };
    let connectorPill = '';
    if (ev.connector_type && connectorTypeLabels[ev.connector_type]) {
        const ct = connectorTypeLabels[ev.connector_type];
        connectorPill = `<span style="font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px;
                                      background: ${ct.bg}; color: ${ct.color}; margin-left: 6px;">${ct.label}</span>`;
    }

    // --- Algorithm badge (inventory changes only) ---
    let algoBadge = '';
    if (ev.algorithm) {
        algoBadge = `<span style="font-size: 10px; color: #64748b; margin-left: 4px;">${escapeHtml(ev.algorithm)}</span>`;
    }

    // --- Expiry badge ---
    let expiryBadge = '';
    if (ev.event_type === 'inventory_change' && ev.days_until_expiry != null && ev.days_until_expiry <= 30) {
        const expColor = ev.days_until_expiry <= 0 ? '#dc2626' : (ev.days_until_expiry <= 7 ? '#ef4444' : '#f59e0b');
        const expLabel = ev.days_until_expiry <= 0 ? 'EXPIRED' : `EXPIRING ${ev.days_until_expiry}d`;
        expiryBadge = `<span style="font-size: 10px; font-weight: 700; padding: 2px 5px; border-radius: 4px;
                                     background: ${expColor}; color: white; margin-left: 4px;">${expLabel}</span>`;
    }

    // --- Relative time ---
    const timeStr = ev.event_type === 'expiry_alert' ? 'Now' : formatTimeAgo(ev.event_at);

    return `
        <div style="display: flex; align-items: flex-start; gap: 10px; padding: 10px 0 10px 10px;
                    border-bottom: 1px solid #f8fafc; border-left: 3px solid ${borderColor}; margin-left: 2px;">
            <span style="font-size: 15px; flex-shrink: 0; margin-top: 1px;">${leftIcon}</span>
            <div style="flex: 1; min-width: 0;">
                <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 2px;">
                    <span style="font-weight: 500; color: #1e293b; font-size: 13px;">${escapeHtml(ev.title)}</span>
                    ${connectorPill}${algoBadge}${expiryBadge}
                </div>
                <div style="font-size: 11px; color: #64748b; margin-top: 2px;">${escapeHtml(ev.subtitle || '')} · ${timeStr}</div>
            </div>
        </div>
    `;
}

// ============================================================================
// COLLECTOR REGISTRATION FUNCTIONS
// ============================================================================

async function generateBootstrapToken() {
    const collectorName = document.getElementById('tokenCollectorName')?.value;
    const organization = document.getElementById('tokenOrganization')?.value;
    const engagementCAId = document.getElementById('tokenEngagementCA')?.value;
    const location = document.getElementById('tokenLocation')?.value;
    const environment = document.getElementById('tokenEnvironment')?.value || 'production';
    const transmissionMode = document.getElementById('tokenTransmissionMode')?.value || 'selective';
    const ttl = parseInt(document.getElementById('tokenTTL')?.value) || 24;
    const maxUses = parseInt(document.getElementById('tokenMaxUses')?.value) || 1;
    const ipRestriction = document.getElementById('tokenIPRestriction')?.value;

    // Validate required fields
    if (!collectorName) {
        alert('Collector Name is required');
        return;
    }
    if (!organization) {
        alert('Organization is required');
        return;
    }
    if (!engagementCAId) {
        alert('Certificate Authority (CA) is required');
        return;
    }

    try {
        const response = await fetch('/api/remote/tokens', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                collector_name: collectorName,
                organization: organization,
                engagement_ca_id: engagementCAId,
                location: location,
                environment: environment,
                transmission_mode: transmissionMode,
                ttl_hours: ttl,
                max_uses: maxUses,
                ip_restriction: ipRestriction || null
            })
        });

        if (response.ok) {
            const data = await response.json();
            displayGeneratedToken(data);
            closeModal('generateTokenModal');
            // Refresh token list
            loadBootstrapTokens();
        } else {
            const error = await response.json();
            alert(`Error: ${error.message || 'Failed to generate token'}`);
        }
    } catch (error) {
        console.error('Error generating token:', error);
        alert('Failed to generate bootstrap token');
    }
}

function displayGeneratedToken(tokenData) {
    const modal = document.getElementById('tokenDisplayModal');
    if (!modal) return;

    const tokenDisplay = modal.querySelector('#generatedTokenValue');
    const tokenExpiresAt = modal.querySelector('#tokenExpiresAt');
    const tokenMaxUsesDisplay = modal.querySelector('#tokenMaxUsesDisplay');

    if (tokenDisplay) {
        tokenDisplay.value = tokenData.token || 'Token not available';
    }

    if (tokenExpiresAt) {
        tokenExpiresAt.textContent = new Date(tokenData.expires_at).toLocaleString();
    }

    if (tokenMaxUsesDisplay) {
        tokenMaxUsesDisplay.textContent = tokenData.max_uses;
    }

    // Show the modal
    modal.classList.add('active');
    modal.style.display = 'flex';
}

function copyGeneratedToken() {
    const tokenInput = document.getElementById('generatedTokenValue');
    if (tokenInput) {
        tokenInput.select();
        document.execCommand('copy');
        alert('Token copied to clipboard');
    }
}

function copyInstallCommand() {
    const commandDiv = document.getElementById('installationCommand');
    if (commandDiv) {
        const text = commandDiv.textContent;
        navigator.clipboard.writeText(text).then(() => {
            alert('Installation command copied to clipboard');
        }).catch(err => {
            console.error('Failed to copy:', err);
            alert('Failed to copy command');
        });
    }
}

function loadBootstrapTokens() {
    fetch('/api/remote/tokens')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById('bootstrap-tokens-body');
            if (!tbody) return;

            if (!data.tokens || data.tokens.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No active tokens. Generate a token to register new collectors.</td></tr>';
                return;
            }

            tbody.innerHTML = data.tokens.map(token => `
                <tr>
                    <td>${token.token_prefix}</td>
                    <td>${token.collector_name}</td>
                    <td>${token.environment}</td>
                    <td>${new Date(token.created_at).toLocaleDateString()}</td>
                    <td>${new Date(token.expires_at).toLocaleDateString()}</td>
                    <td>${token.current_uses}/${token.max_uses}</td>
                    <td><span class="status-badge" style="background: ${token.current_uses >= token.max_uses && token.max_uses > 0 ? '#fee2e2; color: #991b1b' : '#dcfce7; color: #15803d'}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">${token.current_uses >= token.max_uses && token.max_uses > 0 ? 'EXPIRED' : 'ACTIVE'}</span></td>
                    <td>
                        <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="revokeToken('${token.id}')">Revoke</button>
                    </td>
                </tr>
            `).join('');
        })
        .catch(error => console.error('Error loading bootstrap tokens:', error));
}

function revokeToken(tokenId) {
    if (!confirm('Are you sure you want to revoke this token?')) return;

    fetch(`/api/remote/tokens/${tokenId}`, {
        method: 'DELETE'
    })
        .then(res => {
            if (res.ok) {
                loadBootstrapTokens();
            } else {
                alert('Failed to revoke token');
            }
        })
        .catch(error => console.error('Error revoking token:', error));
}

function viewCCAssetDetails(type, name) {
    // Navigate to appropriate tab based on asset type
    if (type === 'certificate') {
        switchMainTab('clm');
        // Could also scroll to or highlight the specific certificate
    } else {
        switchMainTab('kms');
    }
}

function formatTimeAgo(dateString) {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
}

        // ============ PHASE 3: NEW MODULE LOAD FUNCTIONS ============

        async function loadAssetsCertificates(page = 1) {
            try {
                console.log('loadAssetsCertificates called with page:', page);
                const response = await fetch(`/api/v1/inventory/search`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        asset_types: ['certificates'],
                        filters: {},
                        page: page,
                        page_size: 999,
                        include_inactive: true
                    })
                });

                console.log('API response status:', response.status, response.ok);
                if (!response.ok) throw new Error(`Failed to load certificates: ${response.status}`);
                const data = await response.json();

                console.log('API response data:', data);

                // Debug: Log first certificate to see all available fields
                if (data.data && data.data.length > 0) {
                    console.log('First certificate object keys:', Object.keys(data.data[0]));
                    console.log('First certificate source_type:', data.data[0].source_type);
                    console.log('First certificate source_integration:', data.data[0].source_integration);
                }

                // Populate the table
                const tbody = document.getElementById('assetsCertificatesTableBody');
                console.log('Found tbody element:', tbody ? 'YES' : 'NO');

                if (tbody) {
                    if (data.data && data.data.length > 0) {
                        console.log('Populating', data.data.length, 'certificates');
                        window.assetsCurrentCerts = data.data;
                        tbody.innerHTML = data.data.map((cert, idx) => {
                            const notBefore = cert.not_before || cert.valid_from;
                            const validFromDate = notBefore ? new Date(notBefore).toLocaleDateString() : 'N/A';
                            const notAfter = cert.not_after || cert.expires_on;
                            const expiryDate = notAfter ? new Date(notAfter).toLocaleDateString() : 'N/A';
                            let sourceDisplay = 'Unknown';
                            let sourceBadge = '';
                            if (cert.is_promoted || cert.source_type === 'promoted_scan') {
                                sourceDisplay = cert.promoted_from_scan_name || 'Promoted Scan';
                                sourceBadge = '<span class="badge" style="background: #fef3c7; color: #92400e; margin-left: 6px;">📌 Promoted</span>';
                            } else if (cert.integration_name) {
                                sourceDisplay = cert.integration_name;
                                sourceBadge = '<span class="badge" style="background: #dbeafe; color: #1e40af; margin-left: 6px;">🔄 Synced</span>';
                            } else if (cert.source_type) {
                                sourceDisplay = cert.source_type;
                            }
                            let environmentDisplay = cert.environment_type || cert.inferred_environment_type || 'Unknown';
                            let environmentBadge = cert.environment_type ? '<span class="badge" style="background: #fce7f3; color: #be123c; margin-left: 6px; font-size: 10px;">Manual</span>' : '<span class="badge" style="background: #e0e7ff; color: #3730a3; margin-left: 6px; font-size: 10px;">Inferred</span>';
                            return `
                            <tr>
                                <td>${cert.subject_cn || 'N/A'}</td>
                                <td>${cert.issuer_cn || 'N/A'}</td>
                                <td>${validFromDate}</td>
                                <td>${expiryDate}</td>
                                <td>${cert.days_until_expiry !== null ? cert.days_until_expiry : '—'}</td>
                                <td>${cert.public_key_algorithm || 'N/A'}</td>
                                <td>${cert.key_size || 'N/A'}</td>
                                <td>${cert.type || 'Certificate'}</td>
                                <td>${sourceDisplay}${sourceBadge}</td>
                                <td>${environmentDisplay}${environmentBadge}</td>
                                <td><span class="status-badge" style="background: ${cert.days_until_expiry <= 30 ? '#fee2e2' : '#dcfce7'}; color: ${cert.days_until_expiry <= 30 ? '#991b1b' : '#15803d'}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">${cert.days_until_expiry !== null ? (cert.days_until_expiry <= 0 ? 'EXPIRED' : 'ACTIVE') : 'UNKNOWN'}</span></td>
                                <td style="text-align: right;">
                                    <button class="btn-cert-view" data-cert-index="${idx}" style="padding: 4px 8px; font-size: 11px; margin-right: 4px;">View</button>
                                    <button class="btn-cert-enrich" data-cert-index="${idx}" data-cert-id="${cert.fingerprint_sha256 || cert.id}" style="padding: 4px 8px; font-size: 11px; background: #fbbf24; color: #78350f; border: 1px solid #f59e0b; border-radius: 4px; cursor: pointer;">Enrich</button>
                                </td>
                            </tr>
                        `}).join('');

                        // Add event listeners to View buttons
                        tbody.querySelectorAll('.btn-cert-view').forEach(btn => {
                            btn.addEventListener('click', function() {
                                const idx = this.getAttribute('data-cert-index');
                                showCertificateDetails(window.assetsCurrentCerts[idx]);
                            });
                        });

                        // Add event listeners to Enrich buttons
                        tbody.querySelectorAll('.btn-cert-enrich').forEach(btn => {
                            btn.addEventListener('click', function() {
                                const idx = this.getAttribute('data-cert-index');
                                const certId = this.getAttribute('data-cert-id');
                                openAssetEnrichmentModal(window.assetsCurrentCerts[idx], 'certificate', certId);
                            });
                        });

                        // Populate filter dropdowns
                        populateAssetFilterDropdowns();

                        // Update certificate summary cards
                        const totalCerts = data.data.length;
                        const expiredCerts = data.data.filter(c => c.days_until_expiry <= 0).length;
                        const expiringSoon = data.data.filter(c => c.days_until_expiry > 0 && c.days_until_expiry <= 30).length;
                        const activeCerts = data.data.filter(c => c.days_until_expiry > 30).length;

                        document.getElementById('certSummaryTotal').textContent = totalCerts;
                        document.getElementById('certSummaryExpired').textContent = expiredCerts;
                        document.getElementById('certSummaryExpiringSoon').textContent = expiringSoon;
                        document.getElementById('certSummaryActive').textContent = activeCerts;

                        // Add event listeners to filter inputs
                        const certSearchInput = document.getElementById('assetsCertSearchInput');
                        const certFilterSelect = document.getElementById('assetsCertFilterSelect');
                        const certKeySizeFilter = document.getElementById('assetsCertKeySizeFilter');
                        const certSourceFilter = document.getElementById('assetsCertSourceFilter');
                        const certShowExpired = document.getElementById('assetsCertShowExpired');

                        if (certSearchInput) certSearchInput.addEventListener('input', filterAssetsCertificates);
                        if (certFilterSelect) certFilterSelect.addEventListener('change', filterAssetsCertificates);
                        if (certKeySizeFilter) certKeySizeFilter.addEventListener('change', filterAssetsCertificates);
                        if (certSourceFilter) certSourceFilter.addEventListener('change', filterAssetsCertificates);
                        if (certShowExpired) certShowExpired.addEventListener('change', filterAssetsCertificates);

                        // Apply deduplication filtering and rendering on initial load
                        filterAssetsCertificates();
                    } else {
                        console.log('No certificate data returned');
                    }
                }
            } catch (error) {
                console.error('Error loading assets certificates:', error);
            }
        }

        // Helper function to populate filter dropdowns from loaded data
        function populateAssetFilterDropdowns() {
            // Certificate Algorithm Dropdown
            if (window.assetsCurrentCerts && window.assetsCurrentCerts.length > 0) {
                const algorithms = [...new Set(window.assetsCurrentCerts
                    .map(c => c.key_algorithm)
                    .filter(a => a && a !== 'N/A'))].sort();
                const certAlgoSelect = document.getElementById('assetsCertFilterSelect');
                if (certAlgoSelect) {
                    certAlgoSelect.innerHTML = '<option value="">All Algorithms</option>' +
                        algorithms.map(algo => `<option value="${algo}">${algo}</option>`).join('');
                }

                // Certificate Key Size Dropdown - Dynamic from actual data
                const keySizes = [...new Set(window.assetsCurrentCerts
                    .map(c => c.key_size)
                    .filter(s => s && s !== 'N/A' && s !== null))].sort((a, b) => a - b);
                const certKeySizeSelect = document.getElementById('assetsCertKeySizeFilter');
                if (certKeySizeSelect) {
                    certKeySizeSelect.innerHTML = '<option value="">All Sizes</option>' +
                        keySizes.map(size => `<option value="${size}">${size} bits</option>`).join('');
                }

                // Certificate Source Dropdown - Match display logic
                const sources = [...new Set(window.assetsCurrentCerts
                    .map(c => {
                        if (c.is_promoted || c.source_type === 'promoted_scan') {
                            return c.promoted_from_scan_name;
                        } else if (c.integration_name) {
                            return c.integration_name;
                        } else if (c.source_type) {
                            return c.source_type;
                        }
                        return null;
                    })
                    .filter(s => s && s !== 'N/A'))].sort();
                const certSourceSelect = document.getElementById('assetsCertSourceFilter');
                if (certSourceSelect) {
                    certSourceSelect.innerHTML = '<option value="">All Sources</option>' +
                        sources.map(src => `<option value="${src}">${src}</option>`).join('');
                }
            }

            // Key Type Dropdown
            if (window.assetsCurrentKeys && window.assetsCurrentKeys.length > 0) {
                const keyTypes = [...new Set(window.assetsCurrentKeys
                    .map(k => k.key_type)
                    .filter(kt => kt && kt !== 'Unknown'))].sort();
                const keyTypeSelect = document.getElementById('assetsKeyFilterSelect');
                if (keyTypeSelect) {
                    keyTypeSelect.innerHTML = '<option value="">All Key Types</option>' +
                        keyTypes.map(kt => `<option value="${kt}">${kt}</option>`).join('');
                }
            }
        }

        // Sorting state
        window.assetsSortState = {
            certificates: { column: null, direction: 'asc' },
            keys: { column: null, direction: 'asc' }
        };

        // Helper function to sort data
        function sortAssetData(data, column, currentDirection) {
            const direction = currentDirection === 'asc' ? 'desc' : 'asc';
            const sorted = [...data].sort((a, b) => {
                let aVal = a[column];
                let bVal = b[column];

                // Handle null/undefined
                if (aVal == null && bVal == null) return 0;
                if (aVal == null) return direction === 'asc' ? 1 : -1;
                if (bVal == null) return direction === 'asc' ? -1 : 1;

                // Numeric comparison
                if (typeof aVal === 'number' && typeof bVal === 'number') {
                    return direction === 'asc' ? aVal - bVal : bVal - aVal;
                }

                // String comparison
                aVal = String(aVal).toLowerCase();
                bVal = String(bVal).toLowerCase();
                return direction === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });
            return { data: sorted, direction };
        }

        // Column header click handler for certificates
        window.sortCertificateColumn = function(column) {
            const currentDir = window.assetsSortState.certificates.direction;
            const result = sortAssetData(window.assetsCurrentCerts, column, currentDir);
            window.assetsCurrentCerts = result.data;
            window.assetsSortState.certificates = { column, direction: result.direction };
            filterAssetsCertificates();
        };

        // Column header click handler for keys
        window.sortKeyColumn = function(column) {
            const currentDir = window.assetsSortState.keys.direction;
            const result = sortAssetData(window.assetsCurrentKeys, column, currentDir);
            window.assetsCurrentKeys = result.data;
            window.assetsSortState.keys = { column, direction: result.direction };
            filterAssetsKeys();
        };

        // Enhanced filter function for certificates
        function filterAssetsCertificates() {
            if (!window.assetsCurrentCerts) return;

            const searchInput = document.getElementById('assetsCertSearchInput');
            const algorithmFilter = document.getElementById('assetsCertFilterSelect');
            const keySizeFilter = document.getElementById('assetsCertKeySizeFilter');
            const sourceFilter = document.getElementById('assetsCertSourceFilter');
            const showExpired = document.getElementById('assetsCertShowExpired');
            const dedupPromoted = document.getElementById('assetsCertDedupPromoted');

            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const selectedAlgorithm = algorithmFilter ? algorithmFilter.value : '';
            const selectedKeySize = keySizeFilter ? keySizeFilter.value : '';
            const selectedSource = sourceFilter ? sourceFilter.value : '';
            const includeExpired = showExpired ? showExpired.checked : false;
            const hideDuplicates = dedupPromoted ? dedupPromoted.checked : false;

            // Pre-scan: group all certificates by fingerprint (promoted and native integrations)
            const allByFingerprint = {};
            window.assetsCurrentCerts.forEach(cert => {
                const fp = cert.fingerprint_sha256;
                if (fp) {
                    if (!allByFingerprint[fp]) {
                        allByFingerprint[fp] = [];
                    }
                    allByFingerprint[fp].push(cert);
                }
            });

            // Mark duplicates:
            // 1. Promoted scans: all but the newest are marked as duplicates
            // 2. Imported scans: marked as duplicates if a native integration asset exists with same fingerprint
            window.assetsCurrentCerts.forEach(cert => {
                cert._isDuplicate = false;
                const fp = cert.fingerprint_sha256;

                if (fp && allByFingerprint[fp] && allByFingerprint[fp].length > 1) {
                    const groupedCerts = allByFingerprint[fp];

                    // Separate promoted and native integration assets
                    const promoted = groupedCerts.filter(c => c.is_promoted || c.source_type === 'promoted_scan');
                    const nativeIntegrations = groupedCerts.filter(c => !(c.is_promoted || c.source_type === 'promoted_scan'));

                    // If there are native integration assets (EJBCA, Azure KV, Luna HSM, TLS)
                    // mark all promoted scan assets as duplicates
                    if (nativeIntegrations.length > 0 && promoted.length > 0) {
                        promoted.forEach(p => {
                            p._isDuplicate = true;
                        });
                    }
                    // Otherwise, if only promoted scan assets exist
                    // mark all but the newest (by promoted_at) as duplicates
                    else if (promoted.length > 1) {
                        // Sort by promoted_at (newest first)
                        const sorted = promoted.sort((a, b) => {
                            const dateA = new Date(a.promoted_at || 0);
                            const dateB = new Date(b.promoted_at || 0);
                            return dateB - dateA;
                        });
                        // Mark all except the first (newest) as duplicates
                        promoted.forEach((cert, idx) => {
                            if (idx > 0) {
                                cert._isDuplicate = true;
                            }
                        });
                    }
                }
            });

            const filtered = window.assetsCurrentCerts.filter(cert => {
                let searchMatch = !searchTerm;
                if (searchTerm) {
                    // Smart fingerprint detection: hex 8-64 chars
                    const isFingerprintSearch = /^[a-fA-F0-9]{8,64}$/i.test(searchTerm);
                    if (isFingerprintSearch) {
                        searchMatch = cert.fingerprint_sha256 && cert.fingerprint_sha256.toLowerCase().includes(searchTerm);
                    } else {
                        searchMatch = (cert.subject_cn && cert.subject_cn.toLowerCase().includes(searchTerm)) ||
                            (cert.issuer_cn && cert.issuer_cn.toLowerCase().includes(searchTerm)) ||
                            (cert.promoted_from_scan_name && cert.promoted_from_scan_name.toLowerCase().includes(searchTerm));
                    }
                }

                const algoMatch = !selectedAlgorithm || cert.key_algorithm === selectedAlgorithm;
                const sizeMatch = !selectedKeySize || cert.key_size === parseInt(selectedKeySize);

                let sourceMatch = !selectedSource;
                if (selectedSource) {
                    if (cert.is_promoted || cert.source_type === 'promoted_scan') {
                        sourceMatch = cert.promoted_from_scan_name === selectedSource;
                    }
                    if (!sourceMatch && cert.integration_name) {
                        sourceMatch = cert.integration_name === selectedSource;
                    }
                    if (!sourceMatch && cert.source_type) {
                        sourceMatch = cert.source_type === selectedSource;
                    }
                }

                const expiryMatch = includeExpired || !cert.days_until_expiry || cert.days_until_expiry > 0;

                // Dedup filter: hide duplicates if toggle is ON
                const dedupMatch = !hideDuplicates || !cert._isDuplicate;

                return searchMatch && algoMatch && sizeMatch && sourceMatch && expiryMatch && dedupMatch;
            });

            // Re-render table
            const tbody = document.getElementById('assetsCertificatesTableBody');
            if (tbody && filtered.length > 0) {
                tbody.innerHTML = filtered.map((cert, idx) => {
                    const originalIdx = window.assetsCurrentCerts.indexOf(cert);
                    const notBefore = cert.not_before || cert.valid_from;
                    const validFromDate = notBefore ? new Date(notBefore).toLocaleDateString() : 'N/A';
                    const notAfter = cert.not_after || cert.expires_on;
                    const expiryDate = notAfter ? new Date(notAfter).toLocaleDateString() : 'N/A';

                    let sourceDisplay = 'Unknown';
                    let sourceBadge = '';
                    if (cert.is_promoted || cert.source_type === 'promoted_scan') {
                        sourceDisplay = cert.promoted_from_scan_name || 'Promoted Scan';
                        sourceBadge = '<span class="badge" style="background: #fef3c7; color: #92400e; margin-left: 6px;">📌 Promoted</span>';
                    } else if (cert.integration_name) {
                        sourceDisplay = cert.integration_name;
                        sourceBadge = '<span class="badge" style="background: #dbeafe; color: #1e40af; margin-left: 6px;">🔄 Synced</span>';
                    } else if (cert.source_type) {
                        sourceDisplay = cert.source_type;
                    }

                    const rowClass = cert._isDuplicate ? 'row-duplicate' : '';
                    const subjectDisplay = cert.subject_cn || 'N/A';
                    const subjectWithLabel = cert._isDuplicate ?
                        `<div style="display: flex; align-items: center; gap: 8px;"><span>${subjectDisplay}</span><span class="badge" style="background: #fee2e2; color: #dc2626; margin-left: 6px; font-size: 10px;">⚠️ Duplicate</span></div>` :
                        subjectDisplay;

                    return `<tr ${rowClass ? `class="${rowClass}"` : ''}>
                        <td>${subjectWithLabel}</td>
                        <td>${cert.issuer_cn || 'N/A'}</td>
                        <td>${validFromDate}</td>
                        <td>${expiryDate}</td>
                        <td>${cert.days_until_expiry !== null ? cert.days_until_expiry : '—'}</td>
                        <td>${cert.key_algorithm || 'N/A'}</td>
                        <td>${cert.key_size || 'N/A'}</td>
                        <td>${cert.type || 'Certificate'}</td>
                        <td>${sourceDisplay}${sourceBadge}</td>
                        <td><span class="status-badge" style="background: ${cert.days_until_expiry <= 30 ? '#fee2e2' : '#dcfce7'}; color: ${cert.days_until_expiry <= 30 ? '#991b1b' : '#15803d'}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">${cert.days_until_expiry !== null ? (cert.days_until_expiry <= 0 ? 'EXPIRED' : 'ACTIVE') : 'UNKNOWN'}</span></td>
                        <td style="text-align: right;">
                            <button class="btn-cert-view" data-cert-index="${originalIdx}" style="padding: 4px 8px; font-size: 11px; margin-right: 4px;">View</button>
                            <button class="btn-cert-enrich" data-cert-index="${originalIdx}" data-cert-id="${cert.fingerprint_sha256 || cert.id}" style="padding: 4px 8px; font-size: 11px; background: #fbbf24; color: #78350f; border: 1px solid #f59e0b; border-radius: 4px; cursor: pointer;">Enrich</button>
                        </td>
                    </tr>`;
                }).join('');

                // Re-attach event listeners
                tbody.querySelectorAll('.btn-cert-view').forEach(btn => {
                    btn.addEventListener('click', function() {
                        const idx = this.getAttribute('data-cert-index');
                        showCertificateDetails(window.assetsCurrentCerts[idx]);
                    });
                });

                tbody.querySelectorAll('.btn-cert-enrich').forEach(btn => {
                    btn.addEventListener('click', function() {
                        const idx = this.getAttribute('data-cert-index');
                        const certId = this.getAttribute('data-cert-id');
                        openAssetEnrichmentModal(window.assetsCurrentCerts[idx], 'certificate', certId);
                    });
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="11" style="text-align: center; padding: 20px; color: #6b7280;">No certificates match your search/filters</td></tr>';
            }
        }

        // Clear all certificate filters
        function clearAssetsFilters() {
            document.getElementById('assetsCertSearchInput').value = '';
            document.getElementById('assetsCertFilterSelect').value = '';
            document.getElementById('assetsCertKeySizeFilter').value = '';
            document.getElementById('assetsCertSourceFilter').value = '';
            document.getElementById('assetsCertEnvironmentFilter').value = '';
            document.getElementById('assetsCertShowExpired').checked = false;
            document.getElementById('assetsCertDedupPromoted').checked = false;
            loadAssetsCertificates();
        }

        // Add event listeners for certificate filters (including dedup toggle)
        (function() {
            const dedupCheckbox = document.getElementById('assetsCertDedupPromoted');
            if (dedupCheckbox) {
                dedupCheckbox.addEventListener('change', filterAssetsCertificates);
            }
        })();

        // Enhanced filter function for keys
        function filterAssetsKeys() {
            if (!window.assetsCurrentKeys) return;

            const searchInput = document.getElementById('assetsKeySearchInput');
            const keyTypeFilter = document.getElementById('assetsKeyFilterSelect');
            const keySizeFilter = document.getElementById('assetsKeyKeySizeFilter');
            const sourceFilter = document.getElementById('assetsKeySourceFilter');
            const environmentFilter = document.getElementById('assetsKeyEnvironmentFilter');
            const hsmFilter = document.getElementById('assetsKeyHSMFilter');
            const dedupPromoted = document.getElementById('assetsCertDedupPromoted');

            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const selectedKeyType = keyTypeFilter ? keyTypeFilter.value : '';
            const selectedKeySize = keySizeFilter ? keySizeFilter.value : '';
            const selectedSource = sourceFilter ? sourceFilter.value : '';
            const selectedEnvironment = environmentFilter ? environmentFilter.value : '';
            const showHSMOnly = hsmFilter ? hsmFilter.checked : false;
            const hideDuplicates = dedupPromoted ? dedupPromoted.checked : false;

            // Pre-scan: group all keys by identifier
            const allByIdentifier = {};
            window.assetsCurrentKeys.forEach(key => {
                const id = key.key_identifier || key.key_name;
                if (id) {
                    if (!allByIdentifier[id]) {
                        allByIdentifier[id] = [];
                    }
                    allByIdentifier[id].push(key);
                }
            });

            // Mark duplicates: promoted keys are duplicates if synced asset exists with same identifier
            // or if multiple promoted scans exist with same identifier (keep newest)
            window.assetsCurrentKeys.forEach(key => {
                key._isDuplicate = false;
                if (key.is_promoted || key.source_type === 'promoted_scan') {
                    const id = key.key_identifier || key.key_name;
                    if (id && allByIdentifier[id]) {
                        const group = allByIdentifier[id];
                        // Check if any synced asset (non-promoted) exists with this identifier
                        const hasSyncedAsset = group.some(k => !(k.is_promoted || k.source_type === 'promoted_scan'));
                        if (hasSyncedAsset) {
                            // Mark all promoted scans as duplicates if synced asset exists
                            key._isDuplicate = true;
                        } else {
                            // Otherwise, mark all but newest promoted scan as duplicates
                            const promoted = group.filter(k => k.is_promoted || k.source_type === 'promoted_scan');
                            if (promoted.length > 1) {
                                // Sort by promoted_at (newest first)
                                const sorted = promoted.sort((a, b) => {
                                    const dateA = new Date(a.promoted_at || 0);
                                    const dateB = new Date(b.promoted_at || 0);
                                    return dateB - dateA;
                                });
                                // Mark all except the first (newest) as duplicates
                                if (key !== sorted[0]) {
                                    key._isDuplicate = true;
                                }
                            }
                        }
                    }
                }
            });

            const filtered = window.assetsCurrentKeys.filter(key => {
                let searchMatch = !searchTerm;
                if (searchTerm) {
                    searchMatch = (key.key_name && key.key_name.toLowerCase().includes(searchTerm)) ||
                        (key.key_identifier && key.key_identifier.toLowerCase().includes(searchTerm)) ||
                        (key.promoted_from_scan_name && key.promoted_from_scan_name.toLowerCase().includes(searchTerm));
                }

                const typeMatch = !selectedKeyType || key.key_type === selectedKeyType;
                const sizeMatch = !selectedKeySize || key.key_size === parseInt(selectedKeySize);
                const sourceMatch = !selectedSource ||
                    key.promoted_from_scan_name === selectedSource ||
                    key.source_integration === selectedSource;
                const environmentMatch = !selectedEnvironment || key.inferred_environment_type === selectedEnvironment;
                const hsmMatch = !showHSMOnly || key.is_hsm_backed;

                // Dedup filter: hide duplicates if toggle is ON
                const dedupMatch = !hideDuplicates || !key._isDuplicate;

                return searchMatch && typeMatch && sizeMatch && sourceMatch && environmentMatch && hsmMatch && dedupMatch;
            });

            // Re-render table
            const tbody = document.getElementById('assetsKeysTableBody');
            if (tbody && filtered.length > 0) {
                tbody.innerHTML = filtered.map((key, idx) => {
                    const originalIdx = window.assetsCurrentKeys.indexOf(key);

                    let sourceDisplay = 'Unknown';
                    let sourceBadge = '';
                    if (key.is_promoted || key.source_type === 'promoted_scan') {
                        sourceDisplay = key.promoted_from_scan_name || 'Promoted Scan';
                        sourceBadge = '<span class="badge" style="background: #fef3c7; color: #92400e; margin-left: 6px;">📌 Promoted</span>';
                    } else if (key.integration_name) {
                        sourceDisplay = key.integration_name;
                        sourceBadge = '<span class="badge" style="background: #dbeafe; color: #1e40af; margin-left: 6px;">🔄 Synced</span>';
                    } else if (key.source_type) {
                        sourceDisplay = key.source_type;
                    }

                    const rowClass = key._isDuplicate ? 'row-duplicate' : '';
                    const keyNameDisplay = key.key_name || 'N/A';
                    const keyNameWithLabel = key._isDuplicate ?
                        `<div style="display: flex; align-items: center; gap: 8px;"><span>${keyNameDisplay}</span><span class="badge" style="background: #fee2e2; color: #dc2626; margin-left: 6px; font-size: 10px;">⚠️ Duplicate</span></div>` :
                        keyNameDisplay;

                    let envBadgeClass = 'badge-secondary';
                    let envText = 'Unknown';
                    if (key.inferred_environment_type) {
                        envText = key.inferred_environment_type.charAt(0).toUpperCase() + key.inferred_environment_type.slice(1);
                        const envLower = key.inferred_environment_type.toLowerCase();
                        if (envLower === 'production') envBadgeClass = 'badge-danger';
                        else if (envLower === 'staging') envBadgeClass = 'badge-warning';
                        else if (envLower === 'development') envBadgeClass = 'badge-info';
                        else if (envLower === 'testing') envBadgeClass = 'badge-primary';
                    }
                    const confidencePct = key.inferred_discovery_confidence ? (key.inferred_discovery_confidence * 100).toFixed(0) : '0';

                    return `<tr ${rowClass ? `class="${rowClass}"` : ''}>
                        <td>${keyNameWithLabel}</td>
                        <td>${key.key_type || 'Unknown'}</td>
                        <td>${key.key_size || '—'}</td>
                        <td>${sourceDisplay}${sourceBadge}</td>
                        <td><span class="badge ${envBadgeClass}" title="Confidence: ${confidencePct}%">${envText}</span></td>
                        <td>${key.is_hsm_backed ? 'Yes' : 'No'}</td>
                        <td><span class="status-badge" style="background: #dcfce7; color: #15803d; padding: 4px 8px; border-radius: 4px; font-size: 11px;">ACTIVE</span></td>
                        <td style="text-align: right;">
                            <button class="btn-key-view" data-key-index="${originalIdx}" style="padding: 4px 8px; font-size: 11px; margin-right: 4px;">View</button>
                            <button class="btn-key-enrich" data-key-index="${originalIdx}" data-key-id="${key.key_id || key.id}" style="padding: 4px 8px; font-size: 11px; background: #fbbf24; color: #78350f; border: 1px solid #f59e0b; border-radius: 4px; cursor: pointer;">Enrich</button>
                        </td>
                    </tr>`;
                }).join('');

                // Re-attach event listeners
                tbody.querySelectorAll('.btn-key-view').forEach(btn => {
                    btn.addEventListener('click', function() {
                        const idx = this.getAttribute('data-key-index');
                        showKeyDetails(window.assetsCurrentKeys[idx]);
                    });
                });

                // Re-attach event listeners for Enrich buttons
                tbody.querySelectorAll('.btn-key-enrich').forEach(btn => {
                    btn.addEventListener('click', function() {
                        const idx = this.getAttribute('data-key-index');
                        const keyId = this.getAttribute('data-key-id');
                        openAssetEnrichmentModal(window.assetsCurrentKeys[idx], 'key', keyId);
                    });
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: #6b7280;">No keys match your search/filters</td></tr>';
            }
        }

        async function loadAssetsKeys(page = 1) {
            try {
                console.log('loadAssetsKeys called with page:', page);
                const response = await fetch(`/api/v1/inventory/search`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        asset_types: ['keys'],
                        filters: {},
                        page: page,
                        page_size: 999,
                        include_inactive: true
                    })
                });

                console.log('API response status:', response.status, response.ok);
                if (!response.ok) throw new Error(`Failed to load keys: ${response.status}`);
                const data = await response.json();

                console.log('API response data:', data);

                // Populate the table
                const tbody = document.getElementById('assetsKeysTableBody');
                console.log('Found tbody element:', tbody ? 'YES' : 'NO');

                if (tbody) {
                    if (data.data && data.data.length > 0) {
                        console.log('Populating', data.data.length, 'keys');
                        window.assetsCurrentKeys = data.data;
                        tbody.innerHTML = data.data.map((key, idx) => {
                            let sourceDisplay = 'Unknown';
                            let sourceBadge = '';
                            if (key.is_promoted || key.source_type === 'promoted_scan') {
                                sourceDisplay = key.promoted_from_scan_name || 'Promoted Scan';
                                sourceBadge = '<span class="badge" style="background: #fef3c7; color: #92400e; margin-left: 6px;">📌 Promoted</span>';
                            } else if (key.integration_name) {
                                sourceDisplay = key.integration_name;
                                sourceBadge = '<span class="badge" style="background: #dbeafe; color: #1e40af; margin-left: 6px;">🔄 Synced</span>';
                            } else if (key.source_type) {
                                sourceDisplay = key.source_type;
                            }
                            let envBadgeClass = 'badge-secondary';
                            let envText = 'Unknown';
                            if (key.inferred_environment_type) {
                                envText = key.inferred_environment_type.charAt(0).toUpperCase() + key.inferred_environment_type.slice(1);
                                const envLower = key.inferred_environment_type.toLowerCase();
                                if (envLower === 'production') envBadgeClass = 'badge-danger';
                                else if (envLower === 'staging') envBadgeClass = 'badge-warning';
                                else if (envLower === 'development') envBadgeClass = 'badge-info';
                                else if (envLower === 'testing') envBadgeClass = 'badge-primary';
                            }
                            const confidencePct = key.inferred_discovery_confidence ? (key.inferred_discovery_confidence * 100).toFixed(0) : '0';
                            return `
                            <tr>
                                <td>${key.key_name || 'N/A'}</td>
                                <td>${key.key_type || 'Unknown'}</td>
                                <td>${key.key_size || '—'}</td>
                                <td>${sourceDisplay}${sourceBadge}</td>
                                <td><span class="badge ${envBadgeClass}" title="Confidence: ${confidencePct}%">${envText}</span></td>
                                <td>${key.is_hsm_backed ? 'Yes' : 'No'}</td>
                                <td><span class="status-badge" style="background: #dcfce7; color: #15803d; padding: 4px 8px; border-radius: 4px; font-size: 11px;">ACTIVE</span></td>
                                <td style="text-align: right;">
                                    <button class="btn-key-view" data-key-index="${idx}" style="padding: 4px 8px; font-size: 11px; margin-right: 4px;">View</button>
                                    <button class="btn-key-enrich" data-key-index="${idx}" data-key-id="${key.key_id || key.id}" style="padding: 4px 8px; font-size: 11px; background: #fbbf24; color: #78350f; border: 1px solid #f59e0b; border-radius: 4px; cursor: pointer;">Enrich</button>
                                </td>
                            </tr>
                        `;
                        }).join('');

                        // Add event listeners to View buttons
                        tbody.querySelectorAll('.btn-key-view').forEach(btn => {
                            btn.addEventListener('click', function() {
                                const idx = this.getAttribute('data-key-index');
                                showKeyDetails(window.assetsCurrentKeys[idx]);
                            });
                        });

                        // Add event listeners to Enrich buttons
                        tbody.querySelectorAll('.btn-key-enrich').forEach(btn => {
                            btn.addEventListener('click', function() {
                                const idx = this.getAttribute('data-key-index');
                                const keyId = this.getAttribute('data-key-id');
                                openAssetEnrichmentModal(window.assetsCurrentKeys[idx], 'key', keyId);
                            });
                        });

                        // Populate filter dropdowns
                        populateAssetFilterDropdowns();

                        // Update key summary cards
                        const totalKeys = data.data.length;
                        const hsmKeys = data.data.filter(k => k.is_hsm_backed).length;
                        const rsaKeys = data.data.filter(k => k.key_type === 'RSA').length;
                        const ecdsaKeys = data.data.filter(k => k.key_type === 'ECDSA').length;

                        document.getElementById('keySummaryTotal').textContent = totalKeys;
                        document.getElementById('keySummaryHSM').textContent = hsmKeys;
                        document.getElementById('keySummaryRSA').textContent = rsaKeys;
                        document.getElementById('keySummaryECDSA').textContent = ecdsaKeys;

                        // Add event listeners to filter inputs
                        const keySearchInput = document.getElementById('assetsKeySearchInput');
                        const keyFilterSelect = document.getElementById('assetsKeyFilterSelect');
                        const keyKeySizeFilter = document.getElementById('assetsKeyKeySizeFilter');
                        const keySourceFilter = document.getElementById('assetsKeySourceFilter');
                        const keyEnvironmentFilter = document.getElementById('assetsKeyEnvironmentFilter');
                        const keyHSMFilter = document.getElementById('assetsKeyHSMFilter');

                        if (keySearchInput) keySearchInput.addEventListener('input', filterAssetsKeys);
                        if (keyFilterSelect) keyFilterSelect.addEventListener('change', filterAssetsKeys);
                        if (keyKeySizeFilter) keyKeySizeFilter.addEventListener('change', filterAssetsKeys);
                        if (keySourceFilter) keySourceFilter.addEventListener('change', filterAssetsKeys);
                        if (keyEnvironmentFilter) keyEnvironmentFilter.addEventListener('change', filterAssetsKeys);
                        if (keyHSMFilter) keyHSMFilter.addEventListener('change', filterAssetsKeys);

                        // Apply deduplication filtering and rendering on initial load
                        filterAssetsKeys();
                    } else {
                        console.log('No keys data returned');
                    }
                }
            } catch (error) {
                console.error('Error loading assets keys:', error);
            }
        }

        async function loadAssetsDashboard() {
            try {
                console.log('loadAssetsDashboard called');

                // Fetch certificates data
                const certResponse = await fetch(`/api/v1/inventory/search`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        asset_types: ['certificates'],
                        filters: {},
                        page: 1,
                        page_size: 1000
                    })
                });

                console.log('Cert API response status:', certResponse.status, certResponse.ok);
                if (!certResponse.ok) throw new Error(`Failed to load certificates: ${certResponse.status}`);
                const certData = await certResponse.json();
                console.log('Cert API response:', certData);

                const certs = certData.data || [];

                // Fetch keys data from lifecycle/rotations endpoint (includes PQC analysis)
                const keyResponse = await fetch(`/api/v1/lifecycle/rotations`);
                if (!keyResponse.ok) throw new Error(`Failed to load keys: ${keyResponse.status}`);
                const keyData = await keyResponse.json();

                const keys = keyData.keys || [];

                // Calculate metrics - Certificates
                const totalCerts = certs.length;
                const expiringCerts = certs.filter(c => c.days_until_expiry !== null && c.days_until_expiry <= 30 && c.days_until_expiry > 0).length;
                const expiredCerts = certs.filter(c => c.days_until_expiry !== null && c.days_until_expiry <= 0).length;
                const strongCerts = certs.filter(c => {
                    const algo = (c.key_algorithm || c.key_type || '').toUpperCase();
                    const size = c.key_size || 0;
                    return (algo.includes('RSA') && size >= 4096) || (algo.includes('EC') && size >= 256);
                }).length;

                // Calculate metrics - Keys (using same logic as Lifecycle tab)
                const totalKeys = keys.length;
                const hsmKeys = keys.filter(k => k.is_hsm_backed === true || k.is_hsm_backed === 1).length;

                const pqcRiskKeys = keys.filter(k => k.pqc_analysis?.vulnerability_level === 'critical').length;

                // Count enabled integrations (not just unique connectors in certs)
                let enabledIntegrationCount = 0;
                let allIntegrations = [];
                try {
                    const integrationsResponse = await fetch('/api/v1/inventory/integrations');
                    if (integrationsResponse.ok) {
                        const integrationsData = await integrationsResponse.json();
                        allIntegrations = integrationsData.integrations || [];
                        enabledIntegrationCount = allIntegrations.filter(i => i.enabled === true || i.enabled === 1).length;
                    }
                } catch (e) {
                    console.error('Error fetching integrations count:', e);
                    // Fallback to counting unique connectors
                    enabledIntegrationCount = new Set(certs.map(c => c.connector_id)).size;
                }

                console.log('Dashboard metrics:', { totalCerts, expiringCerts, expiredCerts, totalKeys, enabledIntegrations: enabledIntegrationCount });

                // Update metric cards - verify elements exist first
                const certCards = {
                    'metric-total-certs': totalCerts,
                    'metric-expiring-soon': expiringCerts,
                    'metric-expired': expiredCerts,
                    'metric-strong-certs': strongCerts,
                    'metric-total-keys': totalKeys,
                    'metric-hsm-keys': hsmKeys,
                    'metric-pqc-risk-keys': pqcRiskKeys,
                    'metric-active-integrations': enabledIntegrationCount
                };

                Object.entries(certCards).forEach(([id, value]) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = value;
                });

                // Update charts
                updateAssetStatusChart(certs);
                updateAssetAlgorithmChart(certs);
                updateAssetKeyTypeChart(keys);
                updateAssetExpiryChart(certs);
                updateAssetKeySizeChart(certs);
                updateAssetSourceChart(certs, keys);

                // Update Integration Details table
                if (allIntegrations.length > 0) {
                    updateCLMDashboard(certs, keys, allIntegrations);
                }

            } catch (error) {
                console.error('Error loading assets dashboard:', error);
                console.error('Error stack:', error.stack);
            }
        }

        function updateAssetStatusChart(certs) {
            try {
                const activeCount = certs.filter(c => c.days_until_expiry === null || c.days_until_expiry > 0).length;
                const expiringCount = certs.filter(c => c.days_until_expiry !== null && c.days_until_expiry <= 30 && c.days_until_expiry > 0).length;
                const expiredCount = certs.filter(c => c.days_until_expiry !== null && c.days_until_expiry <= 0).length;

                const ctx = document.getElementById('statusPieChart');
                if (!ctx) return;

                if (window.assetStatusChart) {
                    window.assetStatusChart.destroy();
                }

                window.assetStatusChart = new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: ['Active', 'Expiring Soon', 'Expired'],
                        datasets: [{
                            data: [activeCount, expiringCount, expiredCount],
                            backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error updating status chart:', error);
            }
        }

        function updateAssetAlgorithmChart(certs) {
            try {
                const algorithmCounts = {};
                certs.forEach(cert => {
                    const algo = cert.key_algorithm || 'Unknown';
                    algorithmCounts[algo] = (algorithmCounts[algo] || 0) + 1;
                });

                const ctx = document.getElementById('algorithmDoughnutChart');
                if (!ctx) return;

                if (window.assetAlgorithmChart) {
                    window.assetAlgorithmChart.destroy();
                }

                const colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#43e97b', '#fa709a', '#fee140', '#30cfd0'];

                window.assetAlgorithmChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(algorithmCounts),
                        datasets: [{
                            data: Object.values(algorithmCounts),
                            backgroundColor: colors.slice(0, Object.keys(algorithmCounts).length),
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error updating algorithm chart:', error);
            }
        }

        function updateAssetKeyTypeChart(keys) {
            try {
                const typeCounts = {};
                keys.forEach(key => {
                    const type = key.key_type || 'Unknown';
                    typeCounts[type] = (typeCounts[type] || 0) + 1;
                });

                const ctx = document.getElementById('keyUsageChart');
                if (!ctx) return;

                if (window.assetKeyTypeChart) {
                    window.assetKeyTypeChart.destroy();
                }

                const colors = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'];

                window.assetKeyTypeChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(typeCounts),
                        datasets: [{
                            label: 'Count',
                            data: Object.values(typeCounts),
                            backgroundColor: colors.slice(0, Object.keys(typeCounts).length)
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        plugins: {
                            legend: { display: false }
                        }
                    }
                });
            } catch (error) {
                console.error('Error updating key type chart:', error);
            }
        }

        function updateAssetExpiryChart(certs) {
            try {
                const expiryBuckets = {
                    'Expired': 0,
                    'Within 30 days': 0,
                    'Within 90 days': 0,
                    'Within 1 year': 0,
                    'Beyond 1 year': 0,
                    'No expiry': 0
                };

                certs.forEach(cert => {
                    const days = cert.days_until_expiry;
                    if (days === null) {
                        expiryBuckets['No expiry']++;
                    } else if (days <= 0) {
                        expiryBuckets['Expired']++;
                    } else if (days <= 30) {
                        expiryBuckets['Within 30 days']++;
                    } else if (days <= 90) {
                        expiryBuckets['Within 90 days']++;
                    } else if (days <= 365) {
                        expiryBuckets['Within 1 year']++;
                    } else {
                        expiryBuckets['Beyond 1 year']++;
                    }
                });

                const ctx = document.getElementById('expiryTimelineChart');
                if (!ctx) return;

                if (window.assetExpiryChart) {
                    window.assetExpiryChart.destroy();
                }

                window.assetExpiryChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(expiryBuckets),
                        datasets: [{
                            label: 'Certificates',
                            data: Object.values(expiryBuckets),
                            backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#a3e635', '#10b981', '#6b7280']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            } catch (error) {
                console.error('Error updating expiry chart:', error);
            }
        }

        function updateAssetKeySizeChart(certs) {
            try {
                const sizeCounts = {};
                certs.forEach(cert => {
                    const size = cert.key_size ? `${cert.key_size}` : 'Unknown';
                    sizeCounts[size] = (sizeCounts[size] || 0) + 1;
                });

                const ctx = document.getElementById('keySizeChart');
                if (!ctx) return;

                if (window.assetKeySizeChart) {
                    window.assetKeySizeChart.destroy();
                }

                window.assetKeySizeChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(sizeCounts),
                        datasets: [{
                            label: 'Count',
                            data: Object.values(sizeCounts),
                            backgroundColor: '#667eea'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            } catch (error) {
                console.error('Error updating key size chart:', error);
            }
        }

        function updateAssetSourceChart(certs, keys) {
            try {
                const sources = {};
                certs.forEach(cert => {
                    const source = cert.source_type || 'Unknown';
                    sources[source] = (sources[source] || 0) + 1;
                });

                const ctx = document.getElementById('integrationBarChart');
                if (!ctx) return;

                if (window.assetSourceChart) {
                    window.assetSourceChart.destroy();
                }

                window.assetSourceChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(sources),
                        datasets: [{
                            label: 'Certificates',
                            data: Object.values(sources),
                            backgroundColor: '#764ba2'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            } catch (error) {
                console.error('Error updating source chart:', error);
            }
        }

        async function loadLifecycleOverview() {
            try {
                const response = await fetch('/api/v1/lifecycle/overview');
                if (!response.ok) throw new Error('Failed to load lifecycle overview');
                const data = await response.json();

                // Row 1a: Update certificate expiry status cards
                const expiry = data.expiry_summary || {};
                document.getElementById('lc-expired-count').textContent = expiry.expired || 0;
                document.getElementById('lc-expiring7-count').textContent = expiry.expiring_7_days || 0;
                document.getElementById('lc-expiring30-count').textContent = expiry.expiring_30_days || 0;
                document.getElementById('lc-expiring90-count').textContent = expiry.expiring_90_days || 0;

                // Row 1b: Fetch and display key metrics
                const keysResponse = await fetch('/api/v1/lifecycle/rotations');
                if (keysResponse.ok) {
                    const keysData = await keysResponse.json();
                    const keys = keysData.keys || [];

                    // Calculate PQC risk counts
                    const pqcCritical = keys.filter(k => k.pqc_analysis?.vulnerability_level === 'critical').length;
                    const pqcHigh = keys.filter(k => k.pqc_analysis?.vulnerability_level === 'high').length;
                    const hsmBacked = keys.filter(k => k.is_hsm_backed).length;
                    const totalKeys = keys.length;

                    document.getElementById('lc-pqc-critical-count').textContent = pqcCritical;
                    document.getElementById('lc-pqc-high-count').textContent = pqcHigh;
                    document.getElementById('lc-hsm-count').textContent = hsmBacked;
                    document.getElementById('lc-total-keys-count').textContent = totalKeys;
                }

                // Row 2: Render source health grid
                renderSourceHealthGrid(data.source_health || []);

                // Row 3: Render recent changes feed
                renderRecentChangesFeed(data.recent_changes || []);

                // Row 3: Render upcoming renewals table
                renderUpcomingRenewalsTable(data.upcoming_renewals || []);

            } catch (error) {
                console.error('Error loading lifecycle overview:', error);
                document.getElementById('lc-recent-changes').innerHTML = '<div style="text-align: center; color: #e74c3c; padding: 20px;">Error loading data</div>';
            }
        }

        function renderSourceHealthGrid(sources) {
            const grid = document.getElementById('lc-source-health-grid');
            if (!sources || sources.length === 0) {
                grid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; color: #999; padding: 20px;">No integrations configured</div>';
                return;
            }

            grid.innerHTML = sources.map(source => {
                // Get connector icon based on type
                const typeIcon = source.connector_type === 'ejbca' ? '🔑' :
                                source.connector_type === 'luna_hsm' ? '🛡️' :
                                source.connector_type === 'azure_keyvault' ? '☁️' :
                                source.connector_type === 'crl' ? '📋' : '🔗';

                return `
                    <div style="border: 1px solid #e0e0e0; border-radius: 10px; padding: 14px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.08); transition: all 0.2s;">
                        <div style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 12px;">
                            <div style="font-size: 24px;">${typeIcon}</div>
                            <div style="flex: 1; min-width: 0;">
                                <div style="font-weight: 700; color: #1f2937; margin-bottom: 2px; font-size: 13px; word-break: break-word;">
                                    ${source.connector_name || 'Unknown'}
                                </div>
                                <div style="font-size: 11px; color: #6b7280;">
                                    ${source.connector_type || 'Unknown'}
                                </div>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding: 10px 0; border-top: 1px solid #f0f0f0; border-bottom: 1px solid #f0f0f0; font-size: 12px;">
                            <div>
                                <div style="color: #9ca3af; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px;">Certificates</div>
                                <div style="color: #1f2937; font-weight: 600; font-size: 14px;">${source.certificates_total || 0}</div>
                            </div>
                            <div>
                                <div style="color: #9ca3af; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px;">Keys</div>
                                <div style="color: #1f2937; font-weight: 600; font-size: 14px;">${source.keys_total || 0}</div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function renderRecentChangesFeed(changes) {
            const feedDiv = document.getElementById('lc-recent-changes');
            if (!changes || changes.length === 0) {
                feedDiv.innerHTML = '<div style="text-align: center; color: #999; padding: 20px; font-size: 13px;">No recent changes</div>';
                return;
            }

            feedDiv.innerHTML = changes.map(change => {
                const changeType = change.change_type || 'updated';
                const icon = changeType === 'added' ? '✨' :
                            changeType === 'updated' ? '🔄' :
                            changeType === 'removed' ? '❌' :
                            changeType === 'reappeared' ? '⚡' : '🔄';
                const timestamp = change.detected_at ? new Date(change.detected_at).toLocaleString() : 'Unknown';

                // Extract entity name from change_details
                let entityName = 'Unknown';
                let details = change.change_details;

                // Parse if it's a string
                if (typeof details === 'string') {
                    try {
                        details = JSON.parse(details);
                    } catch (e) {
                        details = {};
                    }
                }

                // For ADDED/REAPPEARED, subject_cn is at top level
                if (details.subject_cn || details.key_name) {
                    entityName = details.subject_cn || details.key_name;
                }
                // For UPDATED, need to extract from 'current' JSON (which may be truncated)
                else if (details.current) {
                    // Try parsing the current field
                    try {
                        let currentData = JSON.parse(details.current);
                        entityName = currentData.subject_cn || currentData.key_name || 'Unknown';
                    } catch (e) {
                        // JSON is truncated, use regex to extract commonName from subject
                        let match = details.current.match(/"commonName"\s*:\s*"([^"]+)"/);
                        if (match && match[1]) {
                            entityName = match[1];
                        } else {
                            // Try extracting subject_cn if it exists
                            let cnMatch = details.current.match(/"subject_cn"\s*:\s*"([^"]+)"/);
                            if (cnMatch && cnMatch[1]) {
                                entityName = cnMatch[1];
                            } else {
                                entityName = 'Updated';
                            }
                        }
                    }
                }
                // For REMOVED, may not have details
                else if (changeType === 'removed') {
                    entityName = 'Removed asset';
                }

                const entityType = change.entity_type === 'certificate' ? 'Cert' : 'Key';

                return `
                    <div style="padding: 10px 0; border-bottom: 1px solid #f0f0f0; display: flex; gap: 10px; font-size: 12px;">
                        <span style="font-size: 16px; flex-shrink: 0;">${icon}</span>
                        <div style="flex: 1;">
                            <div style="color: #333; margin-bottom: 2px;">
                                <strong title="${entityName}">${entityName.substring(0, 35)}${entityName.length > 35 ? '...' : ''}</strong>
                            </div>
                            <div style="color: #999; font-size: 11px;">
                                ${changeType.charAt(0).toUpperCase() + changeType.slice(1)} (${entityType}) • ${timestamp}
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function renderUpcomingRenewalsTable(renewals) {
            const tbody = document.getElementById('lc-upcoming-renewals-tbody');
            if (!renewals || renewals.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 20px; color: #999;">No renewals due in the next 90 days</td></tr>';
                return;
            }

            tbody.innerHTML = renewals.map(renewal => {
                const daysUntilExpiry = renewal.days_until_expiry || renewal.days_until_expiration || 0;
                let badgeColor = '#10b981'; // Green
                if (daysUntilExpiry < 0) badgeColor = '#ef4444'; // Red - Expired
                else if (daysUntilExpiry <= 7) badgeColor = '#f97316'; // Orange - Critical
                else if (daysUntilExpiry <= 30) badgeColor = '#f59e0b'; // Yellow - Warning

                const subject = renewal.subject_cn || renewal.subject || 'Unknown';
                const source = renewal.source_integration || renewal.source_type || 'Unknown';

                return `
                    <tr style="border-bottom: 1px solid #f0f0f0;">
                        <td style="padding: 10px 0; color: #333; font-size: 12px;" title="${subject}">${subject.substring(0, 30)}${subject.length > 30 ? '...' : ''}</td>
                        <td style="padding: 10px 0; text-align: center;">
                            <span style="display: inline-block; background: ${badgeColor}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px;">
                                ${daysUntilExpiry}d
                            </span>
                        </td>
                        <td style="padding: 10px 0; color: #666; font-size: 12px;">${source}</td>
                    </tr>
                `;
            }).join('');
        }

        window.lcrAllCerts = [];
        window.lcrCurrentFilter = 'all';

        async function loadLifecycleCertificates() {
            try {
                const response = await fetch('/api/v1/lifecycle/renewals');
                if (!response.ok) throw new Error('Failed to load lifecycle renewals');
                const data = await response.json();

                // Populate summary cards
                const expiry = data.expiry_summary || {};
                document.getElementById('lcr-expired-count').textContent = expiry.expired || 0;
                document.getElementById('lcr-expiring30-count').textContent = expiry.expiring_30_days || 0;
                document.getElementById('lcr-expiring90-count').textContent = expiry.expiring_90_days || 0;

                // Store all certs
                window.lcrAllCerts = data.certificates || [];

                // Attach filter tab event listeners
                document.querySelectorAll('.lcr-filter-btn').forEach(btn => {
                    btn.addEventListener('click', function() {
                        document.querySelectorAll('.lcr-filter-btn').forEach(b => b.classList.remove('active'));
                        this.classList.add('active');
                        this.style.background = '#e5e7eb';
                        this.style.color = '#1f2937';
                        window.lcrCurrentFilter = this.dataset.filter;
                        renderRenewalsTable(window.lcrCurrentFilter);
                    });
                });

                // Initial render
                renderRenewalsTable('all');

            } catch (error) {
                console.error('Error loading lifecycle certificates:', error);
                const tbody = document.getElementById('lcr-cert-tbody');
                if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="padding: 20px; text-align: center; color: #ef4444;">Error loading certificates</td></tr>';
            }
        }

        function renderRenewalsTable(filter) {
            const tbody = document.getElementById('lcr-cert-tbody');
            const countLabel = document.getElementById('lcr-count-label');

            if (!window.lcrAllCerts || window.lcrAllCerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="padding: 40px 16px; text-align: center; color: #9ca3af;">No certificates found</td></tr>';
                countLabel.textContent = 'Showing 0 certificates';
                return;
            }

            // Filter certs by urgency band
            let filtered = window.lcrAllCerts;
            if (filter !== 'all') {
                filtered = window.lcrAllCerts.filter(cert => {
                    const days = cert.days_until_expiration || cert.days_until_expiry || 0;
                    if (filter === 'expired') return days < 0;
                    if (filter === '7d') return days >= 0 && days <= 7;
                    if (filter === '30d') return days > 7 && days <= 30;
                    if (filter === '90d') return days > 30 && days <= 90;
                    if (filter === 'valid') return days > 90;
                    return true;
                });
            }

            // Render rows
            tbody.innerHTML = filtered.map(cert => {
                const days = cert.days_until_expiration || cert.days_until_expiry || 0;
                const subject = cert.subject_cn || 'Unknown';
                const issuer = cert.issuer_cn || 'Unknown';
                const notAfter = cert.not_after ? new Date(cert.not_after).toLocaleDateString() : 'Unknown';
                const algorithm = cert.public_key_algorithm && cert.public_key_size
                    ? `${cert.public_key_algorithm} ${cert.public_key_size}`
                    : 'Unknown';
                const source = cert.source_integration || cert.source_type || 'Unknown';
                const pqcStatus = cert.migration_status === 'needs_migration' ? 'Needs Migration' : 'PQC Ready';
                const pqcColor = cert.migration_status === 'needs_migration' ? '#ef4444' : '#10b981';

                // Days badge color
                let badgeColor = '#10b981';
                if (days < 0) badgeColor = '#ef4444';
                else if (days <= 7) badgeColor = '#f97316';
                else if (days <= 30) badgeColor = '#f59e0b';
                else if (days <= 90) badgeColor = '#eab308';

                // Row border color based on urgency
                let borderColor = '#e5e7eb';
                if (days < 0) borderColor = '#ef4444';
                else if (days <= 7) borderColor = '#f97316';
                else if (days <= 30) borderColor = '#f59e0b';
                else if (days <= 90) borderColor = '#eab308';

                return `
                    <tr style="border-bottom: 1px solid #f0f0f0; border-left: 4px solid ${borderColor};">
                        <td style="padding: 12px 16px; color: #1f2937;" title="${subject}">${subject.substring(0, 40)}${subject.length > 40 ? '...' : ''}</td>
                        <td style="padding: 12px 16px; color: #6b7280;" title="${issuer}">${issuer.substring(0, 35)}${issuer.length > 35 ? '...' : ''}</td>
                        <td style="padding: 12px 16px; text-align: center; color: #6b7280; font-size: 12px;">${notAfter}</td>
                        <td style="padding: 12px 16px; text-align: center;">
                            <span style="display: inline-block; background: ${badgeColor}; color: white; padding: 4px 10px; border-radius: 5px; font-weight: 600; font-size: 12px;">
                                ${days}d
                            </span>
                        </td>
                        <td style="padding: 12px 16px; color: #6b7280; font-size: 12px;">${algorithm}</td>
                        <td style="padding: 12px 16px; color: #6b7280;">${source}</td>
                        <td style="padding: 12px 16px; text-align: center;">
                            <span style="display: inline-block; background: ${pqcColor}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 500; font-size: 11px;">
                                ${pqcStatus}
                            </span>
                        </td>
                    </tr>
                `;
            }).join('');

            countLabel.textContent = `Showing ${filtered.length} of ${window.lcrAllCerts.length} certificates`;
        }

        window.lkrAllKeys = [];
        window.lkrCurrentFilter = 'all';

        async function loadLifecycleKeys() {
            try {
                const response = await fetch('/api/v1/lifecycle/rotations');
                if (!response.ok) throw new Error('Failed to load lifecycle rotations');
                const data = await response.json();

                // Store all keys
                window.lkrAllKeys = data.keys || [];

                // Compute summary stats
                const hsmCount = window.lkrAllKeys.filter(k => k.is_hsm_backed === 1).length;
                const pqcNeedsCount = window.lkrAllKeys.filter(k =>
                    k.pqc_analysis && k.pqc_analysis.migration_status === 'needs_migration'
                ).length;

                // Populate summary cards
                document.getElementById('lkr-total-count').textContent = data.total_keys || 0;
                document.getElementById('lkr-hsm-count').textContent = hsmCount;
                document.getElementById('lkr-pqc-count').textContent = pqcNeedsCount;

                // Attach filter tab event listeners
                document.querySelectorAll('.lkr-filter-btn').forEach(btn => {
                    btn.addEventListener('click', function() {
                        document.querySelectorAll('.lkr-filter-btn').forEach(b => b.classList.remove('active'));
                        this.classList.add('active');
                        this.style.background = '#e5e7eb';
                        this.style.color = '#1f2937';
                        window.lkrCurrentFilter = this.dataset.filter;
                        renderRotationsTable(window.lkrCurrentFilter);
                    });
                });

                // Initial render
                renderRotationsTable('all');

            } catch (error) {
                console.error('Error loading lifecycle keys:', error);
                const tbody = document.getElementById('lkr-key-tbody');
                if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="padding: 20px; text-align: center; color: #ef4444;">Error loading keys</td></tr>';
            }
        }

        function renderRotationsTable(filter) {
            const tbody = document.getElementById('lkr-key-tbody');
            const countLabel = document.getElementById('lkr-count-label');

            if (!window.lkrAllKeys || window.lkrAllKeys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="padding: 40px 16px; text-align: center; color: #9ca3af;">No keys found</td></tr>';
                countLabel.textContent = 'Showing 0 keys';
                return;
            }

            // Filter keys by risk band
            let filtered = window.lkrAllKeys;
            if (filter !== 'all') {
                filtered = window.lkrAllKeys.filter(key => {
                    const pqcLevel = key.pqc_analysis ? key.pqc_analysis.vulnerability_level : null;
                    const hsmBacked = key.is_hsm_backed === 1;
                    const hasExpiry = key.expires_on && key.days_until_expiry !== null;

                    if (filter === 'critical-pqc') return pqcLevel === 'critical';
                    if (filter === 'high-pqc') return pqcLevel === 'high';
                    if (filter === 'has-expiry') return hasExpiry;
                    if (filter === 'hsm') return hsmBacked;
                    if (filter === 'software') return !hsmBacked;
                    return true;
                });
            }

            // Render rows
            tbody.innerHTML = filtered.map(key => {
                const keyName = key.name || 'Unknown';
                const keyType = key.key_type && key.key_size
                    ? `${key.key_type} ${key.key_size}`
                    : key.key_type || 'Unknown';
                const source = key.source_integration || key.source_type || 'Unknown';
                const hsmBadge = key.is_hsm_backed === 1 ? 'HSM' : 'Software';
                const hsmColor = key.is_hsm_backed === 1 ? '#8b5cf6' : '#6b7280';
                const keyClass = key.key_class ? key.key_class.charAt(0).toUpperCase() + key.key_class.slice(1) : 'Unknown';
                const expiryDate = key.expires_on ? new Date(key.expires_on).toLocaleDateString() : 'No expiry set';
                const days = key.days_until_expiry;
                const daysDisplay = days !== null && days !== undefined ? `${days}d` : '—';

                // PQC vulnerability level
                const pqcLevel = key.pqc_analysis ? key.pqc_analysis.vulnerability_level : null;
                const pqcStatus = pqcLevel ? pqcLevel.charAt(0).toUpperCase() + pqcLevel.slice(1) : 'Low';

                let pqcColor = '#10b981';
                if (pqcLevel === 'critical') pqcColor = '#ef4444';
                else if (pqcLevel === 'high') pqcColor = '#f97316';
                else if (pqcLevel === 'medium') pqcColor = '#f59e0b';

                // Row left-border colour based on PQC vulnerability
                let borderColor = '#e5e7eb';
                if (pqcLevel === 'critical') borderColor = '#ef4444';
                else if (pqcLevel === 'high') borderColor = '#f97316';
                else if (pqcLevel === 'medium') borderColor = '#f59e0b';

                return `
                    <tr style="border-bottom: 1px solid #f0f0f0; border-left: 4px solid ${borderColor};">
                        <td style="padding: 12px 16px; color: #1f2937; font-weight: 500;" title="${keyName}">${keyName.substring(0, 40)}${keyName.length > 40 ? '...' : ''}</td>
                        <td style="padding: 12px 16px; color: #6b7280;">${keyType}</td>
                        <td style="padding: 12px 16px; color: #6b7280;">${source}</td>
                        <td style="padding: 12px 16px; text-align: center;">
                            <span style="display: inline-block; background: ${hsmColor}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 500; font-size: 11px;">
                                ${hsmBadge}
                            </span>
                        </td>
                        <td style="padding: 12px 16px; color: #6b7280;">${keyClass}</td>
                        <td style="padding: 12px 16px; text-align: center; color: #6b7280; font-size: 12px;">${expiryDate}</td>
                        <td style="padding: 12px 16px; text-align: center;">
                            <span style="display: inline-block; background: #e5e7eb; color: #374151; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px;">
                                ${daysDisplay}
                            </span>
                        </td>
                        <td style="padding: 12px 16px; text-align: center;">
                            <span style="display: inline-block; background: ${pqcColor}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 500; font-size: 11px;">
                                ${pqcStatus}
                            </span>
                        </td>
                    </tr>
                `;
            }).join('');

            countLabel.textContent = `Showing ${filtered.length} of ${window.lkrAllKeys.length} keys`;
        }

        async function loadLifecyclePolicies() {
            try {
                const response = await fetch('/api/v1/lifecycle/policies');
                if (!response.ok) throw new Error('Failed to load lifecycle policies');
                const data = await response.json();

                const tbody = document.getElementById('lifecycle-policies-table');
                if (tbody && data.policies && data.policies.length > 0) {
                    tbody.innerHTML = data.policies.map(policy => `
                        <tr>
                            <td>${policy.connector_name}</td>
                            <td>${policy.renewal_threshold_days} days</td>
                            <td>${policy.rotation_interval_days || '—'}</td>
                            <td><span class="status-badge" style="background: ${policy.auto_execute ? '#dcfce7' : '#fef3c7'}; color: ${policy.auto_execute ? '#15803d' : '#92400e'}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">${policy.auto_execute ? 'AUTO' : 'HOLD'}</span></td>
                            <td><button class="btn-secondary" onclick="alert('Configure policy for: ' + '${policy.connector_name}')" style="padding: 4px 8px; font-size: 11px;">Configure</button></td>
                        </tr>
                    `).join('');
                } else if (tbody) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No lifecycle policies configured</td></tr>';
                }
            } catch (error) {
                console.error('Error loading lifecycle policies:', error);
            }
        }

function generateColors(count) {
    const baseColors = [
        '#6366f1', '#8b5cf6', '#a855f7', '#d946ef', '#ec4899',
        '#f43f5e', '#ef4444', '#f97316', '#f59e0b', '#eab308',
        '#84cc16', '#22c55e', '#10b981', '#14b8a6', '#06b6d4',
        '#0ea5e9', '#3b82f6', '#6366f1'
    ];
    const colors = [];
    for (let i = 0; i < count; i++) {
        colors.push(baseColors[i % baseColors.length]);
    }
    return colors;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Helper Functions for Modal Display
function formatStatus(status) {
    const labels = {
        'pqc_ready': 'PQC Ready',
        'hybrid_transition': 'Hybrid',
        'needs_migration': 'Needs Migration',
        'unknown': 'Unknown'
    };
    return labels[status] || status;
}

function extractCN(subject) {
    if (!subject) return 'Unknown';

    if (typeof subject === 'object') {
        if (subject.CN) return subject.CN;
        if (subject.commonName) return subject.commonName;
        if (subject.cn) return subject.cn;
        const keys = Object.keys(subject);
        for (const key of keys) {
            if (key.toLowerCase().includes('common') || key.toLowerCase().includes('cn')) {
                return subject[key];
            }
        }
        return 'Unknown';
    }

    return String(subject).split(',').find(part => {
        const [key] = part.split('=');
        return key && key.trim().toUpperCase() === 'CN';
    }) || 'Unknown';
}

// Asset Details Modal Functions

/**
 * Switch between certificate modal tabs
 */
function switchCertTab(event, tabName) {
    event.preventDefault();

    // Hide all tab content
    const tabContents = document.querySelectorAll('.cert-tab-content');
    tabContents.forEach(content => content.style.display = 'none');

    // Remove active class from all buttons
    const tabButtons = document.querySelectorAll('.cert-tab-btn');
    tabButtons.forEach(btn => btn.classList.remove('active'));

    // Show selected tab content
    const activeContent = document.getElementById(`cert-tab-${tabName}`);
    if (activeContent) {
        activeContent.style.display = 'block';
    }

    // Add active class to clicked button
    event.target.classList.add('active');
}

/**
 * Initialize certificate modal tab styling on load
 */
function initCertModalTabs() {
    // First tab is already marked as active in the HTML
    // CSS handles the styling automatically
}

/**
 * Save manual environment enrichment override for certificate
 * POST to /api/v1/context/enrich
 */
function saveEnrichment(button) {
    const certId = window.currentCertificateModalId;
    if (!certId) {
        alert('Certificate ID not found');
        return;
    }

    // Get current engagement ID (or use null for org-wide)
    const engagementId = window.currentEngagementId || null;

    // Collect form data - environment section
    const envType = document.getElementById('enrichment-env-type')?.value || '';
    const serviceName = document.getElementById('enrichment-service-name')?.value || '';
    const appName = document.getElementById('enrichment-app-name')?.value || '';

    // Collect form data - 19 extracted fields
    const extracted = {
        extracted_service_name: document.getElementById('extracted-service-name')?.value || null,
        extracted_organization: document.getElementById('extracted-organization')?.value || null,
        extracted_cloud_provider: document.getElementById('extracted-cloud-provider')?.value || null,
        extracted_region: document.getElementById('extracted-region')?.value || null,
        extracted_service_tier: document.getElementById('extracted-service-tier')?.value || null,
        extracted_domain_type: document.getElementById('extracted-domain-type')?.value || null,
        extracted_primary_purpose: document.getElementById('extracted-primary-purpose')?.value || null,
        extracted_ca_tier: document.getElementById('extracted-ca-tier')?.value || null,
        extracted_issuing_organization: document.getElementById('extracted-issuing-organization')?.value || null,
        extracted_criticality_tier: document.getElementById('extracted-criticality-tier')?.value || null,
        extracted_data_residency: document.getElementById('extracted-data-residency')?.value || null,
        extracted_crypto_strength: document.getElementById('extracted-crypto-strength')?.value || null,
        extracted_pqc_migration_needed: document.getElementById('extracted-pqc-migration-needed')?.value ? parseInt(document.getElementById('extracted-pqc-migration-needed').value) : null,
        extracted_ha_enabled: document.getElementById('extracted-ha-enabled')?.value ? parseInt(document.getElementById('extracted-ha-enabled').value) : null,
        extracted_replication_count: document.getElementById('extracted-replication-count')?.value ? parseInt(document.getElementById('extracted-replication-count').value) : null,
        extracted_san_base_name: document.getElementById('extracted-san-base-name')?.value || null,
        extracted_is_replicated: document.getElementById('extracted-is-replicated')?.value ? parseInt(document.getElementById('extracted-is-replicated').value) : null
    };

    // Show loading state
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Saving...';

    // Build request payload
    const payload = {
        asset_id: certId,
        asset_type: 'certificate',
        environment_type: envType || null,
        service_name: serviceName || null,
        application_name: appName || null,
        ...extracted
    };

    // Determine endpoint based on engagement_id
    const endpoint = engagementId
        ? `/api/v1/engagements/${engagementId}/context`
        : '/api/v1/context/enrich';

    // POST to backend
    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCookie('csrf_token') || ''
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Enrichment saved successfully:', data);

        // Show success message
        const successMsg = document.createElement('div');
        successMsg.style.cssText = 'position: absolute; top: 20px; right: 20px; background: #10b981; color: white; padding: 12px 16px; border-radius: 6px; z-index: 10001; font-size: 13px; font-weight: 600;';
        successMsg.textContent = '✓ Override saved';
        document.body.appendChild(successMsg);

        setTimeout(() => successMsg.remove(), 3000);

        // Update button states
        document.getElementById('enrichment-clear-btn').style.display = 'inline-block';

        // Update the displayed inferred values if needed
        // (Refresh modal to show updated priority chain)
    })
    .catch(error => {
        console.error('Error saving enrichment:', error);
        alert('Failed to save override: ' + error.message);
    })
    .finally(() => {
        button.disabled = false;
        button.textContent = originalText;
    });
}

/**
 * Clear manual environment enrichment override for certificate
 * DELETE to /api/v1/context/enrich
 */
function clearEnrichment(button) {
    const certId = window.currentCertificateModalId;
    if (!certId) {
        alert('Certificate ID not found');
        return;
    }

    // Confirm action
    if (!confirm('Clear all manual overrides for this certificate?')) {
        return;
    }

    // Get current engagement ID (or use null for org-wide)
    const engagementId = window.currentEngagementId || null;

    // Show loading state
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Clearing...';

    // Determine endpoint based on engagement_id
    const endpoint = engagementId
        ? `/api/v1/engagements/${engagementId}/context/${certId}`
        : `/api/v1/context/enrich/${certId}`;

    // DELETE to backend
    fetch(endpoint, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCookie('csrf_token') || ''
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Enrichment cleared successfully:', data);

        // Show success message
        const successMsg = document.createElement('div');
        successMsg.style.cssText = 'position: absolute; top: 20px; right: 20px; background: #10b981; color: white; padding: 12px 16px; border-radius: 6px; z-index: 10001; font-size: 13px; font-weight: 600;';
        successMsg.textContent = '✓ Override cleared';
        document.body.appendChild(successMsg);

        setTimeout(() => successMsg.remove(), 3000);

        // Clear all form inputs
        document.getElementById('enrichment-env-type').value = '';
        document.getElementById('enrichment-service-name').value = '';
        document.getElementById('enrichment-app-name').value = '';

        // Clear 19 extracted fields
        const extractedFields = [
            'extracted-service-name', 'extracted-organization', 'extracted-cloud-provider',
            'extracted-region', 'extracted-service-tier', 'extracted-domain-type',
            'extracted-primary-purpose', 'extracted-ca-tier', 'extracted-issuing-organization',
            'extracted-criticality-tier', 'extracted-data-residency', 'extracted-crypto-strength',
            'extracted-pqc-migration-needed', 'extracted-ha-enabled', 'extracted-replication-count',
            'extracted-san-base-name', 'extracted-is-replicated'
        ];

        extractedFields.forEach(fieldId => {
            const element = document.getElementById(fieldId);
            if (element) element.value = '';
        });

        // Hide clear button (re-enable save button)
        document.getElementById('enrichment-clear-btn').style.display = 'none';
    })
    .catch(error => {
        console.error('Error clearing enrichment:', error);
        alert('Failed to clear override: ' + error.message);
    })
    .finally(() => {
        button.disabled = false;
        button.textContent = originalText;
    });
}

/**
 * Toggle enrichment section collapse/expand
 */
function toggleEnrichmentSection(header) {
    const content = header.nextElementSibling;
    const arrow = header.querySelector('span:last-child');

    if (content && content.classList.contains('enrichment-collapse-content')) {
        const isHidden = content.style.display === 'none';
        content.style.display = isHidden ? 'block' : 'none';
        arrow.textContent = isHidden ? '▼' : '▶';
    }
}

/**
 * Load existing enrichment data for the current certificate modal
 * Populates form fields with existing overrides (if any)
 */
function loadEnrichmentData() {
    const certId = window.currentCertificateModalId;
    const engagementId = window.currentEngagementId || null;

    if (!certId) {
        return; // Certificate ID not available yet
    }

    // Determine endpoint based on engagement_id
    const endpoint = engagementId
        ? `/api/v1/engagements/${engagementId}/context/${certId}`
        : `/api/v1/context/enrich/${certId}`;

    // Fetch existing context data
    fetch(endpoint, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCookie('csrf_token') || ''
        }
    })
    .then(response => {
        if (response.status === 404) {
            console.log('No existing enrichment data for this certificate');
            // Disable clear button if no existing override
            const clearBtn = document.getElementById('enrichment-clear-btn');
            if (clearBtn) clearBtn.style.display = 'none';
            return null;
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (!data) return;

        console.log('Loaded enrichment data:', data);

        // Populate environment fields
        const envTypeSelect = document.getElementById('enrichment-env-type');
        const serviceNameInput = document.getElementById('enrichment-service-name');
        const appNameInput = document.getElementById('enrichment-app-name');

        if (envTypeSelect && data.environment_type) {
            envTypeSelect.value = data.environment_type;
        }
        if (serviceNameInput && data.service_name) {
            serviceNameInput.value = data.service_name;
        }
        if (appNameInput && data.application_name) {
            appNameInput.value = data.application_name;
        }

        // Populate 19 extracted fields
        const extractedFields = [
            'extracted_service_name', 'extracted_organization', 'extracted_cloud_provider',
            'extracted_region', 'extracted_service_tier', 'extracted_domain_type',
            'extracted_primary_purpose', 'extracted_ca_tier', 'extracted_issuing_organization',
            'extracted_criticality_tier', 'extracted_data_residency', 'extracted_crypto_strength',
            'extracted_pqc_migration_needed', 'extracted_ha_enabled', 'extracted_replication_count',
            'extracted_san_base_name', 'extracted_is_replicated'
        ];

        let hasAnyOverride = false;
        extractedFields.forEach(field => {
            const elementId = field.replace(/_/g, '-');
            const element = document.getElementById(elementId);
            if (element && data[field] !== null && data[field] !== undefined && data[field] !== '') {
                element.value = data[field];
                hasAnyOverride = true;
            }
        });

        // Show clear button if any override exists
        const clearBtn = document.getElementById('enrichment-clear-btn');
        if (clearBtn && (data.environment_type || data.service_name || data.application_name || hasAnyOverride)) {
            clearBtn.style.display = 'inline-block';
        }
    })
    .catch(error => {
        console.error('Error loading enrichment data:', error);
        // Don't show error to user, just continue with empty form
    });
}

function showCertificateDetails(cert) {
    // Merge normalised_data if available to get enriched fields
    let fullCert = cert;
    if (cert.normalised_data) {
        try {
            const enrichedData = typeof cert.normalised_data === 'string'
                ? JSON.parse(cert.normalised_data)
                : cert.normalised_data;

            // MERGE ORDER MATTERS (Phase 5):
            // 1. Base with enrichedData (Phase 2-4 normalized fields)
            // 2. Overlay cert (manual enrichment takes precedence)
            // 3. PRESERVE inferred_* and azure_* fields (ensure they're available)
            fullCert = {
                ...enrichedData,                              // Phase 2-4 normalized data
                ...cert,                                      // Manual enrichment overrides
                // Explicitly preserve Phase 2-4 inferred fields
                inferred_environment_type: enrichedData.inferred_environment_type,
                inferred_service_name: enrichedData.inferred_service_name,
                inferred_application_name: enrichedData.inferred_application_name,
                inferred_discovery_method: enrichedData.inferred_discovery_method,
                inferred_discovery_confidence: enrichedData.inferred_discovery_confidence,
                inferred_signal_breakdown: enrichedData.inferred_signal_breakdown,  // Phase 1: Signal breakdown from multi-signal fusion
                // Preserve all Phase 3 metadata fields
                inferred_identity_metadata: enrichedData.inferred_identity_metadata,
                inferred_purpose_metadata: enrichedData.inferred_purpose_metadata,
                inferred_crypto_metadata: enrichedData.inferred_crypto_metadata,
                inferred_ha_metadata: enrichedData.inferred_ha_metadata,
                // Preserve all Phase 2-4 Azure fields
                azure_tags: enrichedData.azure_tags,
                azure_key_type: enrichedData.azure_key_type,
                azure_managed: enrichedData.azure_managed,
                azure_version: enrichedData.azure_version,
                azure_enabled: enrichedData.azure_enabled,
                azure_recovery_level: enrichedData.azure_recovery_level,
                azure_vault_name: enrichedData.azure_vault_name,
                azure_vault_id: enrichedData.azure_vault_id,
                azure_vault_location: enrichedData.azure_vault_location,
                azure_vault_resource_group: enrichedData.azure_vault_resource_group,
                azure_vault_tier: enrichedData.azure_vault_tier,
                azure_subscription_id: enrichedData.azure_subscription_id,
                azure_created_on: enrichedData.azure_created_on,
                azure_updated_on: enrichedData.azure_updated_on,
                azure_expires_on: enrichedData.azure_expires_on,
                azure_not_before: enrichedData.azure_not_before,
            };
        } catch (e) {
            console.warn('Could not parse normalised_data:', e);
        }
    }

    const notAfter = new Date(fullCert.not_after || fullCert.expires_on);
    const notBefore = new Date(fullCert.not_before || fullCert.valid_from);

    let html = `
        <!-- Tab Navigation (4-Tab Structure) -->
        <div class="cert-tabs-container">
            <button class="cert-tab-btn active" onclick="switchCertTab(event, 'overview')">Overview</button>
            <button class="cert-tab-btn" onclick="switchCertTab(event, 'inferred')">Inferred</button>
            <button class="cert-tab-btn" onclick="switchCertTab(event, 'risk')">Risk</button>
            <button class="cert-tab-btn" onclick="switchCertTab(event, 'enrichment')">Enrichment</button>
        </div>

        <!-- TAB 1: OVERVIEW (Raw Certificate Facts) -->
        <div id="cert-tab-overview" class="cert-tab-content" style="display: block;">
        <!-- Basic Information -->
        <div class="modal-section">
            <h3>Basic Information</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Common Name</span>
                    <span class="field-value">${typeof fullCert.subject === 'string' ? (fullCert.subject_cn || fullCert.subject) : (fullCert.subject?.commonName || 'N/A')}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Serial Number</span>
                    <span class="field-value">${fullCert.serial_number || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Fingerprint (SHA-256)</span>
                    <span class="field-value">${fullCert.fingerprint_sha256 || 'N/A'}</span>
                </div>
            </div>
        </div>

        <!-- Validity Period -->
        <div class="modal-section">
            <h3>Validity Period</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Valid From</span>
                    <span class="field-value">${notBefore.toLocaleString()}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Valid Until</span>
                    <span class="field-value">${notAfter.toLocaleString()}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Days Until Expiration</span>
                    <span class="field-value">${Math.ceil((notAfter - new Date()) / (1000 * 60 * 60 * 24))} days</span>
                </div>
            </div>
        </div>

        <!-- Subject Information -->
        <div class="modal-section">
            <h3>Subject Information</h3>
            <div class="modal-section-content">
                ${typeof fullCert.subject === 'string' ? `
                    <div class="field-row">
                        <span class="field-label">Subject (Tokenized)</span>
                        <span class="field-value">${fullCert.subject}</span>
                    </div>
                ` : Object.entries(fullCert.subject || {}).map(([key, value]) => `
                    <div class="field-row">
                        <span class="field-label">${key.replace(/([A-Z])/g, ' $1')}</span>
                        <span class="field-value">${value || 'N/A'}</span>
                    </div>
                `).join('')}
            </div>
        </div>

        <!-- Issuer Information -->
        <div class="modal-section">
            <h3>Issuer Information</h3>
            <div class="modal-section-content">
                ${typeof fullCert.issuer === 'string' ? `
                    <div class="field-row">
                        <span class="field-label">Issuer (Tokenized)</span>
                        <span class="field-value">${fullCert.issuer}</span>
                    </div>
                ` : Object.entries(fullCert.issuer || {}).map(([key, value]) => `
                    <div class="field-row">
                        <span class="field-label">${key.replace(/([A-Z])/g, ' $1')}</span>
                        <span class="field-value">${value || 'N/A'}</span>
                    </div>
                `).join('')}
            </div>
        </div>

        <!-- Public Key Information -->
        <div class="modal-section">
            <h3>Public Key Information</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Algorithm</span>
                    <span class="field-value">${fullCert.public_key_algorithm || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Key Size</span>
                    <span class="field-value">${fullCert.public_key_size || 'N/A'} bits</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Signature Algorithm</span>
                    <span class="field-value">${fullCert.signature_algorithm || 'N/A'}</span>
                </div>
            </div>
        </div>

        <!-- Key Usage -->
        <div class="modal-section">
            <h3>Key Usage</h3>
            <div class="array-list">
                ${(fullCert.key_usage || []).map(usage => `<span class="array-item">${usage}</span>`).join('')}
            </div>
        </div>

        <!-- Extended Key Usage -->
        <div class="modal-section">
            <h3>Extended Key Usage</h3>
            <div class="array-list">
                ${(fullCert.extended_key_usage || []).map(eku => `<span class="array-item">${eku}</span>`).join('')}
            </div>
        </div>

        <!-- Subject Alternative Names -->
        <div class="modal-section">
            <h3>Subject Alternative Names (SANs)</h3>
            <div class="array-list">
                ${(fullCert.san || []).map(san => `<span class="array-item">${san.replace(/[<>]/g, '')}</span>`).join('')}
            </div>
        </div>

        <!-- Basic Constraints -->
        <div class="modal-section">
            <h3>Basic Constraints</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Is CA</span>
                    <span class="field-value">${fullCert.basic_constraints?.ca ? 'Yes' : 'No'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Path Length</span>
                    <span class="field-value">${fullCert.basic_constraints?.path_length || 'N/A'}</span>
                </div>
            </div>
        </div>

        <!-- Distribution Points -->
        <div class="modal-section">
            <h3>Distribution Points</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">CRL Distribution Points</span>
                    <div class="array-list">
                        ${(fullCert.crl_distribution_points || []).map(cdp => `<span class="array-item">${cdp}</span>`).join('')}
                    </div>
                </div>
                <div class="field-row">
                    <span class="field-label">OCSP Responders</span>
                    <div class="array-list">
                        ${(fullCert.ocsp_responders || []).map(ocsp => `<span class="array-item">${ocsp}</span>`).join('')}
                    </div>
                </div>
            </div>
        </div>

        <!-- Certificate Transparency -->
        <div class="modal-section">
            <h3>Certificate Transparency</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">SCTs Present</span>
                    <span class="field-value">${(fullCert.certificate_transparency_scts || []).length > 0 ? 'Yes' : 'No'}</span>
                </div>
            </div>
        </div>

        <!-- Certificate Chain -->
        ${(fullCert.certificate_chain && fullCert.certificate_chain.length > 0) ? `
        <div class="modal-section">
            <h3>Certificate Chain</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Chain Depth</span>
                    <span class="field-value">${fullCert.certificate_chain.length} certificate(s)</span>
                </div>
                <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                    <thead style="background: #f0f0f0; border-bottom: 2px solid #0078d4;">
                        <tr>
                            <th style="padding: 10px; text-align: left; font-weight: bold;">Position</th>
                            <th style="padding: 10px; text-align: left; font-weight: bold;">Subject</th>
                            <th style="padding: 10px; text-align: left; font-weight: bold;">Issuer</th>
                            <th style="padding: 10px; text-align: left; font-weight: bold;">Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${fullCert.certificate_chain.map((chainCert, i) => {
                            const chainSubject = typeof chainCert.subject === 'string' ? (chainCert.subject_cn || chainCert.subject) : (chainCert.subject?.commonName || 'Unknown');
                            const chainIssuer = typeof chainCert.issuer === 'string' ? (chainCert.issuer_cn || chainCert.issuer) : (chainCert.issuer?.commonName || 'Unknown');
                            let certType = 'Intermediate';
                            if (i === 0) certType = 'Leaf';
                            if (chainCert.is_self_signed) certType = 'Root';
                            const rowColor = i % 2 === 0 ? '#ffffff' : '#f9f9f9';

                            return `
                                <tr style="background: ${rowColor}; border-bottom: 1px solid #e0e0e0;">
                                    <td style="padding: 10px; vertical-align: top; font-weight: bold; color: #0078d4;">Cert ${i + 1}</td>
                                    <td style="padding: 10px; vertical-align: top; word-break: break-all;">${chainSubject}</td>
                                    <td style="padding: 10px; vertical-align: top; word-break: break-all;">${chainIssuer}</td>
                                    <td style="padding: 10px; vertical-align: top;">${certType}</td>
                                </tr>
                                <tr style="background: #fafafa; border-bottom: 1px solid #e0e0e0;">
                                    <td colspan="4" style="padding: 10px;">
                                        <div style="font-size: 0.9em; line-height: 1.6;">
                                            <div><strong>Serial:</strong> ${chainCert.serial_number || 'N/A'}</div>
                                            <div><strong>Valid Until:</strong> ${new Date(chainCert.not_after).toLocaleString()}</div>
                                            <div><strong>Self-Signed:</strong> ${chainCert.is_self_signed ? 'Yes' : 'No'}</div>
                                            <div style="margin-top: 8px; word-break: break-all;"><strong>Fingerprint:</strong><br><span style="font-family: monospace; font-size: 0.85em;">${chainCert.fingerprint_sha256 || 'N/A'}</span></div>
                                        </div>
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
        ` : ''}

        <!-- Certificate Details -->
        <div class="modal-section">
            <h3>Certificate Details</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Is Self-Signed</span>
                    <span class="field-value">${fullCert.is_self_signed ? 'Yes' : 'No'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Is CA</span>
                    <span class="field-value">${fullCert.is_ca ? 'Yes' : 'No'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Source</span>
                    <span class="field-value">${fullCert.source || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Unique ID</span>
                    <span class="field-value">${fullCert.unique_id || 'N/A'}</span>
                </div>
            </div>
        </div>

        <!-- SECTION: AZURE KEY VAULT METADATA (Phase 2-4) -->
        ${(fullCert.azure_vault_name) ? `
        <div class="modal-section" style="border-left: 4px solid #0078d4;">
            <h3>Azure Key Vault Metadata</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Vault Name</span>
                    <span class="field-value">${fullCert.azure_vault_name}</span>
                </div>
                ${fullCert.azure_vault_location ? `
                <div class="field-row">
                    <span class="field-label">Region</span>
                    <span class="field-value">${fullCert.azure_vault_location}</span>
                </div>
                ` : ''}
                ${fullCert.azure_vault_resource_group ? `
                <div class="field-row">
                    <span class="field-label">Resource Group</span>
                    <span class="field-value">${fullCert.azure_vault_resource_group}</span>
                </div>
                ` : ''}
                ${fullCert.azure_subscription_id ? `
                <div class="field-row">
                    <span class="field-label">Subscription ID</span>
                    <span class="field-value" style="font-family: monospace; font-size: 12px;">
                        ${fullCert.azure_subscription_id}
                    </span>
                </div>
                ` : ''}
                ${fullCert.azure_vault_tier ? `
                <div class="field-row">
                    <span class="field-label">Vault Tier</span>
                    <span class="field-value">${fullCert.azure_vault_tier}</span>
                </div>
                ` : ''}
                ${fullCert.azure_managed !== null && fullCert.azure_managed !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Managed Key</span>
                    <span class="field-value">${fullCert.azure_managed ? 'Yes' : 'No'}</span>
                </div>
                ` : ''}
                ${fullCert.azure_enabled !== null && fullCert.azure_enabled !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Enabled</span>
                    <span class="field-value">${fullCert.azure_enabled ? 'Yes' : 'No'}</span>
                </div>
                ` : ''}
                ${fullCert.azure_recovery_level ? `
                <div class="field-row">
                    <span class="field-label">Recovery Level</span>
                    <span class="field-value">${fullCert.azure_recovery_level}</span>
                </div>
                ` : ''}
                ${fullCert.azure_version ? `
                <div class="field-row">
                    <span class="field-label">Key Version</span>
                    <span class="field-value">${fullCert.azure_version}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}
        </div><!-- End Overview Tab -->

        <!-- TAB 2: INFERRED (Auto-Discovered Environment Data - Read-Only) -->
        <div id="cert-tab-inferred" class="cert-tab-content" style="display: none;">

        ${(!fullCert.inferred_environment_type && (!fullCert.inferred_signal_breakdown || fullCert.inferred_signal_breakdown.length === 0)) ? `
        <div class="modal-section" style="padding: 20px; text-align: center; color: #64748b;">
            <p>No inferred environment data available for this certificate.</p>
            <small>Environment inference data will appear here once Phase 1 enrichment is complete.</small>
        </div>
        ` : ''}

        <!-- SECTION 1: AUTO-DISCOVERED ENVIRONMENT (Phase 2-4) -->
        ${(fullCert.inferred_environment_type) ? `
        <div class="modal-section">
            <h3>Auto-Discovered Environment</h3>
            <p style="font-size: 12px; color: #64748b; margin-bottom: 12px;">
                Detected via ${(fullCert.inferred_discovery_method || 'unknown').replace(/-/g, ' ')}
                (${((fullCert.inferred_discovery_confidence || 0) * 100).toFixed(0)}% confidence)
            </p>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Environment</span>
                    <span class="field-value">
                        <span class="env-badge env-${fullCert.inferred_environment_type}">
                            ${fullCert.inferred_environment_type.charAt(0).toUpperCase() + fullCert.inferred_environment_type.slice(1)}
                        </span>
                        <span class="confidence-badge">
                            ${((fullCert.inferred_discovery_confidence || 0) * 100).toFixed(0)}%
                        </span>
                    </span>
                </div>
                ${fullCert.inferred_service_name ? `
                <div class="field-row">
                    <span class="field-label">Service Name</span>
                    <span class="field-value">${fullCert.inferred_service_name}</span>
                </div>
                ` : ''}
                ${fullCert.inferred_application_name ? `
                <div class="field-row">
                    <span class="field-label">Application Name</span>
                    <span class="field-value">${fullCert.inferred_application_name}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- SECTION 3: MANUAL ENVIRONMENT ENRICHMENT (Existing - Backward Compatible) -->
        ${(fullCert.environment_type && !fullCert.inferred_environment_type) ? `
        <div class="modal-section">
            <h3>Manual Environment Enrichment</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Environment Type</span>
                    <span class="field-value">
                        <span class="env-badge env-${fullCert.environment_type}">
                            ${fullCert.environment_type.charAt(0).toUpperCase() + fullCert.environment_type.slice(1)}
                        </span>
                        <span style="font-size: 12px; color: #6b7280; margin-left: 8px;">(manually set)</span>
                    </span>
                </div>
                ${fullCert.service_name ? `
                <div class="field-row">
                    <span class="field-label">Service Name</span>
                    <span class="field-value">${fullCert.service_name}</span>
                </div>
                ` : ''}
                ${fullCert.application_name ? `
                <div class="field-row">
                    <span class="field-label">Application Name</span>
                    <span class="field-value">${fullCert.application_name}</span>
                </div>
                ` : ''}
                ${fullCert.discovery_metadata ? `
                <div class="field-row">
                    <span class="field-label">Discovery Method</span>
                    <span class="field-value">${(fullCert.discovery_metadata.discovery_method || 'N/A').replace(/-/g, ' ')}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}


        <!-- SECTION 3d: LIFECYCLE & STATUS (Expiry & Remediation) -->
        ${(fullCert.is_expired !== undefined || fullCert.days_until_expiration !== undefined || fullCert.trusted_issuer_available !== undefined) ? `
        <div class="modal-section" style="border-left: 4px solid #ec4899;">
            <h3>Lifecycle & Status</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">
                Certificate validity and remediation status
            </p>
            <div class="modal-section-content">
                ${fullCert.is_expired !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Status</span>
                    <span class="field-value">
                        ${fullCert.is_expired ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 600;">⚠ EXPIRED</span>` : `<span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 600;">✓ VALID</span>`}
                    </span>
                </div>
                ` : ''}
                ${fullCert.days_until_expiration !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Days Until Expiry</span>
                    <span class="field-value">
                        ${fullCert.days_until_expiration < 0 ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 500;">${Math.abs(fullCert.days_until_expiration)} days ago</span>` :
                          fullCert.days_until_expiration <= 30 ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 500;">URGENT: ${fullCert.days_until_expiration} days</span>` :
                          fullCert.days_until_expiration <= 90 ? `<span style="background: #fed7aa; color: #9a3412; padding: 2px 6px; border-radius: 3px; font-weight: 500;">SOON: ${fullCert.days_until_expiration} days</span>` :
                          `<span style="background: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 3px; font-weight: 500;">${fullCert.days_until_expiration} days</span>`}
                    </span>
                </div>
                ` : ''}
                ${fullCert.trusted_issuer_available !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Issuer Trusted</span>
                    <span class="field-value">
                        ${fullCert.trusted_issuer_available ? `<span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 500;">✓ Yes</span>` : `<span style="background: #fed7aa; color: #9a3412; padding: 2px 6px; border-radius: 3px; font-weight: 500;">⚠ No</span>`}
                    </span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- SECTION 4: AZURE RESOURCE TAGS (Phase 2-4) -->
        ${(fullCert.azure_tags && Object.keys(fullCert.azure_tags).length > 0) ? `
        <div class="modal-section" style="border-left: 4px solid #0078d4;">
            <h3>Azure Resource Tags</h3>
            <div class="modal-section-content">
                ${Object.entries(fullCert.azure_tags).map(([key, value]) => `
                <div class="field-row">
                    <span class="field-label">${key}</span>
                    <span class="field-value">${value}</span>
                </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <!-- PHASE 3: SERVICE IDENTITY (Service name, tier, cloud, region) -->
        ${(fullCert.inferred_identity_metadata && Object.keys(fullCert.inferred_identity_metadata).length > 0) ? `
        <div class="modal-section" style="border-left: 4px solid #10b981;">
            <h3>Service Identity</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">Extracted service identity from certificate CN</p>
            <div class="modal-section-content">
                ${fullCert.inferred_identity_metadata.service_name ? `
                <div class="field-row">
                    <span class="field-label">Service Name</span>
                    <span class="field-value">${fullCert.inferred_identity_metadata.service_name}</span>
                </div>
                ` : ''}
                ${fullCert.inferred_identity_metadata.service_tier ? `
                <div class="field-row">
                    <span class="field-label">Service Tier</span>
                    <span class="field-value"><span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 500;">${fullCert.inferred_identity_metadata.service_tier}</span></span>
                </div>
                ` : ''}
                ${fullCert.inferred_identity_metadata.cloud_provider ? `
                <div class="field-row">
                    <span class="field-label">Cloud Provider</span>
                    <span class="field-value"><span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-weight: 500;">${fullCert.inferred_identity_metadata.cloud_provider.toUpperCase()}</span></span>
                </div>
                ` : ''}
                ${fullCert.inferred_identity_metadata.region ? `
                <div class="field-row">
                    <span class="field-label">Region</span>
                    <span class="field-value">${fullCert.inferred_identity_metadata.region}</span>
                </div>
                ` : ''}
                ${fullCert.inferred_identity_metadata.domain_type ? `
                <div class="field-row">
                    <span class="field-label">Domain Type</span>
                    <span class="field-value">${fullCert.inferred_identity_metadata.domain_type === 'saas' ? '<span style="background: #cffafe; color: #164e63; padding: 2px 6px; border-radius: 3px; font-weight: 500;">SaaS</span>' : fullCert.inferred_identity_metadata.domain_type}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- PHASE 3: PURPOSE & ROLE (Primary purpose, CA tier, criticality) -->
        ${(fullCert.inferred_purpose_metadata && Object.keys(fullCert.inferred_purpose_metadata).length > 0) ? `
        <div class="modal-section" style="border-left: 4px solid #f59e0b;">
            <h3>Purpose & Role</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">Certificate purpose and issuer analysis</p>
            <div class="modal-section-content">
                ${fullCert.inferred_purpose_metadata.primary_purpose ? `
                <div class="field-row">
                    <span class="field-label">Primary Purpose</span>
                    <span class="field-value"><span style="background: #fed7aa; color: #7c2d12; padding: 2px 6px; border-radius: 3px; font-weight: 500;">${fullCert.inferred_purpose_metadata.primary_purpose}</span></span>
                </div>
                ` : ''}
                ${fullCert.inferred_purpose_metadata.ca_tier ? `
                <div class="field-row">
                    <span class="field-label">CA Tier</span>
                    <span class="field-value"><span style="background: ${fullCert.inferred_purpose_metadata.ca_tier === 'public' ? '#fef3c7' : '#f3e8ff'}; color: ${fullCert.inferred_purpose_metadata.ca_tier === 'public' ? '#b45309' : '#6b21a8'}; padding: 2px 6px; border-radius: 3px; font-weight: 500;">${fullCert.inferred_purpose_metadata.ca_tier === 'public' ? 'Public CA' : 'Internal CA'}</span></span>
                </div>
                ` : ''}
                ${fullCert.inferred_purpose_metadata.criticality_tier ? `
                <div class="field-row">
                    <span class="field-label">Criticality Tier</span>
                    <span class="field-value">
                        ${fullCert.inferred_purpose_metadata.criticality_tier === 'critical' ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 600;">CRITICAL</span>` :
                          fullCert.inferred_purpose_metadata.criticality_tier === 'high' ? `<span style="background: #fed7aa; color: #9a3412; padding: 2px 6px; border-radius: 3px; font-weight: 600;">HIGH</span>` :
                          `<span style="background: #fef3c7; color: #b45309; padding: 2px 6px; border-radius: 3px; font-weight: 500;">STANDARD</span>`}
                    </span>
                </div>
                ` : ''}
                ${fullCert.inferred_purpose_metadata.issuing_organization ? `
                <div class="field-row">
                    <span class="field-label">Issuing Organization</span>
                    <span class="field-value">${fullCert.inferred_purpose_metadata.issuing_organization}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- PHASE 3: CRYPTOGRAPHIC ASSESSMENT (Key algorithm, size, strength, PQC status) -->
        ${(fullCert.inferred_crypto_metadata && Object.keys(fullCert.inferred_crypto_metadata).length > 0) ? `
        <div class="modal-section" style="border-left: 4px solid #8b5cf6;">
            <h3>Cryptographic Assessment</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">Key strength and post-quantum readiness</p>
            <div class="modal-section-content">
                ${fullCert.inferred_crypto_metadata.key_algorithm ? `
                <div class="field-row">
                    <span class="field-label">Key Algorithm</span>
                    <span class="field-value">${fullCert.inferred_crypto_metadata.key_algorithm}${fullCert.inferred_crypto_metadata.key_size ? ` (${fullCert.inferred_crypto_metadata.key_size}-bit)` : ''}</span>
                </div>
                ` : ''}
                ${fullCert.inferred_crypto_metadata.crypto_strength ? `
                <div class="field-row">
                    <span class="field-label">Strength</span>
                    <span class="field-value">
                        ${fullCert.inferred_crypto_metadata.crypto_strength === 'strong' ? `<span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 500;">✓ Strong</span>` :
                          fullCert.inferred_crypto_metadata.crypto_strength === 'weak' ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 500;">⚠ Weak</span>` :
                          `<span style="background: #fef3c7; color: #b45309; padding: 2px 6px; border-radius: 3px; font-weight: 500;">○ Moderate</span>`}
                    </span>
                </div>
                ` : ''}
                ${fullCert.inferred_crypto_metadata.signature_algorithm_analysis ? `
                <div class="field-row">
                    <span class="field-label">Signature Algorithm</span>
                    <span class="field-value">
                        ${fullCert.inferred_crypto_metadata.signature_algorithm_analysis.algorithm || 'N/A'}
                        ${fullCert.inferred_crypto_metadata.signature_algorithm_analysis.is_weak ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 500; margin-left: 6px;">⚠ WEAK</span>` : `<span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 500; margin-left: 6px;">✓ Acceptable</span>`}
                    </span>
                </div>
                ` : ''}
                ${fullCert.inferred_crypto_metadata.migration_urgency ? `
                <div class="field-row">
                    <span class="field-label">Migration Urgency</span>
                    <span class="field-value">
                        ${fullCert.inferred_crypto_metadata.migration_urgency === 'HIGH' ? `<span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 600;">HIGH</span>` :
                          fullCert.inferred_crypto_metadata.migration_urgency === 'MEDIUM' ? `<span style="background: #fed7aa; color: #9a3412; padding: 2px 6px; border-radius: 3px; font-weight: 600;">MEDIUM</span>` :
                          `<span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-weight: 600;">LOW</span>`}
                    </span>
                </div>
                ` : ''}
                ${fullCert.inferred_crypto_metadata.pqc_migration_needed ? `
                <div class="field-row">
                    <span class="field-label">PQC Migration</span>
                    <span class="field-value"><span style="background: #fecaca; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-weight: 500;">⚠ Required</span></span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- PHASE 3: HA & CLUSTERING (HA enabled, replication count, clustering) -->
        ${(fullCert.inferred_ha_metadata && Object.keys(fullCert.inferred_ha_metadata).length > 0) ? `
        <div class="modal-section" style="border-left: 4px solid #06b6d4;">
            <h3>HA & Clustering</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">High availability and replication status</p>
            <div class="modal-section-content">
                ${fullCert.inferred_ha_metadata.ha_enabled ? `
                <div class="field-row">
                    <span class="field-label">HA Enabled</span>
                    <span class="field-value"><span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 500;">✓ Yes</span></span>
                </div>
                ` : ''}
                ${fullCert.inferred_ha_metadata.replication_count ? `
                <div class="field-row">
                    <span class="field-label">Replication Count</span>
                    <span class="field-value"><span style="background: #dbeafe; color: #0369a1; padding: 2px 6px; border-radius: 3px; font-weight: 600;">${fullCert.inferred_ha_metadata.replication_count} nodes</span></span>
                </div>
                ` : ''}
                ${fullCert.inferred_ha_metadata.san_base_name ? `
                <div class="field-row">
                    <span class="field-label">Base Name</span>
                    <span class="field-value">${fullCert.inferred_ha_metadata.san_base_name}</span>
                </div>
                ` : ''}
                ${fullCert.inferred_ha_metadata.is_replicated ? `
                <div class="field-row">
                    <span class="field-label">Replicated</span>
                    <span class="field-value"><span style="background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 3px; font-weight: 500;">✓ Yes</span></span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- SECTION 5: ACTIONS REQUIRED (Remediation Summary) -->
        ${(fullCert.is_expired || fullCert.signature_algorithm_analysis?.is_weak || fullCert.extracted_pqc_migration_needed || (fullCert.days_until_expiration && fullCert.days_until_expiration <= 90 && fullCert.days_until_expiration > 0)) ? `
        <div class="modal-section" style="border-left: 4px solid #f59e0b; background-color: #fffbeb;">
            <h3>Actions Required</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">
                Recommended remediation steps
            </p>
            <div class="modal-section-content">
                <ul style="margin: 0; padding-left: 20px; color: #374151;">
                    ${fullCert.is_expired ? `
                    <li style="margin: 6px 0; font-size: 13px;">
                        <span style="color: #991b1b; font-weight: 600;">URGENT:</span> Certificate has expired. Reissue immediately.
                    </li>
                    ` : fullCert.days_until_expiration && fullCert.days_until_expiration <= 30 && fullCert.days_until_expiration > 0 ? `
                    <li style="margin: 6px 0; font-size: 13px;">
                        <span style="color: #991b1b; font-weight: 600;">URGENT:</span> Certificate expires in ${fullCert.days_until_expiration} days. Reissue immediately.
                    </li>
                    ` : fullCert.days_until_expiration && fullCert.days_until_expiration <= 90 && fullCert.days_until_expiration > 0 ? `
                    <li style="margin: 6px 0; font-size: 13px;">
                        <span style="color: #9a3412; font-weight: 600;">IMPORTANT:</span> Certificate expires in ${fullCert.days_until_expiration} days. Plan renewal.
                    </li>
                    ` : ''}
                    ${fullCert.signature_algorithm_analysis?.is_weak ? `
                    <li style="margin: 6px 0; font-size: 13px;">
                        Signature algorithm is weak. Reissue with ${fullCert.signature_algorithm_analysis.remediation || 'SHA256 or stronger'}.
                    </li>
                    ` : ''}
                    ${fullCert.extracted_pqc_migration_needed ? `
                    <li style="margin: 6px 0; font-size: 13px;">
                        PQC migration required. Plan transition to post-quantum algorithms by 2028.
                    </li>
                    ` : ''}
                </ul>
            </div>
        </div>
        ` : ''}

        <!-- SECTION 6: SIGNAL TRANSPARENCY (Decision-Making Basis for All Inferred Conclusions) -->
        <div class="modal-section" style="border-left: 4px solid #8b5cf6; background-color: #faf5ff;">
            <h3>Signal Transparency</h3>
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 12px;">
                Decision-making basis for all inferred conclusions displayed above
            </p>
            <div class="modal-section-content">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead style="background: #f3e8ff; border-bottom: 2px solid #8b5cf6;">
                        <tr>
                            <th style="padding: 10px; text-align: left; font-weight: 600; color: #6b21a8;">Extracted Field</th>
                            <th style="padding: 10px; text-align: center; font-weight: 600; color: #6b21a8;">Value</th>
                            <th style="padding: 10px; text-align: left; font-weight: 600; color: #6b21a8;">Extraction Method</th>
                            <th style="padding: 10px; text-align: center; font-weight: 600; color: #6b21a8;">Confidence</th>
                        </tr>
                    </thead>
                    <tbody>

                        <!-- CATEGORY: IDENTITY FIELDS -->
                        ${(fullCert.extracted_service_name || fullCert.extracted_organization || fullCert.extracted_cloud_provider || fullCert.extracted_region || fullCert.extracted_service_tier || fullCert.extracted_domain_type) ? `
                        <tr style="background: #ecfdf5; border-bottom: 1px solid #8b5cf6;">
                            <td colspan="4" style="padding: 8px 10px; font-weight: 600; color: #059669; font-size: 12px;">IDENTITY FIELDS</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_service_name ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_service_name</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #dbeafe; color: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_service_name}</span>
                                <span style="background: ${fullCert.extracted_service_name_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_service_name_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_service_name_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">CN first segment (before first '.')</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #059669;">95%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_organization ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_organization</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #dbeafe; color: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_organization}</span>
                                <span style="background: ${fullCert.extracted_organization_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_organization_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_organization_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">CN second segment (between first and second '.')</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #059669;">90%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_cloud_provider ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_cloud_provider</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #dbeafe; color: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_cloud_provider.toUpperCase()}</span>
                                <span style="background: ${fullCert.extracted_cloud_provider_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_cloud_provider_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_cloud_provider_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">CN pattern match: 'az'→Azure, 'aws'→AWS, 'gcp'→GCP</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #059669;">85%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_region ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_region</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #dbeafe; color: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_region.toUpperCase()}</span>
                                <span style="background: ${fullCert.extracted_region_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_region_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_region_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">CN geographic token: 'eu'→Europe, 'us'→US, 'ap'→Asia-Pacific</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #059669;">85%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_service_tier ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_service_tier</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #dbeafe; color: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_service_tier}</span>
                                <span style="background: ${fullCert.extracted_service_tier_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_service_tier_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_service_tier_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">CN tier pattern: 'app'→Application, 'db'→Database, 'web'→Web</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #059669;">85%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_domain_type ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_domain_type</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #dbeafe; color: #0369a1; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_domain_type}</span>
                                <span style="background: ${fullCert.extracted_domain_type_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_domain_type_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_domain_type_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">CN suffix: '.com'→SaaS, '.internal'→Internal, '.local'→Local</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #059669;">90%</td>
                        </tr>
                        ` : ''}

                        <!-- CATEGORY: PURPOSE FIELDS -->
                        ${(fullCert.extracted_primary_purpose || fullCert.extracted_ca_tier || fullCert.extracted_issuing_organization || fullCert.extracted_criticality_tier || fullCert.extracted_data_residency) ? `
                        <tr style="background: #fffbeb; border-bottom: 1px solid #8b5cf6;">
                            <td colspan="4" style="padding: 8px 10px; font-weight: 600; color: #d97706; font-size: 12px;">PURPOSE FIELDS</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_primary_purpose ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_primary_purpose</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #fed7aa; color: #7c2d12; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_primary_purpose}</span>
                                <span style="background: ${fullCert.extracted_primary_purpose_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_primary_purpose_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_primary_purpose_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">EKU analysis: serverAuth→TLS Server, clientAuth→Client Auth, codeSigning→Code Signing</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #d97706;">100%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_ca_tier ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_ca_tier</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #f0f9ff; color: #0c4a6e; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_ca_tier}</span>
                                <span style="background: ${fullCert.extracted_ca_tier_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_ca_tier_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_ca_tier_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Issuer DN analysis: Public CA, Internal CA, or Self-Signed</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #d97706;">95%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_issuing_organization ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_issuing_organization</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #fed7aa; color: #7c2d12; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_issuing_organization}</span>
                                <span style="background: ${fullCert.extracted_issuing_organization_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_issuing_organization_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_issuing_organization_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Issuer O= field extraction from distinguished name</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #d97706;">100%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_criticality_tier ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_criticality_tier</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                ${(() => {
                                    const tier = fullCert.extracted_criticality_tier.toLowerCase();
                                    let badgeHtml = '';
                                    if (tier === 'critical') badgeHtml = `<span style="background: #fecaca; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">CRITICAL</span>`;
                                    else if (tier === 'high') badgeHtml = `<span style="background: #fed7aa; color: #9a3412; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">HIGH</span>`;
                                    else if (tier === 'standard') badgeHtml = `<span style="background: #fef3c7; color: #b45309; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">STANDARD</span>`;
                                    else badgeHtml = `<span style="background: #e5e7eb; color: #374151; padding: 4px 8px; border-radius: 4px; font-size: 12px;">${fullCert.extracted_criticality_tier}</span>`;
                                    return badgeHtml;
                                })()}
                                <span style="background: ${fullCert.extracted_criticality_tier_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_criticality_tier_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_criticality_tier_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Validity period: ≥3 years=CRITICAL, 1-3 years=HIGH, <1 year=STANDARD</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #d97706;">90%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_data_residency ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_data_residency</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #fed7aa; color: #7c2d12; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_data_residency}</span>
                                <span style="background: ${fullCert.extracted_data_residency_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_data_residency_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_data_residency_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Issuer C= field extraction (country code from DN)</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #d97706;">100%</td>
                        </tr>
                        ` : ''}

                        <!-- CATEGORY: CRYPTO FIELDS -->
                        ${(fullCert.extracted_crypto_strength || fullCert.extracted_pqc_migration_needed || fullCert.extracted_key_algorithm || fullCert.extracted_key_size) ? `
                        <tr style="background: #faf5ff; border-bottom: 1px solid #8b5cf6;">
                            <td colspan="4" style="padding: 8px 10px; font-weight: 600; color: #7c3aed; font-size: 12px;">CRYPTO FIELDS</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_key_algorithm ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_key_algorithm</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #ddd6fe; color: #5b21b6; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_key_algorithm}</span>
                                <span style="background: ${fullCert.extracted_key_algorithm_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_key_algorithm_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap; background: #e5e7eb; color: #6b7280;">[Derived]</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Public key algorithm field extraction</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #7c3aed;">100%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_key_size ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_key_size</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #ddd6fe; color: #5b21b6; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_key_size} bits</span>
                                <span style="background: #e5e7eb; color: #6b7280; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">[Derived]</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Public key size field extraction</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #7c3aed;">100%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_crypto_strength ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_crypto_strength</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                ${fullCert.extracted_crypto_strength.toLowerCase() === 'strong' ? `<span style="background: #d1fae5; color: #065f46; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">✓ Strong</span>` : `<span style="background: #fecaca; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">⚠ Weak</span>`}
                                <span style="background: ${fullCert.extracted_crypto_strength_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_crypto_strength_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_crypto_strength_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">${fullCert.extracted_key_algorithm === 'RSA' && fullCert.extracted_key_size >= 2048 ? 'RSA ≥2048 bits = Strong' : fullCert.extracted_key_algorithm === 'RSA' ? 'RSA <2048 bits = Weak' : fullCert.extracted_key_algorithm && fullCert.extracted_key_algorithm.includes('EC') && fullCert.extracted_key_size >= 256 ? 'ECDSA ≥256 bits = Strong' : fullCert.extracted_key_algorithm && fullCert.extracted_key_algorithm.includes('EC') ? 'ECDSA <256 bits = Weak' : 'Algorithm/size analysis'}</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #7c3aed;">100%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_pqc_migration_needed !== undefined ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_pqc_migration_needed</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                ${fullCert.extracted_pqc_migration_needed ? `<span style="background: #fecaca; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">REQUIRED</span>` : `<span style="background: #d1fae5; color: #065f46; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">✓ Not Needed</span>`}
                                <span style="background: ${fullCert.extracted_pqc_migration_needed_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_pqc_migration_needed_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_pqc_migration_needed_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Classical algorithm (RSA/ECDSA)=true requires migration, PQC-ready algorithms=false</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #7c3aed;">100%</td>
                        </tr>
                        ` : ''}

                        <!-- CATEGORY: HA FIELDS -->
                        ${(fullCert.extracted_ha_enabled || fullCert.extracted_replication_count || fullCert.extracted_san_base_name || fullCert.extracted_is_replicated) ? `
                        <tr style="background: #f0f9ff; border-bottom: 1px solid #8b5cf6;">
                            <td colspan="4" style="padding: 8px 10px; font-weight: 600; color: #3b82f6; font-size: 12px;">HA FIELDS</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_ha_enabled ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_ha_enabled</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #bfdbfe; color: #1e3a8a; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_ha_enabled ? 'Yes' : 'No'}</span>
                                <span style="background: ${fullCert.extracted_ha_enabled_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_ha_enabled_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_ha_enabled_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">SAN count detection: multiple SANs (>1)=true, single or no SANs=false</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #3b82f6;">95%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_replication_count ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_replication_count</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #bfdbfe; color: #1e3a8a; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_replication_count} nodes</span>
                                <span style="background: ${fullCert.extracted_replication_count_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_replication_count_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_replication_count_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Numbered SAN pattern detection (hostname0, hostname1, etc.)</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #3b82f6;">95%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_san_base_name ? `
                        <tr style="background: #ffffff; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_san_base_name</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #bfdbfe; color: #1e3a8a; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_san_base_name}</span>
                                <span style="background: ${fullCert.extracted_san_base_name_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_san_base_name_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_san_base_name_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">SAN base pattern extraction (common prefix before numbering)</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #3b82f6;">95%</td>
                        </tr>
                        ` : ''}

                        ${fullCert.extracted_is_replicated ? `
                        <tr style="background: #fafafa; border-bottom: 1px solid #f3e8ff;">
                            <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">extracted_is_replicated</td>
                            <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;">
                                <span style="background: #bfdbfe; color: #1e3a8a; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">${fullCert.extracted_is_replicated ? 'Yes' : 'No'}</span>
                                <span style="background: ${fullCert.extracted_is_replicated_source === 'manual' ? '#dbeafe' : '#f3e8ff'}; color: ${fullCert.extracted_is_replicated_source === 'manual' ? '#1e40af' : '#7c3aed'}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">${fullCert.extracted_is_replicated_source === 'manual' ? '👤 Manual' : '🤖 Inferred'}</span>
                            </td>
                            <td style="padding: 10px; font-size: 12px; color: #6b7280;">Replica naming pattern detected (hostname0, hostname1, hostname2, etc.)</td>
                            <td style="padding: 10px; text-align: center; font-weight: 600; color: #3b82f6;">95%</td>
                        </tr>
                        ` : ''}

                        <!-- CATEGORY: ENVIRONMENT INFERENCE SIGNALS (Multi-Signal Fusion) -->
                        ${(fullCert.inferred_signal_breakdown && fullCert.inferred_signal_breakdown.length > 0) ? `
                        <tr style="background: #eff6ff; border-bottom: 1px solid #8b5cf6;">
                            <td colspan="4" style="padding: 8px 10px; font-weight: 600; color: #3b82f6; font-size: 12px;">ENVIRONMENT INFERENCE SIGNALS (Multi-Signal Fusion)</td>
                        </tr>
                        ${fullCert.inferred_signal_breakdown.map((signal, idx) => {
                            const signalTypeDisplay = signal.signal_type.replace(/_/g, ' ').split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                            const envColor = {
                                'production': '#059669',
                                'staging': '#d97706',
                                'development': '#3b82f6',
                                'testing': '#f59e0b',
                                'unknown': '#6b7280'
                            }[signal.environment_type] || '#6b7280';
                            const confidence = (signal.confidence * 100).toFixed(0);
                            const rowColor = idx % 2 === 0 ? '#ffffff' : '#fafafa';

                            return `
                                <tr style="background: ${rowColor}; border-bottom: 1px solid #f3e8ff;">
                                    <td style="padding: 10px; font-family: 'Monaco', monospace; font-size: 12px; color: #6b7280;">
                                        ${signalTypeDisplay}
                                    </td>
                                    <td style="padding: 10px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px;">
                                        <span style="background: ${envColor}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">
                                            ${signal.environment_type}
                                        </span>
                                    </td>
                                    <td style="padding: 10px; font-size: 12px; color: #6b7280;">Multi-signal weighted voting result</td>
                                    <td style="padding: 10px; text-align: center; font-weight: 600; color: #3b82f6;">${confidence}%</td>
                                </tr>
                            `;
                        }).join('')}
                        ` : ''}

                    </tbody>
                </table>
            </div>
        </div>

        </div><!-- End Inferred Tab -->

        <!-- TAB 3: RISK (Security Analysis & Compliance Findings - Read-Only) -->
        <div id="cert-tab-risk" class="cert-tab-content" style="display: none;">

        <!-- SECTION 1: TLS CONFIGURATION (Only for TLS sources) -->
        ${(fullCert.tls_library || fullCert.found_at_destination || fullCert.source_integration === 'TLS') ? `
        <div class="modal-section">
            <h3>TLS Configuration</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">TLS Library</span>
                    <span class="field-value">${fullCert.tls_library || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">TLS Version</span>
                    <span class="field-value">${fullCert.tls_version || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Found At</span>
                    <span class="field-value">${fullCert.found_at_destination || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Port</span>
                    <span class="field-value">${fullCert.found_on_port || 'N/A'}</span>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- SECTION 2: AZURE LIFECYCLE DATES (Phase 2-4) - At Top of Security Tab -->
        ${(fullCert.azure_created_on || fullCert.azure_updated_on || fullCert.azure_expires_on || fullCert.azure_not_before) ? `
        <div class="modal-section" style="border-left: 4px solid #0078d4;">
            <h3>Azure Lifecycle Dates</h3>
            <div class="modal-section-content">
                ${fullCert.azure_created_on ? `
                <div class="field-row">
                    <span class="field-label">Created</span>
                    <span class="field-value">${new Date(fullCert.azure_created_on).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullCert.azure_updated_on ? `
                <div class="field-row">
                    <span class="field-label">Last Updated</span>
                    <span class="field-value">${new Date(fullCert.azure_updated_on).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullCert.azure_not_before ? `
                <div class="field-row">
                    <span class="field-label">Not Before</span>
                    <span class="field-value">${new Date(fullCert.azure_not_before).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullCert.azure_expires_on ? `
                <div class="field-row">
                    <span class="field-label">Azure Expiration</span>
                    <span class="field-value">${new Date(fullCert.azure_expires_on).toLocaleString()}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- SECTION 2: TLS Protocol Security (Phase 1 & 2) - Only for TLS sources -->
        ${(fullCert.source_type === 'tls' || !fullCert.source_type) ? `
        <div class="modal-section">
            <h3>TLS Protocol Security</h3>
            <div class="modal-section-content">
                <!-- Encryption Details -->
                ${fullCert.key_curve || fullCert.has_forward_secrecy !== undefined || fullCert.symmetric_key_bits ? `
                <div style="margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #e5e7eb;">
                    ${fullCert.key_curve ? `
                    <div class="field-row">
                        <span class="field-label">EC Curve</span>
                        <span class="field-value">${fullCert.key_curve}</span>
                    </div>
                    ` : ''}
                    ${fullCert.symmetric_key_bits ? `
                    <div class="field-row">
                        <span class="field-label">Cipher Strength</span>
                        <span class="field-value">${fullCert.symmetric_key_bits} bits</span>
                    </div>
                    ` : ''}
                    ${fullCert.has_forward_secrecy !== undefined ? `
                    <div class="field-row">
                        <span class="field-label">Forward Secrecy</span>
                        <span class="field-value">
                            <span class="status-badge status-${fullCert.has_forward_secrecy ? 'supported' : 'unsupported'}">
                                ${fullCert.has_forward_secrecy ? 'Enabled (ECDHE/DHE)' : 'Not Available'}
                            </span>
                        </span>
                    </div>
                    ` : ''}
                </div>
                ` : ''}

                <!-- Protocol Support -->
                ${fullCert.supported_tls_versions || fullCert.cipher_strength_rating || fullCert.protocol_vulnerabilities ? `
                <div style="margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #e5e7eb;">
                    ${fullCert.supported_tls_versions && fullCert.supported_tls_versions.length > 0 ? `
                    <div class="field-row">
                        <span class="field-label">Supported TLS Versions</span>
                        <div class="array-list">
                            ${fullCert.supported_tls_versions.map(v => `<span class="array-item">${v}</span>`).join('')}
                        </div>
                    </div>
                    ` : ''}
                    ${fullCert.protocol_vulnerabilities && fullCert.protocol_vulnerabilities.length > 0 ? `
                    <div class="field-row">
                        <span class="field-label">Known Vulnerabilities</span>
                        <div class="array-list">
                            ${fullCert.protocol_vulnerabilities.map(v => `<span class="array-item" style="background-color: #fee2e2; color: #991b1b;">${v}</span>`).join('')}
                        </div>
                    </div>
                    ` : ''}
                    ${fullCert.cipher_strength_rating ? `
                    <div class="field-row">
                        <span class="field-label">Cipher Strength Rating</span>
                        <span class="field-value">
                            <span class="cipher-grade cipher-grade-${fullCert.cipher_strength_rating.toLowerCase()}">
                                ${fullCert.cipher_strength_rating}
                            </span>
                        </span>
                    </div>
                    ` : ''}
                </div>
                ` : ''}

                <!-- Protocol Extensions -->
                ${fullCert.lifespan_pattern || fullCert.tls_handshake_time_ms ? `
                <div style="margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #e5e7eb;">
                    ${fullCert.lifespan_pattern ? `
                    <div class="field-row">
                        <span class="field-label">Certificate Lifespan Pattern</span>
                        <span class="field-value">${fullCert.lifespan_pattern}</span>
                    </div>
                    ` : ''}
                    ${fullCert.tls_handshake_time_ms ? `
                    <div class="field-row">
                        <span class="field-label">Handshake Time</span>
                        <span class="field-value">${fullCert.tls_handshake_time_ms.toFixed(0)}ms</span>
                    </div>
                    ` : ''}
                </div>
                ` : ''}

                <!-- Extension Completeness -->
                ${fullCert.precert_poison_present !== undefined || fullCert.freshest_crl_urls ? `
                <div>
                    ${fullCert.precert_poison_present !== undefined ? `
                    <div class="field-row">
                        <span class="field-label">Precert Poison Marker</span>
                        <span class="field-value">
                            <span class="status-badge status-${fullCert.precert_poison_present ? 'present' : 'absent'}">
                                ${fullCert.precert_poison_present ? 'Present (CT Precert)' : 'Not Present'}
                            </span>
                        </span>
                    </div>
                    ` : ''}
                    ${fullCert.freshest_crl_urls && fullCert.freshest_crl_urls.length > 0 ? `
                    <div class="field-row">
                        <span class="field-label">Freshest CRL URLs</span>
                        <div class="array-list">
                            ${fullCert.freshest_crl_urls.map(url => `<span class="array-item">${url}</span>`).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- Certificate Configuration -->
        ${fullCert.ocsp_stapling_supported !== undefined || fullCert.session_ticket_supported !== undefined || fullCert.client_cert_required !== undefined ? `
        <div class="modal-section">
            <h3>Certificate Configuration</h3>
            <div class="modal-section-content">
                ${fullCert.ocsp_stapling_supported !== undefined ? `
                <div class="field-row">
                    <span class="field-label">OCSP Stapling</span>
                    <span class="field-value">
                        <span class="status-badge status-${fullCert.ocsp_stapling_supported ? 'supported' : 'unsupported'}">
                            ${fullCert.ocsp_stapling_supported ? 'Supported' : 'Not Supported'}
                        </span>
                    </span>
                </div>
                ` : ''}
                ${fullCert.session_ticket_supported !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Session Resumption</span>
                    <span class="field-value">
                        <span class="status-badge status-${fullCert.session_ticket_supported ? 'supported' : 'unsupported'}">
                            ${fullCert.session_ticket_supported ? 'Supported (TLS Tickets)' : 'Not Supported'}
                        </span>
                    </span>
                </div>
                ` : ''}
                ${fullCert.client_cert_required !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Client Certificate Required</span>
                    <span class="field-value">
                        <span class="status-badge status-${fullCert.client_cert_required ? 'required' : 'optional'}">
                            ${fullCert.client_cert_required ? 'Required (mTLS)' : 'Optional'}
                        </span>
                    </span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- Signature Algorithm Risk (Phase 1.5) -->
        ${(fullCert.signature_algorithm_analysis) ? `
        <div class="modal-section">
            <h3>Signature Algorithm Risk</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Algorithm</span>
                    <span class="field-value">${fullCert.signature_algorithm_analysis.algorithm || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Risk Level</span>
                    <span class="field-value">
                        <span class="risk-badge risk-${fullCert.signature_algorithm_analysis.risk_level || 'unknown'}">
                            ${(fullCert.signature_algorithm_analysis.risk_level || 'N/A').charAt(0).toUpperCase() + (fullCert.signature_algorithm_analysis.risk_level || 'N/A').slice(1)}
                        </span>
                    </span>
                </div>
                <div class="field-row">
                    <span class="field-label">Risk Score</span>
                    <span class="field-value">
                        <div class="risk-meter">
                            <div class="risk-meter-fill" style="width: ${(fullCert.signature_algorithm_analysis.risk_score || 0) * 100}%"></div>
                        </div>
                        ${((fullCert.signature_algorithm_analysis.risk_score || 0) * 100).toFixed(0)}%
                    </span>
                </div>
                ${fullCert.signature_algorithm_analysis.reason ? `
                <div class="field-row">
                    <span class="field-label">Assessment</span>
                    <span class="field-value">${fullCert.signature_algorithm_analysis.reason}</span>
                </div>
                ` : ''}
                ${fullCert.signature_algorithm_analysis.requires_remediation && fullCert.signature_algorithm_analysis.remediation ? `
                <div class="field-row">
                    <span class="field-label">Remediation</span>
                    <span class="field-value">${fullCert.signature_algorithm_analysis.remediation}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- Key Strength Analysis (Phase 1.5) -->
        ${(fullCert.key_strength_analysis) ? `
        <div class="modal-section">
            <h3>Key Strength Analysis</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Algorithm</span>
                    <span class="field-value">${fullCert.key_strength_analysis.algorithm || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Key Size</span>
                    <span class="field-value">${fullCert.key_strength_analysis.key_size || 'N/A'} bits</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Risk Level</span>
                    <span class="field-value">
                        <span class="risk-badge risk-${fullCert.key_strength_analysis.risk_level || 'unknown'}">
                            ${(fullCert.key_strength_analysis.risk_level || 'N/A').charAt(0).toUpperCase() + (fullCert.key_strength_analysis.risk_level || 'N/A').slice(1)}
                        </span>
                    </span>
                </div>
                <div class="field-row">
                    <span class="field-label">Risk Score</span>
                    <span class="field-value">
                        <div class="risk-meter">
                            <div class="risk-meter-fill" style="width: ${(fullCert.key_strength_analysis.risk_score || 0) * 100}%"></div>
                        </div>
                        ${((fullCert.key_strength_analysis.risk_score || 0) * 100).toFixed(0)}%
                    </span>
                </div>
                ${fullCert.key_strength_analysis.safe_until ? `
                <div class="field-row">
                    <span class="field-label">Safe Until</span>
                    <span class="field-value">${fullCert.key_strength_analysis.safe_until}</span>
                </div>
                ` : ''}
                ${fullCert.key_strength_analysis.reason ? `
                <div class="field-row">
                    <span class="field-label">Assessment</span>
                    <span class="field-value">${fullCert.key_strength_analysis.reason}</span>
                </div>
                ` : ''}
                ${fullCert.key_strength_analysis.requires_remediation && fullCert.key_strength_analysis.remediation ? `
                <div class="field-row">
                    <span class="field-label">Remediation</span>
                    <span class="field-value">${fullCert.key_strength_analysis.remediation}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- PQC Readiness (Phase 1.5) -->
        ${(fullCert.pqc_readiness) ? `
        <div class="modal-section">
            <h3>Post-Quantum Cryptography Readiness</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">PQC Status</span>
                    <span class="field-value">
                        <span class="status-badge status-${fullCert.pqc_readiness.pqc_status || 'unknown'}">
                            ${(fullCert.pqc_readiness.pqc_status || 'N/A').charAt(0).toUpperCase() + (fullCert.pqc_readiness.pqc_status || 'N/A').slice(1)}
                        </span>
                    </span>
                </div>
                ${fullCert.pqc_readiness.quantum_threat_timeline ? `
                <div class="field-row">
                    <span class="field-label">Quantum Threat Timeline</span>
                    <span class="field-value">${fullCert.pqc_readiness.quantum_threat_timeline}</span>
                </div>
                ` : ''}
                ${fullCert.pqc_readiness.harvest_now_decrypt_later_risk ? `
                <div class="field-row">
                    <span class="field-label">Harvest Now, Decrypt Later Risk</span>
                    <span class="field-value">
                        <span class="risk-badge risk-${fullCert.pqc_readiness.harvest_now_decrypt_later_risk.toLowerCase() || 'unknown'}">
                            ${(fullCert.pqc_readiness.harvest_now_decrypt_later_risk || 'N/A').charAt(0).toUpperCase() + (fullCert.pqc_readiness.harvest_now_decrypt_later_risk || 'N/A').slice(1)}
                        </span>
                    </span>
                </div>
                ` : ''}
                ${fullCert.pqc_readiness.migration_urgency ? `
                <div class="field-row">
                    <span class="field-label">Migration Urgency</span>
                    <span class="field-value">
                        <span class="urgency-badge urgency-${fullCert.pqc_readiness.migration_urgency.toLowerCase() || 'unknown'}">
                            ${(fullCert.pqc_readiness.migration_urgency || 'N/A').charAt(0).toUpperCase() + (fullCert.pqc_readiness.migration_urgency || 'N/A').slice(1)}
                        </span>
                    </span>
                </div>
                ` : ''}
                ${fullCert.pqc_readiness.pqc_readiness_score !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Readiness Score</span>
                    <span class="field-value">
                        <div class="risk-meter">
                            <div class="risk-meter-fill" style="width: ${(fullCert.pqc_readiness.pqc_readiness_score || 0) * 100}%"></div>
                        </div>
                        ${((fullCert.pqc_readiness.pqc_readiness_score || 0) * 100).toFixed(0)}%
                    </span>
                </div>
                ` : ''}
                ${fullCert.pqc_readiness.recommendation ? `
                <div class="field-row">
                    <span class="field-label">Recommendation</span>
                    <span class="field-value">${fullCert.pqc_readiness.recommendation}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- Revocation Status (Phase 1.5) -->
        ${(fullCert.revocation_status) ? `
        <div class="modal-section">
            <h3>Revocation Status</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">CRL URLs Present</span>
                    <span class="field-value">
                        <span class="status-badge status-${fullCert.revocation_status.crl_urls_present ? 'present' : 'absent'}">
                            ${fullCert.revocation_status.crl_urls_present ? 'Yes' : 'No'}
                        </span>
                        ${fullCert.revocation_status.crl_count ? ` (${fullCert.revocation_status.crl_count})` : ''}
                    </span>
                </div>
                <div class="field-row">
                    <span class="field-label">OCSP Responders Present</span>
                    <span class="field-value">
                        <span class="status-badge status-${fullCert.revocation_status.ocsp_urls_present ? 'present' : 'absent'}">
                            ${fullCert.revocation_status.ocsp_urls_present ? 'Yes' : 'No'}
                        </span>
                        ${fullCert.revocation_status.ocsp_count ? ` (${fullCert.revocation_status.ocsp_count})` : ''}
                    </span>
                </div>
                ${fullCert.revocation_status.validation_status ? `
                <div class="field-row">
                    <span class="field-label">Validation Status</span>
                    <span class="field-value">${fullCert.revocation_status.validation_status}</span>
                </div>
                ` : ''}
                ${fullCert.revocation_status.note ? `
                <div class="field-row">
                    <span class="field-label">Notes</span>
                    <span class="field-value">${fullCert.revocation_status.note}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}
        </div><!-- End Risk Tab -->

        <!-- TAB 4: ENRICHMENT (Manual Overrides - Editable) -->
        <div id="cert-tab-enrichment" class="cert-tab-content" style="display: none;">

        <!-- Environment Section (Existing 3 fields) -->
        <div class="modal-section">
            <h3>Environment</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Type</span>
                    <select id="enrichment-env-type" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                        <option value="">Use Inferred (${fullCert.inferred_environment_type ? fullCert.inferred_environment_type : 'unknown'})</option>
                        <option value="production">Production</option>
                        <option value="staging">Staging</option>
                        <option value="development">Development</option>
                        <option value="testing">Testing</option>
                        <option value="unknown">Unknown</option>
                    </select>
                </div>
                <div class="field-row" style="margin-top: 12px;">
                    <span class="field-label">Service Name</span>
                    <input type="text" id="enrichment-service-name" placeholder="${fullCert.inferred_service_name ? fullCert.inferred_service_name : 'Not inferred'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                </div>
                <div class="field-row" style="margin-top: 12px;">
                    <span class="field-label">Application Name</span>
                    <input type="text" id="enrichment-app-name" placeholder="${fullCert.inferred_application_name ? fullCert.inferred_application_name : 'Not inferred'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                </div>
            </div>
        </div>

        <!-- Service Identity Section -->
        <div class="modal-section">
            <h3 style="cursor: pointer; user-select: none; display: flex; align-items: center; gap: 8px;" onclick="toggleEnrichmentSection(this)">
                🏢 Service Identity <span style="font-size: 11px; margin-left: auto;">▼</span>
            </h3>
            <div class="enrichment-collapse-content" style="display: none;">
                <div class="modal-section-content">
                    <div class="field-row">
                        <span class="field-label">Service Name</span>
                        <input type="text" id="extracted-service-name" placeholder="Inferred: ${fullCert.extracted_service_name || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Organization</span>
                        <input type="text" id="extracted-organization" placeholder="Inferred: ${fullCert.extracted_organization || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Cloud Provider</span>
                        <select id="extracted-cloud-provider" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_cloud_provider || '(none)'})</option>
                            <option value="azure">Azure</option>
                            <option value="aws">AWS</option>
                            <option value="gcp">GCP</option>
                            <option value="on-prem">On-Premise</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Region</span>
                        <input type="text" id="extracted-region" placeholder="Inferred: ${fullCert.extracted_region || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Service Tier</span>
                        <select id="extracted-service-tier" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_service_tier || '(none)'})</option>
                            <option value="application">Application</option>
                            <option value="database">Database</option>
                            <option value="web">Web</option>
                            <option value="api">API</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Domain Type</span>
                        <select id="extracted-domain-type" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_domain_type || '(none)'})</option>
                            <option value="saas">SaaS</option>
                            <option value="internal">Internal</option>
                            <option value="public">Public</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Certificate Purpose Section -->
        <div class="modal-section">
            <h3 style="cursor: pointer; user-select: none; display: flex; align-items: center; gap: 8px;" onclick="toggleEnrichmentSection(this)">
                🎯 Certificate Purpose <span style="font-size: 11px; margin-left: auto;">▼</span>
            </h3>
            <div class="enrichment-collapse-content" style="display: none;">
                <div class="modal-section-content">
                    <div class="field-row">
                        <span class="field-label">Primary Purpose</span>
                        <select id="extracted-primary-purpose" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_primary_purpose || '(none)'})</option>
                            <option value="TLS Server">TLS Server</option>
                            <option value="TLS Client">TLS Client</option>
                            <option value="Code Signing">Code Signing</option>
                            <option value="Email Protection">Email Protection</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">CA Tier</span>
                        <select id="extracted-ca-tier" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_ca_tier || '(none)'})</option>
                            <option value="public">Public CA</option>
                            <option value="internal">Internal CA</option>
                            <option value="self-signed">Self-Signed</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Issuing Organization</span>
                        <input type="text" id="extracted-issuing-organization" placeholder="Inferred: ${fullCert.extracted_issuing_organization || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Criticality</span>
                        <select id="extracted-criticality-tier" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_criticality_tier || '(none)'})</option>
                            <option value="critical">Critical (≥3yr)</option>
                            <option value="high">High (1-3yr)</option>
                            <option value="standard">Standard (<1yr)</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Data Residency</span>
                        <input type="text" id="extracted-data-residency" placeholder="Inferred: ${fullCert.extracted_data_residency || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                </div>
            </div>
        </div>

        <!-- Cryptographic Strength Section -->
        <div class="modal-section">
            <h3 style="cursor: pointer; user-select: none; display: flex; align-items: center; gap: 8px;" onclick="toggleEnrichmentSection(this)">
                🔐 Cryptographic Strength <span style="font-size: 11px; margin-left: auto;">▼</span>
            </h3>
            <div class="enrichment-collapse-content" style="display: none;">
                <div class="modal-section-content">
                    <div class="field-row">
                        <span class="field-label">Crypto Strength</span>
                        <select id="extracted-crypto-strength" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_crypto_strength || '(none)'})</option>
                            <option value="strong">Strong</option>
                            <option value="weak">Weak</option>
                            <option value="deprecated">Deprecated</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">PQC Migration Needed</span>
                        <select id="extracted-pqc-migration-needed" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_pqc_migration_needed ? 'Yes' : 'No'})</option>
                            <option value="1">Yes</option>
                            <option value="0">No</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Key Algorithm</span>
                        <input type="text" id="extracted-key-algorithm" placeholder="Inferred: ${fullCert.extracted_key_algorithm || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; background: #f5f5f5;" disabled title="Derived from certificate - read-only">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Key Size</span>
                        <input type="number" id="extracted-key-size" placeholder="Inferred: ${fullCert.extracted_key_size || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; background: #f5f5f5;" disabled title="Derived from certificate - read-only">
                    </div>
                </div>
            </div>
        </div>

        <!-- High Availability Section -->
        <div class="modal-section">
            <h3 style="cursor: pointer; user-select: none; display: flex; align-items: center; gap: 8px;" onclick="toggleEnrichmentSection(this)">
                🔄 High Availability <span style="font-size: 11px; margin-left: auto;">▼</span>
            </h3>
            <div class="enrichment-collapse-content" style="display: none;">
                <div class="modal-section-content">
                    <div class="field-row">
                        <span class="field-label">HA Enabled</span>
                        <select id="extracted-ha-enabled" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_ha_enabled ? 'Yes' : 'No'})</option>
                            <option value="1">Yes</option>
                            <option value="0">No</option>
                        </select>
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Replication Count</span>
                        <input type="number" id="extracted-replication-count" placeholder="Inferred: ${fullCert.extracted_replication_count || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">SAN Base Name</span>
                        <input type="text" id="extracted-san-base-name" placeholder="Inferred: ${fullCert.extracted_san_base_name || '(none)'}" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                    </div>
                    <div class="field-row" style="margin-top: 12px;">
                        <span class="field-label">Is Replicated</span>
                        <select id="extracted-is-replicated" style="width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;">
                            <option value="">Use Inferred (${fullCert.extracted_is_replicated ? 'Yes' : 'No'})</option>
                            <option value="1">Yes</option>
                            <option value="0">No</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div style="display: flex; gap: 8px; margin-top: 15px;">
            <button id="enrichment-save-btn" onclick="saveEnrichment(this)" style="padding: 8px 16px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;">Save All Overrides</button>
            <button id="enrichment-clear-btn" onclick="clearEnrichment(this)" style="padding: 8px 16px; background: #ef4444; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;">Clear All Overrides</button>
        </div>

        </div><!-- End Enrichment Tab -->
    `;

    // Update modal header with badges
    const subjectCN = typeof fullCert.subject === 'string' ? (fullCert.subject_cn || fullCert.subject) : (fullCert.subject?.commonName || 'Unknown');

    // Generate badge HTML
    let badgesHtml = '<div class="cert-header-badges">';

    // Cert Type Badge
    const certType = fullCert.is_ca ? 'Root/Intermediate CA' : 'End Entity';
    const typeIcon = fullCert.is_ca ? '🔐' : '📝';
    const typeClass = fullCert.is_ca ? 'type-ca' : 'type-entity';
    badgesHtml += `<div class="cert-badge ${typeClass}"><span class="cert-badge-icon">${typeIcon}</span>${certType}</div>`;

    // Algorithm Badge
    const algo = fullCert.public_key_algorithm || 'N/A';
    let algoClass = 'algo-other';
    let algoIcon = '🔑';
    if (algo.includes('RSA')) {
        algoClass = 'algo-rsa';
        algoIcon = '🔴';
    } else if (algo.includes('ECDSA') || algo.includes('EC')) {
        algoClass = 'algo-ecdsa';
        algoIcon = '🟣';
    }
    const keySize = fullCert.public_key_size ? ` (${fullCert.public_key_size}b)` : '';
    badgesHtml += `<div class="cert-badge ${algoClass}"><span class="cert-badge-icon">${algoIcon}</span>${algo}${keySize}</div>`;

    // Expiry Badge
    const daysUntilExpiry = Math.ceil((notAfter - new Date()) / (1000 * 60 * 60 * 24));
    let expiryClass = 'expiry-valid';
    let expiryIcon = '✓';
    let expiryText = `${daysUntilExpiry}d`;
    if (daysUntilExpiry < 0) {
        expiryClass = 'expiry-expired';
        expiryIcon = '✕';
        expiryText = 'Expired';
    } else if (daysUntilExpiry < 30) {
        expiryClass = 'expiry-warning';
        expiryIcon = '⚠';
        expiryText = `${daysUntilExpiry}d left`;
    }
    badgesHtml += `<div class="cert-badge ${expiryClass}"><span class="cert-badge-icon">${expiryIcon}</span>${expiryText}</div>`;

    badgesHtml += '</div>';

    // Update header structure
    const modalHeader = document.querySelector('#certModal .modal-header');
    modalHeader.innerHTML = `
        <div class="cert-header-title">
            <h2 id="certModalTitle">Certificate: ${subjectCN}</h2>
            <button class="modal-close" onclick="closeAssetModal('cert')">&times;</button>
        </div>
        ${badgesHtml}
    `;

    document.getElementById('certModalBody').innerHTML = html;

    // Store certificate ID for enrichment form functions (saveEnrichment, clearEnrichment)
    window.currentCertificateModalId = fullCert.id || fullCert.unique_id || fullCert.fingerprint_sha256;
    window.currentEngagementId = null; // Set by parent context if available

    document.getElementById('certModal').classList.add('active');

    // Initialize tab styling (default to Overview active) and load enrichment data
    setTimeout(() => {
        initCertModalTabs();
        loadEnrichmentData();
    }, 0);
}

function showKeyDetails(key) {
    // Merge normalised_data if available to get enriched fields
    let fullKey = key;
    if (key.normalised_data) {
        try {
            const enrichedData = typeof key.normalised_data === 'string'
                ? JSON.parse(key.normalised_data)
                : key.normalised_data;

            // MERGE ORDER MATTERS (Phase 5):
            // 1. Base with enrichedData (Phase 2-4 normalized fields)
            // 2. Overlay key (manual enrichment takes precedence)
            // 3. PRESERVE inferred_* and azure_* fields (ensure they're available)
            fullKey = {
                ...enrichedData,                              // Phase 2-4 normalized data
                ...key,                                       // Manual enrichment overrides
                // Explicitly preserve Phase 2-4 inferred fields
                inferred_environment_type: enrichedData.inferred_environment_type,
                inferred_service_name: enrichedData.inferred_service_name,
                inferred_application_name: enrichedData.inferred_application_name,
                inferred_discovery_method: enrichedData.inferred_discovery_method,
                inferred_discovery_confidence: enrichedData.inferred_discovery_confidence,
                // Preserve all Phase 2-4 Azure fields
                azure_tags: enrichedData.azure_tags,
                azure_key_type: enrichedData.azure_key_type,
                azure_managed: enrichedData.azure_managed,
                azure_version: enrichedData.azure_version,
                azure_enabled: enrichedData.azure_enabled,
                azure_recovery_level: enrichedData.azure_recovery_level,
                azure_vault_name: enrichedData.azure_vault_name,
                azure_vault_id: enrichedData.azure_vault_id,
                azure_vault_location: enrichedData.azure_vault_location,
                azure_vault_resource_group: enrichedData.azure_vault_resource_group,
                azure_vault_tier: enrichedData.azure_vault_tier,
                azure_subscription_id: enrichedData.azure_subscription_id,
                azure_created_on: enrichedData.azure_created_on,
                azure_updated_on: enrichedData.azure_updated_on,
                azure_expires_on: enrichedData.azure_expires_on,
                azure_not_before: enrichedData.azure_not_before,
            };
        } catch (e) {
            console.warn('Could not parse normalised_data:', e);
        }
    }

    // Helper to format boolean values with color coding
    const formatBool = (val, trueIsGood = true) => {
        if (val === null || val === undefined) return '<span style="color: #6b7280;">N/A</span>';
        const isTrue = val === true;
        const color = (isTrue === trueIsGood) ? '#10b981' : '#ef4444';
        return `<span style="color: ${color}; font-weight: 600;">${isTrue ? 'Yes' : 'No'}</span>`;
    };

    // Helper for security attributes (sensitive=good, extractable=bad)
    const formatSecurityBool = (val, sensitiveType = true) => {
        if (val === null || val === undefined) return '<span style="color: #6b7280;">N/A</span>';
        const isTrue = val === true;
        const isGood = sensitiveType ? isTrue : !isTrue;
        const color = isGood ? '#10b981' : '#f59e0b';
        return `<span style="color: ${color}; font-weight: 600;">${isTrue ? 'Yes' : 'No'}</span>`;
    };

    let html = `
        <!-- Basic Information -->
        <div class="modal-section">
            <h3>Basic Information</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Key Label/Name</span>
                    <span class="field-value">${fullKey.name || fullKey.label || fullKey.key_name || fullKey.kid || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Key Type</span>
                    <span class="field-value">${fullKey.key_type || fullKey.kty || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Key Size</span>
                    <span class="field-value">${fullKey.key_size || 'N/A'}${fullKey.key_size ? ' bits' : ''}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Key Class</span>
                    <span class="field-value">${fullKey.key_class || 'N/A'}</span>
                </div>
            </div>
        </div>

        <!-- Security Attributes (for HSM keys) -->
        ${(fullKey.is_sensitive !== undefined || fullKey.is_extractable !== undefined) ? `
        <div class="modal-section">
            <h3>🔐 Security Attributes</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Sensitive</span>
                    <span class="field-value">${formatSecurityBool(fullKey.is_sensitive, true)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Extractable</span>
                    <span class="field-value">${formatSecurityBool(fullKey.is_extractable, false)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Modifiable</span>
                    <span class="field-value">${formatSecurityBool(fullKey.is_modifiable, false)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Always Sensitive</span>
                    <span class="field-value">${formatSecurityBool(fullKey.is_always_sensitive, true)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Never Extractable</span>
                    <span class="field-value">${formatSecurityBool(fullKey.is_never_extractable, true)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Local (Generated on HSM)</span>
                    <span class="field-value">${formatSecurityBool(fullKey.is_local, true)}</span>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- Key Operations -->
        ${(fullKey.can_encrypt !== undefined || fullKey.can_sign !== undefined) ? `
        <div class="modal-section">
            <h3>⚙️ Permitted Operations</h3>
            <div class="modal-section-content" style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                <div class="field-row">
                    <span class="field-label">Encrypt</span>
                    <span class="field-value">${formatBool(fullKey.can_encrypt)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Decrypt</span>
                    <span class="field-value">${formatBool(fullKey.can_decrypt)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Sign</span>
                    <span class="field-value">${formatBool(fullKey.can_sign)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Verify</span>
                    <span class="field-value">${formatBool(fullKey.can_verify)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Wrap</span>
                    <span class="field-value">${formatBool(fullKey.can_wrap)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Unwrap</span>
                    <span class="field-value">${formatBool(fullKey.can_unwrap)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Derive</span>
                    <span class="field-value">${formatBool(fullKey.can_derive)}</span>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- AUTO-DISCOVERED ENVIRONMENT (Phase 2-4) -->
        ${(fullKey.inferred_environment_type) ? `
        <div class="modal-section">
            <h3>Auto-Discovered Environment</h3>
            <p style="font-size: 12px; color: #64748b; margin-bottom: 12px;">
                Detected via ${(fullKey.inferred_discovery_method || 'unknown').replace(/-/g, ' ')}
                (${((fullKey.inferred_discovery_confidence || 0) * 100).toFixed(0)}% confidence)
            </p>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Environment</span>
                    <span class="field-value">
                        <span class="env-badge env-${fullKey.inferred_environment_type}">
                            ${fullKey.inferred_environment_type.charAt(0).toUpperCase() + fullKey.inferred_environment_type.slice(1)}
                        </span>
                        <span class="confidence-badge">
                            ${((fullKey.inferred_discovery_confidence || 0) * 100).toFixed(0)}%
                        </span>
                    </span>
                </div>
                ${fullKey.inferred_service_name ? `
                <div class="field-row">
                    <span class="field-label">Service Name</span>
                    <span class="field-value">${fullKey.inferred_service_name}</span>
                </div>
                ` : ''}
                ${fullKey.inferred_application_name ? `
                <div class="field-row">
                    <span class="field-label">Application Name</span>
                    <span class="field-value">${fullKey.inferred_application_name}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- AZURE KEY VAULT METADATA (Phase 2-4) -->
        ${(fullKey.azure_vault_name) ? `
        <div class="modal-section" style="border-left: 4px solid #0078d4;">
            <h3>Azure Key Vault Metadata</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Vault Name</span>
                    <span class="field-value">${fullKey.azure_vault_name}</span>
                </div>
                ${fullKey.azure_vault_location ? `
                <div class="field-row">
                    <span class="field-label">Region</span>
                    <span class="field-value">${fullKey.azure_vault_location}</span>
                </div>
                ` : ''}
                ${fullKey.azure_vault_resource_group ? `
                <div class="field-row">
                    <span class="field-label">Resource Group</span>
                    <span class="field-value">${fullKey.azure_vault_resource_group}</span>
                </div>
                ` : ''}
                ${fullKey.azure_subscription_id ? `
                <div class="field-row">
                    <span class="field-label">Subscription ID</span>
                    <span class="field-value" style="font-family: monospace; font-size: 12px;">
                        ${fullKey.azure_subscription_id}
                    </span>
                </div>
                ` : ''}
                ${fullKey.azure_vault_tier ? `
                <div class="field-row">
                    <span class="field-label">Vault Tier</span>
                    <span class="field-value">${fullKey.azure_vault_tier}</span>
                </div>
                ` : ''}
                ${fullKey.azure_managed !== null && fullKey.azure_managed !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Managed Key</span>
                    <span class="field-value">${fullKey.azure_managed ? 'Yes' : 'No'}</span>
                </div>
                ` : ''}
                ${fullKey.azure_enabled !== null && fullKey.azure_enabled !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Enabled</span>
                    <span class="field-value">${fullKey.azure_enabled ? 'Yes' : 'No'}</span>
                </div>
                ` : ''}
                ${fullKey.azure_recovery_level ? `
                <div class="field-row">
                    <span class="field-label">Recovery Level</span>
                    <span class="field-value">${fullKey.azure_recovery_level}</span>
                </div>
                ` : ''}
                ${fullKey.azure_version ? `
                <div class="field-row">
                    <span class="field-label">Key Version</span>
                    <span class="field-value">${fullKey.azure_version}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- AZURE RESOURCE TAGS (Phase 2-4) -->
        ${(fullKey.azure_tags && Object.keys(fullKey.azure_tags).length > 0) ? `
        <div class="modal-section" style="border-left: 4px solid #0078d4;">
            <h3>Azure Resource Tags</h3>
            <div class="modal-section-content">
                ${Object.entries(fullKey.azure_tags).map(([key, value]) => `
                <div class="field-row">
                    <span class="field-label">${key}</span>
                    <span class="field-value">${value}</span>
                </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <!-- AZURE LIFECYCLE DATES (Phase 2-4) -->
        ${(fullKey.azure_created_on || fullKey.azure_updated_on || fullKey.azure_expires_on || fullKey.azure_not_before) ? `
        <div class="modal-section" style="border-left: 4px solid #0078d4;">
            <h3>Azure Lifecycle Dates</h3>
            <div class="modal-section-content">
                ${fullKey.azure_created_on ? `
                <div class="field-row">
                    <span class="field-label">Created</span>
                    <span class="field-value">${new Date(fullKey.azure_created_on).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullKey.azure_updated_on ? `
                <div class="field-row">
                    <span class="field-label">Last Updated</span>
                    <span class="field-value">${new Date(fullKey.azure_updated_on).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullKey.azure_not_before ? `
                <div class="field-row">
                    <span class="field-label">Not Before</span>
                    <span class="field-value">${new Date(fullKey.azure_not_before).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullKey.azure_expires_on ? `
                <div class="field-row">
                    <span class="field-label">Azure Expiration</span>
                    <span class="field-value">${new Date(fullKey.azure_expires_on).toLocaleString()}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- LEGACY AZURE KEY VAULT (backward compat) -->
        ${(fullKey.vault_name || fullKey.key_ops) && !fullKey.azure_vault_name ? `
        <div class="modal-section">
            <h3>Azure Key Vault</h3>
            <div class="modal-section-content">
                ${fullKey.vault_name ? `
                <div class="field-row">
                    <span class="field-label">Vault Name</span>
                    <span class="field-value">${fullKey.vault_name}</span>
                </div>
                ` : ''}
                ${fullKey.key_ops ? `
                <div class="field-row">
                    <span class="field-label">Key Operations</span>
                    <div class="array-list">
                        ${fullKey.key_ops.map(op => `<span class="array-item">${op}</span>`).join('')}
                    </div>
                </div>
                ` : ''}
                ${fullKey.crv ? `
                <div class="field-row">
                    <span class="field-label">Curve</span>
                    <span class="field-value">${fullKey.crv}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- PQC Analysis -->
        ${fullKey.pqc_analysis ? `
        <div class="modal-section">
            <h3>PQC Analysis</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Migration Status</span>
                    <span class="field-value">${formatStatus(fullKey.pqc_analysis.migration_status || 'unknown')}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Is PQC</span>
                    <span class="field-value">${fullKey.pqc_analysis.is_pqc ? 'Yes' : 'No'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Risk Score</span>
                    <span class="field-value">${fullKey.pqc_analysis.risk_score || 'N/A'}</span>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- Key Properties -->
        <div class="modal-section">
            <h3>Key Properties</h3>
            <div class="modal-section-content">
                <div class="field-row">
                    <span class="field-label">Source</span>
                    <span class="field-value">${fullKey.source || fullKey.source_type || fullKey.source_integration || 'N/A'}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">HSM Backed</span>
                    <span class="field-value">${fullKey.hsm_backed || fullKey.is_hsm_backed ? 'Yes' : (fullKey.source && fullKey.source.toLowerCase().includes('hsm') ? 'Yes' : 'No')}</span>
                </div>
                ${fullKey.enabled !== undefined ? `
                <div class="field-row">
                    <span class="field-label">Enabled</span>
                    <span class="field-value">${fullKey.enabled ? 'Yes' : 'No'}</span>
                </div>
                ` : ''}
            </div>
        </div>

        <!-- Lifecycle -->
        ${(fullKey.start_date || fullKey.end_date || fullKey.created || fullKey.updated || fullKey.created_on) ? `
        <div class="modal-section">
            <h3>📅 Lifecycle</h3>
            <div class="modal-section-content">
                ${(fullKey.created || fullKey.created_on) ? `
                <div class="field-row">
                    <span class="field-label">Created</span>
                    <span class="field-value">${new Date(fullKey.created || fullKey.created_on).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullKey.updated ? `
                <div class="field-row">
                    <span class="field-label">Updated</span>
                    <span class="field-value">${new Date(fullKey.updated).toLocaleString()}</span>
                </div>
                ` : ''}
                ${fullKey.start_date ? `
                <div class="field-row">
                    <span class="field-label">Start Date</span>
                    <span class="field-value">${fullKey.start_date}</span>
                </div>
                ` : ''}
                ${fullKey.end_date ? `
                <div class="field-row">
                    <span class="field-label">End Date</span>
                    <span class="field-value">${fullKey.end_date}</span>
                </div>
                ` : ''}
            </div>
        </div>
        ` : ''}

        <!-- Object Information -->
        ${fullKey.object_id ? `
        <div class="modal-section">
            <h3>Object Information</h3>
            <div class="field-row">
                <span class="field-label">Object ID</span>
                <div class="object-display">${fullKey.object_id || 'N/A'}</div>
            </div>
        </div>
        ` : ''}
    `;

    document.getElementById('keyModalTitle').textContent = `Key: ${fullKey.name || fullKey.label || fullKey.key_name || 'Unknown'}`;
    document.getElementById('keyModalBody').innerHTML = html;
    document.getElementById('keyModal').classList.add('active');
}

function closeAssetModal(type) {
    if (type === 'cert') {
        document.getElementById('certModal').classList.remove('active');
    } else if (type === 'key') {
        document.getElementById('keyModal').classList.remove('active');
    }
}

// Close modals when clicking outside
document.addEventListener('click', function(event) {
    const certModal = document.getElementById('certModal');
    const keyModal = document.getElementById('keyModal');
    if (event.target === certModal) {
        certModal.classList.remove('active');
    }
    if (event.target === keyModal) {
        keyModal.classList.remove('active');
    }
});

// ========== ASSET ENRICHMENT MODAL FUNCTIONS ==========

let currentEnrichmentAsset = null;
let currentEnrichmentAssetType = null;
let currentEnrichmentAssetId = null;

async function openAssetEnrichmentModal(asset, assetType, assetId) {
    try {
        console.log('Opening enrichment modal for:', assetType, assetId);

        currentEnrichmentAsset = asset;
        currentEnrichmentAssetType = assetType;
        currentEnrichmentAssetId = assetId;

        // Load context options first
        const optionsResponse = await fetch('/api/v1/context/options');
        if (!optionsResponse.ok) throw new Error('Failed to load context options');
        const options = await optionsResponse.json();

        // Populate business units dropdown
        const buSelect = document.getElementById('enrichment-business-unit');
        buSelect.innerHTML = '<option value="">-- Select Business Unit --</option>';
        (options.business_units || []).forEach(bu => {
            const opt = document.createElement('option');
            opt.value = bu;
            opt.textContent = bu;
            buSelect.appendChild(opt);
        });

        // Set default scope to org-wide
        document.querySelector('input[name="enrichmentScope"][value="org-wide"]').checked = true;
        updateEnrichmentScopeUI();

        // Show calculated score info (would be populated if we had engagement context)
        document.getElementById('enrichmentCalculatedScore').textContent = asset.priority_score || 'N/A';

        // Reset form
        document.getElementById('enrichment-business-unit').value = '';
        document.getElementById('enrichment-business-function').value = '';
        document.getElementById('enrichment-data-classification').value = '';
        document.getElementById('enrichment-dependencies').value = '';
        document.getElementById('enrichment-migration-path').value = '';
        document.getElementById('enrichment-compliance-scope').value = [];
        document.getElementById('enrichment-owner').value = '';
        document.getElementById('enrichment-notes').value = '';
        document.getElementById('enrichment-override-enabled').checked = false;
        document.getElementById('enrichment-excluded').checked = false;
        document.getElementById('enrichmentOverrideControls').style.display = 'none';
        document.getElementById('enrichmentExclusionControls').style.display = 'none';

        // Open modal
        document.getElementById('assetEnrichmentModal').classList.add('active');

    } catch (error) {
        console.error('Error opening enrichment modal:', error);
        showAlert('Error loading enrichment form: ' + error.message, 'error');
    }
}

function updateEnrichmentScopeUI() {
    const scope = document.querySelector('input[name="enrichmentScope"]:checked').value;
    console.log('Enrichment scope selected:', scope);
    // In a real implementation, this might enable/disable certain fields
}

function toggleOverrideFieldsEnrichment() {
    const checkbox = document.getElementById('enrichment-override-enabled');
    const controls = document.getElementById('enrichmentOverrideControls');
    controls.style.display = checkbox.checked ? 'block' : 'none';

    if (checkbox.checked) {
        updateEnrichmentPhasePreview();
    }
}

function toggleExclusionFieldsEnrichment() {
    const checkbox = document.getElementById('enrichment-excluded');
    const controls = document.getElementById('enrichmentExclusionControls');
    controls.style.display = checkbox.checked ? 'block' : 'none';
}

function updateEnrichmentPhasePreview() {
    const score = parseInt(document.getElementById('enrichment-override-score').value) || 50;
    document.getElementById('enrichmentScoreDisplay').textContent = score;

    // Map score to phase (matching pqc_reporting_service logic)
    let phase = 'Phase Unknown';
    if (score >= 80) phase = 'Phase 1 (Immediate)';
    else if (score >= 60) phase = 'Phase 2 (Urgent)';
    else if (score >= 40) phase = 'Phase 3 (High)';
    else if (score >= 20) phase = 'Phase 4 (Medium)';
    else phase = 'Phase 5 (Low)';

    document.getElementById('enrichmentPhasePreview').textContent = phase;
}

function closeAssetEnrichmentModal() {
    document.getElementById('assetEnrichmentModal').classList.remove('active');
    currentEnrichmentAsset = null;
    currentEnrichmentAssetType = null;
    currentEnrichmentAssetId = null;
}

async function saveAssetEnrichment() {
    try {
        if (!currentEnrichmentAssetId) {
            showAlert('Asset ID not set', 'error');
            return;
        }

        const scope = document.querySelector('input[name="enrichmentScope"]:checked').value;
        const engagement_id = scope === 'engagement-specific' ? 'current_engagement' : null;

        // Collect compliance scope values
        const complianceScopeSelect = document.getElementById('enrichment-compliance-scope');
        const complianceScope = Array.from(complianceScopeSelect.selectedOptions).map(opt => opt.value).join(',');

        // Build request
        const requestBody = {
            asset_id: currentEnrichmentAssetId,
            asset_type: currentEnrichmentAssetType,
            business_unit: document.getElementById('enrichment-business-unit').value || null,
            business_function: document.getElementById('enrichment-business-function').value || null,
            data_classification: document.getElementById('enrichment-data-classification').value || null,
            dependencies: document.getElementById('enrichment-dependencies').value || null,
            migration_path: document.getElementById('enrichment-migration-path').value || null,
            compliance_scope: complianceScope || null,
            owner: document.getElementById('enrichment-owner').value || null,
            notes: document.getElementById('enrichment-notes').value || null,
            override_enabled: document.getElementById('enrichment-override-enabled').checked ? 1 : 0,
            override_score: document.getElementById('enrichment-override-enabled').checked ? parseInt(document.getElementById('enrichment-override-score').value) : null,
            override_reason: document.getElementById('enrichment-override-enabled').checked ? document.getElementById('enrichment-override-reason').value : null,
            excluded: document.getElementById('enrichment-excluded').checked ? 1 : 0,
            exclusion_reason: document.getElementById('enrichment-excluded').checked ? document.getElementById('enrichment-exclusion-reason').value : null
        };

        // Determine endpoint based on scope
        let endpoint;
        if (engagement_id) {
            endpoint = `/api/v1/engagements/${engagement_id}/context`;
        } else {
            // For org-wide, use a generic endpoint - would need API support
            endpoint = `/api/v1/context/enrich`;
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save enrichment');
        }

        const result = await response.json();
        console.log('Enrichment saved:', result);

        closeAssetEnrichmentModal();
        showAlert('Asset enrichment saved successfully', 'success');

        // Refresh the assets table
        loadAssetsCertificates();

    } catch (error) {
        console.error('Error saving enrichment:', error);
        showAlert('Error saving enrichment: ' + error.message, 'error');
    }
}