/**
 * Certificate Management Module
 * Handles CA and certificate management UI and API interactions
 */

class CertificateManagementModule {
    constructor() {
        this.internalCA = null;
        this.currentCA = null;
        this.currentCertificate = null;
        this.currentCAObject = null;
        this.currentCertificateObject = null;
        this.caList = [];
        this.certificateList = [];
        // Phase 3: Engagement CA & Report Signing Certificates
        this.engagementCAs = [];
        this.reportSigningCerts = [];
        this.initEventListeners();
    }

    initEventListeners() {
        // Sidebar navigation
        document.addEventListener('click', (e) => {
            if (e.target.closest('[data-main-tab="certificate-management"]')) {
                this.loadCertificateManagement();
            }
        });

        // CA and Certificate selection
        document.addEventListener('click', (e) => {
            const button = e.target.closest('.cert-item-button');
            if (button) {
                const caId = button.dataset.caId;
                const certId = button.dataset.certId;

                if (caId) {
                    this.selectCA(caId);
                } else if (certId) {
                    this.selectCertificate(certId);
                }
            }
        });

        // Action buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('[data-action="new-ca"]')) {
                this.showNewCAModal();
            }
            if (e.target.closest('[data-action="renew-cert"]')) {
                this.showRenewCertModal();
            }
            if (e.target.closest('[data-action="revoke-cert"]')) {
                this.showRevokeCertModal();
            }
            if (e.target.closest('[data-action="view-cert-details"]')) {
                this.showCertificateDetails();
            }
            if (e.target.closest('[data-action="download-cert"]')) {
                this.downloadCertificate();
            }
            if (e.target.closest('[data-action="decommission-ca"]')) {
                const engagementId = e.target.closest('[data-engagement-id]')?.dataset.engagementId;
                if (engagementId) {
                    this.showDecommissionCAModal(engagementId);
                }
            }
            if (e.target.closest('[data-action="revoke-collector-cert"]')) {
                const certId = e.target.closest('[data-cert-id]')?.dataset.certId;
                const collectorId = e.target.closest('[data-collector-id]')?.dataset.collectorId;
                if (certId && collectorId) {
                    if (confirm(`Revoke certificate for collector "${collectorId}"? This cannot be undone.`)) {
                        this.revokeCollectorCert(certId, collectorId);
                    }
                }
            }
        });

        // Modal close buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('[data-modal-close]')) {
                const modal = e.target.closest('.cert-modal');
                if (modal) modal.classList.remove('active');
            }
        });

        // Modal background click
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('cert-modal')) {
                e.target.classList.remove('active');
            }
        });
    }

    async loadCertificateManagement() {
        const container = document.getElementById('certificate-authorities-content');
        if (!container) return;

        // Show loading state
        container.innerHTML = '<div style="padding: 40px; text-align: center;">Loading certificate management...</div>';

        try {
            // Fetch internal CA, engagement CAs, and certificates
            // Phase 3: Also fetch report signing certificates
            await Promise.all([
                this.fetchInternalCA(),
                this.fetchCAs(),
                this.fetchCertificates(),
                this.fetchReportSigningCerts()
            ]);

            // Default to internal CA if no selection made
            if (!this.currentCA && this.internalCA) {
                this.currentCA = '__internal__';
            }

            this.renderCertificateManagement(container);
        } catch (error) {
            console.error('Failed to load certificate management:', error);
            container.innerHTML = `
                <div style="padding: 40px; text-align: center; color: #ef4444;">
                    <div style="font-size: 24px; margin-bottom: 16px;">⚠️</div>
                    <div style="font-weight: 600; margin-bottom: 8px;">Failed to Load</div>
                    <div style="color: #6b7280; font-size: 13px;">${error.message}</div>
                </div>
            `;
        }
    }

    async fetchInternalCA() {
        try {
            const response = await fetch('/api/v1/ca/internal');
            if (!response.ok) throw new Error('Failed to fetch internal CA');
            const data = await response.json();
            this.internalCA = data.ca || null;
            return this.internalCA;
        } catch (error) {
            console.warn('Could not fetch internal CA:', error);
            this.internalCA = null;
            return null;
        }
    }

    async fetchCAs() {
        try {
            const response = await fetch('/api/v1/ca/engagement-cas');
            if (!response.ok) throw new Error('Failed to fetch CAs');
            const data = await response.json();
            this.caList = data.certificates || [];
            return this.caList;
        } catch (error) {
            console.warn('Could not fetch CA list:', error);
            this.caList = [];
            return [];
        }
    }

    async fetchCertificates() {
        try {
            const caName = this.currentCA || 'engagement-001';
            const response = await fetch(`/api/v1/ca/${caName}/certificates`);
            if (!response.ok) throw new Error('Failed to fetch certificates');
            const data = await response.json();
            this.certificateList = data.certificates || [];
            return this.certificateList;
        } catch (error) {
            console.warn('Could not fetch certificates:', error);
            this.certificateList = [];
            return [];
        }
    }

    // Phase 3: Fetch Engagement CA certificates
    async fetchEngagementCAs() {
        try {
            const response = await fetch('/api/v1/ca/engagement-cas');
            if (!response.ok) {
                // Endpoint may not exist yet if Phase 3 not fully deployed
                console.warn('Could not fetch engagement CAs (Phase 3 not yet deployed)');
                this.engagementCAs = [];
                return [];
            }
            const data = await response.json();
            this.engagementCAs = data.certificates || [];
            return this.engagementCAs;
        } catch (error) {
            console.warn('Could not fetch engagement CAs:', error);
            this.engagementCAs = [];
            return [];
        }
    }

    // Phase 3: Fetch Report Signing certificates
    async fetchReportSigningCerts() {
        try {
            const response = await fetch('/api/v1/ca/report-signing-certs');
            if (!response.ok) {
                // Endpoint may not exist yet if Phase 3 not fully deployed
                console.warn('Could not fetch report signing certs (Phase 3 not yet deployed)');
                this.reportSigningCerts = [];
                return [];
            }
            const data = await response.json();
            this.reportSigningCerts = data.certificates || [];
            return this.reportSigningCerts;
        } catch (error) {
            console.warn('Could not fetch report signing certs:', error);
            this.reportSigningCerts = [];
            return [];
        }
    }

    renderCertificateManagement(container) {
        container.innerHTML = `
            <div class="cert-management-container">
                <!-- Sidebar -->
                <div class="cert-sidebar">
                    ${this.renderCASidebar()}
                </div>

                <!-- Main Content -->
                <div class="cert-content">
                    ${this.currentCA ? this.renderCADetails() : this.renderEmptyState()}
                </div>
            </div>

            <!-- Modals -->
            ${this.renderModals()}
        `;

        // Attach modal handlers
        this.attachModalHandlers();
    }

    renderCASidebar() {
        return `
            ${this.internalCA ? `
            <div class="cert-sidebar-section">
                <div class="cert-sidebar-title">Internal Infrastructure</div>
                <div class="cert-item-list">
                    <button class="cert-item-button ${this.currentCA === '__internal__' ? 'active' : ''}"
                            data-ca-id="__internal__">
                        <div class="cert-item-label">
                            <div class="cert-item-name">🏛️ Internal CA</div>
                            <div class="cert-item-meta">Expires: ${new Date(this.internalCA.expires_at).toLocaleDateString()}</div>
                        </div>
                        <span class="cert-item-status ${this.getCertStatus(this.internalCA.expires_at)}">${this.getCertStatusText(this.internalCA.expires_at)}</span>
                    </button>
                </div>
            </div>
            ` : ''}

            ${this.caList.length > 0 ? `
            <div class="cert-sidebar-section">
                <div class="cert-sidebar-title">Engagement CAs (Legacy)</div>
                <div class="cert-item-list">
                    ${this.caList.map(ca => `
                        <button class="cert-item-button ${this.currentCA === ca.engagement_id ? 'active' : ''}"
                                data-ca-id="${ca.engagement_id}">
                            <div class="cert-item-label">
                                <div class="cert-item-name">🏛️ ${ca.customer_name && ca.project_name ? `${ca.customer_name} - ${ca.project_name}` : ca.engagement_id}</div>
                                <div class="cert-item-meta">Expires: ${new Date(ca.expires_at).toLocaleDateString()}</div>
                            </div>
                            <span class="cert-item-status ${this.getCertStatus(ca.expires_at)}">${this.getCertStatusText(ca.expires_at)}</span>
                        </button>
                    `).join('')}
                </div>
                <button style="width: 100%; margin-top: 12px;" class="cert-action-btn" data-action="new-ca">
                    ➕ New CA
                </button>
            </div>
            ` : ''}

            ${this.reportSigningCerts && this.reportSigningCerts.length > 0 ? `
            <div class="cert-sidebar-section">
                <div class="cert-sidebar-title">Report Signing Certs</div>
                <div class="cert-item-list">
                    ${this.reportSigningCerts.map(cert => {
                        // Look up engagement name and project from caList
                        const ca = this.caList.find(c => c.engagement_id === cert.engagement_id);
                        const displayName = ca && ca.customer_name && ca.project_name
                            ? `${ca.customer_name} - ${ca.project_name}`
                            : ca?.customer_name || cert.engagement_id;
                        return `
                        <button class="cert-item-button ${this.currentCA === 'report-' + cert.engagement_id ? 'active' : ''}"
                                data-ca-id="report-${cert.engagement_id}">
                            <div class="cert-item-label">
                                <div class="cert-item-name">📋 ${displayName}</div>
                                <div class="cert-item-meta">Expires: ${new Date(cert.expires_at).toLocaleDateString()}</div>
                            </div>
                            <span class="cert-item-status ${this.getCertStatus(cert.expires_at)}">${this.getCertStatusText(cert.expires_at)}</span>
                        </button>
                    `;
                    }).join('')}
                </div>
            </div>
            ` : ''}
        `;
    }

    renderCADetails() {
        // Handle internal CA
        if (this.currentCA === '__internal__') {
            return this.renderInternalCADetails();
        }

        // Handle Report Signing certificates
        if (this.currentCA && this.currentCA.startsWith('report-')) {
            const engId = this.currentCA.substring(7);
            const cert = this.reportSigningCerts.find(c => c.engagement_id === engId);
            if (cert) return this.renderReportSigningCertDetails(cert);
        }

        const ca = this.caList.find(c => c.engagement_id === this.currentCA);
        if (!ca) return this.renderEmptyState();

        const daysUntilExpiry = Math.ceil((new Date(ca.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
        const isExpiring = daysUntilExpiry < 30;

        // Format the CA name with customer and project
        const caDisplayName = ca.customer_name && ca.project_name
            ? `${ca.customer_name} - ${ca.project_name}`
            : ca.engagement_id;

        return `
            <div class="cert-content-header">
                <div>
                    <div class="cert-content-title">🏛️ ${caDisplayName} Certificate Authority</div>
                    <div class="cert-content-subtitle">Engagement: ${ca.engagement_id}</div>
                </div>
                <div class="cert-actions">
                    <button class="cert-action-btn secondary" data-action="view-cert-details">📋 View</button>
                    <button class="cert-action-btn secondary" data-action="download-cert">⬇️ Download</button>
                    <button class="cert-action-btn danger" data-action="decommission-ca" data-engagement-id="${ca.engagement_id}">🔴 Decommission CA</button>
                </div>
            </div>

            ${isExpiring ? `
                <div class="cert-expiry-warning">
                    <div class="cert-expiry-warning-icon">⚠️</div>
                    <div class="cert-expiry-warning-content">
                        <div class="cert-expiry-warning-title">Certificate Expiring Soon</div>
                        <div class="cert-expiry-warning-message">
                            This certificate will expire in ${daysUntilExpiry} days. Plan renewal accordingly.
                        </div>
                    </div>
                </div>
            ` : ''}

            <div class="cert-details">
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Serial Number</div>
                    <div class="cert-detail-value mono">${ca.certificate_serial}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Status</div>
                    <div class="cert-detail-value">${ca.status}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issuer</div>
                    <div class="cert-detail-value">${ca.issuer || 'Unknown'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Algorithm</div>
                    <div class="cert-detail-value">${ca.algorithm || 'Unknown'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Key Size</div>
                    <div class="cert-detail-value">${ca.key_size ? (ca.algorithm === 'EC' ? ca.key_size : ca.key_size + '-bit') : 'Unknown'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issued</div>
                    <div class="cert-detail-value">${new Date(ca.issued_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Expires</div>
                    <div class="cert-detail-value">${new Date(ca.expires_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Days Until Expiry</div>
                    <div class="cert-detail-value">${daysUntilExpiry} days</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Rotations</div>
                    <div class="cert-detail-value">${ca.rotation_count || 0}</div>
                </div>
            </div>

            <div style="margin-top: 24px;">
                <div style="font-weight: 600; margin-bottom: 12px; font-size: 14px;">📊 Certificate Health (1-year lifetime)</div>
                <div class="cert-progress-bar">
                    <div class="cert-progress-fill ${isExpiring ? 'expiring' : ''}" style="width: ${Math.max(10, Math.min(100, (daysUntilExpiry / 365) * 100))}%;"></div>
                </div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 8px;">
                    ${(() => {
                        const totalDays = Math.ceil((new Date(ca.expires_at) - new Date(ca.issued_at)) / (1000 * 60 * 60 * 24));
                        const percentRemaining = Math.max(0, (daysUntilExpiry / totalDays) * 100);
                        return percentRemaining.toFixed(1) + '% of certificate lifetime remaining';
                    })()}
                </div>
            </div>

            <div style="margin-top: 32px; border-top: 1px solid #e5e7eb; padding-top: 24px;">
                <div style="font-weight: 600; margin-bottom: 16px; font-size: 14px;">📜 Collector Certificates Issued</div>
                <div id="issued-certs-list-${ca.engagement_id}" style="margin-top: 12px;">
                    <div style="text-align: center; color: #9ca3af; padding: 24px;">Loading issued certificates...</div>
                </div>
            </div>
        `;
    }

    async loadIssuedCertificates(engagementId) {
        const container = document.getElementById(`issued-certs-list-${engagementId}`);
        if (!container) return;

        try {
            const response = await fetch(`/api/v1/ca/${engagementId}/issued-certificates`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();
            const dashboardCerts = data.dashboard_certificates || [];
            const collectorCerts = data.collector_certificates || [];
            const allCerts = [...dashboardCerts, ...collectorCerts];

            if (allCerts.length === 0) {
                container.innerHTML = '<div style="text-align: center; color: #9ca3af; padding: 24px;">No certificates issued yet</div>';
                return;
            }

            let html = '';

            // Dashboard certificates section
            if (dashboardCerts.length > 0) {
                html += `
                    <div style="margin-bottom: 24px;">
                        <h4 style="margin: 0 0 12px 0; font-weight: 600; color: #1f2937;">Dashboard Server Certificate</h4>
                        <div class="cert-table">
                            <table class="cert-table">
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Serial Number</th>
                                        <th>Issued</th>
                                        <th>Expires</th>
                                        <th>Days Remaining</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${dashboardCerts.map(cert => `
                                        <tr>
                                            <td style="font-weight: 500;">🖥️ Dashboard</td>
                                            <td style="font-family: 'Courier New', monospace; font-size: 11px;">${cert.serial_number.substring(0, 16)}...</td>
                                            <td style="font-size: 12px;">${new Date(cert.issued_at).toLocaleDateString()}</td>
                                            <td style="font-size: 12px;">${new Date(cert.expires_at).toLocaleDateString()}</td>
                                            <td style="text-align: center; font-weight: 500;">${cert.days_until_expiry || 'N/A'}</td>
                                            <td>
                                                <span class="status-badge" style="background: ${cert.status === 'retired' ? '#fee2e2; color: #991b1b' : cert.days_until_expiry < 30 ? '#fef3c7; color: #92400e' : '#dcfce7; color: #15803d'}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">
                                                    ${cert.status === 'retired' ? 'RETIRED' : cert.days_until_expiry < 30 ? 'EXPIRING' : 'ACTIVE'}
                                                </span>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }

            // Collector certificates section
            if (collectorCerts.length > 0) {
                html += `
                    <div>
                        <h4 style="margin: 0 0 12px 0; font-weight: 600; color: #1f2937;">Collector Certificates (${collectorCerts.length})</h4>
                        <div class="cert-table">
                            <table class="cert-table">
                                <thead>
                                    <tr>
                                        <th>Collector ID</th>
                                        <th>Serial Number</th>
                                        <th>Issued</th>
                                        <th>Expires</th>
                                        <th>Days Remaining</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${collectorCerts.map(cert => `
                                        <tr>
                                            <td style="font-weight: 500;">${cert.collector_id}</td>
                                            <td style="font-family: 'Courier New', monospace; font-size: 11px;">${cert.serial_number.substring(0, 16)}...</td>
                                            <td style="font-size: 12px;">${new Date(cert.issued_at).toLocaleDateString()}</td>
                                            <td style="font-size: 12px;">${new Date(cert.expires_at).toLocaleDateString()}</td>
                                            <td style="text-align: center; font-weight: 500;">${cert.days_until_expiry || 'N/A'}</td>
                                            <td>
                                                <span class="status-badge" style="background: ${cert.status === 'revoked' ? '#fee2e2; color: #991b1b' : cert.days_until_expiry < 30 ? '#fef3c7; color: #92400e' : '#dcfce7; color: #15803d'}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">
                                                    ${cert.status === 'revoked' ? 'REVOKED' : cert.days_until_expiry < 30 ? 'EXPIRING' : 'ACTIVE'}
                                                </span>
                                            </td>
                                            <td style="text-align: center;">
                                                ${cert.status !== 'revoked' ? `
                                                    <button class="btn btn-sm btn-danger" style="font-size: 11px; padding: 4px 8px;" data-action="revoke-collector-cert" data-cert-id="${cert.id}" data-collector-id="${cert.collector_id}">Revoke</button>
                                                ` : '<span style="font-size: 11px; color: #6b7280;">—</span>'}
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }

            container.innerHTML = html;
        } catch (error) {
            console.error('Error loading issued certificates:', error);
            container.innerHTML = `<div style="text-align: center; color: #ef4444; padding: 24px;">Error loading certificates</div>`;
        }
    }

    async loadInternalCAIssuedCertificates() {
        const container = document.getElementById('internal-ca-issued-certs');
        if (!container) return;

        try {
            const response = await fetch('/api/v1/ca/internal/issued-certificates');
            if (!response.ok) {
                // Endpoint may not exist yet, show placeholder
                container.innerHTML = '<div style="text-align: center; color: #9ca3af; padding: 24px;">No certificates issued yet by Internal CA</div>';
                return;
            }

            const data = await response.json();
            const certs = data.certificates || [];

            if (certs.length === 0) {
                container.innerHTML = '<div style="text-align: center; color: #9ca3af; padding: 24px;">No certificates issued yet by Internal CA</div>';
                return;
            }

            let html = '<div class="cert-table"><table class="cert-table"><thead><tr><th>Component</th><th>Serial Number</th><th>Issued</th><th>Expires</th><th>Days Remaining</th><th>Status</th></tr></thead><tbody>';

            certs.forEach(cert => {
                const daysRemaining = Math.ceil((new Date(cert.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
                const status = cert.status === 'retired' ? 'RETIRED' : daysRemaining < 30 ? 'EXPIRING' : 'ACTIVE';
                const statusColor = cert.status === 'retired' ? '#fee2e2; color: #991b1b' : daysRemaining < 30 ? '#fef3c7; color: #92400e' : '#dcfce7; color: #15803d';

                html += `
                    <tr>
                        <td style="font-weight: 500;">${cert.component_name || cert.component_id}</td>
                        <td style="font-family: 'Courier New', monospace; font-size: 11px;">${cert.serial_number.substring(0, 16)}...</td>
                        <td style="font-size: 12px;">${new Date(cert.issued_at).toLocaleDateString()}</td>
                        <td style="font-size: 12px;">${new Date(cert.expires_at).toLocaleDateString()}</td>
                        <td style="text-align: center; font-weight: 500;">${daysRemaining}</td>
                        <td><span class="status-badge" style="background: ${statusColor}; padding: 4px 8px; border-radius: 4px; font-size: 11px;">${status}</span></td>
                    </tr>
                `;
            });

            html += '</tbody></table></div>';
            container.innerHTML = html;
        } catch (error) {
            console.debug('Could not load internal CA issued certificates:', error);
            // Show placeholder if API not available
            container.innerHTML = '<div style="text-align: center; color: #9ca3af; padding: 24px;">No certificates issued yet by Internal CA</div>';
        }
    }

    renderInternalCADetails() {
        if (!this.internalCA) return this.renderEmptyState();

        const daysUntilExpiry = Math.ceil((new Date(this.internalCA.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
        const isExpiring = daysUntilExpiry < 365;  // Less than 1 year for internal CA

        return `
            <div class="cert-content-header">
                <div>
                    <div class="cert-content-title">🏛️ CAIP Internal CA</div>
                    <div class="cert-content-subtitle">Infrastructure Certificate Authority (10-year lifetime)</div>
                </div>
                <div class="cert-actions">
                    <button class="cert-action-btn secondary" data-action="view-cert-details">📋 View</button>
                    <button class="cert-action-btn secondary" data-action="download-cert">⬇️ Download</button>
                </div>
            </div>

            ${isExpiring ? `
                <div class="cert-expiry-warning">
                    <div class="cert-expiry-warning-icon">⚠️</div>
                    <div class="cert-expiry-warning-content">
                        <div class="cert-expiry-warning-title">Certificate Expiring Soon</div>
                        <div class="cert-expiry-warning-message">
                            This internal CA will expire in ${daysUntilExpiry} days. Plan renewal accordingly.
                        </div>
                    </div>
                </div>
            ` : ''}

            <div class="cert-details">
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Serial Number</div>
                    <div class="cert-detail-value mono">${this.internalCA.serial_number}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Subject</div>
                    <div class="cert-detail-value mono" style="font-size: 11px;">${this.internalCA.subject}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issuer</div>
                    <div class="cert-detail-value">${this.internalCA.issuer || 'Self-signed'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Algorithm</div>
                    <div class="cert-detail-value">${this.internalCA.algorithm || 'N/A'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Key Size</div>
                    <div class="cert-detail-value">${this.internalCA.key_size ? this.internalCA.key_size + '-bit' : 'N/A'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issued</div>
                    <div class="cert-detail-value">${new Date(this.internalCA.issued_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Expires</div>
                    <div class="cert-detail-value">${new Date(this.internalCA.expires_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Days Until Expiry</div>
                    <div class="cert-detail-value">${daysUntilExpiry} days</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Rotations</div>
                    <div class="cert-detail-value">${this.internalCA.rotation_count || 0}</div>
                </div>
            </div>

            <div style="margin-top: 24px;">
                <div style="font-weight: 600; margin-bottom: 12px; font-size: 14px;">📊 Certificate Health (10-year lifetime)</div>
                <div class="cert-progress-bar">
                    <div class="cert-progress-fill ${isExpiring ? 'expiring' : ''}" style="width: ${Math.max(10, Math.min(100, (daysUntilExpiry / 3650) * 100))}%;"></div>
                </div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 8px;">${((daysUntilExpiry / 3650) * 100).toFixed(1)}% of certificate lifetime remaining</div>
            </div>

            <div style="margin-top: 24px; padding: 16px; background: #f0f9ff; border: 1px solid #bfdbfe; border-radius: 6px;">
                <div style="font-weight: 600; color: #1e40af; margin-bottom: 8px;">ℹ️ About Internal CA</div>
                <div style="font-size: 13px; color: #1e40af; line-height: 1.6;">
                    The Internal CA is used to issue TLS certificates for CAIP infrastructure components including:
                    <ul style="margin: 8px 0 0 16px; padding: 0;">
                        <li>Dashboard TLS certificate</li>
                        <li>Signing engagement CA's</li>
                        <li>Future internal services and APIs</li>
                    </ul>
                    It is automatically provisioned at first startup and renewed automatically every 10 years.
                </div>
            </div>

            <div style="margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 24px;">
                <div style="font-weight: 600; margin-bottom: 16px; font-size: 14px;">📜 Certificates Issued by Internal CA</div>
                <div id="internal-ca-issued-certs" style="margin-top: 12px;">
                    <div style="text-align: center; color: #9ca3af; padding: 24px;">Loading issued certificates...</div>
                </div>
            </div>
        `;
    }

    // Render Report Signing Certificate details
    renderReportSigningCertDetails(cert) {
        if (!cert) return this.renderEmptyState();

        const daysUntilExpiry = Math.ceil((new Date(cert.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
        const isExpiring = daysUntilExpiry < 30;

        return `
            <div class="cert-content-header">
                <div>
                    <div class="cert-content-title">📋 Report Signing Cert - ${cert.engagement_id}</div>
                    <div class="cert-content-subtitle">Phase 3 Report Signing Certificate</div>
                </div>
                <div class="cert-actions">
                    <button class="cert-action-btn secondary" data-action="view-cert-details">📋 View</button>
                    <button class="cert-action-btn secondary" data-action="download-cert">⬇️ Download</button>
                </div>
            </div>

            ${isExpiring ? `
                <div class="cert-expiry-warning">
                    <div class="cert-expiry-warning-icon">⚠️</div>
                    <div class="cert-expiry-warning-content">
                        <div class="cert-expiry-warning-title">Certificate Expiring Soon</div>
                        <div class="cert-expiry-warning-message">
                            This certificate will expire in ${daysUntilExpiry} days. Plan renewal accordingly.
                        </div>
                    </div>
                </div>
            ` : ''}

            <div class="cert-details">
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Serial Number</div>
                    <div class="cert-detail-value mono">${cert.certificate_serial}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Status</div>
                    <div class="cert-detail-value">${cert.status}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Subject</div>
                    <div class="cert-detail-value mono">${cert.subject}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issuer</div>
                    <div class="cert-detail-value mono">${cert.issuer}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issued</div>
                    <div class="cert-detail-value">${new Date(cert.issued_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Expires</div>
                    <div class="cert-detail-value">${new Date(cert.expires_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Days Until Expiry</div>
                    <div class="cert-detail-value">${daysUntilExpiry} days</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Rotations</div>
                    <div class="cert-detail-value">${cert.rotation_count || 0}</div>
                </div>
            </div>

            <div style="margin-top: 24px;">
                <div style="font-weight: 600; margin-bottom: 12px; font-size: 14px;">📊 Certificate Health (2-year lifetime)</div>
                <div class="cert-progress-bar">
                    <div class="cert-progress-fill ${isExpiring ? 'expiring' : ''}" style="width: ${Math.max(10, Math.min(100, (daysUntilExpiry / 730) * 100))}%;"></div>
                </div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 8px;">${((daysUntilExpiry / 730) * 100).toFixed(1)}% of certificate lifetime remaining</div>
            </div>

            <div style="margin-top: 24px; padding: 16px; background: #fef2f2; border: 1px solid #fee2e2; border-radius: 6px;">
                <div style="font-weight: 600; color: #b91c1c; margin-bottom: 8px;">ℹ️ About Report Signing Certificate</div>
                <div style="font-size: 13px; color: #b91c1c; line-height: 1.6;">
                    This Report Signing Certificate (Phase 3) is used to digitally sign all reports generated for this engagement. It is:
                    <ul style="margin: 8px 0 0 16px; padding: 0;">
                        <li>Issued by the Engagement CA (2-year validity)</li>
                        <li>Used exclusively for report signing operations</li>
                        <li>Stored securely in the vault with AES-256-GCM encryption</li>
                    </ul>
                </div>
            </div>
        `;
    }

    renderCertificateDetails() {
        const cert = this.certificateList.find(c => c.id === this.currentCertificate);
        if (!cert) return this.renderEmptyState();

        const daysUntilExpiry = Math.ceil((new Date(cert.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
        const isExpiring = daysUntilExpiry < 7;
        const isExpired = daysUntilExpiry < 0;

        return `
            <div class="cert-content-header">
                <div>
                    <div class="cert-content-title">📜 ${cert.collector_id}</div>
                    <div class="cert-content-subtitle">Collector Certificate</div>
                </div>
                <div class="cert-actions">
                    <button class="cert-action-btn secondary" data-action="view-cert-details">📋 View</button>
                    <button class="cert-action-btn" data-action="renew-cert">🔄 Renew</button>
                    <button class="cert-action-btn danger" data-action="revoke-cert">❌ Revoke</button>
                </div>
            </div>

            ${isExpiring || isExpired ? `
                <div class="cert-expiry-warning" style="${isExpired ? 'background: #fee2e2; border-color: #fecaca;' : ''}">
                    <div class="cert-expiry-warning-icon">${isExpired ? '❌' : '⚠️'}</div>
                    <div class="cert-expiry-warning-content">
                        <div class="cert-expiry-warning-title">${isExpired ? 'Certificate Expired' : 'Certificate Expiring'}</div>
                        <div class="cert-expiry-warning-message" style="${isExpired ? 'color: #991b1b;' : ''}">
                            ${isExpired ? 'This certificate has expired and should be renewed immediately.' : `This certificate will expire in ${daysUntilExpiry} days.`}
                        </div>
                    </div>
                </div>
            ` : ''}

            <div class="cert-details">
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Serial Number</div>
                    <div class="cert-detail-value mono">${cert.serial_number}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Status</div>
                    <div class="cert-detail-value">${cert.status}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Issued</div>
                    <div class="cert-detail-value">${new Date(cert.issued_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Expires</div>
                    <div class="cert-detail-value">${new Date(cert.expires_at).toLocaleString()}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Days Until Expiry</div>
                    <div class="cert-detail-value" style="${isExpired ? 'color: #991b1b;' : isExpiring ? 'color: #b45309;' : ''}">${isExpired ? 'EXPIRED' : daysUntilExpiry + ' days'}</div>
                </div>
                <div class="cert-detail-card">
                    <div class="cert-detail-label">Renewals</div>
                    <div class="cert-detail-value">${cert.renewal_count || 0}</div>
                </div>
            </div>

            <div style="margin-top: 24px;">
                <div style="font-weight: 600; margin-bottom: 12px; font-size: 14px;">📊 Certificate Health</div>
                <div class="cert-progress-bar">
                    <div class="cert-progress-fill ${isExpired ? 'expired' : isExpiring ? 'expiring' : ''}" style="width: ${Math.max(10, Math.min(100, (daysUntilExpiry / 30) * 100))}%;"></div>
                </div>
                <div style="font-size: 12px; color: #6b7280; margin-top: 8px;">${((daysUntilExpiry / 30) * 100).toFixed(1)}% of certificate lifetime remaining</div>
            </div>

            <div class="cert-actions-grid">
                <div class="cert-action-card" data-action="renew-cert">
                    <div class="cert-action-card-icon">🔄</div>
                    <div class="cert-action-card-label">Renew Certificate</div>
                </div>
                <div class="cert-action-card" data-action="view-cert-details">
                    <div class="cert-action-card-icon">📋</div>
                    <div class="cert-action-card-label">View Details</div>
                </div>
                <div class="cert-action-card" data-action="download-cert">
                    <div class="cert-action-card-icon">⬇️</div>
                    <div class="cert-action-card-label">Download Cert</div>
                </div>
                <div class="cert-action-card" data-action="revoke-cert">
                    <div class="cert-action-card-icon">❌</div>
                    <div class="cert-action-card-label">Revoke</div>
                </div>
            </div>
        `;
    }

    renderEmptyState() {
        return `
            <div class="cert-empty-state">
                <div class="cert-empty-state-icon">🔑</div>
                <div class="cert-empty-state-title">No Certificate Selected</div>
                <div class="cert-empty-state-message">Select a CA or certificate from the sidebar to view details</div>
            </div>
        `;
    }

    renderModals() {
        return `
            <!-- New CA Modal -->
            <div class="cert-modal" id="newCAModal">
                <div class="cert-modal-content" style="max-width: 700px;">
                    <div class="cert-modal-header">
                        <div class="cert-modal-title">Create New Engagement CA</div>
                        <button class="cert-modal-close" data-modal-close>×</button>
                    </div>
                    <div class="cert-modal-body">
                        <form id="newCAForm">
                            <!-- Engagement Selection -->
                            <div class="cert-form-group">
                                <label class="cert-form-label">Engagement *</label>
                                <select class="cert-form-select" name="engagement_id" id="newCAEngagementDropdown" required>
                                    <option value="">-- Select an active engagement --</option>
                                </select>
                            </div>

                            <!-- Certificate Subject Fields (grid layout) -->
                            <div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 16px; margin-bottom: 16px;">
                                <div style="font-weight: 600; font-size: 13px; color: #6b7280; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">Certificate Subject Details</div>

                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                                    <div class="cert-form-group" style="margin-bottom: 0;">
                                        <label class="cert-form-label">Common Name (CN) *</label>
                                        <input type="text" class="cert-form-input" name="cn" required placeholder="e.g., CAIP-CA-4">
                                    </div>
                                    <div class="cert-form-group" style="margin-bottom: 0;">
                                        <label class="cert-form-label">Organization (O) *</label>
                                        <input type="text" class="cert-form-input" name="organization" required placeholder="e.g., Customer Corp">
                                    </div>
                                </div>

                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                                    <div class="cert-form-group" style="margin-bottom: 0;">
                                        <label class="cert-form-label">Organizational Unit (OU)</label>
                                        <input type="text" class="cert-form-input" id="ouField" readonly style="background-color: #f3f4f6; color: #6b7280; cursor: not-allowed;">
                                    </div>
                                    <div class="cert-form-group" style="margin-bottom: 0;">
                                        <label class="cert-form-label">Country (C) *</label>
                                        <input type="text" class="cert-form-input" name="country" required placeholder="e.g., US" maxlength="2">
                                    </div>
                                </div>
                            </div>

                            <!-- CA Lifetime -->
                            <div class="cert-form-group">
                                <label class="cert-form-label">CA Lifetime (Days)</label>
                                <input type="number" class="cert-form-input" name="lifetime_days" value="1825" min="365">
                                <div style="font-size: 12px; color: #6b7280; margin-top: 4px;">Default: 1825 days (5 years)</div>
                            </div>
                        </form>
                    </div>
                    <div class="cert-modal-footer">
                        <button class="cert-action-btn secondary" data-modal-close>Cancel</button>
                        <button class="cert-action-btn" onclick="certificateManagement.submitNewCA()">Create CA</button>
                    </div>
                </div>
            </div>

            <!-- Renew Certificate Modal -->
            <div class="cert-modal" id="renewCertModal">
                <div class="cert-modal-content">
                    <div class="cert-modal-header">
                        <div class="cert-modal-title">Renew Certificate</div>
                        <button class="cert-modal-close" data-modal-close>×</button>
                    </div>
                    <div class="cert-modal-body">
                        <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 12px; margin-bottom: 16px;">
                            <div style="font-size: 13px; color: #1e40af;">
                                ℹ️ This will generate a new certificate with a new key pair. The old certificate will remain valid for 3 days (grace period).
                            </div>
                        </div>
                        <form id="renewCertForm">
                            <div class="cert-form-group">
                                <label class="cert-form-label">Certificate ID</label>
                                <input type="text" class="cert-form-input" name="cert_id" readonly>
                            </div>
                            <div class="cert-form-group">
                                <label class="cert-form-label">Renewal Reason</label>
                                <select class="cert-form-select" name="reason">
                                    <option value="routine">Routine renewal</option>
                                    <option value="key_compromise">Key compromise</option>
                                    <option value="early_renewal">Early renewal</option>
                                </select>
                            </div>
                        </form>
                    </div>
                    <div class="cert-modal-footer">
                        <button class="cert-action-btn secondary" data-modal-close>Cancel</button>
                        <button class="cert-action-btn" onclick="certificateManagement.submitRenewal()">Renew</button>
                    </div>
                </div>
            </div>

            <!-- Revoke Certificate Modal -->
            <div class="cert-modal" id="revokeCertModal">
                <div class="cert-modal-content">
                    <div class="cert-modal-header">
                        <div class="cert-modal-title">Revoke Certificate</div>
                        <button class="cert-modal-close" data-modal-close>×</button>
                    </div>
                    <div class="cert-modal-body">
                        <div style="background: #fee2e2; border: 1px solid #fecaca; border-radius: 6px; padding: 12px; margin-bottom: 16px;">
                            <div style="font-size: 13px; color: #991b1b;">
                                ⚠️ This action cannot be undone. The certificate will be marked as revoked immediately.
                            </div>
                        </div>
                        <form id="revokeCertForm">
                            <div class="cert-form-group">
                                <label class="cert-form-label">Certificate ID</label>
                                <input type="text" class="cert-form-input" name="cert_id" readonly>
                            </div>
                            <div class="cert-form-group">
                                <label class="cert-form-label">Revocation Reason</label>
                                <select class="cert-form-select" name="reason">
                                    <option value="unspecified">Unspecified</option>
                                    <option value="keyCompromise">Key compromise</option>
                                    <option value="cACompromise">CA compromise</option>
                                    <option value="affiliationChanged">Affiliation changed</option>
                                    <option value="superseded">Superseded</option>
                                    <option value="cessationOfOperation">Cessation of operation</option>
                                    <option value="certificateHold">Certificate hold</option>
                                </select>
                            </div>
                        </form>
                    </div>
                    <div class="cert-modal-footer">
                        <button class="cert-action-btn secondary" data-modal-close>Cancel</button>
                        <button class="cert-action-btn danger" onclick="certificateManagement.submitRevocation()">Revoke</button>
                    </div>
                </div>
            </div>
        `;
    }

    selectCA(caId) {
        this.currentCA = caId;
        this.currentCertificate = null;

        // Store the full object for display purposes
        this.currentCAObject = null;
        if (caId.startsWith('report-')) {
            // Report Signing Certificate
            const engagementId = caId.substring(7); // Remove 'report-' prefix
            this.currentCAObject = this.reportSigningCerts.find(c => c.engagement_id === engagementId);
        } else if (caId === '__internal__') {
            this.currentCAObject = this.internalCA;
        } else {
            // Engagement CA
            this.currentCAObject = this.caList.find(c => c.engagement_id === caId);
        }

        this.loadCertificateManagement();
        // Load issued certificates after CA details are rendered
        if (caId === '__internal__') {
            setTimeout(() => this.loadInternalCAIssuedCertificates(), 100);
        } else if (!caId.startsWith('report-')) {
            setTimeout(() => this.loadIssuedCertificates(caId), 100);
        }
    }

    selectCertificate(certId) {
        this.currentCertificate = certId;
        this.currentCertificateObject = this.reportSigningCerts.find(c => c.engagement_id === certId);
        this.renderCertificateDetails();
    }

    async showNewCAModal() {
        const modal = document.getElementById('newCAModal');
        if (!modal) return;

        // Populate engagement dropdown with active engagements
        try {
            const response = await fetch('/api/v1/engagements');
            if (response.ok) {
                const data = await response.json();
                const engagements = data.engagements || [];
                const dropdown = document.getElementById('newCAEngagementDropdown');

                if (dropdown) {
                    // Keep the placeholder option
                    dropdown.innerHTML = '<option value="">-- Select an active engagement --</option>';

                    // Add active engagements
                    engagements.forEach(engagement => {
                        const option = document.createElement('option');
                        option.value = engagement.engagement_id;
                        // Store numeric ID for OU field population
                        option.dataset.engagementId = engagement.id;
                        // Build display name from customer + project
                        const displayName = engagement.customer_name && engagement.project_name
                            ? `${engagement.customer_name} - ${engagement.project_name}`
                            : engagement.engagement_id;
                        option.textContent = `${displayName} (${engagement.engagement_id})`;
                        dropdown.appendChild(option);
                    });

                    // Add change listener to populate OU field
                    dropdown.addEventListener('change', (e) => {
                        const ouField = document.getElementById('ouField');
                        if (ouField && e.target.value) {
                            const selectedOption = e.target.options[e.target.selectedIndex];
                            const engagementId = selectedOption.dataset.engagementId;
                            if (engagementId) {
                                ouField.value = `engagement-${engagementId}`;
                            }
                        } else if (ouField) {
                            ouField.value = '';
                        }
                    });
                }
            }
        } catch (error) {
            console.warn('Could not fetch engagements for dropdown:', error);
        }

        modal.classList.add('active');
    }

    showRenewCertModal() {
        const modal = document.getElementById('renewCertModal');
        if (modal && this.currentCertificate) {
            modal.querySelector('[name="cert_id"]').value = this.currentCertificate;
            modal.classList.add('active');
        }
    }

    showRevokeCertModal() {
        const modal = document.getElementById('revokeCertModal');
        if (modal && this.currentCertificate) {
            modal.querySelector('[name="cert_id"]').value = this.currentCertificate;
            modal.classList.add('active');
        }
    }

    async revokeCollectorCert(certId, collectorId) {
        try {
            const response = await fetch(`/api/v1/collector/certificates/${certId}/revoke`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            const result = await response.json();
            alert(`Certificate for collector "${collectorId}" has been revoked.`);

            // Reload the CA details to refresh the certificates list
            if (this.currentCA) {
                this.loadIssuedCertificates(this.currentCA);
            }
        } catch (error) {
            alert('Error revoking certificate: ' + error.message);
            console.error('Error revoking collector cert:', error);
        }
    }

    showDecommissionCAModal(engagementId) {
        const modalId = `decommission-ca-modal-${engagementId}`;
        let modal = document.getElementById(modalId);

        if (!modal) {
            const modalHTML = `
                <div id="${modalId}" class="cert-modal">
                    <div class="cert-modal-content">
                        <div class="cert-modal-header">
                            <h2>Decommission Engagement CA</h2>
                            <button class="cert-modal-close" data-modal-close>×</button>
                        </div>
                        <div class="cert-modal-body">
                            <div style="background: #fee2e2; border-left: 4px solid #dc2626; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
                                <div style="color: #991b1b; font-weight: 600; margin-bottom: 4px;">⚠️ Warning: This action cannot be undone</div>
                                <div style="color: #991b1b; font-size: 13px;">This will permanently decommission the CA and revoke all collector certificates.</div>
                            </div>

                            <div style="background: #f3f4f6; padding: 12px; border-radius: 4px; margin-bottom: 16px;">
                                <div style="font-weight: 600; margin-bottom: 8px; font-size: 13px;">This action will:</div>
                                <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #374151;">
                                    <li>Mark the Engagement CA as 'decommissioned'</li>
                                    <li>Revoke all active collector certificates</li>
                                    <li>Retire all dashboard server certificates</li>
                                    <li>Mark all collectors as 'inactive'</li>
                                </ul>
                            </div>

                            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 4px; margin-bottom: 16px;">
                                <div style="color: #92400e; font-size: 13px;">
                                    <strong>Collectors</strong> will no longer be able to connect to the dashboard until the CA is re-issued or a new engagement is created.
                                </div>
                            </div>

                            <div>
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; font-weight: 600;">Confirm by typing the engagement ID:</label>
                                <input type="text" id="decommission-confirm-${engagementId}" placeholder="${engagementId}" style="width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px;" />
                            </div>
                        </div>
                        <div class="cert-modal-footer">
                            <button class="cert-action-btn secondary" data-modal-close>Cancel</button>
                            <button class="cert-action-btn danger" id="confirm-decommission-${engagementId}" style="opacity: 0.5; cursor: not-allowed;">Decommission CA</button>
                        </div>
                    </div>
                </div>
            `;

            document.body.insertAdjacentHTML('beforeend', modalHTML);
            modal = document.getElementById(modalId);

            // Add input validation listener
            const confirmInput = document.getElementById(`decommission-confirm-${engagementId}`);
            const confirmBtn = document.getElementById(`confirm-decommission-${engagementId}`);

            confirmInput.addEventListener('input', (e) => {
                const isValid = e.target.value === engagementId;
                if (isValid) {
                    confirmBtn.style.opacity = '1';
                    confirmBtn.style.cursor = 'pointer';
                    confirmBtn.onclick = () => this.submitDecommissionCA(engagementId);
                } else {
                    confirmBtn.style.opacity = '0.5';
                    confirmBtn.style.cursor = 'not-allowed';
                    confirmBtn.onclick = null;
                }
            });
        }

        modal.classList.add('active');
    }

    async submitDecommissionCA(engagementId) {
        try {
            const response = await fetch(`/api/v1/ca/${engagementId}/decommission`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            const result = await response.json();

            const modalId = `decommission-ca-modal-${engagementId}`;
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('active');
                setTimeout(() => modal.remove(), 300);
            }

            alert(`CA decommissioned successfully. ${result.revoked_certificates} collector certificates were revoked.`);
            await this.loadCertificateManagement();
        } catch (error) {
            alert('Error decommissioning CA: ' + error.message);
            console.error('Error decommissioning CA:', error);
        }
    }

    showCertificateDetails() {
        const cert = this.currentCertificateObject || this.currentCAObject;
        if (!cert) return;

        // Determine label based on which certificate is being displayed
        let label = 'Certificate';
        if (this.currentCertificateObject) {
            label = 'Report Signing Certificate';
        } else if (this.currentCAObject) {
            label = this.currentCA === '__internal__' ? 'Internal CA Certificate' : 'Engagement CA Certificate';
        }
        const serial = cert.certificate_serial || cert.serial_number || 'N/A';

        let modal = document.getElementById('certViewModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'certViewModal';
            modal.className = 'modal';
            document.body.appendChild(modal);
        }

        modal.innerHTML = `
            <div class="modal-content" style="max-width: 700px;">
                <div class="modal-header">
                    <h3>${label}</h3>
                    <button class="close-btn" onclick="document.getElementById('certViewModal').style.display='none'">&times;</button>
                </div>
                <div class="modal-body">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
                        <div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Serial</div><div style="font-weight:600;font-size:13px;word-break:break-all;">${serial}</div></div>
                        <div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Status</div><div style="font-weight:600;font-size:13px;">${cert.status || 'active'}</div></div>
                        <div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Subject</div><div style="font-weight:600;font-size:13px;word-break:break-all;">${cert.subject || 'N/A'}</div></div>
                        <div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Issuer</div><div style="font-weight:600;font-size:13px;word-break:break-all;">${cert.issuer || 'N/A'}</div></div>
                        <div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Issued</div><div style="font-weight:600;font-size:13px;">${cert.issued_at || 'N/A'}</div></div>
                        <div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Expires</div><div style="font-weight:600;font-size:13px;">${cert.expires_at || 'N/A'}</div></div>
                    </div>
                    <div style="font-size:11px;color:#6b7280;text-transform:uppercase;margin-bottom:6px;">PEM</div>
                    <textarea readonly style="width:100%;height:200px;font-family:monospace;font-size:11px;border:1px solid #e5e7eb;border-radius:6px;padding:8px;resize:vertical;">${cert.certificate_pem || ''}</textarea>
                </div>
                <div class="modal-footer">
                    <button class="cert-action-btn secondary" onclick="document.getElementById('certViewModal').style.display='none'">Close</button>
                </div>
            </div>`;

        modal.style.display = 'flex';
    }

    downloadCertificate() {
        const cert = this.currentCertificateObject || this.currentCAObject;
        if (!cert || !cert.certificate_pem) return;

        const engId = cert.engagement_id || 'cert';
        const type = this.currentCertificateObject ? 'report-signing' : 'engagement-ca';
        const filename = `${type}-${engId}.cer`;

        const blob = new Blob([cert.certificate_pem], { type: 'application/x-pem-file' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    async submitNewCA() {
        const form = document.getElementById('newCAForm');
        const formData = new FormData(form);

        try {
            const response = await fetch('/api/v1/ca/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.fromEntries(formData))
            });

            if (!response.ok) throw new Error('Failed to create CA');

            document.getElementById('newCAModal').classList.remove('active');
            await this.loadCertificateManagement();
        } catch (error) {
            alert('Error creating CA: ' + error.message);
        }
    }

    async submitRenewal() {
        const form = document.getElementById('renewCertForm');
        const formData = new FormData(form);

        try {
            const response = await fetch(`/api/v1/ca/${this.currentCA}/certificates/${this.currentCertificate}/renew`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.fromEntries(formData))
            });

            if (!response.ok) throw new Error('Failed to renew certificate');

            document.getElementById('renewCertModal').classList.remove('active');
            await this.loadCertificateManagement();
        } catch (error) {
            alert('Error renewing certificate: ' + error.message);
        }
    }

    async submitRevocation() {
        const form = document.getElementById('revokeCertForm');
        const formData = new FormData(form);

        try {
            const response = await fetch(`/api/v1/ca/${this.currentCA}/certificates/${this.currentCertificate}/revoke`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.fromEntries(formData))
            });

            if (!response.ok) throw new Error('Failed to revoke certificate');

            document.getElementById('revokeCertModal').classList.remove('active');
            await this.loadCertificateManagement();
        } catch (error) {
            alert('Error revoking certificate: ' + error.message);
        }
    }

    attachModalHandlers() {
        // Modal would be attached after render
    }

    getCertStatus(expiresAt) {
        const now = new Date();
        const expiry = new Date(expiresAt);
        const daysUntilExpiry = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry < 0) return 'expired';
        if (daysUntilExpiry < 30) return 'expiring';
        return 'active';
    }

    getCertStatusText(expiresAt) {
        const status = this.getCertStatus(expiresAt);
        if (status === 'expired') return 'EXPIRED';
        if (status === 'expiring') return 'EXPIRING';
        return 'ACTIVE';
    }
}

// Initialize when DOM is ready
let certificateManagement;
document.addEventListener('DOMContentLoaded', () => {
    certificateManagement = new CertificateManagementModule();
});
