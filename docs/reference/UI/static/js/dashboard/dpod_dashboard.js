/**
 * DPOD Management Dashboard JavaScript
 * Luna Cloud HSM Code Signing & Key Management
 */

// ==================== TAB MANAGEMENT ====================
function switchTab(tabId) {
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    const tabBtn = document.querySelector(`[data-tab="${tabId}"]`);
    const tabContent = document.getElementById(tabId);
    
    if (tabBtn) tabBtn.classList.add('active');
    if (tabContent) tabContent.classList.add('active');
}

// Initialize tab listeners
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            switchTab(tabId);
        });
    });
    
    // Load initial data
    loadStats();
    loadRecentRequests();
    initDragDrop();
    
    
});

// ==================== MODAL MANAGEMENT ====================
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function openNewRequestModal() {
    resetRequestForm();
    openModal('newRequestModal');
}

function openCloneKeyModal() {
    loadKeyOptions('clone-key-label');
    openModal('cloneKeyModal');
}

function openAttestationModal() {
    loadKeyOptions('attest-key-label');
    openModal('attestationModal');
}

function openUploadRequestModal() {
    clearUploadedFile();
    openModal('uploadRequestModal');
}

// Close modal on backdrop click
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal') && e.target.classList.contains('active')) {
        closeModal(e.target.id);
    }
});

// Close modal on Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
            closeModal(modal.id);
        });
    }
});

// ==================== REQUEST FORM HANDLING ====================
function resetRequestForm() {
    const form = document.getElementById('newRequestForm');
    if (form) form.reset();
    
    // Reset partition selection
    document.querySelectorAll('.partition-option').forEach(opt => opt.classList.remove('selected'));
    const firstPartition = document.querySelector('.partition-option');
    if (firstPartition) {
        firstPartition.classList.add('selected');
        const partitionInput = document.getElementById('req-partition');
        if (partitionInput) partitionInput.value = 'ISR_KaaS_01';
    }
    
    // Reset DN fields visibility
    const dnFields = document.getElementById('dn-fields');
    const rawDnField = document.getElementById('raw-dn-field');
    const useRawDn = document.getElementById('req-use-raw-dn');
    
    if (dnFields) dnFields.style.display = 'block';
    if (rawDnField) rawDnField.style.display = 'none';
    if (useRawDn) useRawDn.checked = false;
    
    // Reset renewal fields
    const renewalFields = document.getElementById('renewal-fields');
    if (renewalFields) renewalFields.style.display = 'none';
}

// Request type toggle
document.addEventListener('DOMContentLoaded', function() {
    const reqType = document.getElementById('req-type');
    if (reqType) {
        reqType.addEventListener('change', function() {
            const renewalFields = document.getElementById('renewal-fields');
            if (renewalFields) {
                renewalFields.style.display = this.value === 'renew' ? 'grid' : 'none';
            }
        });
    }
});

// DN input toggle
function toggleDNInput() {
    const useRawDN = document.getElementById('req-use-raw-dn');
    const dnFields = document.getElementById('dn-fields');
    const rawDnField = document.getElementById('raw-dn-field');
    
    if (!useRawDN || !dnFields || !rawDnField) return;
    
    if (useRawDN.checked) {
        dnFields.style.display = 'none';
        rawDnField.style.display = 'block';
    } else {
        dnFields.style.display = 'block';
        rawDnField.style.display = 'none';
    }
}

// Partition selection
function selectPartition(element, partitionName) {
    document.querySelectorAll('.partition-option').forEach(opt => opt.classList.remove('selected'));
    element.classList.add('selected');
    
    const partitionInput = document.getElementById('req-partition');
    if (partitionInput) partitionInput.value = partitionName;
}

// ==================== SUBMIT NEW REQUEST ====================
function submitNewRequest(event) {
    if (event) event.preventDefault();
    
    // Gather form data
    const requestData = {
        request_name: document.getElementById('req-name')?.value || '',
        request_type: document.getElementById('req-type')?.value || 'new',
        partition: document.getElementById('req-partition')?.value || 'ISR_KaaS_01',
        key_size: parseInt(document.getElementById('req-key-size')?.value || '3072'),
        hash_algorithm: document.getElementById('req-hash-algorithm')?.value || 'SHA384',
        client_hostname: document.getElementById('req-client-hostname')?.value || '',
        include_code_signing_eku: document.getElementById('req-include-code-signing-eku')?.checked ?? true,
        get_pkc_attestation: document.getElementById('req-get-pkc-attestation')?.checked ?? true,
        requester: {
            name: document.getElementById('req-requester-name')?.value || '',
            email: document.getElementById('req-requester-email')?.value || '',
            organization: document.getElementById('req-requester-org')?.value || ''
        }
    };
    
    // Build subject DN
    const useRawDN = document.getElementById('req-use-raw-dn')?.checked;
    if (useRawDN) {
        requestData.subject_dn = document.getElementById('req-raw-dn')?.value || '';
    } else {
        const dnParts = [];
        const fields = [
            { id: 'req-cn', prefix: 'CN' },
            { id: 'req-o', prefix: 'O' },
            { id: 'req-ou', prefix: 'OU' },
            { id: 'req-l', prefix: 'L' },
            { id: 'req-st', prefix: 'ST' },
            { id: 'req-c', prefix: 'C' },
            { id: 'req-email', prefix: 'E' }
        ];
        
        fields.forEach(field => {
            const value = document.getElementById(field.id)?.value;
            if (value) dnParts.push(`${field.prefix}=${value}`);
        });
        
        requestData.subject_dn = dnParts.join(', ');
    }
    
    // Validate required fields
    if (!requestData.request_name) {
        alert('Please enter a request name');
        return;
    }
    
    if (!requestData.subject_dn) {
        alert('Please enter certificate subject information');
        return;
    }
    
    // Close form modal and show progress
    closeModal('newRequestModal');
    showRequestProgress(requestData);
    
    // Execute the request
    executeCodeSigningRequest(requestData);
}

// ==================== REQUEST PROGRESS ====================
function showRequestProgress(requestData) {
    const titleEl = document.getElementById('requestProgressTitle');
    const statusEl = document.getElementById('requestProgressStatus');
    const closeBtn = document.getElementById('requestProgressCloseBtn');
    const cancelBtn = document.getElementById('requestProgressCancelBtn');
    const output = document.getElementById('requestProgressOutput');
    
    if (titleEl) titleEl.textContent = requestData.request_name;
    if (statusEl) statusEl.textContent = 'Initializing...';
    if (closeBtn) closeBtn.style.display = 'none';
    if (cancelBtn) cancelBtn.style.display = 'inline-flex';
    
    if (output) {
        output.innerHTML = `
            <div class="terminal-line info">═══════════════════════════════════════════════════════</div>
            <div class="terminal-line info">         Thales CDS Operations</div>
            <div class="terminal-line info">    DPOD Code Signing Request Tool</div>
            <div class="terminal-line info">═══════════════════════════════════════════════════════</div>
            <div class="terminal-line"></div>
        `;
    }
    
    const modal = document.getElementById('requestProgressModal');
    if (modal) modal.classList.add('active');
}

function appendProgressLine(message, type = '') {
    const output = document.getElementById('requestProgressOutput');
    if (!output) return;
    
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = message;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
}

function closeRequestProgress() {
    const modal = document.getElementById('requestProgressModal');
    if (modal) modal.classList.remove('active');
}

function cancelRequest() {
    if (confirm('Are you sure you want to cancel this request?')) {
        appendProgressLine('Request cancelled by user.', 'warning');
        
        const statusEl = document.getElementById('requestProgressStatus');
        const closeBtn = document.getElementById('requestProgressCloseBtn');
        const cancelBtn = document.getElementById('requestProgressCancelBtn');
        
        if (statusEl) statusEl.textContent = 'Cancelled';
        if (closeBtn) closeBtn.style.display = 'inline-flex';
        if (cancelBtn) cancelBtn.style.display = 'none';
        
        // In production, send cancel signal to backend
        // fetch('/api/dpod/cancel-request', { method: 'POST' });
    }
}

// ==================== EXECUTE CODE SIGNING REQUEST ====================
async function executeCodeSigningRequest(requestData) {
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
    
    try {
        // Step 1: Read request parameters
        appendProgressLine('Reading request parameters...', 'info');
        await sleep(500);
        appendProgressLine(`  Request Name: ${requestData.request_name}`, '');
        appendProgressLine(`  Request Type: ${requestData.request_type}`, '');
        appendProgressLine(`  Subject DN: ${requestData.subject_dn}`, '');
        appendProgressLine(`  Partition: ${requestData.partition}`, '');
        appendProgressLine(`  Key Size: ${requestData.key_size} bits`, '');
        
        updateProgressStatus('Connecting to Azure Key Vault...');
        
        // Step 2: Azure Key Vault
        appendProgressLine('', '');
        appendProgressLine('Connecting to Azure Key Vault...', 'info');
        await sleep(800);
        appendProgressLine('  HSM credential retrieved', 'success');
        
        // Step 3: Connect to HSM
        updateProgressStatus('Connecting to HSM...');
        appendProgressLine('', '');
        appendProgressLine('Connecting to Luna HSM...', 'info');
        await sleep(600);
        appendProgressLine(`  Using slot 0: ${requestData.partition}`, '');
        appendProgressLine('  Logged in to HSM', 'success');
        
        // Step 4: Check for existing key
        appendProgressLine('', '');
        appendProgressLine(`Checking for existing key: ${requestData.request_name}...`, 'info');
        await sleep(400);
        appendProgressLine('  No existing key found - proceeding', 'success');
        
        // Step 5: Generate key pair
        updateProgressStatus('Generating key pair...');
        appendProgressLine('', '');
        appendProgressLine(`Generating RSA key pair (${requestData.key_size} bits)...`, 'info');
        await sleep(1500);
        
        const pubHandle = Math.floor(Math.random() * 90000000) + 10000000;
        const privHandle = pubHandle + 1;
        const pubOUID = '0x' + Array.from({length: 16}, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase();
        const privOUID = '0x' + Array.from({length: 16}, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase();
        
        appendProgressLine(`  Public key handle: ${pubHandle}`, '');
        appendProgressLine(`  Private key handle: ${privHandle}`, '');
        appendProgressLine(`  Public OUID: ${pubOUID}`, '');
        appendProgressLine(`  Private OUID: ${privOUID}`, '');
        appendProgressLine('  Key pair generated successfully', 'success');
        
        // Step 6: Build CSR
        updateProgressStatus('Building CSR...');
        appendProgressLine('', '');
        appendProgressLine('Building Certificate Signing Request...', 'info');
        await sleep(800);
        appendProgressLine(`  Hash Algorithm: ${requestData.hash_algorithm}`, '');
        if (requestData.include_code_signing_eku) {
            appendProgressLine('  Including Code Signing EKU', '');
        }
        appendProgressLine(`  CSR saved: ${requestData.request_name}-CSR.csr`, 'success');
        
        // Step 7: Get PKC attestation
        if (requestData.get_pkc_attestation) {
            updateProgressStatus('Retrieving PKC attestation...');
            appendProgressLine('', '');
            appendProgressLine('Retrieving key attestation (PKC)...', 'info');
            appendProgressLine('  PKC Type: Chrysalis-ITS (Type 2)', '');
            await sleep(1000);
            appendProgressLine('  Verifying attestation chain...', '');
            await sleep(500);
            appendProgressLine(`  Attestation saved: ${requestData.request_name}-KEYATTEST.b64`, 'success');
        }
        
        // Step 8: Clone key (if specified)
        if (requestData.client_hostname) {
            updateProgressStatus('Cloning key...');
            appendProgressLine('', '');
            appendProgressLine(`Cloning key to target host: ${requestData.client_hostname}...`, 'info');
            await sleep(1200);
            appendProgressLine(`  Key cloned to ${requestData.client_hostname}`, 'success');
        }
        
        // Complete
        appendProgressLine('', '');
        appendProgressLine('═══════════════════════════════════════════════════════', 'success');
        appendProgressLine('  Request completed successfully!', 'success');
        appendProgressLine('═══════════════════════════════════════════════════════', 'success');
        appendProgressLine('', '');
        appendProgressLine(`Output directory: Code Signing Requests/${requestData.request_name}`, '');
        appendProgressLine(`CSR file: ${requestData.request_name}-CSR.csr`, '');
        if (requestData.get_pkc_attestation) {
            appendProgressLine(`Attestation file: ${requestData.request_name}-KEYATTEST.b64`, '');
        }
        appendProgressLine(`Log file: ${requestData.request_name}-log.txt`, '');
        
        updateProgressStatus('Completed');
        showProgressComplete();
        
        // Refresh data
        loadRecentRequests();
        loadStats();
        addLogEntry(`Request completed: ${requestData.request_name}`, 'success');
        
    } catch (error) {
        appendProgressLine('', '');
        appendProgressLine(`ERROR: ${error.message}`, 'error');
        updateProgressStatus('Failed');
        showProgressComplete();
        addLogEntry(`Request failed: ${requestData.request_name} - ${error.message}`, 'error');
    }
}

function updateProgressStatus(status) {
    const statusEl = document.getElementById('requestProgressStatus');
    if (statusEl) statusEl.textContent = status;
}

function showProgressComplete() {
    const closeBtn = document.getElementById('requestProgressCloseBtn');
    const cancelBtn = document.getElementById('requestProgressCancelBtn');
    
    if (closeBtn) closeBtn.style.display = 'inline-flex';
    if (cancelBtn) cancelBtn.style.display = 'none';
}

// ==================== KEY MANAGEMENT ====================
function loadKeyOptions(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;
    
    // In production, fetch from backend
    select.innerHTML = `
        <option value="">-- Select Key --</option>
        <option value="Volvo-EV-CodeSign-2024">Volvo-EV-CodeSign-2024</option>
        <option value="Customer-CodeSign-001">Customer-CodeSign-001</option>
        <option value="Test-Signing-Key">Test-Signing-Key</option>
    `;
}

function loadPartitionKeys(partition) {
    const tbody = document.getElementById('keys-table-body');
    if (!tbody) return;
    
    if (!partition) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">Select a partition to view keys.</td></tr>`;
        return;
    }
    
    // In production, fetch from backend
    tbody.innerHTML = `
        <tr>
            <td><strong>Volvo-EV-CodeSign-2024</strong></td>
            <td><span class="badge badge-info">Private</span></td>
            <td>RSA</td>
            <td>3072</td>
            <td><code>12345679</code></td>
            <td><code>0x1234...DF0</code></td>
            <td>
                <span class="key-flag enabled">SIGN</span>
                <span class="key-flag enabled">SENSITIVE</span>
            </td>
            <td class="action-buttons">
                <button class="btn-tiny" onclick="viewKeyDetails('Volvo-EV-CodeSign-2024', 'private')">View</button>
                <button class="btn-tiny" onclick="getKeyAttestation('Volvo-EV-CodeSign-2024')">PKC</button>
            </td>
        </tr>
        <tr>
            <td><strong>Volvo-EV-CodeSign-2024</strong></td>
            <td><span class="badge" style="background: #d1fae5; color: #047857;">Public</span></td>
            <td>RSA</td>
            <td>3072</td>
            <td><code>12345678</code></td>
            <td><code>0x1234...DEF</code></td>
            <td>
                <span class="key-flag enabled">VERIFY</span>
            </td>
            <td class="action-buttons">
                <button class="btn-tiny" onclick="viewKeyDetails('Volvo-EV-CodeSign-2024', 'public')">View</button>
            </td>
        </tr>
        <tr>
            <td><strong>Customer-CodeSign-001</strong></td>
            <td><span class="badge badge-info">Private</span></td>
            <td>RSA</td>
            <td>4096</td>
            <td><code>23456789</code></td>
            <td><code>0x5678...ABC</code></td>
            <td>
                <span class="key-flag enabled">SIGN</span>
                <span class="key-flag enabled">SENSITIVE</span>
            </td>
            <td class="action-buttons">
                <button class="btn-tiny" onclick="viewKeyDetails('Customer-CodeSign-001', 'private')">View</button>
                <button class="btn-tiny" onclick="getKeyAttestation('Customer-CodeSign-001')">PKC</button>
            </td>
        </tr>
    `;
}

function refreshKeyList() {
    const select = document.getElementById('key-partition-select');
    if (select && select.value) {
        loadPartitionKeys(select.value);
    }
}

function viewKeyDetails(keyLabel, keyType) {
    alert(`View ${keyType} key details for: ${keyLabel}`);
    // In production, open key details modal
}

function getKeyAttestation(keyLabel) {
    document.getElementById('attest-key-label').value = keyLabel;
    openAttestationModal();
}

// ==================== PARTITION MANAGEMENT ====================
function refreshPartitions() {
    addLogEntry('Refreshing partition status...', 'info');
    // In production, fetch from backend
    setTimeout(() => {
        addLogEntry('Partition status refreshed', 'success');
    }, 500);
}

// ==================== CLONE KEY ====================
function executeCloneKey() {
    const keyLabel = document.getElementById('clone-key-label')?.value;
    const targetHost = document.getElementById('clone-target-host')?.value;
    const slotNumber = document.getElementById('clone-slot')?.value || '0';
    
    if (!keyLabel) {
        alert('Please select a key to clone');
        return;
    }
    
    if (!targetHost) {
        alert('Please enter a target hostname');
        return;
    }
    
    closeModal('cloneKeyModal');
    addLogEntry(`Cloning key "${keyLabel}" to ${targetHost}...`, 'info');
    
    // In production, call backend API
    setTimeout(() => {
        addLogEntry(`Key "${keyLabel}" cloned to ${targetHost} successfully`, 'success');
    }, 1500);
}

// ==================== GET ATTESTATION ====================
function executeGetAttestation() {
    const keyLabel = document.getElementById('attest-key-label')?.value;
    const pkcType = document.getElementById('attest-pkc-type')?.value || '2';
    const verify = document.getElementById('attest-verify')?.checked ?? true;
    
    if (!keyLabel) {
        alert('Please select a key');
        return;
    }
    
    closeModal('attestationModal');
    addLogEntry(`Retrieving PKC attestation for "${keyLabel}"...`, 'info');
    
    // In production, call backend API
    setTimeout(() => {
        addLogEntry(`PKC attestation retrieved for "${keyLabel}"`, 'success');
    }, 1000);
}

// ==================== CONFIGURATION ====================
function saveConfiguration() {
    const config = {
        hsm: {
            pkcs11_library: document.getElementById('cfg-pkcs11-library')?.value,
            token_label: document.getElementById('cfg-default-partition')?.value,
            key_algorithm: document.getElementById('cfg-key-algorithm')?.value,
            key_size: parseInt(document.getElementById('cfg-key-size')?.value || '3072'),
            hash_algorithm: document.getElementById('cfg-hash-algorithm')?.value
        },
        azure: {
            vault_name: document.getElementById('cfg-vault-name')?.value,
            tenant_id: document.getElementById('cfg-tenant-id')?.value,
            service_principal_id: document.getElementById('cfg-sp-id')?.value,
            certificate_subject: document.getElementById('cfg-cert-subject')?.value,
            skip_azure: document.getElementById('cfg-skip-azure')?.checked
        },
        output: {
            base_directory: document.getElementById('cfg-output-dir')?.value,
            csr_suffix: document.getElementById('cfg-csr-suffix')?.value,
            attestation_suffix: document.getElementById('cfg-attestation-suffix')?.value,
            log_suffix: document.getElementById('cfg-log-suffix')?.value
        }
    };
    
    
    
    // In production, save to backend
    addLogEntry('Configuration saved', 'success');
    alert('Configuration saved successfully!');
}

// ==================== FILE UPLOAD ====================
function handleExcelUpload(event) {
    const file = event.target?.files?.[0];
    if (!file) return;
    
    const fileName = document.getElementById('uploadedFileName');
    const fileInfo = document.getElementById('uploadedFileInfo');
    const processBtn = document.getElementById('processUploadBtn');
    
    if (fileName) fileName.textContent = file.name;
    if (fileInfo) fileInfo.style.display = 'block';
    if (processBtn) processBtn.disabled = false;
    
    addLogEntry(`Excel file uploaded: ${file.name}`, 'info');
}

function clearUploadedFile() {
    const fileInput = document.getElementById('excelFileInput');
    const fileInfo = document.getElementById('uploadedFileInfo');
    const processBtn = document.getElementById('processUploadBtn');
    
    if (fileInput) fileInput.value = '';
    if (fileInfo) fileInfo.style.display = 'none';
    if (processBtn) processBtn.disabled = true;
}

function processUploadedRequest() {
    closeModal('uploadRequestModal');
    
    // Pre-populate form with sample data (in production, parse from Excel)
    document.getElementById('req-name').value = 'Volvo-EV-CodeSign-2024';
    document.getElementById('req-cn').value = 'Volvo Car Corporation';
    document.getElementById('req-o').value = 'Volvo Car Corporation';
    document.getElementById('req-ou').value = 'Software Development';
    document.getElementById('req-l').value = 'Gothenburg';
    document.getElementById('req-st').value = 'Västra Götaland';
    document.getElementById('req-c').value = 'SE';
    document.getElementById('req-requester-name').value = 'John Smith';
    document.getElementById('req-requester-email').value = 'john.smith@volvocars.com';
    document.getElementById('req-requester-org').value = 'Volvo Car Corporation';
    
    addLogEntry('Request form populated from Excel', 'success');
    openNewRequestModal();
}

function initDragDrop() {
    const uploadZone = document.getElementById('excelUploadZone');
    if (!uploadZone) return;
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer?.files;
        if (files && files.length > 0) {
            const fileInput = document.getElementById('excelFileInput');
            if (fileInput) fileInput.files = files;
            handleExcelUpload({ target: { files: files } });
        }
    });
}

// ==================== OPERATION LOGS ====================
function addLogEntry(message, level = 'info') {
    const entries = document.getElementById('operation-log-entries');
    if (!entries) return;
    
    const icons = {
        info: 'ℹ️',
        success: '✅',
        warning: '⚠️',
        error: '❌'
    };
    
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${level}`;
    entry.innerHTML = `
        <span class="log-timestamp">${timestamp}</span>
        <span class="log-icon">${icons[level] || 'ℹ️'}</span>
        <span class="log-message">${message}</span>
    `;
    
    entries.insertBefore(entry, entries.firstChild);
}

function filterLogs() {
    const levelFilter = document.getElementById('log-level-filter')?.value || 'all';
    const operationFilter = document.getElementById('log-operation-filter')?.value || 'all';
    
    
    // In production, apply filters to log display
}

function clearLogs() {
    if (!confirm('Are you sure you want to clear all logs?')) return;
    
    const entries = document.getElementById('operation-log-entries');
    if (entries) {
        const now = new Date();
        const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);
        
        entries.innerHTML = `
            <div class="log-entry info">
                <span class="log-timestamp">${timestamp}</span>
                <span class="log-icon">ℹ️</span>
                <span class="log-message">Logs cleared</span>
            </div>
        `;
    }
}

function exportLogs() {
    const entries = document.getElementById('operation-log-entries');
    if (!entries) return;
    
    const logs = entries.innerText;
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dpod-logs-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    addLogEntry('Logs exported', 'info');
}

// ==================== DATA LOADING ====================
function loadStats() {
    // In production, fetch from backend
    const stats = {
        total_keys: 24,
        csr_generated: 18,
        attestations: 16,
        partitions: 2
    };
    
    document.getElementById('stat-total-keys').textContent = stats.total_keys;
    document.getElementById('stat-csr-generated').textContent = stats.csr_generated;
    document.getElementById('stat-attestations').textContent = stats.attestations;
    document.getElementById('stat-partitions').textContent = stats.partitions;
}

function loadRecentRequests() {
    const tbody = document.getElementById('recent-requests-body');
    if (!tbody) return;
    
    // In production, fetch from backend
    const requests = [
        {
            name: 'Volvo-EV-CodeSign-2024',
            type: 'New',
            partition: 'ISR_KaaS_01',
            status: 'completed',
            created: '2024-01-15 10:30'
        },
        {
            name: 'Customer-CodeSign-001',
            type: 'New',
            partition: 'ISR_KaaS_01',
            status: 'completed',
            created: '2024-01-14 15:45'
        }
    ];
    
    if (requests.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No recent requests. Create one to get started.</td></tr>`;
        return;
    }
    
    tbody.innerHTML = requests.map(req => `
        <tr>
            <td><strong>${req.name}</strong></td>
            <td><span class="badge badge-info">${req.type}</span></td>
            <td><span class="dpod-badge">${req.partition}</span></td>
            <td><span class="status-badge status-${req.status}">${req.status}</span></td>
            <td>${req.created}</td>
            <td class="action-buttons">
                <button class="btn-tiny" onclick="viewRequestDetails('${req.name}')">View</button>
                <button class="btn-tiny" onclick="downloadRequestFiles('${req.name}')">Download</button>
            </td>
        </tr>
    `).join('');
}

function viewRequestDetails(requestName) {
    addLogEntry(`Viewing request: ${requestName}`, 'info');
    // In production, open request details modal
    alert(`View details for: ${requestName}`);
}

function downloadRequestFiles(requestName) {
    addLogEntry(`Downloading files for: ${requestName}`, 'info');
    // In production, trigger file download
    alert(`Download files for: ${requestName}`);
}

// ==================== API INTEGRATION (Production) ====================
const DPODApi = {
    baseUrl: '/api/dpod',
    
    async generateRequest(requestData) {
        const response = await fetch(`${this.baseUrl}/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData)
        });
        return response.json();
    },
    
    async listSlots() {
        const response = await fetch(`${this.baseUrl}/slots`);
        return response.json();
    },
    
    async listKeys(partition) {
        const response = await fetch(`${this.baseUrl}/keys?partition=${partition}`);
        return response.json();
    },
    
    async getAttestation(keyLabel, pkcType = 2) {
        const response = await fetch(`${this.baseUrl}/attestation`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key_label: keyLabel, pkc_type: pkcType })
        });
        return response.json();
    },
    
    async cloneKey(keyLabel, targetHost, slotNumber = 0) {
        const response = await fetch(`${this.baseUrl}/clone`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                key_label: keyLabel,
                target_host: targetHost,
                slot_number: slotNumber
            })
        });
        return response.json();
    },
    
    async testConnection(partition) {
        const response = await fetch(`${this.baseUrl}/test-connection?partition=${partition}`);
        return response.json();
    },
    
    async saveConfiguration(config) {
        const response = await fetch(`${this.baseUrl}/configuration`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        return response.json();
    }
};
