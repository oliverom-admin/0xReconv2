/**
 * Report Verifier - Phase 4/5 Integration
 *
 * Handles verification and decryption of encrypted reports.
 * Phase 4: Provides encrypted blobs and signature
 * Phase 5: Will provide P12 decryption (placeholder for now)
 */

class ReportVerifier {
    constructor() {
        this.encryptedBlobs = null;
        this.encryptionMetadata = null;
        this.signingResult = null;
        this.reportData = null;
        this.isDecrypted = false;
    }

    /**
     * Extract encrypted blobs from HTML
     * Phase 4 output: {username: base64_encrypted_blob, ...}
     */
    extractEncryptedBlobs() {
        try {
            const elem = document.getElementById('caip-encrypted-blobs');
            if (!elem) {
                console.warn('No encrypted blobs found in HTML');
                return null;
            }
            this.encryptedBlobs = JSON.parse(elem.textContent);
            console.log('Extracted encrypted blobs for ' + Object.keys(this.encryptedBlobs).length + ' recipients');
            return this.encryptedBlobs;
        } catch (error) {
            console.error('Failed to extract encrypted blobs: ' + error.message);
            return null;
        }
    }

    /**
     * Extract encryption metadata from HTML
     * Contains algorithm, recipients, timestamps for Phase 5
     */
    extractEncryptionMetadata() {
        try {
            const elem = document.getElementById('caip-encryption-metadata');
            if (!elem) {
                console.warn('No encryption metadata found in HTML');
                return null;
            }
            this.encryptionMetadata = JSON.parse(elem.textContent);
            console.log('Extracted encryption metadata: ' + JSON.stringify(this.encryptionMetadata));
            return this.encryptionMetadata;
        } catch (error) {
            console.error('Failed to extract encryption metadata: ' + error.message);
            return null;
        }
    }

    /**
     * Extract signing result (signature + certificate)
     * Used for offline verification in Phase 5
     */
    extractSigningResult() {
        try {
            const elem = document.getElementById('caip-signing-result');
            if (!elem) {
                console.warn('No signing result found in HTML');
                return null;
            }
            this.signingResult = JSON.parse(elem.textContent);
            console.log('Extracted signing result: signature=' + this.signingResult.signature.substring(0, 20) + '...');
            return this.signingResult;
        } catch (error) {
            console.error('Failed to extract signing result: ' + error.message);
            return null;
        }
    }

    /**
     * Extract plaintext report data (if present)
     * For backward compatibility with Phase 3 (unencrypted reports)
     */
    extractReportData() {
        try {
            const elem = document.getElementById('pkiReportDataJson');
            if (!elem) {
                console.warn('No plaintext report data found');
                return null;
            }
            this.reportData = JSON.parse(elem.textContent);
            this.isDecrypted = true;
            console.log('Extracted plaintext report data');
            return this.reportData;
        } catch (error) {
            console.error('Failed to extract report data: ' + error.message);
            return null;
        }
    }

    /**
     * Check if report is encrypted
     * Returns true if encrypted blobs exist
     */
    isReportEncrypted() {
        if (this.encryptedBlobs === null) {
            this.extractEncryptedBlobs();
        }
        return this.encryptedBlobs !== null && Object.keys(this.encryptedBlobs).length > 0;
    }

    /**
     * Get recipients of encrypted report
     * Phase 5 will verify user's P12 is in this list
     */
    getRecipients() {
        if (!this.encryptionMetadata) {
            this.extractEncryptionMetadata();
        }
        if (this.encryptionMetadata && this.encryptionMetadata.encryption_recipients) {
            return this.encryptionMetadata.encryption_recipients;
        }
        return [];
    }

    /**
     * Get signing certificate for verification
     * Phase 5 will use this to verify signature offline
     */
    getSigningCertificate() {
        if (!this.signingResult) {
            this.extractSigningResult();
        }
        if (this.signingResult && this.signingResult.certificate_pem) {
            return this.signingResult.certificate_pem;
        }
        return null;
    }

    /**
     * Get signature for verification
     * Signs the encrypted blob (not plaintext)
     */
    getSignature() {
        if (!this.signingResult) {
            this.extractSigningResult();
        }
        if (this.signingResult && this.signingResult.signature) {
            return this.signingResult.signature;
        }
        return null;
    }

    /**
     * Get first encrypted blob (for verification without decryption)
     * Signature verifies on this blob
     */
    getFirstEncryptedBlob() {
        if (!this.encryptedBlobs) {
            this.extractEncryptedBlobs();
        }
        if (this.encryptedBlobs && Object.keys(this.encryptedBlobs).length > 0) {
            return Object.values(this.encryptedBlobs)[0];
        }
        return null;
    }

    /**
     * Show encryption warning to user
     * Phase 5: This is shown before P12 is required
     */
    showEncryptionWarning() {
        const warningDiv = document.createElement('div');
        warningDiv.id = 'encryption-warning-banner';
        warningDiv.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
            padding: 16px 24px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
            z-index: 1000;
            font-size: 14px;
            font-weight: 500;
        `;
        warningDiv.innerHTML = `
            <div style="max-width: 1200px; margin: 0 auto;">
                <strong>Encrypted Report:</strong> This report is encrypted with your organization's public key.
                To view the full report, you must provide your P12 certificate.
            </div>
        `;
        document.body.insertBefore(warningDiv, document.body.firstChild);
        return warningDiv;
    }

    /**
     * Initialize report on page load
     * Detects if encrypted or plaintext
     */
    initialize() {
        console.log('Initializing Report Verifier...');

        // Extract all available data
        this.extractReportData();
        this.extractEncryptedBlobs();
        this.extractEncryptionMetadata();
        this.extractSigningResult();

        // Determine status
        if (this.isReportEncrypted()) {
            console.log('Report is encrypted. Phase 5 will handle decryption.');
            console.log('Recipients: ' + this.getRecipients().join(', '));
            this.showEncryptionWarning();
            return {
                status: 'encrypted',
                recipients: this.getRecipients(),
                message: 'Report is encrypted. Upload P12 to view.'
            };
        } else if (this.reportData) {
            console.log('Report is plaintext (backward compatible)');
            return {
                status: 'plaintext',
                decrypted: true,
                message: 'Report loaded successfully'
            };
        } else {
            console.error('No report data or encrypted blobs found');
            return {
                status: 'error',
                message: 'Report data not found in HTML'
            };
        }
    }

    /**
     * Placeholder for Phase 5 decryption
     * Will be implemented when user provides P12
     */
    decryptWithP12(p12File, password, username) {
        // Phase 5 implementation:
        // 1. Parse P12 to extract private key
        // 2. Validate username in recipients
        // 3. Decrypt encrypted_blobs[username] with private key
        // 4. Return decrypted JSON report
        console.log('Phase 5: Decryption placeholder (Phase 5 will implement)');
        console.log('Would decrypt for username: ' + username);
        return null;
    }
}

// Global instance
let reportVerifier = null;

// Initialize when DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        reportVerifier = new ReportVerifier();
        const status = reportVerifier.initialize();
        console.log('Report Verifier initialized: ' + JSON.stringify(status));
    });
} else {
    reportVerifier = new ReportVerifier();
    const status = reportVerifier.initialize();
    console.log('Report Verifier initialized: ' + JSON.stringify(status));
}
