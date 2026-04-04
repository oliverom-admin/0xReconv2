/**
 * ui-controller.js
 *
 * UI Controller for Encrypted Report Handling
 * Orchestrates all modules: state manager, P12 parser, signature verifier, decryptor
 * Binds to HTML elements and handles user interaction
 *
 * Dependencies:
 *  - report-state-manager.js
 *  - p12-parser.js
 *  - signature-verifier.js
 *  - report-decryptor.js
 *  - jsrsasign (CDN)
 *
 * Usage:
 *   const controller = new EncryptedReportController();
 *   await controller.initialize();
 */

class EncryptedReportController {
  constructor() {
    this.stateManager = new ReportStateManager();
    this.p12Parser = new P12Parser();
    this.signatureVerifier = new SignatureVerifier();
    this.reportDecryptor = new ReportDecryptor();
    this.reportVerifier = null; // Will be initialized from global

    // DOM elements (lazily initialized)
    this.elements = {};

    // Current P12 data
    this.p12Data = null;

    // Bindings
    this.stateManager.onStateChange(this._onStateChange.bind(this));
  }

  /**
   * Initialize controller and set up event listeners
   */
  async initialize() {
    try {
      // Initialize ReportVerifier from global (if available)
      if (typeof ReportVerifier !== 'undefined') {
        this.reportVerifier = new ReportVerifier();
        this.reportVerifier.initialize();
      }

      // Cache DOM elements
      this._cacheElements();

      // Check if report is encrypted
      const isEncrypted = this._isReportEncrypted();

      if (isEncrypted) {
        // Encrypted report flow
        this.stateManager.transitionTo(ReportStateManager.States.SHOW_WARNING);
        this._setupEncryptedFlow();
      } else {
        // Plaintext report flow
        this.stateManager.transitionTo(ReportStateManager.States.DISPLAY_PLAINTEXT, {
          reportType: 'plaintext'
        });
        this._displayPlaintextReport();
      }

      return { success: true };
    } catch (error) {
      console.error('Controller initialization failed:', error);
      this.stateManager.transitionTo(ReportStateManager.States.ERROR_GENERIC, {
        errorMessage: error.message
      });
      return { success: false, error: error.message };
    }
  }

  /**
   * Cache DOM elements
   * @private
   */
  _cacheElements() {
    // Container for report or encryption UI
    this.elements.reportContainer = document.getElementById('pkiReportContainer')
      || document.getElementById('pqcReportContainer')
      || document.querySelector('[data-report-container]');

    // Encryption warning elements
    this.elements.encryptionWarning = document.getElementById('encryptionWarning')
      || this._createEncryptionWarning();

    // P12 upload modal
    this.elements.p12Modal = document.getElementById('p12UploadModal')
      || this._createP12Modal();

    // File input
    this.elements.p12FileInput = document.getElementById('p12FileInput')
      || this._createFileInput();

    // Password input
    this.elements.passwordInput = document.getElementById('p12PasswordInput')
      || this._createPasswordInput();

    // Submit button
    this.elements.submitBtn = document.getElementById('submitP12Btn')
      || this._createSubmitButton();

    // Cancel button
    this.elements.cancelBtn = document.getElementById('cancelP12Btn')
      || this._createCancelButton();

    // Status message
    this.elements.statusMessage = document.getElementById('p12StatusMessage')
      || this._createStatusMessage();

    // Progress spinner
    this.elements.spinner = document.getElementById('p12Spinner')
      || this._createSpinner();

    // Error container
    this.elements.errorContainer = document.getElementById('p12ErrorContainer')
      || this._createErrorContainer();
  }

  /**
   * Check if report is encrypted
   * @private
   */
  _isReportEncrypted() {
    const encryptedBlobs = document.getElementById('caip-encrypted-blobs');
    return !!(encryptedBlobs && encryptedBlobs.textContent);
  }

  /**
   * Set up encrypted report flow
   * @private
   */
  _setupEncryptedFlow() {
    // Extract encryption data
    const encryptedBlobsElement = document.getElementById('caip-encrypted-blobs');
    const metadataElement = document.getElementById('caip-encryption-metadata');
    const signingResultElement = document.getElementById('caip-signing-result');

    if (!encryptedBlobsElement) {
      throw new Error('Encrypted blobs not found in HTML');
    }

    try {
      const encryptedBlobs = JSON.parse(encryptedBlobsElement.textContent);
      const metadata = metadataElement ? JSON.parse(metadataElement.textContent) : {};
      const signingResult = signingResultElement ? JSON.parse(signingResultElement.innerHTML) : {};

      this.stateManager.setContext({
        encryptedBlobs,
        metadata,
        signingResult,
        recipients: metadata.encryption_recipients || []
      });

      // Show warning
      this._showEncryptionWarning();

      // Bind event listeners
      this._bindEventListeners();
    } catch (error) {
      throw new Error(`Failed to parse encryption data: ${error.message}`);
    }
  }

  /**
   * Show encryption warning banner
   * @private
   */
  _showEncryptionWarning() {
    if (!this.elements.encryptionWarning) return;

    this.elements.encryptionWarning.style.display = 'block';
    const loadP12Button = this.elements.encryptionWarning.querySelector('[data-action="load-p12"]');
    if (loadP12Button) {
      loadP12Button.addEventListener('click', () => {
        this.stateManager.transitionTo(ReportStateManager.States.AWAITING_P12);
      });
    }
  }

  /**
   * Bind event listeners
   * @private
   */
  _bindEventListeners() {
    if (this.elements.p12FileInput) {
      this.elements.p12FileInput.addEventListener('change', (e) => this._onFileSelected(e));
    }

    if (this.elements.submitBtn) {
      this.elements.submitBtn.addEventListener('click', () => this._onP12Submitted());
    }

    if (this.elements.cancelBtn) {
      this.elements.cancelBtn.addEventListener('click', () => {
        this.stateManager.transitionTo(ReportStateManager.States.SHOW_WARNING);
      });
    }

    // File input on Enter
    if (this.elements.passwordInput) {
      this.elements.passwordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') this._onP12Submitted();
      });
    }
  }

  /**
   * Handle file selection
   * @private
   */
  _onFileSelected(event) {
    const file = event.target.files[0];
    if (file) {
      this._showStatus(`Selected: ${file.name}`);
      this.stateManager.setContext({ selectedFile: file });
    }
  }

  /**
   * Handle P12 submission
   * @private
   */
  async _onP12Submitted() {
    try {
      const context = this.stateManager.getContext();
      const file = context.selectedFile;
      const password = this.elements.passwordInput?.value;

      if (!file) {
        this._showError('Please select a P12 file');
        return;
      }

      if (!password) {
        this._showError('Please enter the P12 password');
        return;
      }

      // Transition to parsing
      this.stateManager.transitionTo(ReportStateManager.States.PARSING_P12);

      // Parse P12
      const p12Data = await this.p12Parser.parseP12File(file, password);
      this.p12Data = p12Data;

      this.stateManager.setContext({
        p12Username: p12Data.username,
        p12SerialNumber: p12Data.serialNumber,
        privateKey: p12Data.privateKey,
        certificate: p12Data.certificate
      });

      // Check authorization
      const recipients = context.recipients || [];
      if (!recipients.includes(p12Data.username)) {
        this.stateManager.transitionTo(ReportStateManager.States.ERROR_NOT_AUTHORIZED, {
          errorMessage: `Your certificate (${p12Data.username}) is not authorized to view this report. Authorized recipients: ${recipients.join(', ')}`
        });
        return;
      }

      // Verify signature
      this.stateManager.transitionTo(ReportStateManager.States.VERIFYING_SIGNATURE);

      const { signingResult, encryptedBlobs } = context;
      const userEncryptedBlob = encryptedBlobs[p12Data.username];

      if (!userEncryptedBlob) {
        this.stateManager.transitionTo(ReportStateManager.States.ERROR_DECRYPTION_FAILED, {
          errorMessage: 'No encrypted blob found for your username'
        });
        return;
      }

      const isSignatureValid = await this.signatureVerifier.verifySignature(
        userEncryptedBlob,
        signingResult.signature,
        signingResult.certificate_pem
      );

      if (!isSignatureValid) {
        this.stateManager.transitionTo(ReportStateManager.States.ERROR_SIGNATURE_INVALID, {
          errorMessage: 'Report signature is invalid. Report may have been tampered with.'
        });
        return;
      }

      // Decrypt report
      this.stateManager.transitionTo(ReportStateManager.States.DECRYPTING_REPORT);

      const reportData = await this.reportDecryptor.decryptReport(
        userEncryptedBlob,
        p12Data.privateKey
      );

      // Success
      this.stateManager.transitionTo(ReportStateManager.States.DISPLAY_PLAINTEXT, {
        reportData,
        reportType: 'encrypted'
      });

      this._displayDecryptedReport(reportData);
    } catch (error) {
      this.stateManager.recordError(error);

      // Map error to specific error state
      let errorState = ReportStateManager.States.ERROR_GENERIC;
      if (error.message.includes('password')) {
        errorState = ReportStateManager.States.ERROR_WRONG_PASSWORD;
      } else if (error.message.includes('P12')) {
        errorState = ReportStateManager.States.ERROR_P12_INVALID;
      } else if (error.message.includes('signature')) {
        errorState = ReportStateManager.States.ERROR_SIGNATURE_INVALID;
      } else if (error.message.includes('decrypt') || error.message.includes('authorized')) {
        errorState = ReportStateManager.States.ERROR_DECRYPTION_FAILED;
      }

      this.stateManager.transitionTo(errorState, {
        errorMessage: error.message
      });
    }
  }

  /**
   * Display plaintext report (unencrypted)
   * @private
   */
  _displayPlaintextReport() {
    try {
      const reportDataElement = document.getElementById('pkiReportDataJson')
        || document.getElementById('pqcReportDataJson');

      if (!reportDataElement) {
        this._showError('Report data not found');
        return;
      }

      const reportData = JSON.parse(reportDataElement.textContent);
      this._renderReport(reportData);
    } catch (error) {
      this._showError(`Failed to load plaintext report: ${error.message}`);
    }
  }

  /**
   * Display decrypted report
   * @private
   */
  _displayDecryptedReport(reportData) {
    // Hide P12 modal
    if (this.elements.p12Modal) {
      this.elements.p12Modal.style.display = 'none';
    }

    // Render report
    this._renderReport(reportData);
  }

  /**
   * Render report to DOM
   * @private
   */
  _renderReport(reportData) {
    if (!this.elements.reportContainer) return;

    try {
      // Clear any existing error messages
      if (this.elements.errorContainer) {
        this.elements.errorContainer.style.display = 'none';
      }

      // Delegate to ReportVerifier if available
      if (this.reportVerifier && typeof this.reportVerifier.renderReport === 'function') {
        this.reportVerifier.renderReport(reportData);
      } else {
        // Fallback: JSON pretty-print
        this.elements.reportContainer.innerHTML = `<pre>${JSON.stringify(reportData, null, 2)}</pre>`;
      }
    } catch (error) {
      this._showError(`Failed to render report: ${error.message}`);
    }
  }

  /**
   * Handle state change
   * @private
   */
  _onStateChange(newState, context, previousState) {
    console.debug(`State: ${previousState} → ${newState}`);

    const label = this.stateManager.getStateLabel(newState);
    const instructions = this.stateManager.getInstructions();

    // Show/hide UI elements based on state
    switch (newState) {
      case ReportStateManager.States.SHOW_WARNING:
        this._showEncryptionWarning();
        break;

      case ReportStateManager.States.AWAITING_P12:
        this._showP12Modal();
        break;

      case ReportStateManager.States.PARSING_P12:
      case ReportStateManager.States.VERIFYING_SIGNATURE:
      case ReportStateManager.States.DECRYPTING_REPORT:
        this._showProcessing(label);
        break;

      case ReportStateManager.States.DISPLAY_PLAINTEXT:
        this._hideProcessing();
        break;

      default:
        if (newState.startsWith('ERROR_')) {
          this._showError(this.stateManager.getErrorMessage());
        }
    }
  }

  /**
   * Show P12 modal
   * @private
   */
  _showP12Modal() {
    if (this.elements.p12Modal) {
      this.elements.p12Modal.style.display = 'block';
    }
    this._clearErrors();
  }

  /**
   * Hide P12 modal
   * @private
   */
  _hideP12Modal() {
    if (this.elements.p12Modal) {
      this.elements.p12Modal.style.display = 'none';
    }
  }

  /**
   * Show processing status
   * @private
   */
  _showProcessing(label) {
    this._hideP12Modal();
    if (this.elements.spinner) {
      this.elements.spinner.style.display = 'block';
    }
    this._showStatus(label);
  }

  /**
   * Hide processing status
   * @private
   */
  _hideProcessing() {
    if (this.elements.spinner) {
      this.elements.spinner.style.display = 'none';
    }
  }

  /**
   * Show status message
   * @private
   */
  _showStatus(message) {
    if (this.elements.statusMessage) {
      this.elements.statusMessage.textContent = message;
      this.elements.statusMessage.style.display = 'block';
    }
  }

  /**
   * Show error message
   * @private
   */
  _showError(message) {
    if (this.elements.errorContainer) {
      this.elements.errorContainer.textContent = message;
      this.elements.errorContainer.style.display = 'block';
    }
  }

  /**
   * Clear errors
   * @private
   */
  _clearErrors() {
    if (this.elements.errorContainer) {
      this.elements.errorContainer.style.display = 'none';
    }
  }

  // DOM element creation fallbacks
  _createEncryptionWarning() { return document.createElement('div'); }
  _createP12Modal() { return document.createElement('div'); }
  _createFileInput() { return document.createElement('input'); }
  _createPasswordInput() { return document.createElement('input'); }
  _createSubmitButton() { return document.createElement('button'); }
  _createCancelButton() { return document.createElement('button'); }
  _createStatusMessage() { return document.createElement('div'); }
  _createSpinner() { return document.createElement('div'); }
  _createErrorContainer() { return document.createElement('div'); }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
  const controller = new EncryptedReportController();
  const result = await controller.initialize();
  if (!result.success) {
    console.error('Failed to initialize encrypted report controller:', result.error);
  }
});

// Export for use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = EncryptedReportController;
}
