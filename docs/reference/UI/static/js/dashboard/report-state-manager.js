/**
 * report-state-manager.js
 *
 * State Machine for Encrypted Report Flow
 * Manages transitions between 8 states in the report viewing lifecycle
 *
 * States:
 *  1. INITIAL - Page loaded, detection in progress
 *  2. SHOW_WARNING - Encrypted report detected, show warning
 *  3. AWAITING_P12 - Show P12 upload form, waiting for user
 *  4. PARSING_P12 - P12 upload received, extracting credentials
 *  5. VERIFYING_SIGNATURE - Signature verification in progress
 *  6. DECRYPTING_REPORT - Decryption in progress
 *  7. DISPLAY_PLAINTEXT - Success, show report to user (final)
 *  8. ERROR_* - Any error state (user can retry)
 *
 * Usage:
 *   const stateManager = new ReportStateManager();
 *   stateManager.onStateChange((newState, context) => { ... });
 *   stateManager.transitionTo('AWAITING_P12');
 *   stateManager.setContext({ encryptedBlob: ... });
 */

class ReportStateManager {
  // State constants
  static States = {
    INITIAL: 'INITIAL',
    SHOW_WARNING: 'SHOW_WARNING',
    AWAITING_P12: 'AWAITING_P12',
    PARSING_P12: 'PARSING_P12',
    VERIFYING_SIGNATURE: 'VERIFYING_SIGNATURE',
    DECRYPTING_REPORT: 'DECRYPTING_REPORT',
    DISPLAY_PLAINTEXT: 'DISPLAY_PLAINTEXT',
    ERROR_P12_INVALID: 'ERROR_P12_INVALID',
    ERROR_WRONG_PASSWORD: 'ERROR_WRONG_PASSWORD',
    ERROR_NOT_AUTHORIZED: 'ERROR_NOT_AUTHORIZED',
    ERROR_SIGNATURE_INVALID: 'ERROR_SIGNATURE_INVALID',
    ERROR_DECRYPTION_FAILED: 'ERROR_DECRYPTION_FAILED',
    ERROR_GENERIC: 'ERROR_GENERIC'
  };

  // Valid state transitions (from → allowed to states)
  static ValidTransitions = {
    'INITIAL': ['SHOW_WARNING', 'DISPLAY_PLAINTEXT'],
    'SHOW_WARNING': ['AWAITING_P12'],
    'AWAITING_P12': ['PARSING_P12', 'SHOW_WARNING'],
    'PARSING_P12': ['VERIFYING_SIGNATURE', 'ERROR_P12_INVALID', 'ERROR_WRONG_PASSWORD'],
    'VERIFYING_SIGNATURE': ['DECRYPTING_REPORT', 'ERROR_SIGNATURE_INVALID'],
    'DECRYPTING_REPORT': ['DISPLAY_PLAINTEXT', 'ERROR_DECRYPTION_FAILED', 'ERROR_NOT_AUTHORIZED'],
    'DISPLAY_PLAINTEXT': [], // Final state, no transitions
    // Error states - all can transition back to AWAITING_P12 for retry
    'ERROR_P12_INVALID': ['AWAITING_P12'],
    'ERROR_WRONG_PASSWORD': ['AWAITING_P12'],
    'ERROR_NOT_AUTHORIZED': ['AWAITING_P12'],
    'ERROR_SIGNATURE_INVALID': ['AWAITING_P12'],
    'ERROR_DECRYPTION_FAILED': ['AWAITING_P12'],
    'ERROR_GENERIC': ['AWAITING_P12']
  };

  constructor() {
    this.currentState = ReportStateManager.States.INITIAL;
    this.previousState = null;
    this.context = {};
    this.listeners = [];
    this.stateHistory = [this.currentState];
    this.errorLog = [];
    this.startTime = Date.now();
  }

  /**
   * Register callback for state changes
   * @param {Function} callback - Called with (newState, context, previousState)
   */
  onStateChange(callback) {
    if (typeof callback === 'function') {
      this.listeners.push(callback);
    }
  }

  /**
   * Transition to a new state
   * @param {string} newState - Target state
   * @param {Object} context - Optional context data to merge
   * @throws {Error} if transition not allowed
   */
  transitionTo(newState, context = {}) {
    // Validate state name
    if (!Object.values(ReportStateManager.States).includes(newState)) {
      throw new Error(`Invalid state: ${newState}`);
    }

    // Check if transition is allowed
    const allowed = ReportStateManager.ValidTransitions[this.currentState] || [];
    if (!allowed.includes(newState)) {
      throw new Error(`Cannot transition from ${this.currentState} to ${newState}`);
    }

    // Update state
    this.previousState = this.currentState;
    this.currentState = newState;
    this.stateHistory.push(newState);

    // Merge context
    if (context && typeof context === 'object') {
      this.context = { ...this.context, ...context };
    }

    // Notify listeners
    this._notifyListeners();
  }

  /**
   * Set context data without changing state
   * @param {Object} data - Context to merge
   */
  setContext(data) {
    if (data && typeof data === 'object') {
      this.context = { ...this.context, ...data };
      this._notifyListeners();
    }
  }

  /**
   * Get current state
   * @returns {string} Current state name
   */
  getState() {
    return this.currentState;
  }

  /**
   * Get context
   * @returns {Object} Current context
   */
  getContext() {
    return { ...this.context };
  }

  /**
   * Check if in error state
   * @returns {boolean}
   */
  isError() {
    return this.currentState.startsWith('ERROR_');
  }

  /**
   * Check if flow is complete
   * @returns {boolean}
   */
  isComplete() {
    return this.currentState === ReportStateManager.States.DISPLAY_PLAINTEXT;
  }

  /**
   * Check if awaiting user action
   * @returns {boolean}
   */
  isAwaitingUserInput() {
    return [
      ReportStateManager.States.AWAITING_P12,
      ReportStateManager.States.SHOW_WARNING
    ].includes(this.currentState);
  }

  /**
   * Check if operation in progress
   * @returns {boolean}
   */
  isProcessing() {
    return [
      ReportStateManager.States.PARSING_P12,
      ReportStateManager.States.VERIFYING_SIGNATURE,
      ReportStateManager.States.DECRYPTING_REPORT
    ].includes(this.currentState);
  }

  /**
   * Get error message from context
   * @returns {string|null}
   */
  getErrorMessage() {
    if (!this.isError()) return null;
    return this.context.errorMessage || 'An error occurred. Please try again.';
  }

  /**
   * Get human-readable state label
   * @param {string} state - State name (defaults to current)
   * @returns {string}
   */
  getStateLabel(state = this.currentState) {
    const labels = {
      'INITIAL': 'Loading...',
      'SHOW_WARNING': 'Report Encrypted',
      'AWAITING_P12': 'Upload P12 Certificate',
      'PARSING_P12': 'Reading Certificate...',
      'VERIFYING_SIGNATURE': 'Verifying Authenticity...',
      'DECRYPTING_REPORT': 'Decrypting Report...',
      'DISPLAY_PLAINTEXT': 'Report Ready',
      'ERROR_P12_INVALID': 'Invalid Certificate File',
      'ERROR_WRONG_PASSWORD': 'Wrong Password',
      'ERROR_NOT_AUTHORIZED': 'Not Authorized',
      'ERROR_SIGNATURE_INVALID': 'Signature Invalid',
      'ERROR_DECRYPTION_FAILED': 'Decryption Failed',
      'ERROR_GENERIC': 'Error'
    };
    return labels[state] || 'Unknown State';
  }

  /**
   * Get state-specific UI instructions
   * @returns {string}
   */
  getInstructions() {
    const instructions = {
      'INITIAL': 'Loading report...',
      'SHOW_WARNING': 'This report is encrypted. You need your P12 certificate to view it.',
      'AWAITING_P12': 'Select your P12 certificate file and enter its password.',
      'PARSING_P12': 'Reading your certificate...',
      'VERIFYING_SIGNATURE': 'Verifying report authenticity...',
      'DECRYPTING_REPORT': 'Decrypting report (this may take a moment for large reports)...',
      'DISPLAY_PLAINTEXT': 'Report decrypted successfully.',
      'ERROR_P12_INVALID': 'The P12 file is not valid or is corrupted. Try a different file.',
      'ERROR_WRONG_PASSWORD': 'The password is incorrect for this P12 file. Try again.',
      'ERROR_NOT_AUTHORIZED': 'Your certificate is not authorized to view this report.',
      'ERROR_SIGNATURE_INVALID': 'Report signature is invalid. It may have been tampered with.',
      'ERROR_DECRYPTION_FAILED': 'Failed to decrypt the report. Your certificate may not be authorized.',
      'ERROR_GENERIC': 'An unexpected error occurred. Please try again or contact support.'
    };
    return instructions[this.currentState] || 'Please wait...';
  }

  /**
   * Record error for debugging
   * @private
   */
  recordError(error) {
    const timestamp = new Date().toISOString();
    const elapsed = Date.now() - this.startTime;
    this.errorLog.push({
      timestamp,
      state: this.currentState,
      error: error.message || String(error),
      elapsed
    });
  }

  /**
   * Get debug information
   * @returns {Object}
   */
  getDebugInfo() {
    return {
      currentState: this.currentState,
      previousState: this.previousState,
      context: this.context,
      stateHistory: this.stateHistory,
      errorLog: this.errorLog,
      elapsedMs: Date.now() - this.startTime
    };
  }

  /**
   * Reset state machine for retry
   */
  reset() {
    this.currentState = ReportStateManager.States.INITIAL;
    this.previousState = null;
    this.context = {};
    this.stateHistory = [ReportStateManager.States.INITIAL];
    this.startTime = Date.now();
    this._notifyListeners();
  }

  /**
   * Notify all listeners of state change
   * @private
   */
  _notifyListeners() {
    for (const listener of this.listeners) {
      try {
        listener(this.currentState, this.context, this.previousState);
      } catch (error) {
        console.error('State change listener error:', error);
      }
    }
  }

  /**
   * Get all valid next states from current state
   * @returns {string[]}
   */
  getValidNextStates() {
    return ReportStateManager.ValidTransitions[this.currentState] || [];
  }

  /**
   * Log state transition (for diagnostics)
   * @private
   */
  _logTransition() {
    const timestamp = new Date().toISOString();
    const elapsed = Date.now() - this.startTime;
    console.debug(`[${timestamp}] State transition: ${this.previousState} → ${this.currentState} (+${elapsed}ms)`);
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReportStateManager;
}
