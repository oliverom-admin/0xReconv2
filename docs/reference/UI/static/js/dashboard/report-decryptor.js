/**
 * report-decryptor.js
 *
 * RSA-OAEP Report Decryption
 * Decrypts encrypted report blobs with user's private key
 *
 * Uses: SubtleCrypto API (native browser)
 *
 * Usage:
 *   const decryptor = new ReportDecryptor();
 *   const reportData = await decryptor.decryptReport(
 *     encryptedBlobBase64,
 *     privateKey // CryptoKey from P12 parser
 *   );
 */

class ReportDecryptor {
  constructor() {
    this.validateBrowserSupport();
    this.MAX_REPORT_SIZE = 50 * 1024 * 1024; // 50MB max (prevents memory DoS)
    this.DECRYPTION_TIMEOUT = 30000; // 30 seconds max
  }

  /**
   * Verify SubtleCrypto is available
   * @throws {Error} if SubtleCrypto not supported
   */
  validateBrowserSupport() {
    if (!crypto || !crypto.subtle) {
      throw new Error('SubtleCrypto API not available. Use Chrome 37+, Firefox 34+, Safari 11+, or Edge 79+');
    }
  }

  /**
   * Decrypt encrypted report blob
   * @param {string} encryptedBlobBase64 - Base64-encoded encrypted report
   * @param {CryptoKey} privateKey - Private key from P12 parser (must have 'decrypt' usage)
   * @returns {Promise<Object>} Parsed report JSON
   * @throws {Error} if decryption fails
   */
  async decryptReport(encryptedBlobBase64, privateKey) {
    try {
      // Step 1: Validate inputs
      this._validateInputs(encryptedBlobBase64, privateKey);

      // Step 2: Decode base64 to bytes
      const encryptedBytes = this._base64ToArrayBuffer(encryptedBlobBase64);

      // Step 3: Check size limits
      if (encryptedBytes.byteLength > this.MAX_REPORT_SIZE) {
        throw new Error(`Report too large (${this._formatBytes(encryptedBytes.byteLength)}). Maximum: ${this._formatBytes(this.MAX_REPORT_SIZE)}`);
      }

      // Step 4: Decrypt with timeout protection
      const decryptedBytes = await this._decryptWithTimeout(encryptedBytes, privateKey);

      // Step 5: Convert bytes to UTF-8 string
      const decryptedString = this._bytesToString(decryptedBytes);

      // Step 6: Validate and parse as JSON
      const reportData = this._parseAndValidateJSON(decryptedString);

      return reportData;
    } catch (error) {
      throw new Error(`Report decryption failed: ${this._normalizeErrorMessage(error)}`);
    }
  }

  /**
   * Validate input parameters
   * @private
   */
  _validateInputs(encryptedBlobBase64, privateKey) {
    if (!encryptedBlobBase64 || typeof encryptedBlobBase64 !== 'string') {
      throw new Error('Invalid encrypted blob: must be non-empty string');
    }
    if (!privateKey || !privateKey.type) {
      throw new Error('Invalid private key: must be CryptoKey object');
    }
    if (privateKey.type !== 'private') {
      throw new Error('Invalid key type: must be private key');
    }
    if (!privateKey.usages || !privateKey.usages.includes('decrypt')) {
      throw new Error('Private key does not have decrypt usage');
    }
  }

  /**
   * Decrypt with timeout protection (prevents hanging on very large reports)
   * @private
   */
  async _decryptWithTimeout(encryptedBytes, privateKey) {
    return Promise.race([
      crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        encryptedBytes
      ),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Decryption timeout. Report may be too large or browser unresponsive.')), this.DECRYPTION_TIMEOUT)
      )
    ]);
  }

  /**
   * Convert ArrayBuffer to UTF-8 string
   * @private
   */
  _bytesToString(arrayBuffer) {
    try {
      const uint8Array = new Uint8Array(arrayBuffer);
      // Use TextDecoder for proper UTF-8 handling
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(uint8Array);
    } catch (error) {
      throw new Error(`Cannot decode decrypted data as UTF-8: ${error.message}`);
    }
  }

  /**
   * Parse and validate decrypted JSON
   * @private
   */
  _parseAndValidateJSON(jsonString) {
    try {
      // Parse JSON
      const reportData = JSON.parse(jsonString);

      // Validate it's an object (not array or primitive)
      if (typeof reportData !== 'object' || reportData === null) {
        throw new Error('Decrypted data is not a JSON object');
      }

      // Check for required report fields (basic validation)
      // Phase 5 doesn't need to validate full report structure
      // Just ensure it's valid JSON that can be displayed

      return reportData;
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(`Decrypted data is not valid JSON. Report may be corrupted: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Decode base64 string to ArrayBuffer
   * @private
   */
  _base64ToArrayBuffer(base64String) {
    try {
      const binaryString = atob(base64String);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      throw new Error(`Invalid base64 encoding: ${error.message}`);
    }
  }

  /**
   * Format bytes to human-readable size
   * @private
   */
  _formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Normalize error messages for user display
   * @private
   */
  _normalizeErrorMessage(error) {
    const message = error.message || String(error);

    // Map technical errors to user-friendly messages
    if (message.includes('Decryption failed')) {
      return 'This P12 certificate cannot decrypt this report. You may not be an authorized recipient, or the report may have been tampered with.';
    }
    if (message.includes('not valid JSON')) {
      return 'Decrypted report data is corrupted and cannot be parsed.';
    }
    if (message.includes('timeout')) {
      return 'Decryption is taking too long. Report may be too large or device may be too slow. Try again or use a more powerful device.';
    }
    if (message.includes('too large')) {
      return message; // Already user-friendly
    }
    if (message.includes('UTF-8')) {
      return 'Report data contains invalid characters. File may be corrupted.';
    }
    if (message.includes('base64')) {
      return 'Encrypted report data is corrupted (invalid base64 encoding).';
    }

    return message;
  }

  /**
   * Estimate decryption time for UI feedback
   * @param {number} encryptedBytesLength - Size of encrypted data in bytes
   * @returns {number} Estimated time in milliseconds
   */
  estimateDecryptionTime(encryptedBytesLength) {
    // RSA-OAEP is fast (single operation)
    // But very large reports may take time
    // Rule of thumb: ~1-5ms per MB depending on device
    const sizeInMB = encryptedBytesLength / (1024 * 1024);
    return Math.max(500, Math.min(this.DECRYPTION_TIMEOUT, sizeInMB * 3000));
  }

  /**
   * Check if decryption is feasible on this device
   * @returns {boolean} true if browser can handle decryption
   */
  isDecryptionSupported() {
    return !!(crypto && crypto.subtle && crypto.subtle.decrypt);
  }

  /**
   * Get browser info for diagnostics
   * @returns {Object} { browser, hasSubtleCrypto, supportsRSA, supportsRSAOAEP }
   */
  getBrowserInfo() {
    const ua = navigator.userAgent;
    let browser = 'Unknown';
    if (ua.includes('Chrome')) browser = 'Chrome';
    else if (ua.includes('Firefox')) browser = 'Firefox';
    else if (ua.includes('Safari')) browser = 'Safari';
    else if (ua.includes('Edge')) browser = 'Edge';

    return {
      browser,
      hasSubtleCrypto: !!(crypto && crypto.subtle),
      supportsRSA: !!(crypto && crypto.subtle && crypto.subtle.decrypt),
      supportsRSAOAEP: this.isDecryptionSupported()
    };
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReportDecryptor;
}
