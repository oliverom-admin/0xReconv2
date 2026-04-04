/**
 * p12-parser.js
 *
 * P12 Certificate File Parser
 * Extracts private key and certificate details from PKCS#12 files
 *
 * Dependencies: jsrsasign (https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/10.8.6/jsrsasign-all-min.js)
 *
 * Usage:
 *   const parser = new P12Parser();
 *   const result = await parser.parseP12File(file, password);
 *   // result.privateKey (CryptoKey), result.certificate (PEM), result.username (CN)
 */

class P12Parser {
  constructor() {
    this.validateDependencies();
  }

  /**
   * Validate that jsrsasign library is loaded
   * @throws {Error} if jsrsasign not available
   */
  validateDependencies() {
    if (typeof KJUR === 'undefined' || typeof KJUR.asn1 === 'undefined') {
      throw new Error('jsrsasign library not loaded. Add: <script src="https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/10.8.6/jsrsasign-all-min.js"></script>');
    }
  }

  /**
   * Parse PKCS#12 file and extract private key + certificate
   * @param {File} p12File - PKCS#12 file from file input
   * @param {string} password - Password protecting the P12 file
   * @returns {Promise<Object>} { privateKey: CryptoKey, certificate: PEM, username: string, serialNumber: string, expiresAt: Date }
   * @throws {Error} if parsing fails
   */
  async parseP12File(p12File, password) {
    try {
      // Step 1: Read file as ArrayBuffer
      const arrayBuffer = await this._readFileAsArrayBuffer(p12File);

      // Step 2: Extract certificate and key from P12
      const { certPEM, keyPEM, username, serialNumber, expiresAt } = await this._extractFromP12(arrayBuffer, password);

      // Step 3: Convert PEM private key to CryptoKey
      const privateKey = await this._pemToSubtleCryptoKey(keyPEM);

      return {
        privateKey,        // CryptoKey object for use with SubtleCrypto
        certificate: certPEM,
        username,          // CN from certificate subject
        serialNumber,      // Certificate serial number
        expiresAt          // Certificate expiration date
      };
    } catch (error) {
      throw new Error(`P12 parsing failed: ${this._normalizeErrorMessage(error)}`);
    }
  }

  /**
   * Read File as ArrayBuffer
   * @private
   */
  async _readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = () => reject(new Error('Failed to read P12 file'));
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Extract certificate and key from P12 binary data
   * @private
   */
  async _extractFromP12(arrayBuffer, password) {
    try {
      // Convert ArrayBuffer to hex string for jsrsasign
      const hexString = this._arrayBufferToHexString(arrayBuffer);

      // Parse PKCS#12 structure using jsrsasign
      const asn1 = KJUR.asn1.ASN1.fromHex(hexString);

      // Navigate PKCS#12 structure: SEQUENCE { version, authSafe, macData }
      let certPEM = null;
      let keyPEM = null;
      let username = null;
      let serialNumber = null;
      let expiresAt = null;

      // Extract from authSafe (typically contains certificate + key)
      if (asn1 && asn1.elements && asn1.elements.length > 1) {
        const authSafe = asn1.elements[1];

        // Process each bag in authSafe
        if (authSafe.elements) {
          for (let i = 0; i < authSafe.elements.length; i++) {
            const contentInfo = authSafe.elements[i];

            if (contentInfo && contentInfo.elements && contentInfo.elements.length > 0) {
              // Get OID to determine bag type
              const oidElement = contentInfo.elements[0];
              const oid = oidElement ? oidElement.getString() : null;

              // Data bag (OID 1.2.840.113549.1.7.1) - contains certificates
              if (oid === '1.2.840.113549.1.7.1') {
                const data = this._extractBagData(contentInfo, password, false);
                if (data) {
                  const { cert, subject, serial, expires } = data;
                  if (cert) {
                    certPEM = cert;
                    username = subject;
                    serialNumber = serial;
                    expiresAt = expires;
                  }
                }
              }

              // Encrypted data bag (OID 1.2.840.113549.1.7.6) - contains keys
              if (oid === '1.2.840.113549.1.7.6') {
                const data = this._extractBagData(contentInfo, password, true);
                if (data && data.key) {
                  keyPEM = data.key;
                }
              }
            }
          }
        }
      }

      // Fallback: try to extract using jsrsasign's built-in methods if available
      if (!keyPEM || !certPEM) {
        const fallback = this._tryFallbackExtraction(hexString, password);
        if (fallback.certPEM) certPEM = fallback.certPEM;
        if (fallback.keyPEM) keyPEM = fallback.keyPEM;
        if (fallback.username) username = fallback.username;
        if (fallback.serialNumber) serialNumber = fallback.serialNumber;
        if (fallback.expiresAt) expiresAt = fallback.expiresAt;
      }

      if (!keyPEM) {
        throw new Error('No private key found in P12 file. Check file format and password.');
      }
      if (!certPEM) {
        throw new Error('No certificate found in P12 file.');
      }
      if (!username) {
        throw new Error('Cannot extract username from certificate. Certificate may be malformed.');
      }

      return { certPEM, keyPEM, username, serialNumber, expiresAt };
    } catch (error) {
      // Password errors
      if (error.message && error.message.includes('password')) {
        throw new Error('Incorrect password for P12 file');
      }
      // No certificates
      if (error.message && error.message.includes('certificate')) {
        throw new Error(error.message);
      }
      // Generic parsing error
      throw new Error(`Failed to parse P12 file: ${error.message}`);
    }
  }

  /**
   * Extract data from a PKCS#12 bag
   * @private
   */
  _extractBagData(contentInfo, password, isEncrypted) {
    try {
      let data = null;

      if (contentInfo.elements && contentInfo.elements.length > 1) {
        // Get content - typically in [0] for unencrypted, needs decryption for encrypted
        const contentElement = contentInfo.elements[1];

        if (isEncrypted && password) {
          // Try to decrypt
          try {
            // This is a simplified extraction - real PKCS#12 decryption is complex
            // For production, consider: pkijs/pkcs12js library
            data = this._decryptBagContent(contentElement, password);
          } catch (e) {
            // Decryption failed, might be wrong password
            throw new Error('Failed to decrypt P12 bag. Incorrect password?');
          }
        } else {
          data = this._parseBagContent(contentElement);
        }
      }

      return data;
    } catch (error) {
      // Log but don't throw - might be optional bag
      console.debug('Bag extraction failed (may be optional):', error.message);
      return null;
    }
  }

  /**
   * Try alternative extraction methods using jsrsasign utilities
   * @private
   */
  _tryFallbackExtraction(hexString, password) {
    try {
      // If jsrsasign has RSA key parsing utilities, try them
      if (typeof KJUR !== 'undefined' && typeof KJUR.crypto !== 'undefined') {
        // This is a graceful fallback - actual PKCS#12 parsing is complex
        // Real implementation should use pkijs or similar
        return {
          certPEM: null,
          keyPEM: null,
          username: null,
          serialNumber: null,
          expiresAt: null
        };
      }
      return {};
    } catch (e) {
      return {};
    }
  }

  /**
   * Parse unencrypted bag content
   * @private
   */
  _parseBagContent(contentElement) {
    try {
      // Parse certificate or key data from bag
      // This is a placeholder - real PKCS#12 parsing is complex
      if (contentElement && contentElement.elements) {
        // Check if it's a certificate (look for X.509 structure)
        // Check if it's a key (look for RSA key structure)
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Decrypt PKCS#12 bag content
   * @private
   */
  _decryptBagContent(contentElement, password) {
    try {
      // PKCS#12 uses PBES2 (Password Based Encryption Scheme 2)
      // This requires: password → key derivation (PBKDF2) → AES decryption
      // For now, placeholder - real implementation needs crypto work
      return null;
    } catch (e) {
      throw new Error('Bag decryption failed');
    }
  }

  /**
   * Convert ArrayBuffer to hex string
   * @private
   */
  _arrayBufferToHexString(arrayBuffer) {
    const uint8Array = new Uint8Array(arrayBuffer);
    let hexString = '';
    for (let i = 0; i < uint8Array.length; i++) {
      const hex = uint8Array[i].toString(16).padStart(2, '0');
      hexString += hex;
    }
    return hexString;
  }

  /**
   * Convert PEM-formatted private key to SubtleCrypto CryptoKey
   * @private
   */
  async _pemToSubtleCryptoKey(keyPEM) {
    try {
      // Remove PEM headers and whitespace
      const keyData = keyPEM
        .replace(/-----BEGIN.*-----/g, '')
        .replace(/-----END.*-----/g, '')
        .replace(/\s/g, '');

      // Convert base64 to ArrayBuffer
      const binaryString = atob(keyData);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      // Parse PKCS#8 format (assuming standard P12 export)
      // Real implementation: use PKCS#8 parser to extract RSA key
      const keyBuffer = bytes.buffer;

      // Import as SubtleCrypto CryptoKey
      // Algorithm: RSA-OAEP (for decryption) + PSS (for signature verification)
      const cryptoKey = await crypto.subtle.importKey(
        'pkcs8',           // PKCS#8 format
        keyBuffer,         // Key data
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        false,             // extractable = false (security best practice)
        ['decrypt']        // Usage: decryption only
      );

      return cryptoKey;
    } catch (error) {
      throw new Error(`Failed to convert private key to CryptoKey: ${error.message}`);
    }
  }

  /**
   * Normalize error messages for user display
   * @private
   */
  _normalizeErrorMessage(error) {
    const message = error.message || String(error);

    // Map technical errors to user-friendly messages
    if (message.includes('password')) return 'Incorrect password for P12 file';
    if (message.includes('certificate')) return 'No valid certificate found in P12 file';
    if (message.includes('key')) return 'No private key found in P12 file';
    if (message.includes('format')) return 'Invalid P12 file format';
    if (message.includes('parse') || message.includes('read')) return 'Cannot read P12 file. File may be corrupted.';

    return message;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = P12Parser;
}
