/**
 * signature-verifier.js
 *
 * RSA-PSS Signature Verification
 * Verifies that encrypted report hasn't been tampered with before decryption
 *
 * Uses: SubtleCrypto API (native browser)
 *
 * Usage:
 *   const verifier = new SignatureVerifier();
 *   const isValid = await verifier.verifySignature(
 *     encryptedBlob,
 *     signatureBase64,
 *     certificatePEM
 *   );
 */

class SignatureVerifier {
  constructor() {
    this.validateBrowserSupport();
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
   * Verify RSA-PSS signature on encrypted report blob
   * @param {string} encryptedBlobBase64 - Base64-encoded encrypted report
   * @param {string} signatureBase64 - Base64-encoded RSA-PSS signature
   * @param {string} certificatePEM - PEM-formatted certificate (for public key extraction)
   * @returns {Promise<boolean>} true if signature valid, false if invalid
   * @throws {Error} if verification cannot be performed
   */
  async verifySignature(encryptedBlobBase64, signatureBase64, certificatePEM) {
    try {
      // Step 1: Extract public key from certificate
      const publicKey = await this._extractPublicKeyFromCert(certificatePEM);

      // Step 2: Decode base64 inputs
      const encryptedBlob = this._base64ToArrayBuffer(encryptedBlobBase64);
      const signature = this._base64ToArrayBuffer(signatureBase64);

      // Step 3: Verify signature using SubtleCrypto RSA-PSS
      const isValid = await crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: 32  // Match Phase 4: 32-byte salt
        },
        publicKey,                   // Public key from certificate
        signature,                   // Signature bytes
        encryptedBlob                // Data that was signed
      );

      return isValid;
    } catch (error) {
      throw new Error(`Signature verification failed: ${error.message}`);
    }
  }

  /**
   * Extract public key from X.509 certificate
   * @private
   */
  async _extractPublicKeyFromCert(certificatePEM) {
    try {
      // Step 1: Remove PEM headers
      const certData = certificatePEM
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s/g, '');

      // Step 2: Decode base64 to ArrayBuffer
      const binaryString = atob(certData);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      // Step 3: Parse X.509 certificate (DER format)
      // Certificate structure: SEQUENCE { TBSCertificate, SignatureAlgorithm, SignatureValue }
      const certBuffer = bytes.buffer;
      const publicKeyInfo = await this._extractPublicKeyInfo(certBuffer);

      // Step 4: Import public key as CryptoKey
      const publicKey = await crypto.subtle.importKey(
        'spki',                    // SubjectPublicKeyInfo format
        publicKeyInfo,             // Public key data
        {
          name: 'RSA-PSS',
          hash: 'SHA-256'
        },
        true,                      // extractable (we may need it)
        ['verify']                 // Usage: signature verification
      );

      return publicKey;
    } catch (error) {
      throw new Error(`Failed to extract public key from certificate: ${error.message}`);
    }
  }

  /**
   * Extract SubjectPublicKeyInfo from DER-encoded certificate
   * @private
   */
  async _extractPublicKeyInfo(certBuffer) {
    try {
      // This is a simplified extraction
      // Real implementation requires full X.509/DER parsing
      //
      // Certificate DER structure:
      // SEQUENCE {
      //   TBSCertificate SEQUENCE {
      //     version [0] EXPLICIT
      //     serialNumber
      //     signature AlgorithmIdentifier
      //     issuer Name
      //     validity Validity
      //     subject Name
      //     subjectPublicKeyInfo SubjectPublicKeyInfo  <-- We want this
      //     ...
      //   }
      //   signatureAlgorithm AlgorithmIdentifier
      //   signatureValue BIT STRING
      // }
      //
      // For browsers without native X.509 parsing, we need to use:
      // - jsrsasign (already included for P12)
      // - Or implement minimal DER parser
      // - Or use async webcrypto-based parsing

      // Fallback: use jsrsasign if available for cert parsing
      if (typeof KJUR !== 'undefined' && typeof KJUR.crypto !== 'undefined') {
        return this._extractPublicKeyInfoViaJsrsasign(certBuffer);
      }

      // Minimal DER parser as fallback
      return this._extractPublicKeyInfoViaDER(certBuffer);
    } catch (error) {
      throw new Error(`Cannot extract public key info from certificate: ${error.message}`);
    }
  }

  /**
   * Extract public key using jsrsasign (if available)
   * @private
   */
  async _extractPublicKeyInfoViaJsrsasign(certBuffer) {
    try {
      // Convert to hex for jsrsasign
      const uint8 = new Uint8Array(certBuffer);
      let hexString = '';
      for (let i = 0; i < uint8.length; i++) {
        hexString += uint8[i].toString(16).padStart(2, '0');
      }

      // Parse certificate ASN.1
      const asn1 = KJUR.asn1.ASN1.fromHex(hexString);

      // Navigate to subjectPublicKeyInfo
      // Structure: Certificate -> TBSCertificate (elements[0]) -> ...elements[6] = subjectPublicKeyInfo
      if (asn1 && asn1.elements && asn1.elements.length > 0) {
        const tbsCert = asn1.elements[0];
        if (tbsCert && tbsCert.elements) {
          // Find subjectPublicKeyInfo (usually at index 6)
          const spkiElement = tbsCert.elements[6];
          if (spkiElement) {
            // Encode back to DER
            const spkiHex = spkiElement.getEncodedHex();
            // Convert hex to ArrayBuffer
            const bytes = new Uint8Array(spkiHex.length / 2);
            for (let i = 0; i < spkiHex.length; i += 2) {
              bytes[i / 2] = parseInt(spkiHex.substr(i, 2), 16);
            }
            return bytes.buffer;
          }
        }
      }

      throw new Error('Cannot find subjectPublicKeyInfo in certificate');
    } catch (error) {
      throw new Error(`jsrsasign parsing failed: ${error.message}`);
    }
  }

  /**
   * Minimal DER parser for SubjectPublicKeyInfo extraction
   * @private
   */
  async _extractPublicKeyInfoViaDER(certBuffer) {
    try {
      const bytes = new Uint8Array(certBuffer);

      // Very simplified DER parsing
      // A full implementation would properly parse TLV (Tag-Length-Value)
      // For now, we look for the SubjectPublicKeyInfo structure
      // which contains RSA key parameters

      // This is a placeholder - real extraction needs proper DER parsing
      // Recommend using jsrsasign (already included) or asn1.js library

      throw new Error('Native DER parsing not implemented. Include jsrsasign library for certificate parsing.');
    } catch (error) {
      throw new Error(`DER parsing failed: ${error.message}`);
    }
  }

  /**
   * Decode base64 string to ArrayBuffer
   * @private
   */
  _base64ToArrayBuffer(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Get certificate details for display
   * @param {string} certificatePEM - PEM-formatted certificate
   * @returns {Object} { subject, issuer, serialNumber, validFrom, validTo, fingerprint }
   */
  getCertificateDetails(certificatePEM) {
    try {
      const certData = certificatePEM
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s/g, '');

      // Use jsrsasign if available
      if (typeof KJUR !== 'undefined' && typeof KJUR.crypto !== 'undefined') {
        const x509 = new KJUR.crypto.X509();
        x509.readCertPEM(certificatePEM);

        return {
          subject: x509.getSubjectString(),
          issuer: x509.getIssuerString(),
          serialNumber: x509.getSerialNumberHex(),
          validFrom: x509.getNotBefore(),
          validTo: x509.getNotAfter(),
          fingerprint: this._calculateFingerprint(certData)
        };
      }

      // Fallback: partial extraction
      return {
        subject: 'Unknown (jsrsasign required)',
        issuer: 'Unknown',
        serialNumber: 'Unknown',
        validFrom: null,
        validTo: null,
        fingerprint: this._calculateFingerprint(certData)
      };
    } catch (error) {
      console.error('Certificate parsing failed:', error);
      return {
        subject: 'Error parsing certificate',
        issuer: 'Unknown',
        serialNumber: 'Unknown',
        validFrom: null,
        validTo: null,
        fingerprint: null
      };
    }
  }

  /**
   * Calculate SHA-256 fingerprint of certificate
   * @private
   */
  async _calculateFingerprint(base64Data) {
    try {
      const binaryString = atob(base64Data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      const hashBuffer = await crypto.subtle.digest('SHA-256', bytes.buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
    } catch (error) {
      console.error('Fingerprint calculation failed:', error);
      return null;
    }
  }

  /**
   * Check if certificate is expired
   * @param {string} certificatePEM - PEM-formatted certificate
   * @returns {Object} { isExpired: boolean, expiresAt: Date, daysUntilExpiry: number }
   */
  checkCertificateExpiry(certificatePEM) {
    try {
      if (typeof KJUR === 'undefined') {
        return { isExpired: false, expiresAt: null, daysUntilExpiry: null };
      }

      const x509 = new KJUR.crypto.X509();
      x509.readCertPEM(certificatePEM);
      const expiryString = x509.getNotAfter();

      // Parse expiry date (format: YYYYMMDDhhmmssZ)
      const year = parseInt(expiryString.substr(0, 4), 10);
      const month = parseInt(expiryString.substr(4, 2), 10) - 1;
      const day = parseInt(expiryString.substr(6, 2), 10);
      const hour = parseInt(expiryString.substr(8, 2), 10);
      const min = parseInt(expiryString.substr(10, 2), 10);
      const sec = parseInt(expiryString.substr(12, 2), 10);

      const expiresAt = new Date(Date.UTC(year, month, day, hour, min, sec));
      const now = new Date();
      const isExpired = now > expiresAt;
      const daysUntilExpiry = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

      return {
        isExpired,
        expiresAt,
        daysUntilExpiry: isExpired ? 0 : daysUntilExpiry
      };
    } catch (error) {
      console.error('Certificate expiry check failed:', error);
      return { isExpired: false, expiresAt: null, daysUntilExpiry: null };
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SignatureVerifier;
}
