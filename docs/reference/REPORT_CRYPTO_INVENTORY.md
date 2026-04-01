# Report Signing and Encryption — Targeted Analysis

**Generated:** 2026-04-01
**Scope:** Complete documentation of the report signing, encryption, and client-side decryption system in 0xRecon.

---

## Table of Contents

1. [Server-Side Report Generation](#1-server-side-report-generation)
2. [Client-Side Decryption and Verification](#2-client-side-decryption-and-verification)
3. [Key and Certificate Lifecycle](#3-key-and-certificate-lifecycle)
4. [Template Integration (pki_report.html / pqc_report.html)](#4-template-integration)

---

## 1. Server-Side Report Generation

### 1.1 Which Service Generates Signed and Encrypted Reports

**Service:** `CertificateService` in `caip_service_layer/certificate_service.py`

Two methods are responsible:
- `encrypt_report_data()` — encrypts the report JSON for named recipients
- `sign_encrypted_blob()` — signs the encrypted output with the engagement's report signing certificate

**Trigger route:** `POST /api/v1/reports/embed` in `app.py` (lines 3783-4072)

The route handler:
1. Generates the report JSON (`report_data`)
2. Calls `certificate_service.issue_report_viewer_certificate()` for each recipient (Phase 5)
3. Calls `certificate_service.generate_p12_with_password()` for each recipient
4. Calls `certificate_service.encrypt_report_data()` (Phase 4)
5. Calls `certificate_service.sign_encrypted_blob()` (Phase 4)
6. Renders the HTML template with `encrypted_blobs`, `encryption_metadata`, `signing_result`, and `forge_js_content` passed as Jinja2 context variables

**Other report routes (`/api/v1/reports/executive-summary`, `/api/v1/reports/scans/<id>/view`) do NOT encrypt or sign.** Only the embed dashboard route uses the crypto pipeline.

### 1.2 Encryption Algorithm, Mode, Key Size, Key Derivation

**Hybrid encryption: AES-256-GCM + RSA-OAEP-SHA256**

| Parameter | Value |
|-----------|-------|
| Symmetric algorithm | AES-256-GCM |
| Symmetric key size | 256 bits (32 bytes, `os.urandom(32)`) |
| GCM nonce/IV | 12 bytes (`os.urandom(12)`) |
| GCM authentication tag | 16 bytes (appended to ciphertext by AESGCM) |
| GCM AAD | None |
| Key wrapping algorithm | RSA-OAEP |
| RSA key size | 4096 bits |
| OAEP hash | SHA-256 |
| OAEP MGF | MGF1 with SHA-256 |
| OAEP label | None |
| Key derivation | None — the AES key is random, not derived |

A single random AES-256 key encrypts the report once. That AES key is then RSA-OAEP encrypted separately for each recipient using their public key. Each recipient gets the same ciphertext but a different encrypted copy of the AES key.

### 1.3 How the Encryption Key / Recipient Credential Is Sourced

The recipient's **public key** comes from the `user_digital_identities` table. The query prefers `cert_purpose='report_viewer'` certificates (short-lived, per-report) over general `'identity'` certificates:

```python
user_cert = conn.execute('''
    SELECT certificate_serial, public_key_pem,
           (SELECT username FROM users WHERE id=?) as username
    FROM user_digital_identities
    WHERE user_id = ? AND revoked_at IS NULL
    ORDER BY CASE WHEN cert_purpose='report_viewer' THEN 0 ELSE 1 END ASC,
             issued_at DESC LIMIT 1
''', (user_id, user_id)).fetchone()
```

The public key is loaded from PEM and used directly for RSA-OAEP encryption:

```python
public_key = serialization.load_pem_public_key(
    user_cert['public_key_pem'].encode('utf-8'),
    backend=default_backend()
)
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

### 1.4 Signing Algorithm and Certificate

| Parameter | Value |
|-----------|-------|
| Signing algorithm | RSA-PSS |
| Hash | SHA-256 |
| Salt length | 32 bytes |
| Key size | RSA-4096 |

**What is signed:** The entire `encrypted_blobs` dict is JSON-serialized, base64-encoded, then the raw base64 bytes are signed. The signature covers ALL recipients' encrypted data, not individual blobs.

**Which certificate signs:** The **report signing certificate** for the engagement, from `report_signing_certificates` table:

```python
signing_cert_row = conn.execute('''
    SELECT id, certificate_pem, certificate_serial, public_key_pem
    FROM report_signing_certificates
    WHERE engagement_id = ? AND status = 'active'
    ORDER BY issued_at DESC LIMIT 1
''', (engagement_id,)).fetchone()
```

**Where the private key lives:** In the Unified Vault, keyed as `report-signing-key-{numeric_engagement_id}`:

```python
vault_key_name = f'report-signing-key-{numeric_id}'
private_key_pem = self._get_private_key_from_vault(vault_key_name)
```

**Signing code:**

```python
signature_bytes = private_key.sign(
    encrypted_blob_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=32
    ),
    hashes.SHA256()
)
```

### 1.5 Structure of the Output HTML File

The encrypted payload is embedded in the HTML as `<script type="application/json">` elements in the `<body>`:

```html
<!-- Plaintext report (if NOT encrypted — backward compat) -->
{% if report_data %}
<script type="application/json" id="pkiReportDataJson">{{ report_data | safe }}</script>
{% endif %}

<!-- Phase 4: Encrypted report blobs -->
{% if encrypted_blobs %}
<script type="application/json" id="caip-encrypted-blobs">{{ encrypted_blobs | safe }}</script>
{% endif %}

<!-- Phase 4: Encryption metadata -->
{% if encryption_metadata %}
<script type="application/json" id="caip-encryption-metadata">{{ encryption_metadata | safe }}</script>
{% endif %}

<!-- Phase 4: Signing result -->
{% if signing_result %}
<script type="application/json" id="caip-signing-result">
{
    "signature": "{{ signing_result.signature | safe }}",
    "signature_algorithm": "{{ signing_result.signature_algorithm }}",
    "certificate_pem": "{{ signing_result.certificate_pem | replace('\n', '\\n') | safe }}",
    "certificate_serial": "{{ signing_result.certificate_serial }}",
    "signed_timestamp": "{{ signing_result.signed_timestamp }}",
    "metadata": {{ signing_result.metadata | tojson | safe }}
}
</script>
{% endif %}

<!-- Phase 5: Inline forge.min.js for offline P12 parsing -->
{% if forge_js_content %}
<script>{{ forge_js_content | safe }}</script>
{% endif %}
```

**DOM element IDs and their contents:**

| Element ID | Content |
|------------|---------|
| `pkiReportDataJson` / `pqcReportDataJson` | Plaintext report JSON (only present if NOT encrypted) |
| `caip-encrypted-blobs` | JSON dict: `{username: {encrypted_aes_key, encrypted_report, iv, tag}}` — all values base64 |
| `caip-encryption-metadata` | JSON: `{encryption_algorithm, encryption_recipients, recipient_certificates, encryption_timestamp, report_type}` |
| `caip-signing-result` | JSON: `{signature, signature_algorithm, certificate_pem, certificate_serial, signed_timestamp, metadata}` |

**Encrypted blob structure per recipient:**

```json
{
  "username1": {
    "encrypted_aes_key": "<base64: RSA-OAEP encrypted 32-byte AES key>",
    "encrypted_report": "<base64: AES-256-GCM ciphertext + 16-byte auth tag>",
    "iv": "<base64: 12-byte GCM nonce>",
    "tag": "aes-256-gcm"
  }
}
```

### 1.6 Full encrypt_report_data Code

```python
def encrypt_report_data(
    self,
    report_data: Dict[str, Any],
    recipient_user_ids: List[int],
    engagement_id: str
) -> Dict[str, Dict]:
    """
    Encrypt entire JSON report using hybrid encryption (AES-256-GCM + RSA-OAEP-SHA256).
    """
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    report_json = json.dumps(report_data, sort_keys=True).encode('utf-8')

    aes_key = os.urandom(32)
    aes_iv = os.urandom(12)

    cipher = AESGCM(aes_key)
    encrypted_report = cipher.encrypt(aes_iv, report_json, None)

    encrypted_blobs = {}

    for user_id in recipient_user_ids:
        try:
            conn = self.database_service.get_connection()
            user_cert = conn.execute('''
                SELECT certificate_serial, public_key_pem,
                       (SELECT username FROM users WHERE id=?) as username
                FROM user_digital_identities
                WHERE user_id = ? AND revoked_at IS NULL
                ORDER BY CASE WHEN cert_purpose='report_viewer' THEN 0 ELSE 1 END ASC,
                         issued_at DESC LIMIT 1
            ''', (user_id, user_id)).fetchone()
            conn.close()

            if not user_cert or not user_cert['public_key_pem']:
                continue

            username = user_cert['username']

            public_key = serialization.load_pem_public_key(
                user_cert['public_key_pem'].encode('utf-8'),
                backend=default_backend()
            )

            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_blobs[username] = {
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'encrypted_report': base64.b64encode(encrypted_report).decode('utf-8'),
                'iv': base64.b64encode(aes_iv).decode('utf-8'),
                'tag': 'aes-256-gcm'
            }

        except Exception as e:
            logger.error(f"Failed to encrypt report for user_id {user_id}: {e}")
            continue

    if not encrypted_blobs:
        raise ValueError(f"Failed to encrypt report for any of {len(recipient_user_ids)} recipients")

    return encrypted_blobs
```

### 1.7 Full sign_encrypted_blob Code

```python
def sign_encrypted_blob(
    self,
    encrypted_blob_b64: str,
    engagement_id: str,
    user_id: int,
    report_id: int,
    report_type: str
) -> Dict[str, Any]:
    """
    Sign encrypted report blob using Report Signing Certificate (RSA-PSS-SHA256).
    """
    try:
        encrypted_blob_bytes = base64.b64decode(encrypted_blob_b64.encode('utf-8'))

        conn = self.database_service.get_connection()
        signing_cert_row = conn.execute('''
            SELECT id, certificate_pem, certificate_serial, public_key_pem
            FROM report_signing_certificates
            WHERE engagement_id = ? AND status = 'active'
            ORDER BY issued_at DESC LIMIT 1
        ''', (engagement_id,)).fetchone()

        if not signing_cert_row:
            conn.close()
            raise ValueError(f"No valid Report Signing Certificate found for engagement {engagement_id}")

        numeric_engagement_id = conn.execute(
            "SELECT id FROM engagements WHERE engagement_id = ?",
            (engagement_id,)
        ).fetchone()
        conn.close()

        numeric_id = numeric_engagement_id['id']
        signing_cert_pem = signing_cert_row['certificate_pem']
        cert_serial = signing_cert_row['certificate_serial']

        vault_key_name = f'report-signing-key-{numeric_id}'
        private_key_pem = self._get_private_key_from_vault(vault_key_name)

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        signature_bytes = private_key.sign(
            encrypted_blob_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )

        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        signed_at = datetime.now(timezone.utc).isoformat()
        metadata = {
            'signed_by_user_id': user_id,
            'report_id': report_id,
            'report_type': report_type,
            'engagement_id': engagement_id,
            'signed_at': signed_at,
            'signature_algorithm': 'RSA-PSS-SHA256',
            'salt_length_bytes': 32
        }

        return {
            'signature': signature_b64,
            'signature_algorithm': 'RSA-PSS-SHA256',
            'certificate_pem': signing_cert_pem,
            'certificate_serial': cert_serial,
            'signed_timestamp': signed_at,
            'metadata': metadata
        }

    except Exception as e:
        logger.error(f"Failed to sign encrypted blob: {e}")
        raise
```

### 1.8 Route Trigger — Full Encryption/Signing Flow in app.py

```python
# POST /api/v1/reports/embed  (app.py lines ~3783-4072)

# Phase 5: Create report_viewer certificates for recipients BEFORE encryption
p12_info_for_recipients = {}
recipient_cert_serials = {}
if recipient_user_ids and engagement_id:
    for user_id in recipient_user_ids:
        try:
            cert = certificate_service.issue_report_viewer_certificate(
                user_id=user_id,
                engagement_id=engagement_id,
                report_type=report_type,
                report_id=report_id,
                report_name=name,
                validity_days=validity_days
            )

            try:
                p12_data = certificate_service.generate_p12_with_password(
                    user_id=user_id,
                    engagement_id=engagement_id
                )
                p12_b64 = base64.b64encode(p12_data['p12_bytes']).decode('utf-8')
                username = p12_data['username']
                p12_info_for_recipients[user_id] = {
                    'username': username,
                    'p12_password': p12_data['p12_password'],
                    'expires_at': p12_data['expires_at'],
                    'p12_b64': p12_b64
                }
                recipient_cert_serials[username] = cert['certificate_serial']
            except Exception as p12_error:
                logger.warning(f"Failed to generate P12 for user {user_id}: {p12_error}")

        except Exception as e:
            logger.warning(f"Failed to create report_viewer cert for user {user_id}: {e}")

# Phase 4: Encrypt report for each recipient
if recipient_user_ids and engagement_id:
    encrypted_blobs = certificate_service.encrypt_report_data(
        report_data=report_data,
        recipient_user_ids=recipient_user_ids,
        engagement_id=engagement_id
    )

    # Sign the encrypted blobs (entire structure as JSON)
    if encrypted_blobs:
        encrypted_blobs_json = json.dumps(encrypted_blobs)
        encrypted_blobs_b64 = base64.b64encode(encrypted_blobs_json.encode('utf-8')).decode('utf-8')
        signing_result = certificate_service.sign_encrypted_blob(
            encrypted_blob_b64=encrypted_blobs_b64,
            engagement_id=engagement_id,
            user_id=session.get('user_id'),
            report_id=report_id,
            report_type=report_type
        )

        encryption_metadata = {
            'encryption_algorithm': 'RSA-OAEP-SHA256',
            'encryption_recipients': list(encrypted_blobs.keys()),
            'recipient_certificates': recipient_cert_serials,
            'encryption_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'report_type': report_type
        }
```

---

## 2. Client-Side Decryption and Verification

### 2.1 report-decryptor.js — Full Content

```javascript
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

  validateBrowserSupport() {
    if (!crypto || !crypto.subtle) {
      throw new Error('SubtleCrypto API not available. Use Chrome 37+, Firefox 34+, Safari 11+, or Edge 79+');
    }
  }

  async decryptReport(encryptedBlobBase64, privateKey) {
    try {
      this._validateInputs(encryptedBlobBase64, privateKey);
      const encryptedBytes = this._base64ToArrayBuffer(encryptedBlobBase64);

      if (encryptedBytes.byteLength > this.MAX_REPORT_SIZE) {
        throw new Error(`Report too large (${this._formatBytes(encryptedBytes.byteLength)}). Maximum: ${this._formatBytes(this.MAX_REPORT_SIZE)}`);
      }

      const decryptedBytes = await this._decryptWithTimeout(encryptedBytes, privateKey);
      const decryptedString = this._bytesToString(decryptedBytes);
      const reportData = this._parseAndValidateJSON(decryptedString);
      return reportData;
    } catch (error) {
      throw new Error(`Report decryption failed: ${this._normalizeErrorMessage(error)}`);
    }
  }

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

  async _decryptWithTimeout(encryptedBytes, privateKey) {
    return Promise.race([
      crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedBytes
      ),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Decryption timeout.')), this.DECRYPTION_TIMEOUT)
      )
    ]);
  }

  _bytesToString(arrayBuffer) {
    const uint8Array = new Uint8Array(arrayBuffer);
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(uint8Array);
  }

  _parseAndValidateJSON(jsonString) {
    const reportData = JSON.parse(jsonString);
    if (typeof reportData !== 'object' || reportData === null) {
      throw new Error('Decrypted data is not a JSON object');
    }
    return reportData;
  }

  _base64ToArrayBuffer(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  _formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  _normalizeErrorMessage(error) {
    const message = error.message || String(error);
    if (message.includes('Decryption failed')) {
      return 'This P12 certificate cannot decrypt this report.';
    }
    if (message.includes('not valid JSON')) {
      return 'Decrypted report data is corrupted.';
    }
    if (message.includes('timeout')) {
      return 'Decryption timed out. Report may be too large.';
    }
    return message;
  }

  estimateDecryptionTime(encryptedBytesLength) {
    const sizeInMB = encryptedBytesLength / (1024 * 1024);
    return Math.max(500, Math.min(this.DECRYPTION_TIMEOUT, sizeInMB * 3000));
  }

  isDecryptionSupported() {
    return !!(crypto && crypto.subtle && crypto.subtle.decrypt);
  }

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

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReportDecryptor;
}
```

**What it does:** Decrypts a single RSA-OAEP encrypted blob using a `CryptoKey` private key. Takes base64 input, returns parsed JSON.

**Web Crypto API calls:**
- `crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedBytes)` — RSA-OAEP decryption

**IMPORTANT NOTE:** This class decrypts a SINGLE RSA-OAEP blob. It is designed for the case where the entire report is RSA-encrypted directly. However, the actual template code (`decryptWithP12Certificate()`) does NOT use this class — it implements the full hybrid decryption inline (RSA-OAEP to unwrap AES key, then AES-GCM to decrypt report). This class appears to be an earlier design that was superseded by the inline implementation.

### 2.2 signature-verifier.js — Full Content

```javascript
/**
 * signature-verifier.js
 *
 * RSA-PSS Signature Verification
 * Verifies that encrypted report hasn't been tampered with before decryption
 *
 * Uses: SubtleCrypto API (native browser)
 */

class SignatureVerifier {
  constructor() {
    this.validateBrowserSupport();
  }

  validateBrowserSupport() {
    if (!crypto || !crypto.subtle) {
      throw new Error('SubtleCrypto API not available.');
    }
  }

  async verifySignature(encryptedBlobBase64, signatureBase64, certificatePEM) {
    try {
      const publicKey = await this._extractPublicKeyFromCert(certificatePEM);
      const encryptedBlob = this._base64ToArrayBuffer(encryptedBlobBase64);
      const signature = this._base64ToArrayBuffer(signatureBase64);

      const isValid = await crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: 32 },
        publicKey,
        signature,
        encryptedBlob
      );

      return isValid;
    } catch (error) {
      throw new Error(`Signature verification failed: ${error.message}`);
    }
  }

  async _extractPublicKeyFromCert(certificatePEM) {
    const certData = certificatePEM
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s/g, '');

    const binaryString = atob(certData);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const certBuffer = bytes.buffer;
    const publicKeyInfo = await this._extractPublicKeyInfo(certBuffer);

    const publicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyInfo,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      true,
      ['verify']
    );

    return publicKey;
  }

  async _extractPublicKeyInfo(certBuffer) {
    // Uses jsrsasign (KJUR) if available for DER certificate parsing
    if (typeof KJUR !== 'undefined' && typeof KJUR.crypto !== 'undefined') {
      return this._extractPublicKeyInfoViaJsrsasign(certBuffer);
    }
    // Fallback: native DER parser NOT implemented
    throw new Error('Native DER parsing not implemented. Include jsrsasign library.');
  }

  async _extractPublicKeyInfoViaJsrsasign(certBuffer) {
    const uint8 = new Uint8Array(certBuffer);
    let hexString = '';
    for (let i = 0; i < uint8.length; i++) {
      hexString += uint8[i].toString(16).padStart(2, '0');
    }
    const asn1 = KJUR.asn1.ASN1.fromHex(hexString);
    if (asn1 && asn1.elements && asn1.elements.length > 0) {
      const tbsCert = asn1.elements[0];
      if (tbsCert && tbsCert.elements) {
        const spkiElement = tbsCert.elements[6];
        if (spkiElement) {
          const spkiHex = spkiElement.getEncodedHex();
          const bytes = new Uint8Array(spkiHex.length / 2);
          for (let i = 0; i < spkiHex.length; i += 2) {
            bytes[i / 2] = parseInt(spkiHex.substr(i, 2), 16);
          }
          return bytes.buffer;
        }
      }
    }
    throw new Error('Cannot find subjectPublicKeyInfo in certificate');
  }

  _base64ToArrayBuffer(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  getCertificateDetails(certificatePEM) {
    // Uses jsrsasign if available; otherwise returns partial info
    // Returns: { subject, issuer, serialNumber, validFrom, validTo, fingerprint }
    // ...
  }

  async _calculateFingerprint(base64Data) {
    const binaryString = atob(base64Data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes.buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
  }

  checkCertificateExpiry(certificatePEM) {
    // Uses jsrsasign to parse NotAfter, returns { isExpired, expiresAt, daysUntilExpiry }
    // ...
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SignatureVerifier;
}
```

**What it does:** Verifies RSA-PSS-SHA256 signature on the encrypted blob using the signing certificate's public key.

**Web Crypto API calls:**
- `crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, publicKey, signature, data)` — RSA-PSS verification
- `crypto.subtle.importKey('spki', publicKeyInfo, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify'])` — import public key
- `crypto.subtle.digest('SHA-256', bytes)` — fingerprint calculation

**Dependency:** Requires `jsrsasign` (KJUR) for X.509 certificate parsing. The native DER parser fallback is NOT implemented (throws error).

**Integration status:** This class IS available but is NOT called from the template's `decryptWithP12Certificate()` function. Signature verification is not performed during the current decryption flow. The signing result is displayed in the modal UI but the cryptographic verification step is skipped.

### 2.3 report_verifier.js — Full Content

```javascript
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

    extractEncryptedBlobs() {
        const elem = document.getElementById('caip-encrypted-blobs');
        if (!elem) return null;
        this.encryptedBlobs = JSON.parse(elem.textContent);
        return this.encryptedBlobs;
    }

    extractEncryptionMetadata() {
        const elem = document.getElementById('caip-encryption-metadata');
        if (!elem) return null;
        this.encryptionMetadata = JSON.parse(elem.textContent);
        return this.encryptionMetadata;
    }

    extractSigningResult() {
        const elem = document.getElementById('caip-signing-result');
        if (!elem) return null;
        this.signingResult = JSON.parse(elem.textContent);
        return this.signingResult;
    }

    extractReportData() {
        const elem = document.getElementById('pkiReportDataJson');
        if (!elem) return null;
        this.reportData = JSON.parse(elem.textContent);
        this.isDecrypted = true;
        return this.reportData;
    }

    isReportEncrypted() {
        if (this.encryptedBlobs === null) this.extractEncryptedBlobs();
        return this.encryptedBlobs !== null && Object.keys(this.encryptedBlobs).length > 0;
    }

    getRecipients() { /* returns encryption_recipients from metadata */ }
    getSigningCertificate() { /* returns certificate_pem from signing result */ }
    getSignature() { /* returns signature from signing result */ }

    showEncryptionWarning() {
        // Creates fixed-position red warning banner at top of page
        // "This report is encrypted with your organization's public key."
    }

    initialize() {
        this.extractReportData();
        this.extractEncryptedBlobs();
        this.extractEncryptionMetadata();
        this.extractSigningResult();

        if (this.isReportEncrypted()) {
            this.showEncryptionWarning();
            return { status: 'encrypted', recipients: this.getRecipients() };
        } else if (this.reportData) {
            return { status: 'plaintext', decrypted: true };
        } else {
            return { status: 'error', message: 'Report data not found' };
        }
    }

    decryptWithP12(p12File, password, username) {
        // PLACEHOLDER - not implemented
        console.log('Phase 5: Decryption placeholder');
        return null;
    }
}

// Global instance auto-initialized on DOMContentLoaded
let reportVerifier = null;
document.addEventListener('DOMContentLoaded', function() {
    reportVerifier = new ReportVerifier();
    reportVerifier.initialize();
});
```

**What it does:** Orchestrator that detects whether a report is encrypted or plaintext on page load. Extracts all embedded crypto elements from the DOM. Its `decryptWithP12()` method is a placeholder — actual decryption is implemented inline in the template.

**Web Crypto API calls:** None. This class only reads DOM elements and parses JSON.

### 2.4 p12-parser.js — Full Content

```javascript
/**
 * p12-parser.js
 *
 * P12 Certificate File Parser
 * Extracts private key and certificate details from PKCS#12 files
 *
 * Dependencies: jsrsasign
 */

class P12Parser {
  constructor() {
    this.validateDependencies();
  }

  validateDependencies() {
    if (typeof KJUR === 'undefined' || typeof KJUR.asn1 === 'undefined') {
      throw new Error('jsrsasign library not loaded.');
    }
  }

  async parseP12File(p12File, password) {
    const arrayBuffer = await this._readFileAsArrayBuffer(p12File);
    const { certPEM, keyPEM, username, serialNumber, expiresAt } =
      await this._extractFromP12(arrayBuffer, password);
    const privateKey = await this._pemToSubtleCryptoKey(keyPEM);
    return { privateKey, certificate: certPEM, username, serialNumber, expiresAt };
  }

  async _extractFromP12(arrayBuffer, password) {
    const hexString = this._arrayBufferToHexString(arrayBuffer);
    const asn1 = KJUR.asn1.ASN1.fromHex(hexString);

    // Attempts to parse PKCS#12 ASN.1 structure
    // Navigates authSafe bags to find certificate and key
    // Falls back to _tryFallbackExtraction()
    // ...

    // NOTE: The actual P12 bag decryption methods (_decryptBagContent,
    // _parseBagContent, _extractBagData) are PLACEHOLDER implementations
    // that return null. They do not actually parse PKCS#12.
  }

  async _pemToSubtleCryptoKey(keyPEM) {
    const keyData = keyPEM
      .replace(/-----BEGIN.*-----/g, '')
      .replace(/-----END.*-----/g, '')
      .replace(/\s/g, '');

    const binaryString = atob(keyData);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      bytes.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );

    return cryptoKey;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = P12Parser;
}
```

**What it does:** Attempts to parse a PKCS#12 file using jsrsasign, extract the private key and certificate, and convert the private key to a Web Crypto `CryptoKey`.

**Web Crypto API calls:**
- `crypto.subtle.importKey('pkcs8', keyBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt'])` — import private key

**CRITICAL NOTE:** The P12 bag extraction methods (`_extractBagData`, `_decryptBagContent`, `_parseBagContent`, `_tryFallbackExtraction`) are all **placeholder implementations that return null**. This class **cannot actually parse a P12 file**. The actual working P12 parsing uses **forge.js** (node-forge), NOT this class or jsrsasign. See Section 2.6.

### 2.5 report-state-manager.js — Full Content

```javascript
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
 */

class ReportStateManager {
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

  static ValidTransitions = {
    'INITIAL': ['SHOW_WARNING', 'DISPLAY_PLAINTEXT'],
    'SHOW_WARNING': ['AWAITING_P12'],
    'AWAITING_P12': ['PARSING_P12', 'SHOW_WARNING'],
    'PARSING_P12': ['VERIFYING_SIGNATURE', 'ERROR_P12_INVALID', 'ERROR_WRONG_PASSWORD'],
    'VERIFYING_SIGNATURE': ['DECRYPTING_REPORT', 'ERROR_SIGNATURE_INVALID'],
    'DECRYPTING_REPORT': ['DISPLAY_PLAINTEXT', 'ERROR_DECRYPTION_FAILED', 'ERROR_NOT_AUTHORIZED'],
    'DISPLAY_PLAINTEXT': [],
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

  onStateChange(callback) { this.listeners.push(callback); }
  transitionTo(newState, context = {}) { /* validates transition, updates state, notifies */ }
  setContext(data) { /* merges context data */ }
  getState() { return this.currentState; }
  getContext() { return { ...this.context }; }
  isError() { return this.currentState.startsWith('ERROR_'); }
  isComplete() { return this.currentState === 'DISPLAY_PLAINTEXT'; }
  isAwaitingUserInput() { /* AWAITING_P12 or SHOW_WARNING */ }
  isProcessing() { /* PARSING_P12 or VERIFYING_SIGNATURE or DECRYPTING_REPORT */ }
  getErrorMessage() { /* from context.errorMessage */ }
  getStateLabel(state) { /* human-readable labels */ }
  getInstructions() { /* state-specific user instructions */ }
  reset() { /* resets to INITIAL */ }
  getDebugInfo() { /* returns full debug state */ }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReportStateManager;
}
```

**What it does:** A state machine that defines the complete encrypted report viewing lifecycle with 8 primary states + 6 error states. Enforces valid transitions, provides UI labels and instructions for each state.

**Web Crypto API calls:** None. Pure state management.

**Integration status:** This class is defined but is **NOT used by the template code**. The inline `decryptWithP12Certificate()` function manages its own state directly (button text changes, alert on error) without using this state machine.

### 2.6 What Actually Happens — The Working Decryption Flow

The working decryption is implemented **inline in both templates** (not using the external JS modules). It uses **forge.js** (node-forge), which is inlined into the HTML at build time via the `forge_js_content` Jinja2 variable.

**Credential required:** P12 file + password (both provided by user via file input + password field)

**Decryption is entirely client-side.** No server call is made during decryption.

**Signature verification is NOT performed.** The signing result is displayed in the modal UI but the `SignatureVerifier` class is never called.

**Complete working flow (from `decryptWithP12Certificate()` in both templates):**

```javascript
async function decryptWithP12Certificate() {
    const p12File = document.getElementById('p12FileInput').files[0];
    const password = document.getElementById('p12PasswordInput').value;

    // 1. Read P12 file as ArrayBuffer
    const p12Buffer = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = e => resolve(e.target.result);
        reader.onerror = reject;
        reader.readAsArrayBuffer(p12File);
    });

    // 2. Parse P12 with forge.js (NOT jsrsasign, NOT p12-parser.js)
    const p12Asn1 = forge.asn1.fromDer(
        forge.util.binary.raw.encode(new Uint8Array(p12Buffer))
    );
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    // 3. Extract private key from shrouded key bag
    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBag = (keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || [])[0];

    // 4. Extract certificate, get username from CN
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBag = (certBags[forge.pki.oids.certBag] || [])[0];
    const cn = certBag.cert.subject.getField('CN').value;
    // CN format: "viewer:{username}:report:{report_name}"
    const username = cn.startsWith('viewer:') ? cn.split(':')[1] : cn;

    // 5. Look up recipient's encrypted blob by username
    const encryptedBlobs = JSON.parse(
        document.getElementById('caip-encrypted-blobs').textContent
    );
    const blob = encryptedBlobs[username];

    // 6. Convert forge private key → PKCS8 DER → Web Crypto CryptoKey
    const pkcs8Der = forge.asn1.toDer(
        forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keyBag.key))
    ).getBytes();
    const pkcs8Buffer = Uint8Array.from(pkcs8Der, c => c.charCodeAt(0));
    const cryptoKey = await crypto.subtle.importKey(
        'pkcs8', pkcs8Buffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false, ['decrypt']
    );

    // 7. RSA-OAEP decrypt the AES-256 key
    const encAesKey = Uint8Array.from(atob(blob.encrypted_aes_key), c => c.charCodeAt(0));
    const aesKeyBuf = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' }, cryptoKey, encAesKey
    );

    // 8. Import decrypted bytes as AES-GCM CryptoKey
    const aesKey = await crypto.subtle.importKey(
        'raw', aesKeyBuf, { name: 'AES-GCM' }, false, ['decrypt']
    );

    // 9. AES-GCM decrypt the report payload
    const iv = Uint8Array.from(atob(blob.iv), c => c.charCodeAt(0));
    const encReport = Uint8Array.from(atob(blob.encrypted_report), c => c.charCodeAt(0));
    const decryptedBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv }, aesKey, encReport
    );

    // 10. Parse JSON, close modal, render dashboard
    reportData = JSON.parse(new TextDecoder().decode(decryptedBuf));
    closeEncryptionModal();
    initializeDashboard();
}
```

**Web Crypto API calls in the working flow:**

| Step | API Call | Algorithm | Purpose |
|------|----------|-----------|---------|
| 6 | `crypto.subtle.importKey('pkcs8', ...)` | RSA-OAEP / SHA-256 | Import private key from P12 |
| 7 | `crypto.subtle.decrypt({ name: 'RSA-OAEP' }, ...)` | RSA-OAEP | Unwrap AES key |
| 8 | `crypto.subtle.importKey('raw', ...)` | AES-GCM | Import AES key |
| 9 | `crypto.subtle.decrypt({ name: 'AES-GCM', iv }, ...)` | AES-256-GCM | Decrypt report payload |

---

## 3. Key and Certificate Lifecycle

### 3.1 report_signing_certificates Table Schema

```sql
CREATE TABLE IF NOT EXISTS report_signing_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    certificate_serial TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    private_key_ref TEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    status TEXT DEFAULT 'active',
    rotation_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id),
    UNIQUE(engagement_id, status)
);

CREATE INDEX IF NOT EXISTS idx_report_signing_certs_engagement
    ON report_signing_certificates(engagement_id);
CREATE INDEX IF NOT EXISTS idx_report_signing_certs_status
    ON report_signing_certificates(status);
```

### 3.2 engagement_ca_certificates Table Schema

```sql
CREATE TABLE IF NOT EXISTS engagement_ca_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    certificate_serial TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    private_key_ref TEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    status TEXT DEFAULT 'active',
    rotation_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id),
    UNIQUE(engagement_id, status)
);

CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_engagement
    ON engagement_ca_certificates(engagement_id);
CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_status
    ON engagement_ca_certificates(status);
CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_serial
    ON engagement_ca_certificates(certificate_serial);
CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_expires
    ON engagement_ca_certificates(expires_at);
```

### 3.3 user_digital_identities Table Schema (Evolved)

```sql
CREATE TABLE user_digital_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    engagement_id TEXT,
    cert_purpose TEXT NOT NULL DEFAULT 'identity',
    report_ref TEXT,
    validity_days INTEGER NOT NULL DEFAULT 365,
    certificate_pem TEXT NOT NULL,
    certificate_serial TEXT UNIQUE NOT NULL,
    public_key_pem TEXT NOT NULL,
    private_key_ref TEXT,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    p12_generated_at TIMESTAMP,
    p12_downloaded_at TIMESTAMP,
    p12_deleted_at TIMESTAMP,
    private_key_destroyed_at TIMESTAMP,
    status TEXT DEFAULT 'pending_p12_creation',
    rotation_count INTEGER DEFAULT 0,
    last_rotation_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(engagement_id) REFERENCES engagements(engagement_id),
    UNIQUE(user_id, engagement_id, cert_purpose, report_ref)
);
```

### 3.4 Certificate Hierarchy and Relationships

```
internal_ca (auto-provisioned at app startup)
  └── CN: "CAIP Internal CA"
  └── Key: RSA-4096, stored in vault as "internal-ca-key"
  └── Validity: 10 years
  └── Key Usage: keyCertSign, cRLSign
      │
      ├── engagement_ca_certificates (one per engagement)
      │   └── CN: "CAIP-CA-{engagement_id}"
      │   └── Key: RSA-4096, vault: "engagement-ca-key-{numeric_id}"
      │   └── Validity: 5 years (1825 days)
      │   └── Key Usage: keyCertSign, cRLSign, digitalSignature
      │   └── BasicConstraints: CA=True
      │       │
      │       ├── report_signing_certificates (one per engagement)
      │       │   └── CN: "CAIP Report Signing - {engagement_id}"
      │       │   └── Key: RSA-4096, vault: "report-signing-key-{numeric_id}"
      │       │   └── Validity: 2 years (730 days)
      │       │   └── Key Usage: digitalSignature, contentCommitment (nonRepudiation)
      │       │   └── PURPOSE: Signs encrypted report blobs
      │       │
      │       ├── user_digital_identities (cert_purpose='report_viewer')
      │       │   └── CN: "viewer:{username}:report:{report_name}"
      │       │   └── Key: RSA-4096, vault: "report-viewer-key-{user_id}-{type}-{id}"
      │       │   └── Validity: 7/30/90 days (configurable)
      │       │   └── Key Usage: digitalSignature, keyEncipherment
      │       │   └── EKU: clientAuth
      │       │   └── PURPOSE: Recipient decryption key (public key encrypts AES key)
      │       │
      │       └── collector_certificates (for mTLS)
      │           └── CN: "{collector_id}"
      │           └── Validity: 30 days
```

### 3.5 Provisioning

**Report signing certificates** are auto-generated during engagement CA provisioning (Step 6 of the `ensure_engagement_ca()` flow in `certificate_service.py`). They are not manually uploaded.

The full provisioning sequence when an engagement CA is first created:

1. Generate engagement CA key (RSA-4096)
2. Create engagement CA cert (signed by internal CA)
3. Store CA key in vault
4. Insert CA cert in `engagement_ca_certificates`
5. Create engagement dashboard cert (signed by engagement CA)
6. **Generate report signing key (RSA-4096)**
7. **Store report signing key in vault** (`report-signing-key-{numeric_id}`)
8. **Insert report signing cert in `report_signing_certificates`**

### 3.6 Certificate Lifetime and Rotation

| Certificate Type | Lifetime | Rotation Policy |
|-----------------|----------|----------------|
| Internal CA | 10 years | Manual (not implemented) |
| Engagement CA | 5 years | `rotation_count` tracked, no auto-rotation |
| Report Signing | 2 years | `rotation_count` tracked, no auto-rotation |
| Report Viewer | 7-90 days (configurable) | New cert per report, idempotent (reused if exists) |

**No automatic rotation is implemented.** The `rotation_count` field is tracked but never incremented by automated processes. Rotation would require manual intervention or a scheduled job that does not yet exist.

### 3.7 P12 Generation for Recipients

When a report is generated with encryption, the server:
1. Issues a `report_viewer` certificate for each recipient
2. Generates a P12 file containing the private key + certificate, protected by a random password (`secrets.token_urlsafe(20)`)
3. The P12 password must be communicated to the recipient through a separate secure channel (not embedded in the HTML)
4. The P12 file itself is returned as base64 in the API response (for admin to distribute)

```python
def generate_p12_with_password(self, user_id, engagement_id=None):
    # Gets most recent report_viewer cert for user
    # Retrieves private key from vault
    # Generates random password: secrets.token_urlsafe(20)
    # Creates PKCS#12 via pyOpenSSL: crypto.PKCS12()
    # Returns { username, p12_bytes, p12_password, expires_at }
```

---

## 4. Template Integration

### 4.1 pki_report.html — Encrypted Payload Embedding

**Lines 2717-2750 — Data embedding in `<body>`:**

```html
<!-- Phase 5: Inline forge.min.js for offline P12 decryption -->
{% if forge_js_content %}
<script>{{ forge_js_content | safe }}</script>
{% endif %}
</head>
<body>
    <!-- Embedded report data from Flask -->
    {% if report_data %}
    <script type="application/json" id="pkiReportDataJson">{{ report_data | safe }}</script>
    {% endif %}

    <!-- Phase 4: Encrypted report blobs (full payload encryption) -->
    {% if encrypted_blobs %}
    <script type="application/json" id="caip-encrypted-blobs">{{ encrypted_blobs | safe }}</script>
    {% endif %}

    <!-- Phase 4: Encryption metadata for Phase 5 verification -->
    {% if encryption_metadata %}
    <script type="application/json" id="caip-encryption-metadata">{{ encryption_metadata | safe }}</script>
    {% endif %}

    <!-- Phase 4: Signing result (signature + certificate) -->
    {% if signing_result %}
    <script type="application/json" id="caip-signing-result">
    {
        "signature": "{{ signing_result.signature | safe }}",
        "signature_algorithm": "{{ signing_result.signature_algorithm }}",
        "certificate_pem": "{{ signing_result.certificate_pem | replace('\n', '\\n') | safe }}",
        "certificate_serial": "{{ signing_result.certificate_serial }}",
        "signed_timestamp": "{{ signing_result.signed_timestamp }}",
        "metadata": {{ signing_result.metadata | tojson | safe }}
    }
    </script>
    {% endif %}
```

**Lines 3824-3891 — Encryption modal:**

```html
<!-- Phase 5: Encryption Modal - Prompt for P12 certificate to decrypt report -->
<div id="encryptionModal" class="modal">
    <div class="modal-content" style="max-width: 600px;">
        <div class="modal-header">
            <h2>🔒 Report Encryption Service</h2>
            <button class="modal-close" onclick="closeEncryptionModal()">&times;</button>
        </div>
        <div style="padding: 20px; font-size: 14px;">
            <!-- Report Metadata Section -->
            <div id="reportMetadataSection" style="background: #e0e7ff; ...">
                <p><strong>📋 Report Information</strong></p>
                <div>
                    <strong>Created for:</strong> <span id="reportRecipient">—</span>
                </div>
                <div>
                    <strong>Required Certificate Thumbprint:</strong>
                    <span id="reportCertThumb" style="font-family: monospace;">—</span>
                </div>
            </div>

            <!-- Signing Status Section (hidden until populated) -->
            <div id="signingStatusSection" style="background: #dcfce7; ... display: none;">
                <p><strong>✓ Signing Verified</strong></p>
                <div><strong>Signed with:</strong> <span id="signingCertSerial">—</span></div>
                <div><strong>Timestamp:</strong> <span id="signingTimestamp">—</span></div>
                <div><strong>Algorithm:</strong> <span id="signingAlgorithm">—</span></div>
            </div>

            <p>This report is encrypted with your public key. You need your P12
               certificate file and password to decrypt and view the data.</p>

            <div style="background: #fef3c7; ...">
                <p><strong>ℹ️ What is a P12 certificate?</strong></p>
                <p>Your P12 file contains the private key needed to decrypt this report.
                   You received it alongside this HTML file.</p>
            </div>

            <div>
                <label>Select P12 Certificate File:</label>
                <input type="file" id="p12FileInput" accept=".p12,.pfx">
            </div>

            <div>
                <label>P12 Certificate Password:</label>
                <input type="password" id="p12PasswordInput" placeholder="Enter password">
            </div>

            <button class="btn-primary" onclick="decryptWithP12Certificate()">
                🔓 Decrypt & View Report
            </button>
        </div>
    </div>
</div>
```

**Lines 3967-3978 — loadData() entry point with TODO:**

```javascript
async function loadData() {
    try {
        // FIRST: Check if data is ENCRYPTED and requires decryption
        const encryptedBlobsStr = document.getElementById('caip-encrypted-blobs');
        if (encryptedBlobsStr) {
            const encryptedBlobs = JSON.parse(encryptedBlobsStr.textContent);
            console.log('Encrypted report detected. Prompting for P12 decryption...');
            // TODO: Call Phase 5 decryption UI here
            showEncryptionModal(encryptedBlobs);
            return;
        }

        // Otherwise, check if plaintext data is embedded from Flask
        const embeddedDataStr = document.getElementById('pkiReportDataJson');
        if (embeddedDataStr) {
            reportData = JSON.parse(embeddedDataStr.textContent);
            initializeDashboard();
            return;
        }
        // ... fallback loading methods
    }
}
```

**Lines 4036-4171 — Full encryption modal + decryption implementation:**

```javascript
// Phase 5: Encryption modal functions
let encryptedBlobsData = null;

function showEncryptionModal(encryptedBlobs) {
    encryptedBlobsData = encryptedBlobs;

    // Display report metadata (recipients, cert thumbprints)
    try {
        const encryptionMetadataEl = document.getElementById('caip-encryption-metadata');
        if (encryptionMetadataEl) {
            const metadata = JSON.parse(encryptionMetadataEl.textContent);
            const recipients = metadata.encryption_recipients || [];
            if (recipients.length > 0) {
                document.getElementById('reportRecipient').textContent = recipients.join(', ');
            }
            const recipientCerts = metadata.recipient_certificates || {};
            const certDetails = recipients
                .map(email => recipientCerts[email] || 'Unknown')
                .filter(cert => cert !== 'Unknown')
                .join(', ');
            document.getElementById('reportCertThumb').textContent =
                certDetails.length > 0 ? certDetails : 'Contact administrator';
        }
    } catch (err) { console.log('Could not load encryption metadata:', err); }

    // Display signing status
    try {
        const signingResultEl = document.getElementById('caip-signing-result');
        if (signingResultEl) {
            const signingResult = JSON.parse(signingResultEl.textContent);
            document.getElementById('signingCertSerial').textContent =
                signingResult.certificate_serial || '—';
            document.getElementById('signingTimestamp').textContent =
                new Date(signingResult.signed_timestamp).toLocaleString() || '—';
            document.getElementById('signingAlgorithm').textContent =
                signingResult.signature_algorithm || '—';
            document.getElementById('signingStatusSection').style.display = 'block';
        }
    } catch (err) { console.log('Could not load signing result:', err); }

    document.getElementById('encryptionModal').classList.add('active');
}

function closeEncryptionModal() {
    document.getElementById('encryptionModal').classList.remove('active');
}

async function decryptWithP12Certificate() {
    // [Full 10-step decryption implementation — see Section 2.6]
}
```

### 4.2 pqc_report.html — Identical Structure

The PQC report template has an **identical** encryption integration structure. Differences are cosmetic only:

| Element | pki_report.html | pqc_report.html |
|---------|----------------|-----------------|
| Report data element ID | `pkiReportDataJson` | `pqcReportDataJson` |
| Encrypted blobs element ID | `caip-encrypted-blobs` | `caip-encrypted-blobs` (same) |
| Encryption metadata element ID | `caip-encryption-metadata` | `caip-encryption-metadata` (same) |
| Signing result element ID | `caip-signing-result` | `caip-signing-result` (same) |
| TODO line | Line 3975 | Line 4919 |
| Decryption function | `decryptWithP12Certificate()` | `decryptWithP12Certificate()` (identical) |

**pqc_report.html lines 3593-3626 (data embedding):**

```html
<!-- Phase 5: Inline forge.min.js for offline P12 decryption -->
{% if forge_js_content %}
<script>{{ forge_js_content | safe }}</script>
{% endif %}
</head>
<body>
    {% if report_data %}
    <script type="application/json" id="pqcReportDataJson">{{ report_data | safe }}</script>
    {% endif %}

    {% if encrypted_blobs %}
    <script type="application/json" id="caip-encrypted-blobs">{{ encrypted_blobs | safe }}</script>
    {% endif %}

    {% if encryption_metadata %}
    <script type="application/json" id="caip-encryption-metadata">{{ encryption_metadata | safe }}</script>
    {% endif %}

    {% if signing_result %}
    <script type="application/json" id="caip-signing-result">
    {
        "signature": "{{ signing_result.signature | safe }}",
        "signature_algorithm": "{{ signing_result.signature_algorithm }}",
        "certificate_pem": "{{ signing_result.certificate_pem | replace('\n', '\\n') | safe }}",
        "certificate_serial": "{{ signing_result.certificate_serial }}",
        "signed_timestamp": "{{ signing_result.signed_timestamp }}",
        "metadata": {{ signing_result.metadata | tojson | safe }}
    }
    </script>
    {% endif %}
```

**pqc_report.html lines 4912-4924 (DOMContentLoaded with TODO):**

```javascript
document.addEventListener('DOMContentLoaded', function() {
    // FIRST: Check if report is ENCRYPTED and requires P12 decryption
    const encryptedBlobsEl = document.getElementById('caip-encrypted-blobs');
    if (encryptedBlobsEl) {
        try {
            const encryptedBlobs = JSON.parse(encryptedBlobsEl.textContent);
            console.log('Encrypted report detected. Prompting for P12 decryption...');
            // TODO: Call Phase 5 decryption UI here
            showEncryptionModal(encryptedBlobs);
            return;
        } catch (e) {
            console.error('Error parsing encrypted blobs:', e);
        }
    }

    const embeddedDataEl = document.getElementById('pqcReportDataJson');
    if (embeddedDataEl) {
        try {
            reportData = JSON.parse(embeddedDataEl.textContent);
            initializeDashboard();
        } catch (e) {
            console.error('Error parsing embedded report data:', e);
        }
    }
});
```

### 4.3 What Is Implemented vs What the TODO Is Waiting For

**What IS implemented (Phase 4 + inline Phase 5):**
- Server-side report encryption (AES-256-GCM + RSA-OAEP)
- Server-side report signing (RSA-PSS-SHA256)
- Report viewer certificate issuance
- P12 generation with random password
- HTML embedding of encrypted blobs, metadata, and signing result
- Inline forge.js for offline P12 parsing
- Encryption modal with recipient info and signing status display
- Complete client-side hybrid decryption via `decryptWithP12Certificate()`

**What the TODO comments are about:**
The TODO at lines 3975 (pki) and 4919 (pqc) says `// TODO: Call Phase 5 decryption UI here`. Despite the TODO comment, the actual Phase 5 decryption UI IS implemented — `showEncryptionModal()` is called on the very next line. The TODO appears to be a stale comment from when the decryption modal was planned but not yet built. The implementation exists and is functional.

**What is genuinely NOT implemented:**
1. **Signature verification before decryption** — The `SignatureVerifier` class exists but is never called. The signing status is displayed visually but not cryptographically verified.
2. **State machine integration** — `ReportStateManager` defines a proper state machine but is never used. The inline flow manages its own UI state.
3. **P12Parser class** — The jsrsasign-based P12 parser has placeholder methods that return null. Only the forge.js-based inline parser works.
4. **ReportDecryptor class** — Designed for single-step RSA-OAEP decryption, but the actual flow is two-step hybrid (RSA-OAEP unwrap + AES-GCM decrypt). Not used.
5. **Certificate chain validation** — No verification that the recipient's certificate chains back to the engagement CA.
6. **Certificate expiry checking** — No check that the report_viewer cert hasn't expired at decryption time.

---

## Summary — Crypto Parameters Quick Reference

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Report payload encryption | AES-256-GCM | 256 bit | 12-byte nonce, no AAD |
| AES key wrapping (per recipient) | RSA-OAEP | 4096 bit | SHA-256 hash + MGF1 |
| Report blob signing | RSA-PSS | 4096 bit | SHA-256 hash, 32-byte salt |
| Vault encryption | AES-256-GCM | 256 bit | PBKDF2-SHA256, 600k iterations |
| Signing cert | RSA-4096 | 4096 bit | 2-year validity, digitalSignature + contentCommitment |
| Viewer cert | RSA-4096 | 4096 bit | 7-90 day validity, digitalSignature + keyEncipherment |
| P12 password | `secrets.token_urlsafe(20)` | ~160 bit | ~27 character random string |
| Client P12 parsing | forge.js | — | Not jsrsasign, not p12-parser.js |
| Client decryption | Web Crypto API | — | RSA-OAEP unwrap → AES-GCM decrypt |
| Client signature verification | **NOT IMPLEMENTED** | — | SignatureVerifier exists but is never called |
