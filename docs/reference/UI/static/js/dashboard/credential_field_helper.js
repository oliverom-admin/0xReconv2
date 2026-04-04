/**
 * Credential Field Helper
 *
 * Provides utilities for integrating the Secret Picker with credential input fields
 * in configuration forms. Allows users to either enter plaintext credentials or
 * select secrets from registered secret stores.
 */

const CredentialFieldHelper = (() => {
    /**
     * Create a credential field with secret picker integration
     *
     * Returns a container div with:
     * - Input field for plaintext credential entry
     * - Button to open secret picker
     * - Display of selected secret reference
     *
     * @param {Object} options - Configuration options
     * @param {String} options.fieldId - ID for the credential input field
     * @param {String} options.fieldName - Name for form submission
     * @param {String} options.label - Label for the field
     * @param {String} options.placeholder - Placeholder text
     * @param {Boolean} options.required - Whether field is required
     * @param {String} options.fieldType - Input type ('password' or 'text')
     * @returns {String} HTML for the credential field with picker button
     */
    function createCredentialFieldHTML(options = {}) {
        const {
            fieldId = 'credentialField',
            fieldName = fieldId,
            label = 'Credential',
            placeholder = 'Enter credential or select from secret store',
            required = false,
            fieldType = 'password'
        } = options;

        // Debug logging
        

        const requiredAttr = required ? 'required' : '';

        return `
            <div class="credential-field-container">
                <label for="${fieldId}" style="display: block; font-weight: 600; font-size: 13px; color: #374151; margin-bottom: 8px;">
                    ${escapeHtml(label)}
                    ${required ? ' <span style="color: #ef4444;">*</span>' : ''}
                </label>
                <div class="credential-field-wrapper">
                    <input
                        type="${fieldType}"
                        id="${fieldId}"
                        name="${fieldName}"
                        class="credential-input"
                        placeholder="${placeholder}"
                        ${requiredAttr}
                        style="flex: 1; padding: 12px 16px; border: 1.5px solid #e5e7eb; border-radius: 8px 0 0 8px; font-size: 14px; transition: all 0.2s;"
                    />
                    <button
                        type="button"
                        class="credential-picker-btn"
                        onclick="CredentialFieldHelper.openPickerForField('${fieldId}')"
                        title="Select from secret store"
                        style="padding: 12px 16px; background: #0ea5e9; color: white; border: none; border-radius: 0 8px 8px 0; font-weight: 600; font-size: 13px; cursor: pointer; transition: all 0.2s; white-space: nowrap;"
                    >
                        🔐 Select
                    </button>
                </div>
                <div id="${fieldId}-hint" class="credential-field-hint" style="display: none; margin-top: 8px; font-size: 12px; color: #0ea5e9;">
                    <strong>Selected Secret:</strong> <span id="${fieldId}-secret-path"></span>
                </div>
            </div>
        `;
    }

    /**
     * Open secret picker for a specific credential field
     *
     * @param {String} fieldId - ID of the credential field
     */
    function openPickerForField(fieldId) {
        
        const field = document.getElementById(fieldId);
        if (!field) {
            
            return;
        }

        
        // Open the secret picker modal
        SecretPicker.open({
            targetFieldId: fieldId,
            onSelect: (secretRef) => {
                
                // Update the hint display
                updateFieldHint(fieldId, secretRef);
            }
        });
    }

    /**
     * Update the hint display for a credential field
     *
     * @param {String} fieldId - ID of the credential field
     * @param {Object} secretRef - Secret reference object
     */
    function updateFieldHint(fieldId, secretRef) {
        const hintDiv = document.getElementById(`${fieldId}-hint`);
        const secretPathSpan = document.getElementById(`${fieldId}-secret-path`);

        if (hintDiv && secretPathSpan) {
            secretPathSpan.textContent = secretRef.path || 'Unknown';
            hintDiv.style.display = 'block';
        }
    }

    /**
     * Get credential value from a field
     *
     * Returns either the plaintext value or the secret reference
     * stored in the data attribute.
     *
     * @param {String} fieldId - ID of the credential field
     * @returns {Object} Credential object with either 'value' or 'secret_ref'
     */
    function getCredentialValue(fieldId) {
        const field = document.getElementById(fieldId);
        if (!field) return null;

        // Check if field has a secret reference
        const secretRefAttr = field.getAttribute('data-secret-ref');
        if (secretRefAttr) {
            try {
                return {
                    type: 'secret_ref',
                    secret_ref: JSON.parse(secretRefAttr)
                };
            } catch (error) {
                
            }
        }

        // Otherwise return plaintext value
        const value = field.value.trim();
        if (value) {
            return {
                type: 'plaintext',
                value: value
            };
        }

        return null;
    }

    /**
     * Clear a credential field and its hint
     *
     * @param {String} fieldId - ID of the credential field
     */
    function clearField(fieldId) {
        const field = document.getElementById(fieldId);
        const hintDiv = document.getElementById(`${fieldId}-hint`);

        if (field) {
            field.value = '';
            field.removeAttribute('data-secret-ref');
            field.style.color = '';
        }

        if (hintDiv) {
            hintDiv.style.display = 'none';
        }
    }

    /**
     * Validate that credential is provided (either plaintext or secret ref)
     *
     * @param {String} fieldId - ID of the credential field
     * @returns {Boolean} True if credential is valid, false otherwise
     */
    function validateField(fieldId) {
        const credential = getCredentialValue(fieldId);
        return credential !== null;
    }

    /**
     * Extract credential value from field - returns hybrid format for Phase 6
     *
     * Returns object with both plaintext_value and secret_reference fields
     * (one will be null, the other will have value)
     *
     * @param {Element} fieldElement - The credential field wrapper element
     * @returns {Object} {plaintext_value: string|null, secret_reference: object|null}
     */
    function extractCredentialValue(fieldElement) {
        if (!fieldElement) {
            
            return { plaintext_value: null, secret_reference: null };
        }

        // Find the input field within the wrapper
        const input = fieldElement.querySelector('.credential-input');

        if (!input) {
            
            return { plaintext_value: null, secret_reference: null };
        }

        // PRIORITY 1: Check for secret reference in data attribute (most reliable)
        // This is the authoritative indicator that a secret was selected
        const secretRefAttr = input.getAttribute('data-secret-ref');
        if (secretRefAttr) {
            try {
                
                return {
                    plaintext_value: null,
                    secret_reference: JSON.parse(secretRefAttr)
                };
            } catch (error) {
                
                return { plaintext_value: null, secret_reference: null };
            }
        }

        // PRIORITY 2: Return plaintext value if no secret reference exists
        const plaintext = input.value.trim();

        // Filter out the display string "Secret: ..." which indicates a missing reference
        if (plaintext && plaintext.startsWith('Secret:')) {
            
            return { plaintext_value: null, secret_reference: null };
        }

        return {
            plaintext_value: plaintext || null,
            secret_reference: null
        };
    }

    /**
     * Populate credential field from config data
     *
     * Handles both plaintext and secret reference data, setting up
     * the field display and data attributes appropriately.
     *
     * @param {Element} fieldElement - The credential field wrapper element
     * @param {Object} credentialData - {plaintext_value, secret_reference}
     */
    function populateCredentialField(fieldElement, credentialData) {
        if (!fieldElement || !credentialData) {
            
            return;
        }

        const input = fieldElement.querySelector('.credential-input');
        const hintDiv = fieldElement.querySelector('.credential-field-hint');
        const secretPathSpan = fieldElement.querySelector('[id$="-secret-path"]');

        if (!input) {
            
            return;
        }

        // Clear field first
        input.value = '';
        input.removeAttribute('data-secret-ref');
        input.style.color = '';

        if (hintDiv) {
            hintDiv.style.display = 'none';
        }

        // Case 1: Plaintext value
        if (credentialData.plaintext_value) {
            input.value = credentialData.plaintext_value;
            input.style.color = '#1f2937'; // Normal text color
            return;
        }

        // Case 2: Secret reference
        if (credentialData.secret_reference) {
            const ref = credentialData.secret_reference;

            // Store reference in data attribute
            input.setAttribute('data-secret-ref', JSON.stringify(ref));

            // Show secret path in field with blue styling
            input.value = `Secret: ${ref.path}`;
            input.style.color = '#0ea5e9'; // Blue text

            // Show hint
            if (hintDiv && secretPathSpan) {
                secretPathSpan.textContent = ref.path;
                hintDiv.style.display = 'block';
            }
            return;
        }

        // Case 3: No data - leave field empty
        input.value = '';
        input.style.color = '';
    }

    /**
     * HTML escape utility
     */
    function escapeHtml(unsafe) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return unsafe.replace(/[&<>"']/g, m => map[m]);
    }

    // Public API
    return {
        createCredentialFieldHTML: createCredentialFieldHTML,
        openPickerForField: openPickerForField,
        updateFieldHint: updateFieldHint,
        getCredentialValue: getCredentialValue,
        clearField: clearField,
        validateField: validateField,
        extractCredentialValue: extractCredentialValue,
        populateCredentialField: populateCredentialField
    };
})();

/* CSS for credential field wrapper */
const credentialFieldCSS = `
    .credential-field-container {
        margin-bottom: 24px;
    }

    .credential-field-wrapper {
        display: flex;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    }

    .credential-input {
        flex: 1;
    }

    .credential-input:focus {
        outline: none;
        border-color: #0ea5e9 !important;
        box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.1) !important;
    }

    .credential-picker-btn:hover {
        background: #0284c7;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(14, 165, 233, 0.3);
    }

    .credential-picker-btn:active {
        transform: translateY(0);
    }

    .credential-field-hint {
        padding: 8px 12px;
        background: #ecf8ff;
        border-left: 3px solid #0ea5e9;
        border-radius: 4px;
        font-family: monospace;
    }

    .credential-field-hint span {
        font-family: monospace;
        word-break: break-all;
    }
`;

// Inject CSS if not already present
if (!document.querySelector('style[data-credential-field-css]')) {
    const styleTag = document.createElement('style');
    styleTag.setAttribute('data-credential-field-css', '');
    styleTag.textContent = credentialFieldCSS;
    document.head.appendChild(styleTag);
    
} else {
    
}
