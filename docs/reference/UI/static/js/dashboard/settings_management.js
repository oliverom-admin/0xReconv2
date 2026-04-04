/**
 * Settings Management Module
 *
 * Handles user management and authentication provider configuration
 */

// Prevent form submission on Enter key
document.addEventListener('DOMContentLoaded', function() {
    const userForm = document.getElementById('newUserForm');
    if (userForm) {
        userForm.addEventListener('submit', function(e) {
            e.preventDefault();
            submitUserForm();
            return false;
        });
    }
});

// ==================== NOTIFICATION HELPER ====================

// Simple notification function with fallback
function showNotification(message, type = 'info') {
    // Try to use global notification system if available
    if (typeof window.showMessage === 'function') {
        window.showMessage(message, type);
        return;
    }

    // Fallback: Create a simple toast notification
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 24px;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
        color: white;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ==================== USER MANAGEMENT ====================

async function loadUsers() {
    
    try {
        // Populate role dropdown with RBAC roles when available
        if (typeof populateRoleDropdown === 'function') {
            
            await populateRoleDropdown();
            
        } else {
            
        }

        
        const response = await fetch('/api/v1/users');
        

        // Check if response is ok
        if (!response.ok) {
            
            const errorData = await response.json().catch(() => ({error: response.statusText}));
            throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        

        const tbody = document.getElementById('users-table-body');
        if (!tbody) {
            
            return;
        }

        if (!data || !data.users) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No users data returned</td></tr>';
            
            return;
        }

        if (!Array.isArray(data.users)) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Invalid data format (not an array)</td></tr>';
            
            return;
        }

        if (data.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No users found</td></tr>';
            
            return;
        }

        
        tbody.innerHTML = data.users.map(user => {
            const enabled = user.enabled !== undefined ? user.enabled : 1;
            const statusBadge = enabled ?
                '<span class="badge" style="background: #51cf66; color: white;">Active</span>' :
                '<span class="badge" style="background: #ff6b6b; color: white;">Disabled</span>';

            // Auth provider badge - show provider name or "Local" if none
            let authProviderBadge;
            if (user.auth_provider_name && user.auth_provider_name.trim() !== '') {
                authProviderBadge = `<span class="badge" style="background: #4c6ef5; color: white;">${user.auth_provider_name}</span>`;
            } else {
                authProviderBadge = '<span class="badge" style="background: #868e96; color: white;">Local</span>';
            }

            return `
                <tr style="${!enabled ? 'opacity: 0.6;' : ''}">
                    <td>${user.username}</td>
                    <td><span class="badge">${user.role}</span></td>
                    <td>${authProviderBadge}</td>
                    <td>${statusBadge}</td>
                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                    <td style="text-align: right;">
                        <button class="btn-icon" onclick="editUser(${user.id})" title="Edit User">✏️</button>
                        <button class="btn-icon" onclick="deleteUser(${user.id}, '${user.username}')" title="Delete User">🗑️</button>
                    </td>
                </tr>
            `;
        }).join('');
        
    } catch (error) {
        
        
        showNotification('Failed to load users: ' + error.message, 'error');
        const tbody = document.getElementById('users-table-body');
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state" style="color: #ef4444;">Error: ${error.message}</td></tr>`;
        }
    }
}

// Removed - RBAC table no longer in Users tab (moved to Settings > Roles & Permissions)
// async function loadRBAC() {
//     
//     try {
//         
//         const response = await fetch('/api/v1/rbac/roles');
//
//         if (!response.ok) {
//             
//             throw new Error(`HTTP ${response.status}: ${response.statusText}`);
//         }
//
//         const data = await response.json();
//         
//
//         const tbody = document.getElementById('rbac-table-body');
//         if (!tbody) {
//             
//             return;
//         }
//
//         if (!data || !data.roles || !Array.isArray(data.roles)) {
//             
//             tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Invalid data format</td></tr>';
//             return;
//         }
//
//         if (data.roles.length === 0) {
//             tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No roles defined</td></tr>';
//             
//             return;
//         }
//
//         
//         tbody.innerHTML = data.roles.map(role => `
//             <tr>
//                 <td><code>${role.name}</code></td>
//                 <td>${role.display_name}</td>
//                 <td>${role.permissions && Array.isArray(role.permissions) ? role.permissions.map(p => `<span class="badge">${p}</span>`).join(' ') : 'N/A'}</td>
//             </tr>
//         `).join('');
//         
//     } catch (error) {
//         
//         
//         const tbody = document.getElementById('rbac-table-body');
//         if (tbody) {
//             tbody.innerHTML = `<tr><td colspan="3" class="empty-state" style="color: #ef4444;">Error: ${error.message}</td></tr>`;
//         }
//     }
// }

async function openNewUserModal() {
    // Populate role dropdown from RBAC system
    if (typeof populateRoleDropdown === 'function') {
        await populateRoleDropdown('newUserRole', 'new-role-description', 'new-role-description-text');
    }

    // Populate engagement checkboxes
    await populateEngagementCheckboxes();

    // Clear form fields
    document.getElementById('newUsername').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('newPasswordConfirm').value = '';
    document.getElementById('newUserRole').value = '';
    document.getElementById('newUserEnabled').checked = true;

    // Hide password match indicators
    document.getElementById('newPasswordMatch').style.display = 'none';
    document.getElementById('newPasswordNoMatch').style.display = 'none';

    // Hide role description initially
    const descContainer = document.getElementById('new-role-description');
    if (descContainer) {
        descContainer.style.display = 'none';
    }

    // Setup password match validation
    const password = document.getElementById('newPassword');
    const confirmPassword = document.getElementById('newPasswordConfirm');
    const checkPasswordMatch = () => {
        const match = document.getElementById('newPasswordMatch');
        const noMatch = document.getElementById('newPasswordNoMatch');

        if (confirmPassword.value === '') {
            match.style.display = 'none';
            noMatch.style.display = 'none';
        } else if (password.value === confirmPassword.value) {
            match.style.display = 'block';
            noMatch.style.display = 'none';
        } else {
            match.style.display = 'none';
            noMatch.style.display = 'block';
        }
    };

    password.oninput = checkPasswordMatch;
    confirmPassword.oninput = checkPasswordMatch;

    const modal = document.getElementById('newUserModal');
    modal.style.display = '';  // Clear any inline display style
    modal.classList.add('active');
}

function closeNewUserModal(skipRefresh = false) {
    const modal = document.getElementById('newUserModal');
    if (modal) {
        // Force remove active class and ensure modal is hidden
        modal.classList.remove('active');
        modal.style.display = 'none';

        // Clear form fields
        document.getElementById('newUsername').value = '';
        document.getElementById('newPassword').value = '';
        document.getElementById('newUserRole').value = '';
        document.getElementById('newUserEnabled').checked = true;

        // Clear engagement checkboxes
        document.getElementById('newUserEngagementsList').innerHTML = '<div style="padding: 12px 16px; font-size: 13px; color: #6b7280;">Loading engagements...</div>';

        // Hide role description
        const descContainer = document.getElementById('new-role-description');
        if (descContainer) {
            descContainer.style.display = 'none';
        }

        // Refresh users table when modal closes
        if (!skipRefresh) {
            const usersTab = document.getElementById('settings-users');
            if (usersTab && usersTab.classList.contains('active')) {
                setTimeout(() => {
                    loadUsers();
                }, 100);
            }
        }
    }
}

function closeEditUserModal(skipRefresh = false) {
    const modal = document.getElementById('editUserModal');
    if (modal) {
        // Force remove active class and ensure modal is hidden
        modal.classList.remove('active');
        modal.style.display = 'none';

        // Clear form fields
        document.getElementById('editUserId').value = '';
        document.getElementById('editUsername').value = '';
        document.getElementById('editPassword').value = '';
        document.getElementById('editUserRole').value = '';
        document.getElementById('editUserEnabled').checked = true;

        // Hide role description
        const descContainer = document.getElementById('edit-role-description');
        if (descContainer) {
            descContainer.style.display = 'none';
        }

        // Refresh users table when modal closes
        if (!skipRefresh) {
            const usersTab = document.getElementById('settings-users');
            if (usersTab && usersTab.classList.contains('active')) {
                setTimeout(() => {
                    loadUsers();
                }, 100);
            }
        }
    }
}

async function editUser(userId) {
    try {
        // Populate role dropdown from RBAC system first
        if (typeof populateRoleDropdown === 'function') {
            await populateRoleDropdown('editUserRole', 'edit-role-description', 'edit-role-description-text');
        }

        const response = await fetch('/api/v1/users');
        const data = await response.json();
        const user = data.users.find(u => u.id === userId);

        if (!user) {
            showNotification('User not found', 'error');
            return;
        }

        document.getElementById('editUserId').value = user.id;
        document.getElementById('editUsername').value = user.username;
        document.getElementById('editPassword').value = '';
        document.getElementById('editPasswordConfirm').value = '';
        document.getElementById('editUserRole').value = user.role;
        document.getElementById('editUserEnabled').checked = user.enabled !== undefined ? user.enabled : true;

        // Hide password match indicators
        document.getElementById('editPasswordMatch').style.display = 'none';
        document.getElementById('editPasswordNoMatch').style.display = 'none';

        // Setup password match validation
        const password = document.getElementById('editPassword');
        const confirmPassword = document.getElementById('editPasswordConfirm');
        const checkPasswordMatch = () => {
            const match = document.getElementById('editPasswordMatch');
            const noMatch = document.getElementById('editPasswordNoMatch');

            if (confirmPassword.value === '' && password.value === '') {
                match.style.display = 'none';
                noMatch.style.display = 'none';
            } else if (password.value === confirmPassword.value) {
                match.style.display = 'block';
                noMatch.style.display = 'none';
            } else {
                match.style.display = 'none';
                noMatch.style.display = 'block';
            }
        };

        password.oninput = checkPasswordMatch;
        confirmPassword.oninput = checkPasswordMatch;

        // Trigger change event to show role description
        const roleSelect = document.getElementById('editUserRole');
        if (roleSelect) {
            roleSelect.dispatchEvent(new Event('change'));
        }

        const modal = document.getElementById('editUserModal');
        modal.style.display = '';  // Clear any inline display style
        modal.classList.add('active');
    } catch (error) {
        
        showNotification('Failed to load user', 'error');
    }
}

async function submitNewUserForm() {
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;
    const passwordConfirm = document.getElementById('newPasswordConfirm').value;
    const role = document.getElementById('newUserRole').value;
    const enabled = document.getElementById('newUserEnabled').checked;

    if (!username || !role || !password || !passwordConfirm) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    if (password !== passwordConfirm) {
        showNotification('Passwords do not match', 'error');
        return;
    }

    try {
        // Collect selected engagement IDs from checkboxes
        const engagementCheckboxes = document.querySelectorAll('input[name="newUserEngagement"]:checked');
        const engagement_ids = Array.from(engagementCheckboxes).map(cb => cb.value);

        const payload = { username, password, role, enabled, engagement_ids };

        const response = await fetch('/api/v1/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('User created successfully', 'success');

            // Show certificate and engagement results
            if (data.certificate_results || data.engagement_results) {
                showCertDownloadResults(data);
            }

            // Close modal IMMEDIATELY
            requestAnimationFrame(() => {
                const modal = document.getElementById('newUserModal');
                if (modal) {
                    modal.classList.remove('active');
                    modal.style.display = 'none';
                }
            });

            // Refresh data in background
            setTimeout(async () => {
                try {
                    await loadUsers();
                } catch (loadError) {

                }
            }, 150);
        } else {
            showNotification(data.error || 'Failed to create user', 'error');
        }
    } catch (error) {

        showNotification('Failed to create user: ' + error.message, 'error');
    }
}

async function submitEditUserForm() {
    const userId = document.getElementById('editUserId').value;
    const username = document.getElementById('editUsername').value;
    const password = document.getElementById('editPassword').value;
    const passwordConfirm = document.getElementById('editPasswordConfirm').value;
    const role = document.getElementById('editUserRole').value;
    const enabled = document.getElementById('editUserEnabled').checked;

    if (!userId || !username || !role) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    // Check password matching if password is being changed
    if (password && password.trim() !== '') {
        if (password !== passwordConfirm) {
            showNotification('Passwords do not match', 'error');
            return;
        }
    }

    try {
        const payload = { username, role, enabled };
        // Only include password if it was changed
        if (password && password.trim() !== '') {
            payload.password = password;
        }

        const response = await fetch(`/api/v1/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('User updated successfully', 'success');

            // Close modal IMMEDIATELY
            requestAnimationFrame(() => {
                const modal = document.getElementById('editUserModal');
                if (modal) {
                    modal.classList.remove('active');
                    modal.style.display = 'none';
                }
            });

            // Refresh data in background
            setTimeout(async () => {
                try {
                    await loadUsers();
                } catch (loadError) {
                    
                }
            }, 150);
        } else {
            showNotification(data.error || 'Failed to update user', 'error');
        }
    } catch (error) {
        
        showNotification('Failed to update user: ' + error.message, 'error');
    }
}

// Legacy function - kept for backward compatibility (remove later)
async function submitUserForm() {
    const userId = document.getElementById('editUserId').value;
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;
    const role = document.getElementById('newUserRole').value;
    const enabled = document.getElementById('newUserEnabled').checked;

    if (!username || !role) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    if (!userId && !password) {
        showNotification('Password is required for new users', 'error');
        return;
    }

    try {
        const payload = { username, role, enabled };
        if (password) {
            payload.password = password;
        }

        const response = userId
            ? await fetch(`/api/v1/users/${userId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            : await fetch('/api/v1/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

        const data = await response.json();

        if (response.ok) {
            showNotification(userId ? 'User updated successfully' : 'User created successfully', 'success');

            // Close modal IMMEDIATELY - use requestAnimationFrame to ensure it happens after current execution
            requestAnimationFrame(() => {
                const modal = document.getElementById('newUserModal');
                if (modal) {
                    modal.classList.remove('active');
                    modal.style.display = 'none';
                }
            });

            // Then refresh data in background after a short delay
            setTimeout(async () => {
                try {
                    await loadUsers();
                } catch (loadError) {
                    
                }

                // Removed - RBAC table no longer in Users tab
                // try {
                //     await loadRBAC();
                // } catch (loadError) {
                //     
                // }
            }, 100);
        } else {
            showNotification(data.error || 'Failed to save user', 'error');
        }
    } catch (error) {
        
        showNotification('Failed to save user', 'error');
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/users/${userId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('User deleted successfully', 'success');
            loadUsers();
        } else {
            showNotification(data.error || 'Failed to delete user', 'error');
        }
    } catch (error) {
        
        showNotification('Failed to delete user', 'error');
    }
}


// ==================== AUTH PROVIDER MANAGEMENT ====================

async function loadAuthProviders() {
    try {
        const response = await fetch('/api/v1/settings/auth-providers');
        const data = await response.json();

        const tbody = document.getElementById('auth-providers-table-body');
        if (!data.providers || data.providers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No authentication providers configured. Click "+ New Provider" to add one.</td></tr>';
            return;
        }

        // Transform table to grid of cards
        const table = tbody.closest('table');
        table.style.display = 'none';  // Hide table

        // Create container for cards if it doesn't exist - insert in the settings-auth-providers tab
        let cardsContainer = document.getElementById('auth-providers-cards-container');
        if (!cardsContainer) {
            cardsContainer = document.createElement('div');
            cardsContainer.id = 'auth-providers-cards-container';
            cardsContainer.style.cssText = 'display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 16px; margin-bottom: 30px;';
            table.parentElement.insertBefore(cardsContainer, table);
        }

        cardsContainer.innerHTML = data.providers.map(provider => {
            const statusColor = provider.enabled
                ? { bg: 'rgba(16, 185, 129, 0.1)', border: '#10b981', text: '#10b981', icon: '✓' }
                : { bg: 'rgba(107, 114, 128, 0.1)', border: '#6b7280', text: '#6b7280', icon: '—' };

            return `
                <div style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <!-- Header -->
                    <div style="padding: 20px 24px; background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;">
                        <div style="flex: 1;">
                            <div style="font-size: 18px; font-weight: 700; color: #1f2937; margin-bottom: 4px;">${provider.name}</div>
                            <div style="font-size: 13px; color: #6b7280; display: flex; align-items: center; gap: 8px;">
                                <span>🔐</span>
                                <span>${formatProviderType(provider.type)}</span>
                            </div>
                        </div>
                        <div style="background: ${statusColor.bg}; border: 1.5px solid ${statusColor.border}; border-radius: 8px; padding: 8px 16px; text-align: center; flex-shrink: 0;">
                            <div style="font-size: 12px; font-weight: 600; color: ${statusColor.text};">${statusColor.icon} ${provider.enabled ? 'ENABLED' : 'DISABLED'}</div>
                        </div>
                    </div>

                    <!-- Details -->
                    <div style="padding: 20px 24px; border-bottom: 1px solid #e5e7eb;">
                        <div style="display: grid; grid-template-columns: auto 1fr; gap: 16px 24px; font-size: 14px;">
                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Client ID</div>
                            <div style="color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; font-size: 12px; word-break: break-all;">${provider.config_summary.client_id || 'N/A'}</div>

                            <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Auto-Provision</div>
                            <div style="color: #1f2937; font-weight: 500;">${provider.config_summary.auto_provision_users ? '✅ Yes' : '❌ No'}</div>

                            ${provider.config_summary.tenant_id ? `
                                <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Tenant ID</div>
                                <div style="color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; font-size: 12px; word-break: break-all;">${provider.config_summary.tenant_id}</div>
                            ` : ''}

                            ${provider.config_summary.default_role ? `
                                <div style="font-weight: 600; text-transform: uppercase; color: #6b7280; font-size: 11px; letter-spacing: 0.5px;">Default Role</div>
                                <div style="color: #1f2937; font-weight: 500;">${provider.config_summary.default_role}</div>
                            ` : ''}
                        </div>
                    </div>

                    <!-- Actions -->
                    <div style="padding: 16px 24px; background: #f9fafb; border-top: 1px solid #e5e7eb; display: flex; gap: 8px; flex-wrap: wrap;">
                        <button onclick="editAuthProvider(${provider.id})"
                            style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                            ✏️ Edit
                        </button>
                        <button onclick="toggleAuthProvider(${provider.id}, ${!provider.enabled})"
                            style="padding: 6px 12px; background: white; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                            ${provider.enabled ? '🔴 Disable' : '🟢 Enable'}
                        </button>
                        <button onclick="deleteAuthProvider(${provider.id}, '${provider.name}')"
                            style="padding: 6px 12px; background: white; color: #dc2626; border: 1px solid #fecaca; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.2s; font-weight: 500;">
                            🗑️ Delete
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {

        showNotification('Failed to load authentication providers', 'error');
    }
}

function formatProviderType(type) {
    const typeMap = {
        'azure_entra_id': 'Azure Entra ID',
        'okta': 'Okta',
        'auth0': 'Auth0',
        'google': 'Google'
    };
    return typeMap[type] || type;
}

function openNewAuthProviderModal() {
    document.getElementById('authProviderModalTitle').textContent = 'New Authentication Provider';
    document.getElementById('editAuthProviderId').value = '';
    document.getElementById('authProviderName').value = '';
    document.getElementById('authProviderType').value = '';
    document.getElementById('authProviderClientId').value = '';
    document.getElementById('authProviderClientSecret').value = '';
    document.getElementById('authProviderTenantId').value = '';
    document.getElementById('authProviderScopes').value = 'User.Read,email';
    document.getElementById('authProviderAutoProvision').checked = false;
    document.getElementById('authProviderDefaultRole').value = 'new-user';
    document.getElementById('authProviderEnabled').checked = true;
    document.getElementById('azureEntraIdFields').style.display = 'none';
    document.getElementById('newAuthProviderModal').style.display = 'flex';
}

function closeNewAuthProviderModal(skipRefresh = false) {
    const modal = document.getElementById('newAuthProviderModal');
    if (modal) {
        modal.style.display = 'none';

        // Refresh the auth providers table when modal closes (unless skipped for explicit refresh)
        if (!skipRefresh) {
            const authProvidersTab = document.getElementById('settings-auth-providers');
            if (authProvidersTab && authProvidersTab.classList.contains('active')) {
                setTimeout(() => loadAuthProviders(), 100);
            }
        }
    }
}

function toggleAuthProviderFields() {
    const type = document.getElementById('authProviderType').value;
    const azureFields = document.getElementById('azureEntraIdFields');
    const oktaFields = document.getElementById('oktaFields');

    // Hide all provider-specific fields first
    azureFields.style.display = 'none';
    oktaFields.style.display = 'none';

    // Show fields for selected provider
    if (type === 'azure_entra_id') {
        azureFields.style.display = 'block';
    } else if (type === 'okta') {
        oktaFields.style.display = 'block';
    }
}

async function editAuthProvider(providerId) {
    try {
        const response = await fetch(`/api/v1/settings/auth-providers/${providerId}`);
        const provider = await response.json();

        if (!response.ok) {
            showNotification(provider.error || 'Failed to load provider', 'error');
            return;
        }

        document.getElementById('authProviderModalTitle').textContent = 'Edit Authentication Provider';
        document.getElementById('editAuthProviderId').value = provider.id;
        document.getElementById('authProviderName').value = provider.name;
        document.getElementById('authProviderType').value = provider.type;

        // Populate common fields
        document.getElementById('authProviderAutoProvision').checked = provider.config.auto_provision_users || false;
        document.getElementById('authProviderDefaultRole').value = provider.config.default_role || 'new-user';
        document.getElementById('authProviderEnabled').checked = provider.enabled;

        // Populate provider-specific fields
        if (provider.type === 'azure_entra_id') {
            document.getElementById('authProviderClientId').value = provider.config.client_id || '';
            document.getElementById('authProviderClientSecret').value = ''; // Don't populate secrets
            document.getElementById('authProviderTenantId').value = provider.config.tenant_id || '';
            document.getElementById('authProviderScopes').value = (provider.config.scopes || []).join(',');
            document.querySelector('#authProviderClientSecret').placeholder = 'Leave blank to keep current secret';
        } else if (provider.type === 'okta') {
            const oktaDomain = provider.config.metadata?.okta_domain || provider.config.tenant_id || '';
            document.getElementById('oktaDomain').value = oktaDomain;
            document.getElementById('oktaClientId').value = provider.config.client_id || '';
            document.getElementById('oktaClientSecret').value = ''; // Don't populate secrets
            document.getElementById('oktaScopes').value = (provider.config.scopes || []).join(',');
            document.querySelector('#oktaClientSecret').placeholder = 'Leave blank to keep current secret';
        }

        toggleAuthProviderFields();

        document.getElementById('newAuthProviderModal').style.display = 'flex';
    } catch (error) {
        
        showNotification('Failed to load provider', 'error');
    }
}

async function submitAuthProviderForm() {
    const providerId = document.getElementById('editAuthProviderId').value;
    const name = document.getElementById('authProviderName').value;
    const type = document.getElementById('authProviderType').value;

    if (!name || !type) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    // Build config based on provider type
    const config = {
        auto_provision_users: document.getElementById('authProviderAutoProvision').checked,
        default_role: document.getElementById('authProviderDefaultRole').value
    };

    if (type === 'azure_entra_id') {
        const clientId = document.getElementById('authProviderClientId').value;
        const clientSecret = document.getElementById('authProviderClientSecret').value;
        const tenantId = document.getElementById('authProviderTenantId').value;
        const scopes = document.getElementById('authProviderScopes').value.split(',').map(s => s.trim());

        if (!clientId || !tenantId) {
            showNotification('Please fill in all Azure Entra ID fields', 'error');
            return;
        }

        if (!providerId && !clientSecret) {
            showNotification('Client secret is required for new providers', 'error');
            return;
        }

        config.client_id = clientId;
        if (clientSecret) {
            config.client_secret = clientSecret;
        }
        config.tenant_id = tenantId;
        config.scopes = scopes;
    } else if (type === 'okta') {
        const oktaDomain = document.getElementById('oktaDomain').value.trim();
        const clientId = document.getElementById('oktaClientId').value.trim();
        const clientSecret = document.getElementById('oktaClientSecret').value;
        const scopes = document.getElementById('oktaScopes').value.split(',').map(s => s.trim());

        if (!oktaDomain || !clientId) {
            showNotification('Please fill in all Okta fields', 'error');
            return;
        }

        if (!providerId && !clientSecret) {
            showNotification('Client secret is required for new providers', 'error');
            return;
        }

        // Normalize domain (remove protocol if present)
        let normalizedDomain = oktaDomain;
        if (normalizedDomain.startsWith('https://')) {
            normalizedDomain = normalizedDomain.substring(8);
        } else if (normalizedDomain.startsWith('http://')) {
            normalizedDomain = normalizedDomain.substring(7);
        }
        normalizedDomain = normalizedDomain.replace(/\/$/, '');

        config.client_id = clientId;
        if (clientSecret) {
            config.client_secret = clientSecret;
        }
        config.tenant_id = normalizedDomain;  // Used by oauth_service
        config.scopes = scopes;
        config.metadata = {
            okta_domain: normalizedDomain,
            authorization_server_id: 'default',
            use_pkce: true
        };
    }

    const payload = {
        name,
        type,
        config,
        enabled: document.getElementById('authProviderEnabled').checked
    };

    try {
        const response = providerId
            ? await fetch(`/api/v1/settings/auth-providers/${providerId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            : await fetch('/api/v1/settings/auth-providers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

        const data = await response.json();

        if (response.ok) {
            showNotification(providerId ? 'Provider updated successfully' : 'Provider created successfully', 'success');
            closeNewAuthProviderModal(true); // Skip auto-refresh since we're doing explicit refresh
            await loadAuthProviders(); // Explicit refresh after successful save
        } else {
            showNotification(data.error || 'Failed to save provider', 'error');
        }
    } catch (error) {
        
        showNotification('Failed to save provider', 'error');
    }
}

async function toggleAuthProvider(providerId, enable) {
    try {
        const response = await fetch(`/api/v1/settings/auth-providers/${providerId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enable })
        });

        const data = await response.json();

        if (response.ok) {
            showNotification(`Provider ${enable ? 'enabled' : 'disabled'} successfully`, 'success');
            loadAuthProviders();
        } else {
            showNotification(data.error || 'Failed to toggle provider', 'error');
        }
    } catch (error) {
        
        showNotification('Failed to toggle provider', 'error');
    }
}

async function deleteAuthProvider(providerId, providerName) {
    if (!confirm(`Are you sure you want to delete authentication provider "${providerName}"?\n\nThis will prevent users from signing in with this provider.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/settings/auth-providers/${providerId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('Provider deleted successfully', 'success');
            loadAuthProviders();
        } else {
            showNotification(data.error || 'Failed to delete provider', 'error');
        }
    } catch (error) {
        
        showNotification('Failed to delete provider', 'error');
    }
}


// ==================== INITIALIZATION ====================

// Load data when settings tab is opened
document.addEventListener('DOMContentLoaded', () => {
    // Display redirect URI for Azure setup
    const redirectUriDisplay = document.getElementById('redirect-uri-display');
    if (redirectUriDisplay) {
        redirectUriDisplay.textContent = `${window.location.origin}/api/v1/auth/oauth/callback`;
    }

    // Load data when switching to settings tabs
    const settingsObserver = new MutationObserver(() => {
        if (document.getElementById('settings-users')?.classList.contains('active')) {
            loadUsers();
            // loadRBAC(); // Removed - RBAC table no longer in Users tab
        }
        if (document.getElementById('settings-auth-providers')?.classList.contains('active')) {
            loadAuthProviders();
        }
    });

    const settingsUsers = document.getElementById('settings-users');
    const settingsAuthProviders = document.getElementById('settings-auth-providers');

    if (settingsUsers) {
        settingsObserver.observe(settingsUsers, { attributes: true, attributeFilter: ['class'] });
    }
    if (settingsAuthProviders) {
        settingsObserver.observe(settingsAuthProviders, { attributes: true, attributeFilter: ['class'] });
    }

    // Initial load if settings is active
    if (document.getElementById('settings')?.style.display !== 'none') {
        if (settingsUsers?.classList.contains('active')) {
            loadUsers();
            // loadRBAC(); // Removed - RBAC table no longer in Users tab
        }
        if (settingsAuthProviders?.classList.contains('active')) {
            loadAuthProviders();
        }
    }
});

// ==================== ENGAGEMENT CHECKBOX HELPERS ====================

async function populateEngagementCheckboxes() {
    try {
        const response = await fetch('/api/v1/engagements');
        if (!response.ok) {
            console.warn('Could not fetch engagements');
            return;
        }

        const data = await response.json();
        const engagements = (data.engagements || []).filter(e => e.status === 'Active');

        const container = document.getElementById('newUserEngagementsList');
        if (!container) return;

        if (engagements.length === 0) {
            container.innerHTML = '<div style="padding: 12px 16px; font-size: 13px; color: #6b7280;">No active engagements available</div>';
            return;
        }

        let html = '';
        engagements.forEach(eng => {
            const displayName = (eng.customer_name && eng.project_name)
                ? `${eng.customer_name} - ${eng.project_name}`
                : eng.engagement_id;

            html += `
                <label style="display: flex; align-items: center; padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #f0f0f0; transition: background 0.2s;" onmouseover="this.style.background='#f9fafb'" onmouseout="this.style.background='transparent'">
                    <input type="checkbox" name="newUserEngagement" value="${eng.engagement_id}"
                           style="margin-right: 12px; width: 18px; height: 18px; cursor: pointer; accent-color: #0ea5e9;">
                    <div>
                        <span style="font-weight: 500; font-size: 13px; color: #1f2937; display: block;">${displayName}</span>
                        <small style="color: #6b7280; font-size: 11px;">ID: ${eng.engagement_id}</small>
                    </div>
                </label>
            `;
        });

        container.innerHTML = html;
    } catch (error) {
        console.error('Error loading engagements:', error);
        const container = document.getElementById('newUserEngagementsList');
        if (container) {
            container.innerHTML = '<div style="padding: 12px 16px; font-size: 13px; color: #ef4444;">Error loading engagements</div>';
        }
    }
}

function showCertDownloadResults(data) {
    // Show certificate results panel with auto-dismiss after 30 seconds
    const resultsPanel = document.createElement('div');
    resultsPanel.id = 'cert-results-panel';
    resultsPanel.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 20px;
        max-width: 400px;
        max-height: 300px;
        overflow-y: auto;
        box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        z-index: 10000;
        font-size: 13px;
    `;

    let content = '<div style="font-weight: 600; margin-bottom: 12px;">Certificate Issuance Results</div>';

    if (data.certificate_results && data.certificate_results.length > 0) {
        content += '<div style="margin-bottom: 12px;"><strong>Certificates:</strong></div>';
        data.certificate_results.forEach(cert => {
            const statusColor = cert.status === 'issued' ? '#10b981' : '#ef4444';
            const statusText = cert.status === 'issued' ? '✓ Issued' : '✗ Error';
            const engagementLabel = cert.engagement_id ? cert.engagement_id : 'Internal CA';

            content += `
                <div style="padding: 8px; background: #f9fafb; border-radius: 4px; margin-bottom: 8px; border-left: 3px solid ${statusColor};">
                    <div style="color: ${statusColor}; font-weight: 500;">${statusText}</div>
                    <div style="color: #6b7280; font-size: 12px; margin-top: 4px;">
                        ${engagementLabel} (${cert.cert_purpose || 'identity'})
                    </div>
                    ${cert.message ? `<div style="color: #6b7280; font-size: 11px; margin-top: 4px;">${cert.message}</div>` : ''}
                </div>
            `;
        });
    }

    if (data.engagement_results && data.engagement_results.length > 0) {
        content += '<div style="margin-bottom: 12px; margin-top: 12px;"><strong>Engagements:</strong></div>';
        data.engagement_results.forEach(eng => {
            const statusColor = eng.status === 'assigned' ? '#10b981' : '#ef4444';
            const statusText = eng.status === 'assigned' ? '✓ Assigned' : '✗ Error';

            content += `
                <div style="padding: 8px; background: #f9fafb; border-radius: 4px; margin-bottom: 8px; border-left: 3px solid ${statusColor};">
                    <div style="color: ${statusColor}; font-weight: 500;">${statusText}</div>
                    <div style="color: #6b7280; font-size: 12px; margin-top: 4px;">${eng.engagement_id}</div>
                </div>
            `;
        });
    }

    content += '<div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #e5e7eb;"><button onclick="document.getElementById(\'cert-results-panel\')?.remove()" style="width: 100%; padding: 8px; background: #0ea5e9; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500;">Dismiss</button></div>';

    resultsPanel.innerHTML = content;
    document.body.appendChild(resultsPanel);

    // Auto-dismiss after 30 seconds
    setTimeout(() => {
        if (resultsPanel.parentNode) {
            resultsPanel.remove();
        }
    }, 30000);
}

// Modal close on background click
window.addEventListener('click', (event) => {
    if (event.target.id === 'newUserModal') {
        closeNewUserModal();
    }
    if (event.target.id === 'newAuthProviderModal') {
        closeNewAuthProviderModal();
    }
});
