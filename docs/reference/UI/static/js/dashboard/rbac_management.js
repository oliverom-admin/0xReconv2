/**
 * RBAC Management Module
 *
 * Provides comprehensive role-based access control management interface
 * including role visualization, permission matrix, and user assignments
 */

// ==================== STATE ====================

let rbacData = {
    roles: [],
    permissions: [],
    users: [],
    rolePermissions: {},
    engagementAssignments: []
};

// ==================== INITIALIZATION ====================

async function initializeRBAC() {
    
    try {
        
        await loadRBACData();
        

        
        setupRBACTabs();

        
        switchRBACTab('rbac-overview');

        
    } catch (error) {
        
        
    }
}

async function loadRBACData() {
    
    try {
        // Load all RBAC data
        const [rolesResp, permissionsResp, usersResp] = await Promise.all([
            fetch('/api/v1/rbac/roles'),
            fetch('/api/v1/rbac/permissions'),
            fetch('/api/v1/users')
        ]);

        

        const rolesData = await rolesResp.json();
        const permissionsData = await permissionsResp.json();
        const usersData = await usersResp.json();

        
        
        

        rbacData.roles = rolesData.roles || [];
        rbacData.permissions = permissionsData.permissions || [];
        rbacData.users = usersData.users || [];

        // Roles already include their permissions from the API
        // Just map them for easy access
        for (const role of rbacData.roles) {
            rbacData.rolePermissions[role.id] = role.permissions || [];
        }

        

    } catch (error) {
        
        
        throw error;
    }
}

// ==================== TAB MANAGEMENT ====================

function setupRBACTabs() {
    const tabButtons = document.querySelectorAll('.rbac-tab-button');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-rbac-tab');
            switchRBACTab(tabId);
        });
    });
}

function switchRBACTab(tabId) {
    

    // Hide all tab contents
    document.querySelectorAll('.rbac-tab-content').forEach(content => {
        content.style.display = 'none';
    });

    // Remove active class from all buttons
    document.querySelectorAll('.rbac-tab-button').forEach(button => {
        button.classList.remove('active');
        button.style.color = '#666';
        button.style.borderBottom = '3px solid transparent';
    });

    // Show selected tab
    const selectedTab = document.getElementById(tabId);
    
    if (selectedTab) {
        selectedTab.style.display = 'block';
        selectedTab.style.visibility = 'visible';
        selectedTab.style.opacity = '1';
        selectedTab.style.minHeight = '600px';
        selectedTab.style.height = 'auto';
        selectedTab.style.overflow = 'visible';
        
    } else {
        
    }

    // Mark button as active
    const activeButton = document.querySelector(`[data-rbac-tab="${tabId}"]`);
    if (activeButton) {
        activeButton.classList.add('active');
        activeButton.style.color = '#3b82f6';
        activeButton.style.borderBottom = '3px solid #3b82f6';
    }

    // Render tab content
    
    switch(tabId) {
        case 'rbac-overview':
            renderRBACOverview();
            break;
        case 'rbac-roles':
            renderRoles();
            break;
        case 'rbac-permissions':
            renderPermissionsMatrix();
            break;
        case 'rbac-assignments':
            renderUserAssignments();
            break;
        case 'rbac-engagements':
            renderEngagementAssignments();
            break;
    }
}

// ==================== OVERVIEW TAB ====================

function renderRBACOverview() {
    // Update stats
    document.getElementById('rbac-total-roles').textContent = rbacData.roles.length;
    document.getElementById('rbac-total-permissions').textContent = rbacData.permissions.length;
    document.getElementById('rbac-total-users').textContent = rbacData.users.filter(u => u.enabled).length;
    document.getElementById('rbac-total-assignments').textContent = rbacData.engagementAssignments.length;

    // Render role hierarchy
    renderRoleHierarchy();
}

function renderRoleHierarchy() {
    const container = document.getElementById('rbac-hierarchy-chart');

    const tiers = {
        'Tier 1: Administrative': ['system-administrator', 'security-auditor'],
        'Tier 2: Operational Management': ['engagement-manager', 'integration-manager'],
        'Tier 3: Specialist': ['assessment-coordinator', 'report-analyst'],
        'Tier 4: Read-Only': ['engagement-viewer', 'global-viewer']
    };

    const tierColors = {
        'Tier 1: Administrative': '#ef4444',
        'Tier 2: Operational Management': '#f59e0b',
        'Tier 3: Specialist': '#3b82f6',
        'Tier 4: Read-Only': '#10b981'
    };

    let html = '<div style="display: flex; flex-direction: column; gap: 20px;">';

    for (const [tierName, roleNames] of Object.entries(tiers)) {
        const tierRoles = rbacData.roles.filter(r => roleNames.includes(r.name));
        const color = tierColors[tierName];

        html += `
            <div style="border-left: 4px solid ${color}; padding-left: 20px;">
                <h4 style="color: ${color}; margin-bottom: 12px; font-size: 16px; font-weight: 600;">${tierName}</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px;">
        `;

        for (const role of tierRoles) {
            const permCount = rbacData.rolePermissions[role.id]?.length || 0;
            const userCount = rbacData.users.filter(u => u.role === role.name).length;

            html += `
                <div style="background: white; border: 1px solid #e1e8ed; border-radius: 6px; padding: 16px; cursor: pointer; transition: all 0.2s;" onmouseover="this.style.boxShadow='0 4px 12px rgba(0,0,0,0.1)'" onmouseout="this.style.boxShadow='none'" onclick="viewRoleDetails('${role.name}')">
                    <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;">${role.display_name}</div>
                    <div style="font-size: 12px; color: #64748b; margin-bottom: 12px;">${role.description || ''}</div>
                    <div style="display: flex; gap: 16px; font-size: 13px; color: #475569;">
                        <span><strong>${permCount}</strong> permissions</span>
                        <span><strong>${userCount}</strong> users</span>
                    </div>
                </div>
            `;
        }

        html += `
                </div>
            </div>
        `;
    }

    html += '</div>';
    container.innerHTML = html;
}

function viewRoleDetails(roleName) {
    switchRBACTab('rbac-roles');
    // Scroll to role
    setTimeout(() => {
        const roleCard = document.querySelector(`[data-role-name="${roleName}"]`);
        if (roleCard) {
            roleCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
            roleCard.style.boxShadow = '0 0 0 3px #3b82f6';
            setTimeout(() => {
                roleCard.style.boxShadow = 'none';
            }, 2000);
        }
    }, 100);
}

// ==================== ROLES TAB ====================

function renderRoles() {
    
    const container = document.getElementById('rbac-roles-container');
    

    if (!container) {
        
        return;
    }

    let html = '<div style="display: flex; flex-direction: column; gap: 24px;">';

    for (const role of rbacData.roles) {
        const permissions = rbacData.rolePermissions[role.id] || [];
        
        const userCount = rbacData.users.filter(u => u.role === role.name).length;

        // Group permissions by domain
        // Note: permissions are strings like "users:create", not objects
        const permissionsByDomain = {};
        for (const permName of permissions) {
            // Extract domain from permission name (e.g., "users:create" -> "users")
            const parts = permName.split(':');
            const domain = parts[0] || 'general';
            const action = parts[1] || permName;

            if (!permissionsByDomain[domain]) {
                permissionsByDomain[domain] = [];
            }
            permissionsByDomain[domain].push({ name: permName, action: action });
        }

        html += `
            <div class="role-card" data-role-name="${role.name}" style="background: white; border: 1px solid #e1e8ed; border-radius: 8px; padding: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 16px;">
                    <div>
                        <h3 style="color: #1e293b; margin-bottom: 8px;">${role.display_name}</h3>
                        <p style="color: #64748b; font-size: 14px; margin-bottom: 8px;">${role.description || ''}</p>
                        <div style="display: flex; gap: 16px; font-size: 13px; color: #475569;">
                            <span><strong>${permissions.length}</strong> permissions</span>
                            <span><strong>${userCount}</strong> users</span>
                            ${role.is_system_role ? '<span style="background: #fef3c7; color: #92400e; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">SYSTEM ROLE</span>' : ''}
                        </div>
                    </div>
                </div>

                <details style="margin-top: 16px;">
                    <summary style="cursor: pointer; color: #3b82f6; font-weight: 600; padding: 8px 0;">View Permissions (${permissions.length})</summary>
                    <div style="margin-top: 16px; display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
        `;

        for (const [domain, domainPerms] of Object.entries(permissionsByDomain)) {
            html += `
                <div style="background: #f8fafc; padding: 12px; border-radius: 6px;">
                    <div style="font-weight: 600; color: #334155; margin-bottom: 8px; text-transform: capitalize;">${domain.replace(/_/g, ' ')}</div>
                    <ul style="list-style: none; padding: 0; margin: 0;">
            `;

            for (const perm of domainPerms) {
                html += `
                    <li style="padding: 4px 0; font-size: 13px; color: #64748b;">
                        <span style="color: #3b82f6; font-family: monospace; font-size: 12px;">${perm.name}</span>
                    </li>
                `;
            }

            html += `
                    </ul>
                </div>
            `;
        }

        html += `
                    </div>
                </details>
            </div>
        `;
    }

    html += '</div>';

    
    container.innerHTML = html;

    // CRITICAL FIX: Force all role-card divs to display block using !important
    const roleCards = container.querySelectorAll('.role-card');
    
    roleCards.forEach((card, index) => {
        // Use setProperty with !important to override any CSS
        card.style.setProperty('display', 'block', 'important');
        card.style.setProperty('visibility', 'visible', 'important');
        if (index === 0) {
            
        }
    });

    // Force BOTH parent and container styling for visibility
    const parentTab = document.getElementById('rbac-roles');
    if (parentTab) {
        parentTab.style.display = 'block';
        parentTab.style.visibility = 'visible';
        parentTab.style.minHeight = '600px';
        parentTab.style.height = 'auto';
        parentTab.style.maxHeight = 'none';
        parentTab.style.overflow = 'visible';
        
    }

    // Force container to expand to content
    container.style.display = 'block';
    container.style.visibility = 'visible';
    container.style.height = 'auto';
    container.style.minHeight = 'fit-content';

    

    // Debug the first child (the flex wrapper)
    if (container.children.length > 0) {
        const firstChild = container.children[0];
        

        // Debug first role card
        if (firstChild.children.length > 0) {
            const firstRole = firstChild.children[0];
            
        }
    }
}

// ==================== PERMISSIONS MATRIX TAB ====================

function renderPermissionsMatrix() {
    const container = document.getElementById('rbac-permissions-matrix');

    // Group permissions by resource type
    const permissionsByResource = {};
    for (const perm of rbacData.permissions) {
        if (!permissionsByResource[perm.resource_type]) {
            permissionsByResource[perm.resource_type] = [];
        }
        permissionsByResource[perm.resource_type].push(perm);
    }

    let html = '<table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';

    // Header
    html += '<thead><tr style="background: #f8fafc;">';
    html += '<th style="padding: 16px; text-align: left; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b;">Permission</th>';

    for (const role of rbacData.roles) {
        html += `<th style="padding: 16px; text-align: center; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b; min-width: 80px; font-size: 12px;" title="${role.description}">${role.display_name.split(' ')[0]}</th>`;
    }

    html += '</tr></thead><tbody>';

    // Rows grouped by resource type
    for (const [resourceType, perms] of Object.entries(permissionsByResource)) {
        html += `<tr style="background: #f1f5f9;"><td colspan="${rbacData.roles.length + 1}" style="padding: 12px 16px; font-weight: 600; color: #475569; text-transform: capitalize;">${resourceType.replace(/_/g, ' ')}</td></tr>`;

        for (const perm of perms) {
            html += `<tr style="border-bottom: 1px solid #f1f5f9;" onmouseover="this.style.background='#f8fafc'" onmouseout="this.style.background='white'">`;
            html += `<td style="padding: 12px 16px; color: #64748b; font-size: 14px;"><span style="color: #3b82f6; font-family: monospace; font-size: 13px;">${perm.name}</span><br><small style="color: #94a3b8;">${perm.description || ''}</small></td>`;

            for (const role of rbacData.roles) {
                // Check if role has this permission (permissions are stored as strings, not objects)
                const hasPermission = rbacData.rolePermissions[role.id]?.includes(perm.name);
                html += `<td style="padding: 12px; text-align: center;">${hasPermission ? '<span style="color: #10b981; font-size: 20px;">✓</span>' : '<span style="color: #e5e7eb;">—</span>'}</td>`;
            }

            html += '</tr>';
        }
    }

    html += '</tbody></table>';
    container.innerHTML = html;

    // Setup search
    setupPermissionSearch();
}

function setupPermissionSearch() {
    const searchInput = document.getElementById('permission-search');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#rbac-permissions-matrix tbody tr');

        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    });
}

// ==================== USER ASSIGNMENTS TAB ====================

function renderUserAssignments() {
    const container = document.getElementById('rbac-user-assignments');

    let html = '<div style="background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden;">';
    html += '<table style="width: 100%; border-collapse: collapse;">';

    // Header
    html += `
        <thead>
            <tr style="background: #f8fafc;">
                <th style="padding: 16px; text-align: left; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b;">User</th>
                <th style="padding: 16px; text-align: left; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b;">Role</th>
                <th style="padding: 16px; text-align: left; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b;">Permissions</th>
                <th style="padding: 16px; text-align: center; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b;">Status</th>
                <th style="padding: 16px; text-align: center; border-bottom: 2px solid #e1e8ed; font-weight: 600; color: #1e293b;">Actions</th>
            </tr>
        </thead>
        <tbody>
    `;

    for (const user of rbacData.users) {
        const role = rbacData.roles.find(r => r.name === user.role);
        const permissions = role ? rbacData.rolePermissions[role.id] || [] : [];
        const enabled = user.enabled !== undefined ? user.enabled : 1;

        html += `
            <tr style="border-bottom: 1px solid #f1f5f9;" onmouseover="this.style.background='#f8fafc'" onmouseout="this.style.background='white'">
                <td style="padding: 16px; color: #1e293b; font-weight: 500;">${user.username}</td>
                <td style="padding: 16px;">
                    <span style="background: #dbeafe; color: #1e40af; padding: 4px 12px; border-radius: 4px; font-size: 13px; font-weight: 600;">${role ? role.display_name : user.role}</span>
                </td>
                <td style="padding: 16px; color: #64748b; font-size: 14px;">${permissions.length} permissions</td>
                <td style="padding: 16px; text-align: center;">
                    ${enabled ?
                        '<span style="background: #d1fae5; color: #065f46; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600;">Active</span>' :
                        '<span style="background: #fee2e2; color: #991b1b; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600;">Disabled</span>'
                    }
                </td>
                <td style="padding: 16px; text-align: center;">
                    <button onclick="viewUserPermissions(${user.id})" style="background: #3b82f6; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600;">View Details</button>
                </td>
            </tr>
        `;
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

async function viewUserPermissions(userId) {
    const user = rbacData.users.find(u => u.id === userId);
    if (!user) return;

    // Fetch user's actual permissions from the API (handles both old and new role systems)
    let permissions = [];
    let role = null;

    try {
        const response = await fetch(`/api/v1/rbac/users/${userId}/permissions`);
        const data = await response.json();
        permissions = data.permissions || [];

        // Try to find the role in our cached data
        role = rbacData.roles.find(r => r.name === user.role);
    } catch (error) {
        
        // Fallback to cached data if API fails
        role = rbacData.roles.find(r => r.name === user.role);
        permissions = role ? rbacData.rolePermissions[role.id] || [] : [];
    }

    // Group permissions by domain
    const permissionsByDomain = {};
    for (const permName of permissions) {
        const parts = permName.split(':');
        const domain = parts[0] || 'general';

        if (!permissionsByDomain[domain]) {
            permissionsByDomain[domain] = [];
        }
        permissionsByDomain[domain].push(permName);
    }

    // Create modal
    const modal = document.createElement('div');
    modal.id = 'user-permissions-modal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;';

    modal.innerHTML = `
        <div style="background: white; border-radius: 12px; padding: 0; max-width: 700px; width: 90%; max-height: 85vh; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04);">
            <!-- Header -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 24px; border-bottom: 1px solid #e1e8ed; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <div>
                    <h3 style="margin: 0 0 4px 0; color: white; font-size: 20px;">User Permission Details</h3>
                    <p style="margin: 0; color: rgba(255,255,255,0.9); font-size: 14px;">${user.username}</p>
                </div>
                <button onclick="closeUserPermissionsModal()" style="background: rgba(255,255,255,0.2); border: none; width: 32px; height: 32px; border-radius: 6px; cursor: pointer; color: white; font-size: 20px; line-height: 1; transition: all 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.3)'" onmouseout="this.style.background='rgba(255,255,255,0.2)'">&times;</button>
            </div>

            <!-- User Info -->
            <div style="padding: 20px; background: #f8fafc; border-bottom: 1px solid #e1e8ed;">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                    <div>
                        <div style="font-size: 12px; color: #64748b; margin-bottom: 4px; font-weight: 600;">ROLE</div>
                        <div style="background: #dbeafe; color: #1e40af; padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: 600; display: inline-block;">${role ? role.display_name : user.role}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #64748b; margin-bottom: 4px; font-weight: 600;">STATUS</div>
                        ${(user.enabled !== undefined ? user.enabled : 1) ?
                            '<div style="background: #d1fae5; color: #065f46; padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: 600; display: inline-block;">Active</div>' :
                            '<div style="background: #fee2e2; color: #991b1b; padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: 600; display: inline-block;">Disabled</div>'
                        }
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #64748b; margin-bottom: 4px; font-weight: 600;">TOTAL PERMISSIONS</div>
                        <div style="color: #1e293b; font-size: 24px; font-weight: 700;">${permissions.length}</div>
                    </div>
                </div>
            </div>

            <!-- Permissions List -->
            <div style="padding: 20px; overflow-y: auto; max-height: calc(85vh - 280px);">
                <h4 style="margin: 0 0 16px 0; color: #1e293b; font-size: 16px;">Granted Permissions</h4>

                ${Object.keys(permissionsByDomain).length === 0 ?
                    '<div style="text-align: center; padding: 40px; color: #94a3b8;"><div style="font-size: 48px; margin-bottom: 16px;">🔒</div><p style="margin: 0;">No permissions assigned</p></div>' :
                    Object.entries(permissionsByDomain).map(([domain, perms]) => `
                        <div style="margin-bottom: 24px;">
                            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                                <div style="font-weight: 700; color: #475569; text-transform: capitalize; font-size: 14px;">${domain.replace(/_/g, ' ')}</div>
                                <div style="background: #e2e8f0; color: #475569; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">${perms.length}</div>
                            </div>
                            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                                ${perms.map(permName => {
                                    const permObj = rbacData.permissions.find(p => p.name === permName);
                                    return `
                                        <div style="background: #f1f5f9; border: 1px solid #e2e8f0; padding: 6px 12px; border-radius: 6px; font-size: 12px;" title="${permObj ? permObj.description : ''}">
                                            <span style="color: #3b82f6; font-family: monospace; font-weight: 600;">${permName}</span>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    `).join('')
                }
            </div>

            <!-- Footer -->
            <div style="padding: 16px 24px; border-top: 1px solid #e1e8ed; background: #f8fafc; display: flex; justify-content: flex-end;">
                <button onclick="closeUserPermissionsModal()" style="background: #3b82f6; color: white; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 14px; transition: all 0.2s;" onmouseover="this.style.background='#2563eb'" onmouseout="this.style.background='#3b82f6'">Close</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
}

function closeUserPermissionsModal() {
    const modal = document.getElementById('user-permissions-modal');
    if (modal) {
        modal.remove();
    }
}

// ==================== ENGAGEMENT ASSIGNMENTS TAB ====================

async function renderEngagementAssignments() {
    
    const container = document.getElementById('rbac-engagement-assignments-container');

    if (!container) {
        
        return;
    }

    // Show loading state
    container.innerHTML = '<div style="text-align: center; padding: 40px; color: #64748b;">Loading engagements...</div>';

    try {
        // Fetch engagements
        const engagementsResp = await fetch('/api/v1/engagements');
        const engagementsData = await engagementsResp.json();
        const engagements = engagementsData.engagements || [];

        

        if (engagements.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <div style="font-size: 48px; margin-bottom: 16px;">📋</div>
                    <h3 style="color: #475569; margin-bottom: 8px;">No Engagements Found</h3>
                    <p style="color: #94a3b8; margin: 0;">Create engagements first to manage user assignments</p>
                </div>
            `;
            return;
        }

        // Render engagement cards
        let html = '<div style="display: flex; flex-direction: column; gap: 16px;">';

        for (const engagement of engagements) {
            // Fetch users assigned to this engagement
            const assignmentsResp = await fetch(`/api/v1/rbac/engagements/${engagement.engagement_id}/users`);
            const assignmentsData = await assignmentsResp.json();
            const assignedUsers = assignmentsData.users || [];

            html += `
                <div class="engagement-assignment-card" style="background: white; border: 1px solid #e1e8ed; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 16px;">
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 8px 0; color: #1e293b; font-size: 16px;">${engagement.name || engagement.engagement_id}</h4>
                            <div style="display: flex; gap: 12px; font-size: 13px; color: #64748b;">
                                <span><strong>ID:</strong> ${engagement.engagement_id}</span>
                                <span><strong>Status:</strong> ${engagement.status || 'Active'}</span>
                                <span><strong>Assigned Users:</strong> ${assignedUsers.length}</span>
                            </div>
                        </div>
                        <button onclick="openAssignUserModal('${engagement.engagement_id}', '${(engagement.name || engagement.engagement_id).replace(/'/g, "\\'")}')"
                                style="background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s;"
                                onmouseover="this.style.background='#2563eb'" onmouseout="this.style.background='#3b82f6'">
                            + Assign User
                        </button>
                    </div>

                    ${assignedUsers.length > 0 ? `
                        <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #f1f5f9;">
                            <div style="font-size: 13px; font-weight: 600; color: #475569; margin-bottom: 12px;">Assigned Users:</div>
                            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                                ${assignedUsers.map(user => `
                                    <div style="display: inline-flex; align-items: center; gap: 8px; background: #f8fafc; border: 1px solid #e1e8ed; border-radius: 6px; padding: 6px 12px;">
                                        <span style="color: #1e293b; font-size: 13px; font-weight: 500;">${user.username}</span>
                                        <span style="color: #64748b; font-size: 12px;">(${user.role})</span>
                                        <button onclick="unassignUser('${engagement.engagement_id}', ${user.id}, '${user.username.replace(/'/g, "\\'")}')"
                                                style="background: #ef4444; color: white; border: none; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 11px; font-weight: 600;"
                                                title="Remove assignment">
                                            ×
                                        </button>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : `
                        <div style="margin-top: 16px; padding: 16px; background: #fef3c7; border: 1px solid #fde047; border-radius: 6px; text-align: center; color: #92400e; font-size: 13px;">
                            No users assigned to this engagement yet
                        </div>
                    `}
                </div>
            `;
        }

        html += '</div>';
        container.innerHTML = html;

    } catch (error) {
        
        container.innerHTML = `
            <div style="text-align: center; padding: 40px; background: #fee2e2; border: 1px solid #fecaca; border-radius: 8px; color: #991b1b;">
                <strong>Error loading engagements:</strong> ${error.message}
            </div>
        `;
    }
}

function openAssignUserModal(engagementId, engagementName) {
    

    // Get unassigned users
    const modal = document.createElement('div');
    modal.id = 'assign-user-modal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;';

    modal.innerHTML = `
        <div style="background: white; border-radius: 12px; padding: 24px; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h3 style="margin: 0; color: #1e293b; font-size: 18px;">Assign User to Engagement</h3>
                <button onclick="closeAssignUserModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #64748b; line-height: 1;">&times;</button>
            </div>

            <div style="background: #f8fafc; padding: 12px; border-radius: 6px; margin-bottom: 20px;">
                <strong>Engagement:</strong> ${engagementName}
            </div>

            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #475569; font-size: 14px;">Select User:</label>
                <select id="assign-user-select" style="width: 100%; padding: 10px; border: 1px solid #e1e8ed; border-radius: 6px; font-size: 14px;">
                    <option value="">Loading users...</option>
                </select>
            </div>

            <div style="display: flex; gap: 12px; justify-content: flex-end;">
                <button onclick="closeAssignUserModal()" style="background: #f1f5f9; color: #475569; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: 600;">Cancel</button>
                <button onclick="confirmAssignUser('${engagementId}')" style="background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: 600;">Assign User</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Populate user dropdown
    fetch('/api/v1/users')
        .then(resp => resp.json())
        .then(data => {
            const select = document.getElementById('assign-user-select');
            const users = data.users || [];

            // Filter to only engagement-viewer role users (or show all)
            select.innerHTML = '<option value="">-- Select a user --</option>' +
                users.map(user => `<option value="${user.id}">${user.username} (${user.role})</option>`).join('');
        })
        .catch(err => {
            
            document.getElementById('assign-user-select').innerHTML = '<option value="">Error loading users</option>';
        });
}

function closeAssignUserModal() {
    const modal = document.getElementById('assign-user-modal');
    if (modal) {
        modal.remove();
    }
}

async function confirmAssignUser(engagementId) {
    const select = document.getElementById('assign-user-select');
    const userId = select.value;

    if (!userId) {
        alert('Please select a user');
        return;
    }

    try {
        const response = await fetch(`/api/v1/rbac/engagements/${engagementId}/assign`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user_id: parseInt(userId) })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to assign user');
        }

        // Close modal and refresh
        closeAssignUserModal();
        renderEngagementAssignments();

        if (typeof showNotification === 'function') {
            showNotification('User assigned successfully', 'success');
        }
    } catch (error) {
        
        alert('Error: ' + error.message);
    }
}

async function unassignUser(engagementId, userId, username) {
    if (!confirm(`Remove ${username} from this engagement?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/v1/rbac/engagements/${engagementId}/unassign/${userId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to unassign user');
        }

        // Refresh
        renderEngagementAssignments();

        if (typeof showNotification === 'function') {
            showNotification('User unassigned successfully', 'success');
        }
    } catch (error) {
        
        alert('Error: ' + error.message);
    }
}

// ==================== UTILITY FUNCTIONS ====================

async function populateRoleDropdown(selectId = 'newUserRole', descContainerId = 'role-description', descTextId = 'role-description-text') {
    try {
        const select = document.getElementById(selectId);
        if (!select) return;

        const response = await fetch('/api/v1/rbac/roles');
        const data = await response.json();
        const roles = data.roles || [];

        select.innerHTML = '<option value="">-- Select Role --</option>';

        for (const role of roles) {
            const option = document.createElement('option');
            option.value = role.name;
            option.textContent = role.display_name;
            option.setAttribute('data-description', role.description || '');
            select.appendChild(option);
        }

        // Add change handler to show description (use onchange to replace existing handler)
        select.onchange = function(e) {
            const selectedOption = e.target.options[e.target.selectedIndex];
            const description = selectedOption.getAttribute('data-description');
            const descContainer = document.getElementById(descContainerId);
            const descText = document.getElementById(descTextId);

            if (descContainer && descText) {
                if (description && description.trim()) {
                    descText.textContent = description;
                    descContainer.style.display = 'block';
                } else {
                    descContainer.style.display = 'none';
                }
            }
        };

    } catch (error) {
        
    }
}

// ==================== EXPORTS ====================

window.initializeRBAC = initializeRBAC;
window.loadRBACData = loadRBACData;
window.switchRBACTab = switchRBACTab;
window.viewRoleDetails = viewRoleDetails;
window.viewUserPermissions = viewUserPermissions;
window.populateRoleDropdown = populateRoleDropdown;
