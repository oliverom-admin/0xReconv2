/**
 * RBAC Initialization - Handles initialization when Settings > RBAC tab is accessed
 */

(function() {
    'use strict';

    let rbacInitialized = false;

    // Initialize RBAC when settings tab becomes active
    function initializeRBACIfNeeded() {
        

        const rbacTab = document.getElementById('settings-rbac');
        if (!rbacTab) {
            
            return;
        }

        // Check if RBAC tab is visible
        const isVisible = rbacTab.classList.contains('active') ||
                         getComputedStyle(rbacTab).display !== 'none';

        

        if (isVisible && !rbacInitialized) {
            
            if (typeof initializeRBAC === 'function') {
                initializeRBAC();
                rbacInitialized = true;
            } else {
                
            }
        }
    }

    // Watch for tab changes
    function setupTabObserver() {
        

        // Method 1: Observe Settings module visibility
        const settingsModule = document.getElementById('settings');
        if (settingsModule) {
            
            const observer = new MutationObserver(() => {
                initializeRBACIfNeeded();
            });

            observer.observe(settingsModule, {
                attributes: true,
                attributeFilter: ['class', 'style']
            });
        }

        // Method 2: Listen for clicks on RBAC tab button
        const rbacTabButton = document.querySelector('[data-tab="settings-rbac"]');
        if (rbacTabButton) {
            
            rbacTabButton.addEventListener('click', () => {
                
                setTimeout(initializeRBACIfNeeded, 100);
            });
        } else {
            
        }

        // Method 3: Listen for clicks on Settings module
        const settingsNavButton = document.querySelector('[data-module="settings"]');
        if (settingsNavButton) {
            
            settingsNavButton.addEventListener('click', () => {
                setTimeout(initializeRBACIfNeeded, 200);
            });
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupTabObserver);
    } else {
        setupTabObserver();
    }

})();
