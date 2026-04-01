# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_policy_functions/rule_assessment.py
# Copied: 2026-04-01
# Used in: Phase 8 — Policy Engine
#
# When porting logic from this file:
#   - Rewrite using the new stack (FastAPI, asyncpg, python-pkcs11, httpx)
#   - Remove all Flask/SQLite/PyKCS11/requests dependencies
#   - Remove all caip_* naming conventions
#   - Fix any bare except: or except Exception: pass blocks
#   - Add proper async/await patterns
#   - Do not copy — port deliberately
# =============================================================================

"""
Modular Rule Assessment Engine

Implements standardized policy evaluation using a registry pattern.
Provides collector-agnostic rule evaluation for certificates, TLS endpoints, CRL, and keys.

Can coexist with existing assessment.py without modification.
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    """Result of evaluating a single rule"""
    rule_id: str
    rule_name: str
    triggered: bool
    severity: str
    risk_score: float
    title: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    compliance_impact: str = ""
    evaluation_time_ms: float = 0.0
    category: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'triggered': self.triggered,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'evidence': self.evidence,
            'compliance_impact': self.compliance_impact,
            'evaluation_time_ms': self.evaluation_time_ms,
            'category': self.category
        }


class RuleRegistry:
    """
    Manages assessment rules and their discovery.
    
    Loads policies in the new standardized format and provides
    methods to retrieve applicable rules for different collectors.
    """
    
    def __init__(self):
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.policy_metadata: Dict[str, Any] = {}
        self.policy_parameters: Dict[str, Any] = {}
        
    def load_policy(self, policy_dict: Dict[str, Any]) -> bool:
        """
        Load a policy in the standardized v2 format.

        Args:
            policy_dict: Policy dictionary with rules array

        Returns:
            True if successful, False otherwise
        """
        try:
            # DEBUG: Trace policy structure at entry point
            logger.info(f"[REGISTRY] load_policy() called with policy object: {type(policy_dict)}")
            logger.debug(f"[REGISTRY] Policy is None: {policy_dict is None}")

            if policy_dict is None:
                logger.error("[REGISTRY] Policy dict is None!")
                return False

            # DEBUG: Show top-level keys
            policy_keys = list(policy_dict.keys()) if isinstance(policy_dict, dict) else []
            logger.debug(f"[REGISTRY] Policy top-level keys: {policy_keys}")

            # Validate policy structure
            if 'version' not in policy_dict:
                logger.error("[REGISTRY] Policy missing 'version' field")
                return False

            if policy_dict.get('version') != '2.0':
                logger.warning(f"[REGISTRY] Policy version {policy_dict.get('version')} may not be fully compatible")

            # Store metadata and parameters
            self.policy_metadata = policy_dict.get('metadata', {})
            self.policy_parameters = policy_dict.get('parameters', {})

            logger.debug(f"[REGISTRY] Metadata keys: {list(self.policy_metadata.keys())}")
            logger.debug(f"[REGISTRY] Parameters count: {len(self.policy_parameters)}")

            # Load rules
            rules_list = policy_dict.get('rules', [])
            logger.debug(f"[REGISTRY] Rules list type: {type(rules_list)}, is None: {rules_list is None}")
            logger.info(f"[REGISTRY] Extracting rules from policy: {len(rules_list) if isinstance(rules_list, list) else 'NOT_A_LIST'} rules found")

            for rule in rules_list:
                rule_id = rule.get('rule_id')
                if not rule_id:
                    logger.warning("[REGISTRY] Rule missing 'rule_id', skipping")
                    continue

                self.rules[rule_id] = rule
                logger.debug(f"[REGISTRY] Loaded rule: {rule_id} ({rule.get('metadata', {}).get('name', 'unnamed')})")

            logger.info(f"[REGISTRY] Policy loaded successfully: {len(self.rules)} rules stored in registry")
            return True

        except Exception as e:
            logger.error(f"[REGISTRY] Failed to load policy: {e}", exc_info=True)
            return False
    
    def get_rules_for_collector(self, 
                               collector_type: str,
                               asset_type: str = None) -> List[Dict[str, Any]]:
        """
        Get applicable rules for a specific collector and asset type.
        
        Args:
            collector_type: Type of collector (tls, azure, ejbca, luna_hsm, crl, file_scan, or 'all')
            asset_type: Type of asset (certificate, key, tls_endpoint, crl, etc)
            
        Returns:
            List of applicable rules
        """
        applicable_rules = []
        
        for rule_id, rule in self.rules.items():
            if not rule.get('enabled', True):
                continue
                
            scope = rule.get('scope', {})
            rule_collector_types = scope.get('collector_types', [])
            rule_asset_types = scope.get('asset_types', [])
            
            # Check if this rule applies to the collector
            # Rule applies if:
            # 1. collector_type is 'all' and rule has 'all' in collector_types, OR
            # 2. collector_type matches exactly, OR  
            # 3. rule has 'all' in collector_types (applies to all collectors)
            collector_matches = (
                collector_type in rule_collector_types or 
                'all' in rule_collector_types
            )
            if not collector_matches:
                continue
                
            # Check if asset type matches (if specified)
            if asset_type and asset_type not in rule_asset_types:
                continue
                
            applicable_rules.append(rule)
        
        return applicable_rules
    
    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID"""
        return self.rules.get(rule_id)
    
    def list_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List all rules in the policy"""
        rules = list(self.rules.values())
        if enabled_only:
            rules = [r for r in rules if r.get('enabled', True)]
        return rules


class RuleEvaluator:
    """
    Evaluates rule conditions against assets.
    
    Supports three condition types:
    - Simple: Basic field comparisons (equals, in_list, less_than, etc)
    - Expression: Complex multi-condition logic
    - Temporal: Date-based conditions
    """
    
    COMPARISON_OPERATORS = {
        'equals': lambda a, b: a == b,
        'not_equals': lambda a, b: a != b,
        'in_list': lambda a, b: (a in b if isinstance(a, (str, int, float)) else any(item in b for item in a)) if isinstance(b, list) else a == b,
        'not_in_list': lambda a, b: a not in b if isinstance(b, list) else a != b,
        'less_than': lambda a, b: a < b,
        'less_than_or_equal': lambda a, b: a <= b,
        'greater_than': lambda a, b: a > b,
        'greater_than_or_equal': lambda a, b: a >= b,
        'contains': lambda a, b: b in a if isinstance(a, str) else False,
        'matches_regex': lambda a, b: bool(re.search(b, str(a))) if b else False,
    }
    
    def __init__(self, registry: RuleRegistry):
        """Initialize evaluator with a rule registry"""
        self.registry = registry
        self.custom_functions: Dict[str, callable] = {}
        self._register_custom_functions()
    
    def evaluate_rule(self, rule: Dict[str, Any], asset: Dict[str, Any]) -> RuleResult:
        """
        Evaluate a rule against an asset.
        
        Args:
            rule: Rule definition from policy
            asset: Asset object (certificate, TLS endpoint, etc)
            
        Returns:
            RuleResult indicating if rule triggered and findings
        """
        import time
        start_time = time.time()
        
        try:
            rule_id = rule.get('rule_id', 'unknown')
            rule_name = rule.get('metadata', {}).get('name', rule_id)
            
            # Evaluate condition
            condition_result = self._evaluate_condition(rule, asset)
            
            evaluation_time = (time.time() - start_time) * 1000
            
            if condition_result:
                # Rule triggered - generate finding
                return self._generate_finding(rule, asset, evaluation_time)
            else:
                # Rule did not trigger - return negative result
                return RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    triggered=False,
                    severity="none",
                    risk_score=0.0,
                    title="",
                    description="",
                    remediation="",
                    evaluation_time_ms=evaluation_time
                )
                
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.get('rule_id')}: {e}")
            return RuleResult(
                rule_id=rule.get('rule_id', 'unknown'),
                rule_name=rule.get('metadata', {}).get('name', 'unknown'),
                triggered=False,
                severity="error",
                risk_score=0.0,
                title="Evaluation Error",
                description=str(e),
                remediation="",
                evaluation_time_ms=0.0
            )
    
    def _evaluate_condition(self, rule: Dict[str, Any], asset: Dict[str, Any]) -> bool:
        """
        Evaluate the rule condition.
        
        Returns:
            True if condition is met (rule triggers), False otherwise
        """
        condition = rule.get('condition', {})
        condition_type = condition.get('type', 'simple')
        
        if condition_type == 'simple':
            return self._evaluate_simple_condition(condition, asset, rule)
        elif condition_type == 'expression':
            return self._evaluate_expression_condition(condition, asset, rule)
        elif condition_type == 'temporal':
            return self._evaluate_temporal_condition(condition, asset, rule)
        else:
            logger.warning(f"Unknown condition type: {condition_type}")
            return False
    
    def _convert_not_function_syntax(self, expression: str) -> str:
        """
        Convert NOT operator patterns to Python 'not' syntax.
        
        Handles patterns like:
        - NOT(field) -> not (field)         [function call syntax]
        - NOT field -> not field             [prefix operator]
        - NOT(field AND other) -> not (field and other)
        - NOT(some_function(args)) -> not some_function(args)
        """
        import re
        
        # Match NOT(...) function call patterns and convert to 'not (...)'
        expression = re.sub(r'\bNOT\s*\(', 'not (', expression)
        
        # Match NOT followed by whitespace and a word/identifier (prefix operator)
        # This handles "NOT field", "NOT(", etc.
        expression = re.sub(r'\bNOT\s+', 'not ', expression)
        
        return expression
    
    def _convert_matches_operator(self, expression: str) -> str:
        """
        Convert MATCHES operator to Python regex matching.
        
        Handles patterns like:
        - field MATCHES pattern -> allows_regex_match(field, pattern)
        
        Since we don't have the parameter values at this stage,
        we create a placeholder that will be resolved in the context.
        """
        import re
        
        # Find patterns like: field_name MATCHES parameter_or_pattern
        # Convert to: content_matches_any([parameter_or_pattern]) if it's a simple field
        # Or: re.search(pattern, field) for hardcoded patterns
        
        # Match: word/variable MATCHES word/variable/string
        def replace_matches(match):
            field = match.group(1).strip()
            pattern = match.group(2).strip()
            
            # If pattern is a parameter name (no quotes), use content_matches_any
            if not pattern.startswith('"') and not pattern.startswith("'"):
                # It's a parameter reference
                return f"content_matches_any([{pattern}])"
            else:
                # It's a quoted string, use re.search
                # Remove quotes and use the pattern directly
                pattern_clean = pattern.strip('"\'')
                return f"re.search(r'{pattern_clean}', str({field}))"
        
        # Replace MATCHES operators
        result = re.sub(r'(\w+)\s+MATCHES\s+([^\s,)]+)', replace_matches, expression)
        
        return result

    def _evaluate_simple_condition(self, condition: Dict[str, Any], asset: Dict[str, Any], rule: Dict[str, Any] = None) -> bool:
        """
        Evaluate a simple condition (field comparison).
        
        Condition structure:
        {
            "type": "simple",
            "asset_field": "field_name",
            "operator": "in_list",
            "values": [...] or "values_from_parameter": "param_name"
        }
        """
        asset_field = condition.get('asset_field')
        operator = condition.get('operator', 'equals')
        
        if not asset_field:
            logger.warning("Simple condition missing asset_field")
            return False
        
        # Get asset value
        asset_value = self._get_asset_field(asset, asset_field)
        if asset_value is None:
            logger.debug(f"Asset field not found: {asset_field}")
            return False
        
        # Get comparison values
        if 'values' in condition:
            comparison_values = condition['values']
        elif 'values_from_parameter' in condition:
            param_name = condition['values_from_parameter']
            # Try to get from rule parameters first, then policy parameters
            if rule and 'parameters' in rule:
                param_def = rule['parameters'].get(param_name, {})
                comparison_values = param_def.get('value')
            else:
                comparison_values = self.registry.policy_parameters.get(param_name, {}).get('value')
            
            if comparison_values is None:
                logger.warning(f"Parameter not found: {param_name}")
                return False
        else:
            comparison_values = condition.get('value')
        
        # Apply operator
        if operator not in self.COMPARISON_OPERATORS:
            logger.warning(f"Unknown operator: {operator}")
            return False
        
        try:
            result = self.COMPARISON_OPERATORS[operator](asset_value, comparison_values)
            return bool(result)
        except Exception as e:
            logger.error(f"Error applying operator {operator}: {e}")
            return False
    
    def _evaluate_expression_condition(self, 
                                      condition: Dict[str, Any],
                                      asset: Dict[str, Any],
                                      rule: Dict[str, Any]) -> bool:
        """
        Evaluate a complex expression condition.
        
        Supports basic Python expressions with custom functions.
        For security, this uses a restricted evaluation context.
        """
        expression = condition.get('expression', '')
        if not expression:
            return False
        
        try:
            # Convert policy-level expression language to Python
            python_expr = expression
            
            # Handle NOT() function call syntax: NOT(field) -> not field
            # This must be done before general NOT replacement
            python_expr = self._convert_not_function_syntax(python_expr)
            
            # Handle MATCHES operator: field MATCHES pattern -> use re.search or content_matches_any
            python_expr = self._convert_matches_operator(python_expr)
            
            # Replace common operators with Python equivalents
            # Order matters: do these after custom conversions
            python_expr = python_expr.replace(' AND ', ' and ')
            python_expr = python_expr.replace(' OR ', ' or ')
            python_expr = python_expr.replace(' NOT ', ' not ')  # Handle space-separated NOT (e.g., NOT field)
            python_expr = python_expr.replace(' IN ', ' in ')
            
            # Build evaluation context from asset
            # Keep all values including None - the variable needs to be defined
            context = dict(asset)
            
            # Create asset-aware custom functions with access to file_content
            asset_aware_functions = self._create_asset_aware_functions(asset)
            
            # Add custom functions
            context.update(asset_aware_functions)
            
            # Add policy-level parameters as variables (from policy definition)
            # These are global parameters like minimum_key_size, approved_curves, etc.
            for param_key, param_def in self.registry.policy_parameters.items():
                if isinstance(param_def, dict):
                    context[param_key] = param_def.get('value')
                else:
                    # Handle case where parameter is stored directly as value
                    context[param_key] = param_def
            
            # Add rule parameters as variables (from rule definition)
            # Rule-level parameters override policy-level parameters
            rule_params = rule.get('parameters', {})
            for param_key, param_def in rule_params.items():
                if isinstance(param_def, dict):
                    context[param_key] = param_def.get('value')
                else:
                    context[param_key] = param_def
            
            # Add re module to context for regex operations
            context['re'] = re
            
            # Log available context keys for debugging complex expressions
            #logger.debug(f"Expression evaluation context keys: {list(context.keys())}")
            
            # Simple evaluation (production should use restricted eval or CEL)
            # This is a safe subset without __builtins__
            result = eval(python_expr, {"__builtins__": {}}, context)
            return bool(result)
            
        except NameError as e:
            # Specific handling for undefined variable errors
            context_keys = sorted(list(context.keys())) if 'context' in dir() else []
            logger.error(f"Error evaluating expression '{expression}': {e}")
            logger.error(f"  Available context keys: {context_keys}")
            logger.error(f"  Rule: {rule.get('rule_id', 'unknown')}")
            return False
            
        except Exception as e:
            # Log more detail for debugging
            context_keys = sorted(list(context.keys())) if 'context' in dir() else []
            asset_keys = sorted(list(asset.keys())) if asset else []
            logger.error(f"Error evaluating expression '{expression}': {e}")
            logger.debug(f"  Asset keys available: {asset_keys}")
            logger.debug(f"  Context keys available: {context_keys}")
            return False
    
    def _evaluate_temporal_condition(self, condition: Dict[str, Any], asset: Dict[str, Any], rule: Dict[str, Any] = None) -> bool:
        """
        Evaluate a temporal (date-based) condition.
        
        Condition structure:
        {
            "type": "temporal",
            "date_field": "not_after",
            "operator": "expires_within_days",
            "days": 30,
            "days_from_parameter": "notification_expiration_days"  (optional)
        }
        """
        date_field = condition.get('date_field')
        operator = condition.get('operator')
        threshold_days = condition.get('days', 0)
        
        # Allow parameter reference for dynamic thresholds
        if 'days_from_parameter' in condition and rule:
            param_name = condition.get('days_from_parameter')
            rule_params = rule.get('parameters', {})
            if param_name in rule_params:
                threshold_days = rule_params[param_name].get('value', threshold_days)
        
        if not date_field or not operator:
            return False
        
        # Get date value from asset
        date_value = self._get_asset_field(asset, date_field)
        if not date_value:
            return False
        
        # Parse date if string
        if isinstance(date_value, str):
            try:
                date_value = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            except:
                try:
                    date_value = datetime.strptime(date_value, '%Y-%m-%d')
                except:
                    logger.warning(f"Could not parse date: {date_value}")
                    return False
        
        # Calculate days difference
        now = datetime.now(timezone.utc) if date_value.tzinfo else datetime.now()
        days_diff = (date_value - now).days
        
        # Apply operator
        if operator == 'expires_within_days':
            return days_diff <= threshold_days and days_diff >= 0
        elif operator == 'expired':
            return days_diff < 0
        elif operator == 'expires_after_days':
            return days_diff >= threshold_days
        else:
            logger.warning(f"Unknown temporal operator: {operator}")
            return False
    
    def _create_asset_aware_functions(self, asset: Dict[str, Any]) -> Dict[str, callable]:
        """
        Create asset-aware versions of custom functions that have access to the asset context.
        This is particularly important for content_matches_any which needs file_content.
        """
        def content_matches_any(patterns_list):
            """Check if file content matches any of the provided regex patterns"""
            if not patterns_list or not isinstance(patterns_list, list):
                return False
            
            # Get file content from asset context
            file_content = asset.get('file_content')
            if not file_content:
                return False
            
            try:
                for pattern in patterns_list:
                    if re.search(pattern, file_content, re.MULTILINE):
                        return True
                return False
            except Exception as e:
                logger.debug(f"Error in content_matches_any: {e}")
                return False
        
        # Return asset-aware versions of custom functions
        return {
            'content_matches_any': content_matches_any,
            'is_weak_hash': self.custom_functions['is_weak_hash'],
            'is_old_tls': self.custom_functions['is_old_tls'],
            'days_until': self.custom_functions['days_until'],
            'days_since': self.custom_functions['days_since'],
        }
    
    def _get_asset_field(self, asset: Dict[str, Any], field_path: str) -> Any:
        """
        Get a field value from asset, supporting nested paths.
        
        Examples:
            'subject_cn' -> asset['subject_cn']
            'certificate.subject_cn' -> asset['certificate']['subject_cn']
        """
        if not field_path:
            return None
        
        parts = field_path.split('.')
        value = asset
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value
    
    def _generate_finding(self, 
                         rule: Dict[str, Any],
                         asset: Dict[str, Any],
                         evaluation_time: float) -> RuleResult:
        """
        Generate a finding when rule condition is triggered.
        
        Interpolates template strings with asset and parameter values.
        """
        rule_id = rule.get('rule_id', 'unknown')
        rule_name = rule.get('metadata', {}).get('name', rule_id)
        
        findings_config = rule.get('findings', {}).get('if_triggered', {})
        
        # Get severity (can be static or dynamic)
        severity = findings_config.get('severity', 'medium')
        risk_score = float(findings_config.get('risk_score', 5.0))
        
        # Check for severity_rules (can be in findings.if_triggered or at rule root level)
        severity_rules = findings_config.get('severity_rules', []) or rule.get('severity_rules', [])
        
        # Apply dynamic severity if rules exist (auto-detect) or explicitly set to dynamic
        if severity_rules and (severity == 'dynamic' or rule.get('severity_rules')):
            severity, risk_score = self._apply_dynamic_severity(
                severity_rules,
                asset,
                rule
            )
        
        # Get title and description with interpolation
        title = findings_config.get('title', '')
        description = findings_config.get('description', '')
        remediation = findings_config.get('remediation', '')
        
        # Interpolate template variables
        interpolation_vars = self._build_interpolation_vars(asset, rule)
        title = self._interpolate_string(title, interpolation_vars)
        description = self._interpolate_string(description, interpolation_vars)
        remediation = self._interpolate_string(remediation, interpolation_vars)
        
        # Build evidence from specified fields
        evidence = {}
        for field in findings_config.get('evidence_fields', []):
            value = self._get_asset_field(asset, field)
            if value is not None:
                evidence[field] = value
        
        compliance_impact = findings_config.get('compliance_impact', '')
        
        # Extract category from rule metadata
        category = rule.get('metadata', {}).get('category', '')
        
        return RuleResult(
            rule_id=rule_id,
            rule_name=rule_name,
            triggered=True,
            severity=severity,
            risk_score=risk_score,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence,
            compliance_impact=compliance_impact,
            evaluation_time_ms=evaluation_time,
            category=category
        )
    
    def _apply_dynamic_severity(self,
                               severity_rules: List[Dict[str, Any]],
                               asset: Dict[str, Any],
                               rule: Dict[str, Any]) -> Tuple[str, float]:
        """
        Apply dynamic severity rules to determine final severity.
        
        Returns:
            Tuple of (severity_string, risk_score)
        """
        for sev_rule in severity_rules:
            condition = sev_rule.get('condition', '')
            if self._evaluate_expression_condition(
                {'type': 'expression', 'expression': condition},
                asset,
                rule
            ):
                return sev_rule.get('severity', 'medium'), float(sev_rule.get('risk_score', 5.0))
        
        # Default if no dynamic rules match
        return 'medium', 5.0
    
    def _build_interpolation_vars(self, asset: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build variable dictionary for template interpolation.
        
        Includes asset fields, rule parameters, and computed values.
        """
        vars_dict = dict(asset)
        
        # Add rule parameters
        for param_key, param_def in rule.get('parameters', {}).items():
            vars_dict[param_key] = param_def.get('value')
        
        # Add computed fields
        if 'not_after' in asset and 'not_before' in asset:
            try:
                not_after = asset['not_after']
                if isinstance(not_after, str):
                    not_after = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                
                now = datetime.now(timezone.utc) if not_after.tzinfo else datetime.now()
                days_until = (not_after - now).days
                vars_dict['days_until_expiration'] = max(0, days_until)
            except:
                pass
        
        return vars_dict
    
    def _interpolate_string(self, template: str, variables: Dict[str, Any]) -> str:
        """
        Interpolate template string with variables.
        
        Uses {variable_name} syntax.
        """
        if not template:
            return ""
        
        try:
            return template.format(**variables)
        except KeyError as e:
            logger.debug(f"Missing interpolation variable: {e}")
            return template
        except Exception as e:
            logger.error(f"Error interpolating string: {e}")
            return template
    
    def _register_custom_functions(self):
        """Register custom functions available in expressions"""
        
        def is_weak_hash(alg: str) -> bool:
            """Check if hash algorithm is weak"""
            weak_algs = ['MD5', 'SHA1', 'SHA224', 'RIPEMD160', 'MD2']
            return any(weak in str(alg).upper() for weak in weak_algs)
        
        def is_old_tls(protocol: str) -> bool:
            """Check if TLS version is old"""
            old_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1']
            return protocol in old_protocols
        
        def days_until(date_str: str) -> int:
            """Calculate days until a given date"""
            try:
                target_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc) if target_date.tzinfo else datetime.now()
                return (target_date - now).days
            except:
                return 0
        
        def days_since(date_str: str) -> int:
            """Calculate days since a given date"""
            try:
                past_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc) if past_date.tzinfo else datetime.now()
                return (now - past_date).days
            except:
                return 0
        
        def content_matches_any(patterns_list):
            """
            Check if file content matches any of the provided regex patterns.
            NOTE: This is a placeholder. The asset-aware version is created per-asset
            in _create_asset_aware_functions() to have access to file_content.
            """
            return False
        
        self.custom_functions = {
            'is_weak_hash': is_weak_hash,
            'is_old_tls': is_old_tls,
            'days_until': days_until,
            'days_since': days_since,
            'content_matches_any': content_matches_any,
        }

class UnifiedAssessor:
    """
    Main entry point for the unified rule assessment system.
    
    Provides a simple API for evaluating assets against policies
    using the new rule engine.
    """
    
    def __init__(self):
        self.registry = RuleRegistry()
        self.evaluator = RuleEvaluator(self.registry)
    
    def load_policy(self, policy: Dict[str, Any]) -> bool:
        """Load a policy (v2 format)"""
        logger.info(f"[ASSESSOR] load_policy() called with policy object: {type(policy)}")
        logger.debug(f"[ASSESSOR] Policy is None: {policy is None}")

        result = self.registry.load_policy(policy)

        logger.info(f"[ASSESSOR] load_policy() returned {result}, registry now has {len(self.registry.rules)} rules")
        return result
    
    def assess_certificate(self, cert: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate a certificate against applicable rules"""
        # Extract collector type from source field if available
        source = cert.get('source', '')
        collector_type = 'all'
        
        # Parse collector type from source string
        # Format: "TLS: host", "Azure Key Vault: ...", "EJBCA: ...", "Luna HSM: ...", "File: ...", etc.
        if source:
            if source.startswith('TLS'):
                collector_type = 'tls'
            elif 'Azure' in source or 'azure' in source:
                collector_type = 'azure'
            elif 'EJBCA' in source or 'ejbca' in source:
                collector_type = 'ejbca'
            elif 'Luna' in source or 'HSM' in source:
                collector_type = 'luna_hsm'
            elif 'File' in source or 'file' in source:
                collector_type = 'file_scan'
            else:
                collector_type = 'all'
        
        # Get rules for both the specific collector and 'all' rules
        rules = self.registry.get_rules_for_collector(collector_type, 'certificate')
        results = []
        
        for rule in rules:
            result = self.evaluator.evaluate_rule(rule, cert)
            results.append(result)
        
        return results
    
    def assess_tls_endpoint(self, tls_scan: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate a TLS endpoint against applicable rules"""
        rules = self.registry.get_rules_for_collector('tls', 'tls_endpoint')
        results = []
        
        for rule in rules:
            result = self.evaluator.evaluate_rule(rule, tls_scan)
            results.append(result)
        
        return results
    
    def assess_crl(self, crl: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate a CRL against applicable rules"""
        rules = self.registry.get_rules_for_collector('crl', 'crl')
        results = []
        
        for rule in rules:
            result = self.evaluator.evaluate_rule(rule, crl)
            results.append(result)
        
        return results
    
    def assess_key(self, key: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate a key against applicable rules"""
        # Extract collector type from source field if available
        source = key.get('source', '')
        collector_type = 'all'
        
        # Parse collector type from source string
        if source:
            if 'Azure' in source or 'azure' in source:
                collector_type = 'azure'
            elif 'Luna' in source or 'HSM' in source:
                collector_type = 'luna_hsm'
            elif 'File' in source or 'file' in source:
                collector_type = 'file_scan'
            else:
                collector_type = 'all'
        
        rules = self.registry.get_rules_for_collector(collector_type, 'key')
        results = []
        
        for rule in rules:
            result = self.evaluator.evaluate_rule(rule, key)
            results.append(result)
        
        return results
    
    def assess_file(self, file_info: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate a file scan result against applicable rules"""
        rules = self.registry.get_rules_for_collector('file_scan', 'file')
        results = []
        
        for rule in rules:
            result = self.evaluator.evaluate_rule(rule, file_info)
            results.append(result)
        
        return results
    
    def assess_batch(self, 
                        assets: List[Dict[str, Any]],
                        asset_type: str = 'certificate') -> Dict[str, List[RuleResult]]:
            """
            Evaluate multiple assets against applicable rules.
            
            Args:
                assets: List of asset dictionaries
                asset_type: Type of assets (certificate, key, tls_endpoint, crl, file)
                
            Returns:
                Dictionary mapping asset IDs to their rule evaluation results
            """
            results = {}
            
            for asset in assets:
                asset_id = asset.get('id') or asset.get('subject_cn') or asset.get('file_path') or str(hash(json.dumps(asset, default=str)))
                
                if asset_type == 'certificate':
                    results[asset_id] = self.assess_certificate(asset)
                elif asset_type == 'key':
                    results[asset_id] = self.assess_key(asset)
                elif asset_type == 'tls_endpoint':
                    results[asset_id] = self.assess_tls_endpoint(asset)
                elif asset_type == 'crl':
                    results[asset_id] = self.assess_crl(asset)
                elif asset_type == 'file':
                    results[asset_id] = self.assess_file(asset)
            
            return results

