# SPDX-License-Identifier: GPL-3.0-only ( contact authors for upgrade consent )
# Trust Analyzer - A service to evaluate the trustworthiness of a system
# using five trust evaluation categories: security, resilience, reliability,
# threat exposure, and intentions. Output is a trust score (0-100) and a
# behavior type (normal, suspicious, compromised).
#
# Copyright (c) 2026 Pasindu Kurupparachchi <pasindu.kurupparachchi@mtu.ie>, Nimbus Research Centre, Munster Technological University
#
# This work is partially supported by the Horizon Europe TELEMETRY project,
# funded by the European Commission under grant number 101119747, and by the
# Science Foundation Ireland Centre Advance CRT under grant number 18/CRT/6222.
#
# Trust analyzer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (subject to
# explicit consent) any later version.
#
# This tool is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE or SATISFACTORY QUALITY or PERFORMANCE,
# comply with any description or regulatory standard, or are safe, accurate,
# up to date or complete. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see [https://www.gnu.org/licenses/.](https://www.gnu.org/licenses/)

"""
services/rules_engine.py — Advanced rules evaluation engine.

Provides functions to evaluate rules and conditions against a JSON payload.
All functions are pure (no database access) and can be called from any router
or service.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Optional


def process_value(value: Any, processing_steps: List[Dict]) -> Any:
    """
    Processes a value through a series of transformations defined in processing_steps.

    Example processing_steps::

        [
            {"type": "substring", "separator": ",", "index": 0},
            {"type": "substring", "separator": ":", "index": 1}
        ]
    """
    if not processing_steps or not isinstance(processing_steps, list):
        return value

    current_value = value
    for step in processing_steps:
        try:
            if step.get("type") == "substring":
                separator = step.get("separator", ",")
                index = step.get("index", 0)
                if isinstance(current_value, str):
                    parts = current_value.split(separator)
                    if 0 <= index < len(parts):
                        current_value = parts[index].strip()
            elif step.get("type") == "json_key":
                key = step.get("key")
                if isinstance(current_value, dict) and key in current_value:
                    current_value = current_value[key]
        except Exception as e:
            print(f"Error processing value with step {step}: {e}")
            continue

    return current_value


def get_field_value(payload: dict, json_path: str) -> Any:
    """
    Extract value from payload using a dot-notation JSON path.

    If the path starts with ``payload.``, that prefix is stripped since
    ``payload`` is already the root object.

    Returns ``None`` if the path cannot be resolved.
    """
    if not json_path or not payload:
        print(f"[get_field_value] Early return: json_path={json_path}, payload exists={payload is not None}")
        return None

    if json_path.startswith("payload."):
        json_path = json_path[8:]  # strip 'payload.' prefix
        print(f"[get_field_value] Stripped 'payload.' prefix, using path: {json_path}")

    keys = json_path.split(".")
    value = payload
    print(f"[get_field_value] Starting extraction from path: {json_path}")
    print(f"[get_field_value] Payload keys: {list(payload.keys()) if isinstance(payload, dict) else 'not a dict'}")

    for i, key in enumerate(keys):
        print(f"[get_field_value] Step {i}: Looking for key '{key}' in type {type(value).__name__}")
        if isinstance(value, dict):
            if key in value:
                value = value.get(key)
                print(f"[get_field_value]   → Found '{key}', value={value}, type={type(value).__name__}")
            else:
                print(f"[get_field_value]   → Key '{key}' NOT FOUND. Available keys: {list(value.keys())}")
                return None
        elif isinstance(value, list):
            try:
                idx = int(key)
                if 0 <= idx < len(value):
                    value = value[idx]
                    print(f"[get_field_value]   → Found index {idx}, value={value}")
                else:
                    print(f"[get_field_value]   → Index {idx} out of range (list length={len(value)})")
                    return None
            except (ValueError, IndexError) as e:
                print(f"[get_field_value]   → Error accessing list with key '{key}': {e}")
                return None
        else:
            print(f"[get_field_value]   → Cannot traverse {type(value).__name__} with key '{key}'")
            return None

        if value is None:
            print(f"[get_field_value]   → Value became None at step {i}")
            return None

    print(f"[get_field_value] Final result: {value}")
    return value


def compare_values(actual: Any, operator: str, expected: Any, data_type: Optional[str]) -> bool:
    """Compare two values using the specified operator."""
    try:
        print(f"Comparing values: actual={actual} (type {data_type}), operator={operator}, expected={expected}")
        if operator == "equals":
            return actual == expected
        elif operator == "not_equals":
            return actual != expected
        elif operator == "contains":
            return str(expected) in str(actual)
        elif operator == "not_contains":
            return str(expected) not in str(actual)
        elif operator == "starts_with":
            return str(actual).startswith(str(expected))
        elif operator == "ends_with":
            return str(actual).endswith(str(expected))
        elif operator == "in_list":
            return actual in expected if isinstance(expected, list) else False
        elif operator == "not_in_list":
            return actual not in expected if isinstance(expected, list) else False
        elif operator == "matches_regex":
            try:
                return bool(re.search(str(expected), str(actual)))
            except Exception:
                return False
        elif operator == "gt":
            return float(actual) > float(expected)
        elif operator == "gte":
            return float(actual) >= float(expected)
        elif operator == "lt":
            return float(actual) < float(expected)
        elif operator == "lte":
            return float(actual) <= float(expected)
        elif operator == "between":
            if isinstance(expected, list) and len(expected) >= 2:
                return float(expected[0]) <= float(actual) <= float(expected[1])
            return False
        elif operator == "not_between":
            if isinstance(expected, list) and len(expected) >= 2:
                return not (float(expected[0]) <= float(actual) <= float(expected[1]))
            return False
        elif operator == "is_true":
            return bool(actual)
        elif operator == "is_false":
            return not bool(actual)
        else:
            return False
    except (ValueError, TypeError):
        return False


def evaluate_condition(payload: dict, condition: dict):
    """
    Evaluate a single condition against a payload.

    Returns:
        Tuple of (result: bool, extracted_value: any)
    """
    try:
        print("eval condition", condition)
        field_path = condition.get("field")
        field_data_type = "string"
        if isinstance(field_path, dict):
            field_data_type = field_path.get("data_type", "string")
            field_path = field_path.get("json_path")

        print(f"Extracting field value from path: {field_path} with data type: {field_data_type}")
        field_value = get_field_value(payload, field_path)
        print(f"Field value extracted: {field_value} (type {field_data_type})")

        if field_value is None:
            return False, None

        result = compare_values(
            field_value,
            condition["operator"],
            condition.get("expected_value"),
            field_data_type,
        )
        return result, field_value
    except Exception as e:
        print(f"Error evaluating condition: {e}")
        return False, None


def evaluate_condition_group(payload: dict, group: dict):
    """
    Evaluate a condition group (multiple conditions with AND/OR logic).

    Returns:
        Tuple of (result: bool, extracted_values: dict)
    """
    try:
        results = []
        extracted = {}
        print("eval condition group", group)
        for condition in group["conditions"]:
            result, value = evaluate_condition(payload, condition)
            results.append(result)
            if value is not None:
                field_path = condition.get("field")
                if isinstance(field_path, dict):
                    field_path = field_path.get("json_path", str(field_path))
                extracted[field_path] = value

        connector = group.get("connector", "AND").upper()
        final_result = all(results) if connector == "AND" else any(results)
        if not results:
            final_result = False
        return final_result, extracted
    except Exception as e:
        print(f"Error evaluating condition group: {e}")
        return False, {}


def evaluate_rule(payload: dict, rule: dict, mapping: Optional[dict] = None) -> dict:
    """
    Evaluate a complete rule against a payload.

    Logic:
    1. Primary field must match (required).
    2. If no secondary conditions: rule matches if primary matches.
    3. If secondary conditions exist: combine them with *within_rule_connector*.
    4. Final result: primary_matches AND (secondary_conditions result).

    If *mapping* is provided and ``mapping.value_processing_required`` is True,
    the extracted primary field value is processed through
    ``mapping.value_processing_steps`` before comparison.

    Returns a dict with keys: ``matched``, ``matched_groups``,
    ``extracted_values``, ``impact_level``.
    """
    try:
        print(f"Evaluating rule: {rule.get('name', 'Unknown')}")
        primary_field_path = rule.get("primary_field_path")
        primary_value = rule.get("primary_value")

        if not primary_field_path or primary_value is None:
            return {"matched": False, "matched_groups": [], "extracted_values": {}, "impact_level": None}

        primary_field_actual = get_field_value(payload, primary_field_path)
        print(f"Primary field {primary_field_path}: expected='{primary_value}', actual='{primary_field_actual}'")

        if (
            mapping
            and mapping.get("value_processing_required")
            and mapping.get("value_processing_steps")
            and primary_field_actual is not None
        ):
            processed = process_value(primary_field_actual, mapping.get("value_processing_steps"))
            print(f"[ValueProcessing] Primary field '{primary_field_path}': raw='{primary_field_actual}' → processed='{processed}'")
            primary_field_actual = processed

        primary_matches = str(primary_field_actual) == str(primary_value)
        print(f"Primary field matches: {primary_matches}")

        all_extracted = {primary_field_path: primary_field_actual}
        matched_groups = []

        if not primary_matches:
            return {"matched": False, "matched_groups": [], "extracted_values": all_extracted, "impact_level": None}

        matched_groups.append({
            "field_path": primary_field_path,
            "operator": "equals",
            "expected_value": primary_value,
            "actual_value": primary_field_actual,
        })

        secondary_conditions = rule.get("secondary_conditions", [])
        if not secondary_conditions:
            return {
                "matched": True,
                "matched_groups": matched_groups,
                "extracted_values": all_extracted,
                "impact_level": rule.get("impact_level", "medium"),
            }

        condition_results = []
        secondary_matched_groups = []

        for condition in secondary_conditions:
            secondary_field_path = condition.get("secondary_field")
            operator = condition.get("operator")
            expected_value = condition.get("secondary_value")
            secondary_value = get_field_value(payload, secondary_field_path)
            print(f"Evaluating: {secondary_field_path} {operator} {expected_value} (actual: {secondary_value})")
            result = compare_values(secondary_value, operator, expected_value, None)
            condition_results.append(result)
            all_extracted[secondary_field_path] = secondary_value
            if result:
                secondary_matched_groups.append({
                    "field_path": secondary_field_path,
                    "operator": operator,
                    "expected_value": expected_value,
                    "actual_value": secondary_value,
                })

        within_rule_connector = rule.get("within_rule_connector", "AND").upper()
        secondary_result = (
            all(condition_results) if within_rule_connector == "AND" else any(condition_results)
        )
        if not condition_results:
            secondary_result = False

        final_result = primary_matches and secondary_result

        if secondary_result:
            matched_groups.extend(secondary_matched_groups)

        return {
            "matched": final_result,
            "matched_groups": matched_groups if final_result else [],
            "extracted_values": all_extracted,
            "impact_level": rule.get("impact_level", "medium") if final_result else None,
        }
    except Exception as e:
        import traceback
        print(f"Error evaluating rule: {e}")
        traceback.print_exc()
        return {"matched": False, "matched_groups": [], "extracted_values": {}, "impact_level": None}


def evaluate_all_rules(
    payload: dict,
    rules: List[dict],
    between_rules_connector: str = "AND",
    mapping: Optional[dict] = None,
) -> dict:
    """
    Evaluate all rules against a payload with hierarchical connector logic.

    Two-level connector architecture:

    1. **WITHIN-RULE**: Primary field + secondary conditions combined with
       ``within_rule_connector``.
    2. **BETWEEN-RULE**: Multiple rule outcomes combined with
       ``between_rules_connector``.

    Returns a dict with keys: ``overall_result``, ``matched_rules``,
    ``rule_count``, ``matched_count``, ``evaluations``, ``impact_level``.
    """
    try:
        print(f"\n--- EVALUATING {len(rules or [])} RULES ---")
        print(f"Between-rules connector: {between_rules_connector}")

        if not rules:
            return {
                "overall_result": False,
                "matched_rules": [],
                "rule_count": 0,
                "matched_count": 0,
                "evaluations": [],
                "impact_level": None,
            }

        rule_results = []
        matched_rules = []
        all_matched_details = []
        impact_levels = []

        for i, rule in enumerate(rules):
            rule_name = rule.get("name", f"Rule {i}")
            print(f"\n--- Evaluating rule {i+1}/{len(rules)}: {rule_name} ---")
            result = evaluate_rule(payload, rule, mapping=mapping)
            rule_results.append(result["matched"])

            rule_detail = {
                "rule_index": i,
                "rule_name": rule_name,
                "matched": result["matched"],
                "matched_groups": result["matched_groups"],
                "extracted_values": result["extracted_values"],
                "impact_level": result["impact_level"],
            }
            all_matched_details.append(rule_detail)

            if result["matched"]:
                matched_rules.append(rule_name)
                if result["impact_level"]:
                    impact_levels.append(result["impact_level"].lower())

        connector = between_rules_connector.upper()
        overall_result = (
            all(rule_results) if connector == "AND" else any(rule_results)
        )
        if not rule_results:
            overall_result = False

        highest_impact = None
        if impact_levels:
            if "high" in impact_levels:
                highest_impact = "high"
            elif "medium" in impact_levels:
                highest_impact = "medium"
            elif "low" in impact_levels:
                highest_impact = "low"

        return {
            "overall_result": overall_result,
            "matched_rules": matched_rules,
            "rule_count": len(rules),
            "matched_count": len(matched_rules),
            "evaluations": all_matched_details,
            "impact_level": highest_impact,
        }
    except Exception as e:
        import traceback
        print(f"Error evaluating all rules: {e}")
        traceback.print_exc()
        return {
            "overall_result": False,
            "matched_rules": [],
            "rule_count": len(rules) if rules else 0,
            "matched_count": 0,
            "evaluations": [],
            "impact_level": None,
        }
