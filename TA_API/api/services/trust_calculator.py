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
services/trust_calculator.py — Trust score and behaviour calculation.

Functions here require database access and use the shared collection handles
from ``database.py``.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

from database import (
    TRUST_CONFIG_STEP1_COLLECTION,
    TRUST_CONFIG_STEP2_COLLECTION,
    TRUST_CONFIG_STEP3_COLLECTION,
    TRUST_CONFIG_STEP4_COLLECTION,
    TOOL_CONFIG_STEP5_COLLECTION,
    TRUST_SCORE_WEIGHTS_COLLECTION,
    TOOL_MANUAL_IMPACTS_COLLECTION,
    MAPPED_COLLECTION,
    db,
)
from services import get_by_path
from services.rules_engine import process_value, evaluate_all_rules

_DEFAULT_WEIGHTS = {
    "category_weights": {
        "Security": 20,
        "Reliability": 20,
        "Resilience": 20,
        "Threat Exposure": 20,
        "Intentions": 20,
    },
    "behaviour_weights": {"normal": 100, "suspicious": 50, "compromised": 0},
}


def _load_weights() -> dict:
    return TRUST_SCORE_WEIGHTS_COLLECTION.find_one({}) or _DEFAULT_WEIGHTS


def calculate_trust_score_and_behaviour(
    tool: dict,
    payload: dict,
    submitted_rules: Optional[List[Dict[str, Any]]] = None,
    between_rules_connector: str = "AND",
    is_new_submission: bool = True,
) -> dict:
    """
    Calculate trust score and behaviour for a single tool/payload pair.

    Returns a dict with keys: ``tool_name``, ``trust_evaluation_category``,
    ``unique_id_value``, ``value``, ``count``, ``impact``, ``behaviour``,
    ``category_behaviour``, ``system_behaviour``, ``trust_score``,
    ``max_score``, ``percent``.
    """
    step1 = list(TRUST_CONFIG_STEP1_COLLECTION.find({}))
    step2 = list(TRUST_CONFIG_STEP2_COLLECTION.find({}))
    step3 = list(TRUST_CONFIG_STEP3_COLLECTION.find({}))
    step4 = TRUST_CONFIG_STEP4_COLLECTION.find_one({}) or {}
    weights = _load_weights()

    cat = (tool.get("trust_evaluation_category") or "Uncategorized").strip()
    cat_key = cat.lower()
    tool_name = tool.get("tool_name")
    key = f"{tool_name}|||{cat_key}"

    step1_map = {f"{c.get('tool_name')}|||{(c.get('trust_evaluation_category') or 'Uncategorized').strip().lower()}": c for c in step1}
    step2_map = {f"{c.get('tool_name')}|||{(c.get('trust_evaluation_category') or 'Uncategorized').strip().lower()}": c for c in step2}
    step3_map = {(c.get("trust_evaluation_category") or "Uncategorized").strip().lower(): c for c in step3}

    value_path = tool.get("value_path")
    value = get_by_path(payload, value_path) if value_path else None
    if tool.get("value_processing_required") and tool.get("value_processing_steps"):
        value = process_value(value, tool.get("value_processing_steps"))

    rule_evaluation_result = None
    rules_to_evaluate = submitted_rules if submitted_rules else tool.get("advanced_rules")
    between_connector = between_rules_connector if submitted_rules else tool.get("between_rules_connector", "AND")
    if rules_to_evaluate:
        rule_evaluation_result = evaluate_all_rules(payload, rules_to_evaluate, between_connector, mapping=tool)

    count = tool.get("count", 1)
    impact = "Mid"
    step1_cfg = step1_map.get(key, {})
    step2_cfg = step2_map.get(key, {})

    # Priority 0: manual override (only when no new submission this cycle)
    manual_override_applied = False
    if not is_new_submission:
        manual_override = TOOL_MANUAL_IMPACTS_COLLECTION.find_one({"tool_name": tool_name, "category": cat})
        if manual_override and manual_override.get("impact"):
            raw = manual_override["impact"].strip().capitalize()
            if raw in ("Low", "Mid", "High"):
                impact = raw
                manual_override_applied = True

    if not manual_override_applied:
        if rule_evaluation_result and rule_evaluation_result.get("overall_result") and rule_evaluation_result.get("impact_level"):
            rule_impact = rule_evaluation_result["impact_level"]
            impact = {"low": "Low", "medium": "Mid", "high": "High"}.get(rule_impact, "Mid")
        else:
            if step2_cfg.get("override_active") == "true" and count >= int(step2_cfg.get("override_count", "0")):
                impact = step2_cfg.get("override_impact", "Mid")
            else:
                data_type = tool.get("data_type")
                if data_type == "binary":
                    impact = step1_cfg.get(f"{tool_name}_{cat_key}_on" if value == "ON" else f"{tool_name}_{cat_key}_off", "Mid")
                elif data_type == "categorical":
                    impact = step1_cfg.get(f"{tool_name}_{cat_key}_{value}", "Mid")
                elif data_type == "continuous":
                    val = float(value or tool.get("min_value", 0))
                    lower = float(step1_cfg.get(f"{tool_name}_{cat_key}_slider_lower", tool.get("min_value", 0)))
                    upper = float(step1_cfg.get(f"{tool_name}_{cat_key}_slider_upper", tool.get("max_value", 100)))
                    impact = "Low" if val <= lower else ("Mid" if val <= upper else "High")

    # Tool behaviour
    behaviour = "suspicious"
    if step2_cfg.get("override_active") == "true" and count >= int(step2_cfg.get("override_count", "0")):
        behaviour = step2_cfg.get("override_behaviour", "suspicious")
    else:
        behaviour = {"Low": "normal", "Mid": "suspicious", "High": "compromised"}.get(impact, "suspicious")

    # Category behaviour
    step3_cfg = step3_map.get(cat_key, {})
    mapped_tools = list(MAPPED_COLLECTION.find({"trust_evaluation_category": cat}))
    tool_behaviours = []
    for t in mapped_tools:
        if t.get("tool_name") == tool_name:
            tool_behaviours.append(behaviour)
        else:
            last = db["tool_behaviour_results"].find_one({"tool_name": t.get("tool_name"), "trust_evaluation_category": cat})
            tool_behaviours.append(last["behaviour"] if last else "suspicious")

    final_cat_behaviour = _majority_behaviour(tool_behaviours, step3_cfg)

    # System behaviour
    all_cat_behaviours = []
    for c_cfg in TRUST_CONFIG_STEP3_COLLECTION.find({}):
        cat_name = c_cfg.get("trust_evaluation_category")
        last_cat = db["category_behaviour_results"].find_one({"trust_evaluation_category": {"$regex": f"^{cat_name}$", "$options": "i"}})
        b = last_cat["behaviour"] if last_cat else "suspicious"
        if cat_name.strip().lower() == cat.strip().lower():
            b = final_cat_behaviour
        all_cat_behaviours.append(b)

    system_behaviour = _majority_behaviour(all_cat_behaviours, step4)

    # Trust score
    behaviour_weights = weights.get("behaviour_weights", {"normal": 100, "suspicious": 50, "compromised": 0})
    cat_weights = weights.get("category_weights", {})
    cat_weight = cat_weights.get(cat, 20)
    beh_weight = behaviour_weights.get(behaviour, 100)
    max_beh_weight = max(behaviour_weights.values())
    max_score = max_beh_weight * cat_weight
    real_score = beh_weight * cat_weight
    percent = (real_score / max_score) * 100 if max_score > 0 else 0

    return {
        "tool_name": tool_name,
        "trust_evaluation_category": cat,
        "unique_id_value": get_by_path(payload, tool.get("unique_id_path", "")),
        "value": value,
        "count": count,
        "impact": impact,
        "behaviour": behaviour,
        "category_behaviour": final_cat_behaviour,
        "system_behaviour": system_behaviour,
        "trust_score": real_score,
        "max_score": max_score,
        "percent": percent,
    }


def calculate_trust_score_and_behaviour_with_steps(
    tool: dict,
    payload: dict,
    submitted_rules: Optional[List[Dict[str, Any]]] = None,
    between_rules_connector: str = "AND",
    is_new_submission: bool = True,
) -> dict:
    """
    Enhanced version of :func:`calculate_trust_score_and_behaviour` that also
    captures detailed step-by-step information for audit/display purposes.

    Returns the standard result dict plus ``behavior_determination_steps`` and
    ``trust_score_calculation_steps``.
    """
    step1 = list(TRUST_CONFIG_STEP1_COLLECTION.find({}))
    step2 = list(TRUST_CONFIG_STEP2_COLLECTION.find({}))
    step3 = list(TRUST_CONFIG_STEP3_COLLECTION.find({}))
    step4 = TRUST_CONFIG_STEP4_COLLECTION.find_one({}) or {}
    weights = _load_weights()

    cat = (tool.get("trust_evaluation_category") or "Uncategorized").strip()
    cat_key = cat.lower()
    tool_name = tool.get("tool_name")
    key = f"{tool_name}|||{cat_key}"

    step1_map = {f"{c.get('tool_name')}|||{(c.get('trust_evaluation_category') or 'Uncategorized').strip().lower()}": c for c in step1}
    step2_map = {f"{c.get('tool_name')}|||{(c.get('trust_evaluation_category') or 'Uncategorized').strip().lower()}": c for c in step2}
    step3_map = {(c.get("trust_evaluation_category") or "Uncategorized").strip().lower(): c for c in step3}

    value_path = tool.get("value_path")
    value = get_by_path(payload, value_path) if value_path else None
    if tool.get("value_processing_required") and tool.get("value_processing_steps"):
        value = process_value(value, tool.get("value_processing_steps"))

    rule_evaluation_result = None
    rules_to_evaluate = submitted_rules if submitted_rules else tool.get("advanced_rules")
    between_connector = between_rules_connector if submitted_rules else tool.get("between_rules_connector", "AND")
    if rules_to_evaluate:
        rule_evaluation_result = evaluate_all_rules(payload, rules_to_evaluate, between_connector, mapping=tool)

    count = tool.get("count", 1)
    behavior_steps = []
    impact = "Mid"
    step1_cfg = step1_map.get(key, {})
    step2_cfg = step2_map.get(key, {})

    step1_info = {
        "step": 1,
        "name": "Tool Impact Categorization",
        "description": "Determine impact level based on tool value and configuration",
        "input": {"value": value, "count": count, "data_type": tool.get("data_type")},
        "logic": "Uses Step 2 override or Step 1 rules based on count and value",
        "result": None,
    }

    _manual_applied = False
    if not is_new_submission:
        manual_doc = TOOL_MANUAL_IMPACTS_COLLECTION.find_one({"tool_name": tool_name, "category": cat})
        if manual_doc and manual_doc.get("impact"):
            raw = manual_doc["impact"].strip().capitalize()
            if raw in ("Low", "Mid", "High"):
                impact = raw
                step1_info["logic"] = f"No new submission — manual override: {impact} (reason: {manual_doc.get('reason', 'N/A')})"
                step1_info["result"] = impact
                behavior_steps.append(step1_info)
                _manual_applied = True

    if not _manual_applied:
        if tool.get("evaluation_mode") == "advanced" and rule_evaluation_result:
            if rule_evaluation_result.get("overall_result") and rule_evaluation_result.get("impact_level"):
                rule_impact = rule_evaluation_result["impact_level"]
                impact = {"low": "Low", "medium": "Mid", "high": "High"}.get(rule_impact, "Mid")
                rule_source = "submitted rules" if submitted_rules else "configured rules"
                step1_info["logic"] = f"Advanced rules matched ({rule_source}) with impact: {impact}"
                step1_info["result"] = impact
            else:
                impact, step1_info = _step1_from_config(impact, step1_info, step2_cfg, step1_cfg, tool_name, cat_key, count, value, tool)
        else:
            impact, step1_info = _step1_from_config(impact, step1_info, step2_cfg, step1_cfg, tool_name, cat_key, count, value, tool)
        behavior_steps.append(step1_info)

    # Step 2: Tool behaviour
    behaviour = "suspicious"
    step2_info = {
        "step": 2, "name": "Tool Behavior Determination",
        "description": "Determine tool behavior from impact level",
        "input": {"impact": impact}, "logic": None, "result": None,
    }
    if step2_cfg.get("override_active") == "true" and count >= int(step2_cfg.get("override_count", "0")):
        behaviour = step2_cfg.get("override_behaviour", "suspicious")
        step2_info["logic"] = f"Override active: {behaviour}"
    else:
        behaviour = {"Low": "normal", "Mid": "suspicious", "High": "compromised"}.get(impact, "suspicious")
        step2_info["logic"] = f"Impact {impact} → {behaviour}"
    step2_info["result"] = behaviour
    behavior_steps.append(step2_info)

    # Step 3: Category behaviour
    step3_cfg = step3_map.get(cat_key, {})
    mapped_tools = list(MAPPED_COLLECTION.find({"trust_evaluation_category": cat}))
    tool_behaviours = []
    for t in mapped_tools:
        if t.get("tool_name") == tool_name:
            tool_behaviours.append(behaviour)
        else:
            last = db["tool_behaviour_results"].find_one({"tool_name": t.get("tool_name"), "trust_evaluation_category": cat})
            tool_behaviours.append(last["behaviour"] if last else "suspicious")

    final_cat_behaviour, step3_info = _step3_with_info(tool_behaviours, step3_cfg)
    behavior_steps.append(step3_info)

    # Step 4: System behaviour
    all_cat_behaviours = []
    for c_cfg in TRUST_CONFIG_STEP3_COLLECTION.find({}):
        cat_name = c_cfg.get("trust_evaluation_category")
        last_cat = db["category_behaviour_results"].find_one({"trust_evaluation_category": {"$regex": f"^{cat_name}$", "$options": "i"}})
        b = last_cat["behaviour"] if last_cat else "suspicious"
        if cat_name.strip().lower() == cat.strip().lower():
            b = final_cat_behaviour
        all_cat_behaviours.append(b)

    system_behaviour, step4_info = _step4_with_info(all_cat_behaviours, step4)
    behavior_steps.append(step4_info)

    # Step 5: Trust score
    behaviour_weights = weights.get("behaviour_weights", {"normal": 100, "suspicious": 50, "compromised": 0})
    cat_weights = weights.get("category_weights", {})
    cat_weight = cat_weights.get(cat, 20)
    beh_weight = behaviour_weights.get(behaviour, 100)
    max_beh_weight = max(behaviour_weights.values())
    max_score = max_beh_weight * cat_weight
    real_score = beh_weight * cat_weight
    percent = (real_score / max_score) * 100 if max_score > 0 else 0

    score_steps = [
        {"step": 1, "name": "Get Category Weight", "description": f'Lookup weight for category "{cat}"', "formula": f"cat_weight = weights['category_weights']['{cat}']", "input": {"category": cat}, "result": cat_weight},
        {"step": 2, "name": "Get Behavior Weight", "description": f'Lookup weight for behavior "{behaviour}"', "formula": f"beh_weight = weights['behaviour_weights']['{behaviour}']", "input": {"behavior": behaviour}, "result": beh_weight},
        {"step": 3, "name": "Calculate Maximum Score", "description": "max_score = max_behavior_weight × category_weight", "formula": f"max_score = {max_beh_weight} × {cat_weight}", "input": {"max_behavior_weight": max_beh_weight, "category_weight": cat_weight}, "result": max_score},
        {"step": 4, "name": "Calculate Actual Score", "description": "real_score = behavior_weight × category_weight", "formula": f"real_score = {beh_weight} × {cat_weight}", "input": {"behavior_weight": beh_weight, "category_weight": cat_weight}, "result": real_score},
        {"step": 5, "name": "Calculate Percentage", "description": "percent = (actual_score / max_score) × 100", "formula": f"percent = ({real_score} / {max_score}) × 100", "input": {"actual_score": real_score, "max_score": max_score}, "result": percent},
    ]

    return {
        "tool_name": tool_name,
        "trust_evaluation_category": cat,
        "unique_id_value": get_by_path(payload, tool.get("unique_id_path", "")),
        "value": value,
        "count": count,
        "impact": impact,
        "behaviour": behaviour,
        "category_behaviour": final_cat_behaviour,
        "system_behaviour": system_behaviour,
        "trust_score": real_score,
        "max_score": max_score,
        "percent": percent,
        "behavior_determination_steps": behavior_steps,
        "trust_score_calculation_steps": score_steps,
    }


# ── Private helpers ──────────────────────────────────────────────────────────

def _majority_behaviour(behaviours: list, cfg: dict) -> str:
    """Return the majority behaviour from a list, respecting override config."""
    if cfg.get("override_active") == "true":
        count_override = int(cfg.get("override_count", "0"))
        target = cfg.get("override_behaviour") or cfg.get("final_behaviour", "suspicious")
        trigger_beh = cfg.get("tool_behaviour") or cfg.get("override_behaviour", "suspicious")
        num = behaviours.count(trigger_beh)
        if num >= count_override:
            return target
    counts = {b: behaviours.count(b) for b in ["normal", "suspicious", "compromised"]}
    max_count = max(counts.values()) if counts else 0
    max_behs = [k for k, v in counts.items() if v == max_count]
    return max_behs[0] if len(max_behs) == 1 else "suspicious"


def _step1_from_config(impact, step1_info, step2_cfg, step1_cfg, tool_name, cat_key, count, value, tool):
    if step2_cfg.get("override_active") == "true" and count >= int(step2_cfg.get("override_count", "0")):
        impact = step2_cfg.get("override_impact", "Mid")
        step1_info["logic"] = f"Step 2 override active (count {count} >= {step2_cfg.get('override_count', '0')})"
    else:
        data_type = tool.get("data_type")
        if data_type == "binary":
            impact = step1_cfg.get(f"{tool_name}_{cat_key}_on" if value == "ON" else f"{tool_name}_{cat_key}_off", "Mid")
        elif data_type == "categorical":
            impact = step1_cfg.get(f"{tool_name}_{cat_key}_{value}", "Mid")
        elif data_type == "continuous":
            val = float(value or tool.get("min_value", 0))
            lower = float(step1_cfg.get(f"{tool_name}_{cat_key}_slider_lower", tool.get("min_value", 0)))
            upper = float(step1_cfg.get(f"{tool_name}_{cat_key}_slider_upper", tool.get("max_value", 100)))
            impact = "Low" if val <= lower else ("Mid" if val <= upper else "High")
            step1_info["logic"] = f"Continuous value {val}: Low if ≤{lower}, Mid if ≤{upper}, else High"
    step1_info["result"] = impact
    return impact, step1_info


def _step3_with_info(tool_behaviours, step3_cfg):
    step3_info = {"step": 3, "name": "Category Behavior Determination", "description": "Aggregate tool behaviors to determine category behavior", "input": {"tool_behaviors": tool_behaviours}, "logic": None, "result": None}
    if step3_cfg.get("override_active") == "true":
        count_override = int(step3_cfg.get("override_count", "0"))
        target = step3_cfg.get("override_behaviour", "suspicious")
        tool_behaviour = step3_cfg.get("tool_behaviour", "suspicious")
        num = sum(1 for b in tool_behaviours if b == tool_behaviour)
        if num >= count_override:
            final_cat_behaviour = target
            step3_info["logic"] = f"Override: {num} tools with {tool_behaviour} >= threshold {count_override}, result: {target}"
        else:
            counts = {b: tool_behaviours.count(b) for b in ["normal", "suspicious", "compromised"]}
            max_count = max(counts.values())
            max_behs = [k for k, v in counts.items() if v == max_count]
            final_cat_behaviour = max_behs[0] if len(max_behs) == 1 else "suspicious"
            step3_info["logic"] = f"Override inactive, counts: {counts}, selected: {final_cat_behaviour}"
    else:
        counts = {b: tool_behaviours.count(b) for b in ["normal", "suspicious", "compromised"]}
        max_count = max(counts.values()) if counts else 0
        max_behs = [k for k, v in counts.items() if v == max_count]
        final_cat_behaviour = max_behs[0] if len(max_behs) == 1 else "suspicious"
        step3_info["logic"] = f"Counts: {counts}, selected: {final_cat_behaviour}"
    step3_info["result"] = final_cat_behaviour
    return final_cat_behaviour, step3_info


def _step4_with_info(all_cat_behaviours, step4_cfg):
    step4_info = {"step": 4, "name": "System Behavior Determination", "description": "Aggregate category behaviors to determine system behavior", "input": {"category_behaviors": all_cat_behaviours}, "logic": None, "result": None}
    if step4_cfg.get("override_active") == "true":
        count_override = int(step4_cfg.get("override_count", "0"))
        target = step4_cfg.get("final_behaviour", "suspicious")
        category_behaviour = step4_cfg.get("override_behaviour", "suspicious")
        num = all_cat_behaviours.count(category_behaviour)
        if num >= count_override:
            system_behaviour = target
            step4_info["logic"] = f"Override: {num} categories with {category_behaviour} >= {count_override}, result: {target}"
        else:
            counts = {b: all_cat_behaviours.count(b) for b in ["normal", "suspicious", "compromised"]}
            max_count = max(counts.values())
            max_behs = [k for k, v in counts.items() if v == max_count]
            system_behaviour = max_behs[0] if len(max_behs) == 1 else "suspicious"
            step4_info["logic"] = f"Override inactive, counts: {counts}, selected: {system_behaviour}"
    else:
        counts = {b: all_cat_behaviours.count(b) for b in ["normal", "suspicious", "compromised"]}
        max_count = max(counts.values()) if counts else 0
        max_behs = [k for k, v in counts.items() if v == max_count]
        system_behaviour = max_behs[0] if len(max_behs) == 1 else "suspicious"
        step4_info["logic"] = f"Counts: {counts}, selected: {system_behaviour}"
    step4_info["result"] = system_behaviour
    return system_behaviour, step4_info
