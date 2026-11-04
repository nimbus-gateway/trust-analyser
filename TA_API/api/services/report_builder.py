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
services/report_builder.py — Builds structured evaluation reports from analysis results.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Any, Dict, List, Optional


def build_simple_evaluation_report(
    results: list,
    system_behaviour: str,
    system_percent: float,
    category_weights: dict,
    behaviour_weights: dict,
) -> dict:
    """
    Build a simplified evaluation report for immediate (non-cycle) submissions.

    Args:
        results: List of trust score calculation results (from calculate_trust_score_and_behaviour_with_steps)
        system_behaviour: Determined system behavior
        system_percent: System trust score percentage
        category_weights: Category weight configuration
        behaviour_weights: Behavior weight configuration

    Returns:
        Dict with ``trust_evaluation_report`` and ``behaviour_classification_overrides``.
    """
    trust_evaluation_report = []
    behaviour_overrides = []

    results_by_category: dict = defaultdict(list)
    for result in results:
        cat = result.get("trust_evaluation_category", "Uncategorized")
        results_by_category[cat].append(result)

    for cat, cat_results in results_by_category.items():
        reporting_tools = []
        previous_tools = []

        for result in cat_results:
            tool_name = result.get("tool_name")
            behaviour = result.get("behaviour", "suspicious")
            impact = (result.get("impact") or "Mid").lower()
            value = result.get("value")

            detailed_analysis = {
                "impact_determination": {
                    "method": "advanced_rules" if result.get("advanced_rules_matched") else "config_based",
                    "data_type": result.get("data_type", "unknown"),
                    "value": value,
                    "result_impact": impact,
                },
                "advanced_rules_evaluation": result.get("advanced_rules_evaluation"),
                "behavior_determination": {
                    "impact_to_behavior_mapping": {"low": "normal", "mid": "suspicious", "high": "compromised"},
                    "applied_mapping": f"{impact} → {behaviour}",
                    "result_behavior": behaviour,
                },
            }

            tool_entry = {
                "tool_name": tool_name,
                "behaviour": behaviour,
                "tool_final_behaviour": behaviour,
                "impact": impact,
                "final_impact": impact,
                "value": str(value) if value is not None else "N/A",
                "count": result.get("count", 1),
                "tool_reports_submitted": result.get("count", 1),
                "trust_score": result.get("trust_score"),
                "max_score": result.get("max_score"),
                "percent": result.get("percent"),
                "tool_reporting_id": result.get("tool_reporting_id"),
                "advanced_rules_matched": result.get("advanced_rules_matched", False),
                "detailed_analysis": detailed_analysis,
                "activated_impacts": [],
            }

            if result.get("is_new_submission", True):
                reporting_tools.append(tool_entry)
            else:
                previous_tools.append(tool_entry)

        cat_behaviour = cat_results[-1]["category_behaviour"] if cat_results else "suspicious"
        cat_weight = category_weights.get(cat, 20)
        max_beh_weight = max(behaviour_weights.values()) if behaviour_weights else 100
        n_tools = len(cat_results)
        cat_max = n_tools * max_beh_weight * cat_weight
        cat_real = sum(behaviour_weights.get(r.get("behaviour", "suspicious"), 0) * cat_weight for r in cat_results)
        cat_percent = (cat_real / cat_max * 100) if cat_max > 0 else 0

        trust_evaluation_report.append({
            "category_name": cat,
            "category_behaviour": cat_behaviour,
            "category_final_behaviour": cat_behaviour,
            "category_weight": cat_weight,
            "category_trust_score": cat_real,
            "category_max_score": cat_max,
            "category_max_trust_score": cat_max,
            "category_trust_percent": cat_percent,
            "category_trust_score_percentage": cat_percent,
            "number_of_tools_registered": n_tools,
            "numer_of_tools_reporting": len(reporting_tools),
            "reporting_tools": reporting_tools,
            "previous_value_tools": previous_tools,
        })

    return {
        "trust_evaluation_report": trust_evaluation_report,
        "behaviour_classification_overrides": behaviour_overrides,
        "system_behaviour": system_behaviour,
        "system_trust_score_percentage": system_percent,
    }


def build_full_evaluation_report(
    category_tools: dict,
    tool_category_behaviours: dict,
    category_behaviours_map: dict,
    category_tool_value_impacts: dict,
    tool_results_map: dict,
    category_weights: dict,
    behaviour_weights: dict,
    system_behaviour: str,
    system_percent: float,
    step2_configs: list,
    step3_configs: list,
    step4_config: dict,
) -> dict:
    """
    Build a full evaluation report for batch/cycle analysis.

    Returns the same shape as :func:`build_simple_evaluation_report` but enriched
    with ``activated_impacts`` across the whole cycle.
    """
    trust_evaluation_report = []
    behaviour_overrides = []

    for cat, tools_info in category_tools.items():
        cat_key = cat.lower()
        step3_cfg = next(
            (cfg for cfg in step3_configs if cfg.get("trust_evaluation_category", "").strip().lower() == cat_key), {}
        )
        cat_behaviour = category_behaviours_map.get(cat, "suspicious")
        cat_weight = category_weights.get(cat, 20)
        max_beh_weight = max(behaviour_weights.values()) if behaviour_weights else 100
        n_tools = len(tools_info)
        cat_max = n_tools * max_beh_weight * cat_weight
        cat_real = sum(behaviour_weights.get(t["behaviour"], 0) * cat_weight for t in tools_info)
        cat_percent = (cat_real / cat_max * 100) if cat_max > 0 else 0

        reporting_tools = []
        previous_tools = []

        for tool_info in tools_info:
            tool_name = tool_info["tool_name"]
            behaviour = tool_info["behaviour"]

            # Collect activated impacts from category_tool_value_impacts
            activated_impacts = []
            for (c, tn, val), data in category_tool_value_impacts.items():
                if c == cat and tn == tool_name:
                    mapping = data.get("mapping") or {}
                    for idx, impact in enumerate(data.get("impacts", [])):
                        ts = data["timestamps"][idx] if idx < len(data.get("timestamps", [])) else None
                        activated_impacts.append({
                            "impact": impact,
                            "value": str(val) if val is not None else "N/A",
                            "tool_report_timestamp": ts,
                        })

            res = tool_results_map.get((tool_name, cat), {})
            impact = activated_impacts[-1]["impact"].lower() if activated_impacts else "mid"

            tool_entry = {
                "tool_name": tool_name,
                "behaviour": behaviour,
                "tool_final_behaviour": behaviour,
                "impact": impact,
                "final_impact": impact,
                "value": res.get("value"),
                "count": res.get("count", 1),
                "tool_reports_submitted": res.get("count", 1),
                "trust_score": res.get("trust_score"),
                "max_score": res.get("max_score"),
                "percent": res.get("percent"),
                "tool_reporting_id": res.get("tool_reporting_id"),
                "activated_impacts": activated_impacts,
            }

            is_prev = tool_info.get("is_previous_value", True)
            if not is_prev:
                reporting_tools.append(tool_entry)
            else:
                previous_tools.append(tool_entry)

        trust_evaluation_report.append({
            "category_name": cat,
            "category_behaviour": cat_behaviour,
            "category_final_behaviour": cat_behaviour,
            "category_weight": cat_weight,
            "category_trust_score": cat_real,
            "category_max_score": cat_max,
            "category_max_trust_score": cat_max,
            "category_trust_percent": cat_percent,
            "category_trust_score_percentage": cat_percent,
            "number_of_tools_registered": n_tools,
            "numer_of_tools_reporting": len(reporting_tools),
            "reporting_tools": reporting_tools,
            "previous_value_tools": previous_tools,
        })

    return {
        "trust_evaluation_report": trust_evaluation_report,
        "behaviour_classification_overrides": behaviour_overrides,
        "system_behaviour": system_behaviour,
        "system_trust_score_percentage": system_percent,
    }
