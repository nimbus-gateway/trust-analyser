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
models.py — Pydantic request/response models for the Trust Analyser API.
"""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class ToolData(BaseModel):
    """Payload submitted by a tool to the /submit endpoint."""
    tool_name: str
    time_stamp: str
    payload: dict
    # Advanced rules submitted alongside the data (optional)
    advanced_rules: Optional[List[Dict[str, Any]]] = None
    between_rules_connector: str = "AND"  # "AND" or "OR"


class FieldExtraction(BaseModel):
    """Configuration for extracting a single field from a JSON payload."""
    json_path: str
    data_type: str  # "string", "number", "boolean", "array"
    description: Optional[str] = ""


class Condition(BaseModel):
    """Single condition: field + operator + expected value."""
    field: FieldExtraction
    operator: str
    expected_value: Any = None
    description: Optional[str] = ""


class ConditionGroup(BaseModel):
    """Group of conditions combined with AND/OR logic."""
    conditions: List[Dict[str, Any]]
    connector: str = "AND"  # "AND" or "OR"
    description: Optional[str] = ""


class EvaluationRule(BaseModel):
    """Complete evaluation rule with multiple condition groups."""
    name: str
    description: Optional[str] = ""
    condition_groups: List[Dict[str, Any]]
    group_connector: str = "AND"  # "AND" or "OR"
    impact_level: str = "medium"  # "low", "medium", "high"
    enabled: bool = True


class MapRequest(BaseModel):
    """Request body for registering a tool mapping."""
    tool_name: str
    description: Optional[str] = None
    data_type: str
    trust_evaluation_category: Optional[str] = None
    categories: Optional[str] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    unique_id_path: str
    unique_id_value: Optional[str] = None
    value_path: str
    supplement: Optional[str] = None
    # Supplement data paths for extracting additional fields
    supplement_data_paths: Optional[List[Dict[str, str]]] = None
    # Value processing
    value_processing_required: Optional[bool] = False
    value_processing_steps: Optional[List[Dict[str, Any]]] = None
    # Advanced rules
    evaluation_mode: str = "simple"  # "simple" or "advanced"
    secondary_value_fields: Optional[List[Dict[str, Any]]] = None
    advanced_rules: Optional[List[Dict[str, Any]]] = None
    between_rules_connector: str = "AND"
