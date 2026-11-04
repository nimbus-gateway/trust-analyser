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
routers/rules.py — Advanced rules engine test & operator endpoints.
"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from services.rules_engine import compare_values, evaluate_condition, evaluate_rule, evaluate_all_rules

router = APIRouter(prefix="/advanced-rules")


@router.get("/operators")
async def get_operators():
    return {
        "string_operators": ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "in_list", "not_in_list", "matches_regex"],
        "numeric_operators": ["equals", "not_equals", "gt", "gte", "lt", "lte", "between", "not_between"],
        "boolean_operators": ["is_true", "is_false", "equals"],
    }


@router.post("/validate-operator")
async def validate_operator(request: Request):
    try:
        data = await request.json()
        result = compare_values(data.get("field_value"), data.get("operator"), data.get("expected_value"), data.get("data_type", "string"))
        return {"valid": result, "message": f"Operator '{data.get('operator')}' result: {result}"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"valid": False, "message": str(e)})


@router.post("/test-condition")
async def test_condition(request: Request):
    try:
        data = await request.json()
        result, extracted_value = evaluate_condition(data.get("payload", {}), data.get("condition", {}))
        return {"result": result, "extracted_value": extracted_value, "message": f"Condition {'matched' if result else 'did not match'}"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"result": False, "message": str(e)})


@router.post("/test-rule")
async def test_rule(request: Request):
    try:
        data = await request.json()
        result = evaluate_rule(data.get("payload", {}), data.get("rule", {}))
        return {"result": result["matched"], "matched_groups": result["matched_groups"], "extracted_values": result["extracted_values"], "impact_level": result["impact_level"], "message": f"Rule {'matched' if result['matched'] else 'did not match'}"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"result": False, "message": str(e)})


@router.post("/test-all-rules")
async def test_all_rules(request: Request):
    try:
        data = await request.json()
        result = evaluate_all_rules(data.get("payload", {}), data.get("rules", []), data.get("global_connector", "AND"))
        return {
            "overall_result": result["overall_result"],
            "matched_rules": result["matched_rules"],
            "rule_count": result["rule_count"],
            "matched_count": result["matched_count"],
            "evaluations": result["evaluations"],
            "message": f"Evaluation complete: {result['matched_count']}/{result['rule_count']} rules matched",
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"overall_result": False, "message": str(e)})
