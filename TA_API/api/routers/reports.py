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
routers/reports.py — Trust evaluation report retrieval & analysis logging endpoints.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from bson import ObjectId

import adi_connector
from database import (
    db,
    TOOL_MANUAL_IMPACTS_COLLECTION,
    TOOL_REPORTINGS_COLLECTION,
)

router = APIRouter()


def _fmt_ts(ts):
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    return str(ts) if ts else None


def _fix_report_timestamps(report: dict):
    """Format activated_impact timestamps inside a report doc."""
    if "report" in report and "trust_evaluation_report" in report["report"]:
        for cat_report in report["report"]["trust_evaluation_report"]:
            all_tools = list(cat_report.get("reporting_tools", [])) + list(cat_report.get("previous_value_tools", []))
            for tool in all_tools:
                for impact in tool.get("activated_impacts", []):
                    ts = impact.get("tool_report_timestamp")
                    if isinstance(ts, datetime):
                        impact["tool_report_timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
                    elif isinstance(ts, str) and "T" in ts:
                        try:
                            impact["tool_report_timestamp"] = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass


@router.get("/trust-evaluation-reports")
async def get_evaluation_reports(limit: int = 0):
    try:
        query = db["trust_evaluation_reports"].find({}).sort("timestamp", -1)
        if limit > 0:
            query = query.limit(limit)
        reports = list(query)
        for r in reports:
            r["_id"] = str(r["_id"])
            if "timestamp" in r:
                r["timestamp"] = r["timestamp"].isoformat()
        return {"status": "success", "reports": reports}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-evaluation-reports/latest")
async def get_latest_evaluation_report():
    try:
        report = db["trust_evaluation_reports"].find_one({}, sort=[("timestamp", -1)])
        if not report:
            return JSONResponse(status_code=404, content={"status": "fail", "error": "No reports found"})
        report["_id"] = str(report["_id"])
        if "timestamp" in report:
            report["timestamp"] = report["timestamp"].isoformat()
        _fix_report_timestamps(report)
        return {"status": "success", "report": report}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-evaluation-reports/{report_id}")
async def get_evaluation_report(report_id: str):
    try:
        report = db["trust_evaluation_reports"].find_one({"_id": ObjectId(report_id)})
        if not report:
            return JSONResponse(status_code=404, content={"status": "fail", "error": "Report not found"})
        report["_id"] = str(report["_id"])
        if "timestamp" in report:
            report["timestamp"] = report["timestamp"].isoformat()
        _fix_report_timestamps(report)
        return {"status": "success", "report": report}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/api/analysis-report/{report_id}")
async def get_analysis_report(report_id: str):
    try:
        report_oid = ObjectId(report_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid report ID format"})

    try:
        report = db["trust_evaluation_reports"].find_one({"_id": report_oid})

        newly_submitted = list(db["tool_reportings"].find(
            {"evaluation_report_id": report_oid},
            {"_id": 1, "tool_name": 1, "unique_id": 1, "value": 1, "category": 1, "impact": 1, "timestamp": 1, "value_source": 1},
        ))
        for rep in newly_submitted:
            if not rep.get("value_source"):
                rep["value_source"] = "new_report"

        tool_reportings = list(newly_submitted)
        newly_submitted_pairs = {(r.get("tool_name"), r.get("category")) for r in newly_submitted}

        tool_category_pairs: set = set()
        if report and "report" in report:
            for cat_report in report["report"].get("trust_evaluation_report", []):
                cat = cat_report.get("category_name", "Uncategorized")
                for tool in list(cat_report.get("reporting_tools", [])) + list(cat_report.get("previous_value_tools", [])):
                    tool_category_pairs.add((tool.get("tool_name"), cat))

        for tool_name, category in tool_category_pairs:
            if (tool_name, category) in newly_submitted_pairs:
                continue
            most_recent = db["tool_reportings"].find_one({"tool_name": tool_name, "category": category}, sort=[("timestamp", -1)])
            if most_recent:
                most_recent["_id"] = str(most_recent["_id"])
                most_recent["timestamp"] = _fmt_ts(most_recent.get("timestamp"))
                manual_doc = TOOL_MANUAL_IMPACTS_COLLECTION.find_one({"tool_name": tool_name, "category": category})
                if manual_doc and manual_doc.get("impact") and manual_doc["impact"].strip().capitalize() in ("Low", "Mid", "High"):
                    most_recent["value_source"] = "manual_impact"
                    most_recent["impact"] = manual_doc["impact"].strip().capitalize()
                else:
                    most_recent["value_source"] = "past_value"
                tool_reportings.append(most_recent)

        for item in newly_submitted:
            if "_id" in item:
                item["_id"] = str(item["_id"])

        def _fetch_logs(collection_name, newly_linked, all_pairs):
            new_logs = list(db[collection_name].find({"evaluation_report_id": report_oid}, {"_id": 1, "tool_name": 1, "category": 1, "steps": 1, "final_behaviour": 1, "advanced_rules": 1, "value_source": 1, "final_score": 1, "final_max_score": 1, "final_percentage": 1, "overall_result": 1, "rules_evaluated": 1, "summary": 1}))
            all_logs = list(new_logs)
            covered = {(r.get("tool_name"), r.get("category")) for r in new_logs}
            for tn, cat in all_pairs:
                if (tn, cat) not in covered:
                    mr = db[collection_name].find_one({"tool_name": tn, "category": cat}, sort=[("timestamp", -1)])
                    if mr:
                        mr["_id"] = str(mr["_id"])
                        if "timestamp" in mr and hasattr(mr["timestamp"], "strftime"):
                            mr["timestamp"] = mr["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                        all_logs.append(mr)
            return all_logs

        behavior_logs = _fetch_logs("behavior_determination_logs", newly_submitted, tool_category_pairs)
        score_logs = _fetch_logs("trust_score_calculation_logs", newly_submitted, tool_category_pairs)
        rule_logs = list(db["rule_evaluation_logs"].find({"evaluation_report_id": report_oid}, {"_id": 1, "tool_name": 1, "category": 1, "overall_result": 1, "rules_evaluated": 1, "summary": 1}))

        for item in tool_reportings + behavior_logs + score_logs + rule_logs:
            if "_id" in item:
                item["_id"] = str(item["_id"])
            if "evaluation_report_id" in item:
                item["evaluation_report_id"] = str(item["evaluation_report_id"])
            if "timestamp" in item:
                item["timestamp"] = _fmt_ts(item["timestamp"])

        return {"status": "success", "tool_reportings": tool_reportings, "behavior_determination_logs": behavior_logs, "trust_score_calculation_logs": score_logs, "rule_evaluation_logs": rule_logs}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/tool-reporting/{reporting_id}")
async def get_tool_reporting(reporting_id: str):
    try:
        reporting_oid = ObjectId(reporting_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid reporting ID format"})
    try:
        reporting = db["tool_reportings"].find_one({"_id": reporting_oid})
        if not reporting:
            return JSONResponse(status_code=404, content={"error": "Reporting not found"})
        reporting["_id"] = str(reporting["_id"])
        if "evaluation_report_id" in reporting and reporting["evaluation_report_id"]:
            reporting["evaluation_report_id"] = str(reporting["evaluation_report_id"])
        if "timestamp" in reporting and hasattr(reporting["timestamp"], "isoformat"):
            reporting["timestamp"] = reporting["timestamp"].isoformat()
        return {"status": "success", "reporting": reporting}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/behavior-steps/{report_id}/{tool_name}/{category}")
async def get_behavior_steps(report_id: str, tool_name: str, category: str):
    try:
        report_oid = ObjectId(report_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid report ID format"})
    try:
        log = db["behavior_determination_logs"].find_one({"evaluation_report_id": report_oid, "tool_name": tool_name, "category": category})
        if not log:
            return JSONResponse(status_code=404, content={"error": "Behavior log not found"})
        log["_id"] = str(log["_id"]); log["evaluation_report_id"] = str(log["evaluation_report_id"])
        if "timestamp" in log and hasattr(log["timestamp"], "isoformat"):
            log["timestamp"] = log["timestamp"].isoformat()
        return {"status": "success", "tool_name": tool_name, "category": category, "steps": log.get("steps", []), "final_behaviour": log.get("final_behaviour"), "confidence": log.get("confidence", 0)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/trust-score-steps/{report_id}/{tool_name}/{category}")
async def get_trust_score_steps(report_id: str, tool_name: str, category: str):
    try:
        report_oid = ObjectId(report_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid report ID format"})
    try:
        log = db["trust_score_calculation_logs"].find_one({"evaluation_report_id": report_oid, "tool_name": tool_name, "category": category})
        if not log:
            return JSONResponse(status_code=404, content={"error": "Score calculation log not found"})
        log["_id"] = str(log["_id"]); log["evaluation_report_id"] = str(log["evaluation_report_id"])
        if "timestamp" in log and hasattr(log["timestamp"], "isoformat"):
            log["timestamp"] = log["timestamp"].isoformat()
        return {"status": "success", "tool_name": tool_name, "category": category, "steps": log.get("steps", []), "final_score": log.get("final_score"), "final_max_score": log.get("final_max_score"), "final_percentage": log.get("final_percentage")}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/rule-evaluation/{report_id}/{tool_name}/{category}")
async def get_rule_evaluation(report_id: str, tool_name: str, category: str):
    try:
        report_oid = ObjectId(report_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid report ID format"})
    try:
        log = db["rule_evaluation_logs"].find_one({"evaluation_report_id": report_oid, "tool_name": tool_name, "category": category})
        if not log:
            return {"status": "success", "message": "No advanced rules were evaluated for this tool", "tool_name": tool_name, "category": category, "rules_evaluated": [], "summary": {"total_rules": 0, "rules_matched": 0}}
        log["_id"] = str(log["_id"]); log["evaluation_report_id"] = str(log["evaluation_report_id"])
        if "timestamp" in log and hasattr(log["timestamp"], "isoformat"):
            log["timestamp"] = log["timestamp"].isoformat()
        return {"status": "success", "tool_name": tool_name, "category": category, "rules_evaluated": log.get("rules_evaluated", []), "summary": log.get("summary", {})}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
