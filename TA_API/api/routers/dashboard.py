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
routers/dashboard.py — Dashboard data retrieval endpoints.
"""
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from database import db

router = APIRouter()


def _safe_serialize(doc):
    doc = dict(doc)
    doc["_id"] = str(doc.get("_id", ""))
    for key, value in doc.items():
        if isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc


@router.get("/dashboard/trust-scores")
async def get_dashboard_trust_scores():
    scores = [_safe_serialize(d) for d in db["trust_score_results"].find({})]
    behaviours = [_safe_serialize(d) for d in db["tool_behaviour_results"].find({})]
    cat_behaviours = [_safe_serialize(d) for d in db["category_behaviour_results"].find({})]
    return JSONResponse({"trust_scores": scores, "tool_behaviours": behaviours, "category_behaviours": cat_behaviours})


@router.get("/dashboard/system-behaviour")
async def get_dashboard_system_behaviour():
    res = db["system_behaviour_result"].find_one({})
    current_behaviour = res.get("system_behaviour", "normal") if res else "normal"
    hist_res = db["system_behaviour_history"].find_one({})
    recent_behaviour = []
    if hist_res and "history" in hist_res:
        history = hist_res["history"]
        recent_behaviour = history[-10:] if len(history) > 10 else history
    return JSONResponse({"system_behaviour": current_behaviour, "recent_behaviour": recent_behaviour})


@router.get("/system-behaviour-history-frequencies")
async def get_system_behaviour_history_frequencies():
    doc = db["system_behaviour_history"].find_one({})
    freq = {"normal": 0, "suspicious": 0, "compromised": 0}
    if doc and "history" in doc:
        for beh in doc["history"]:
            if beh in freq:
                freq[beh] += 1
    return freq


@router.get("/category-behaviour-history-frequencies")
async def get_category_behaviour_history_frequencies():
    result = {}
    for doc in db["category_behaviour_history"].find({}):
        cat = doc.get("trust_evaluation_category", "Uncategorized")
        freq = {"normal": 0, "suspicious": 0, "compromised": 0}
        for beh in doc.get("history", []):
            if beh in freq:
                freq[beh] += 1
        result[cat] = freq
    return result


@router.get("/category-behaviour-recent")
async def get_category_behaviour_recent():
    docs = list(db["category_behaviour_history"].find({}))
    merged = {}
    for doc in docs:
        cat = doc.get("trust_evaluation_category", "Uncategorized")
        lower = cat.strip().lower()
        history = doc.get("history", [])
        if lower not in merged:
            merged[lower] = {"canonical": cat, "history": list(history)}
        else:
            merged[lower]["history"].extend(history)

    result = {}
    for lower, entry in merged.items():
        cat = entry["canonical"]
        history = entry["history"]
        recent_10 = history[-10:] if len(history) >= 10 else history
        result[cat] = recent_10
        result[cat.title()] = recent_10
        result[cat.lower()] = recent_10
    return result


@router.get("/tool-value-frequency/{tool_name}/{category}")
async def get_tool_value_frequency(tool_name: str, category: str):
    docs = list(db["tool_value_frequencies"].find({"tool_name": tool_name, "trust_evaluation_category": category}))
    result = {}
    for doc in docs:
        if "value" in doc and "count" in doc:
            result[doc["value"]] = doc["count"]
    return result


@router.get("/tool-trust-score-history/{tool_name}/{category}")
async def get_tool_trust_score_history(tool_name: str, category: str):
    doc = db["tool_trust_score_history"].find_one({"tool_name": tool_name, "trust_evaluation_category": category})
    if doc and "scores" in doc:
        return doc["scores"]
    return []


@router.get("/system-trust-score-history")
async def get_system_trust_score_history():
    doc = db["system_trust_score_history"].find_one({})
    if doc and "scores" in doc:
        return doc["scores"]
    return []


@router.get("/tool-value-history/{tool_name}/{category}")
async def get_tool_value_history(tool_name: str, category: str):
    doc = db["tool_value_frequencies"].find_one({"tool_name": tool_name, "trust_evaluation_category": category})
    if doc:
        if "values" in doc and isinstance(doc["values"], list):
            return doc["values"]
        return []
    return []


@router.get("/debug/tool-frequencies")
async def debug_tool_frequencies():
    result = []
    for doc in db["tool_value_frequencies"].find({}).limit(100):
        doc_copy = dict(doc)
        doc_copy["_id"] = str(doc_copy["_id"])
        if "values" in doc_copy:
            doc_copy["values_count"] = len(doc_copy.get("values", []))
        result.append(doc_copy)
    return result
