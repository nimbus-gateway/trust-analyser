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

from annotated_types import doc 
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Optional
import json
import traceback
import asyncio
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import Body
from bson import ObjectId
import os, sys
from fastapi.middleware.cors import CORSMiddleware
import requests

#TODO: Change this to point to your ADI instance
# service_url = "http://172.31.5.12:8000/"
# service_url = "http://localhost:8000"
SERVICE_IP = os.getenv("SERVICE_IP", "localhost")
service_url = f"http://{SERVICE_IP}:9002"

ADI_SERVICE_URL = os.getenv("ADI_SERVICE_URL", service_url)

# MongoDB connection (shared with main.py via env vars)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME   = os.getenv("DB_NAME", "telemetry")
_adi_client = MongoClient(MONGO_URI)
_adi_db     = _adi_client[DB_NAME]
_current_reporting_tools_col  = _adi_db.get_collection('current_reporting_tools')
_tool_most_recent_values_col  = _adi_db.get_collection('tool_most_recent_values')
# TA Report
class ActivatedImpact(BaseModel):
    rule: str
    impact: str
    tool_report_timestamp: datetime


class ReportingTool(BaseModel):
    tool_name: str
    tool_reports_submitted: int
    activated_impacts: List[ActivatedImpact]
    final_impact: str
    tool_final_behaviour: str


class PreviousToolReport(BaseModel):
    tool_name: str
    tool_reports_submitted: int
    activated_impacts: List[ActivatedImpact]
    final_impact: str
    tool_final_behaviour: str


class CategoryEvaluation(BaseModel):
    category_name: str
    category_final_behaviour: str
    category_max_trust_score: float
    category_trust_score: float
    category_trust_score_percentage: float
    number_of_tools_registered: int
    numer_of_tools_reporting: int


class BehaviourOverride(BaseModel):
    category_name: str
    original_behaviour_classification: str
    overridden_behaviour_classification: str
    override_reason: str


class InputIndicator(BaseModel):
    asset_id: str = Field(alias="asset-id")


class TrustAnalyserReport(BaseModel):
    type: str
    severity: str
    value: float
    timestamp: datetime
    source: str
    subject: str

    category_evaluation_report: List[CategoryEvaluation]
    reporting_tools: List[ReportingTool]
    previous_tool_reports: List[PreviousToolReport]
    behaviour_classification_overrides: List[BehaviourOverride]
    input_indicators: List[InputIndicator] = Field(alias="input-indicators")

    class Config:
        populate_by_name = True

def transform_trust_eval_to_report(analysis_type: str, data: dict) -> TrustAnalyserReport:
    report_data = data["reports"][0]
    inner_report = report_data["report"]

    categories = []
    all_reporting_tools = []
    all_previous_tools = []

    for cat in inner_report["trust_evaluation_report"]:
        # Build reporting tools per category
        reporting_tools = []
        for tool in cat.get("reporting_tools", []):
            impacts = [
                ActivatedImpact(
                    rule=imp["rule"],
                    impact=imp["impact"],
                    tool_report_timestamp=imp["tool_report_timestamp"]
                )
                for imp in tool.get("activated_impacts", [])
            ]

            tool_obj = ReportingTool(
                tool_name=tool["tool_name"],
                tool_reports_submitted=tool["tool_reports_submitted"],
                activated_impacts=impacts,
                final_impact=tool["final_impact"],
                tool_final_behaviour=tool["tool_final_behaviour"]
            )

            reporting_tools.append(tool_obj)
            all_reporting_tools.append(tool_obj)

        # Previous tools
        prev_tools = []
        for tool in cat.get("previous_value_tools", []):
            impacts = [
                ActivatedImpact(
                    rule=imp["rule"],
                    impact=imp["impact"],
                    tool_report_timestamp=imp["tool_report_timestamp"]
                )
                for imp in tool.get("activated_impacts", [])
            ]

            prev_obj = PreviousToolReport(
                tool_name=tool["tool_name"],
                tool_reports_submitted=tool["tool_reports_submitted"],
                activated_impacts=impacts,
                final_impact=tool["final_impact"],
                tool_final_behaviour=tool["tool_final_behaviour"]
            )

            prev_tools.append(prev_obj)
            all_previous_tools.append(prev_obj)

        # Category object (NOTE: reporting tools are flattened later)
        category_obj = CategoryEvaluation(
            category_name=cat["category_name"],
            category_final_behaviour=cat["category_final_behaviour"].capitalize(),
            category_max_trust_score=cat["category_max_trust_score"],
            category_trust_score=cat["category_trust_score"],
            category_trust_score_percentage=cat["category_trust_score_percentage"],
            number_of_tools_registered=cat["number_of_tools_registered"],
            numer_of_tools_reporting=cat["numer_of_tools_reporting"],
        )

        categories.append(category_obj)

    # Overrides
    overrides = [
        BehaviourOverride(**o)
        for o in inner_report.get("behaviour_classification_overrides", [])
    ]

    # ── Build input_indicators from asset IDs ──────────────────────────────
    # Collect every unique (tool_name, category) pair across all tools in report
    all_tool_pairs = set()
    for cat in inner_report["trust_evaluation_report"]:
        for tool in cat.get("reporting_tools", []):
            all_tool_pairs.add((tool["tool_name"], cat["category_name"]))
        for tool in cat.get("previous_value_tools", []):
            all_tool_pairs.add((tool["tool_name"], cat["category_name"]))

    collected_asset_ids = set()
    for tool_name, category in all_tool_pairs:
        # 1st choice: current_reporting_tools (may have multiple docs per tool)
        crt_docs = list(_current_reporting_tools_col.find(
            {'tool_name': tool_name, 'category': category},
            {'asset_id': 1, '_id': 0}
        ))
        if crt_docs:
            for doc in crt_docs:
                aid = doc.get('asset_id')
                if aid is not None:
                    collected_asset_ids.add(str(aid))
        else:
            # Fallback: tool_most_recent_values — asset_id lives inside payload
            mrv = _tool_most_recent_values_col.find_one(
                {'tool_name': tool_name, 'trust_evaluation_category': category},
                {'payload': 1, '_id': 0}
            )
            if mrv and mrv.get('payload'):
                aid = mrv['payload'].get('asset_id')
                if aid is not None:
                    collected_asset_ids.add(str(aid))

    input_indicators = [InputIndicator(**{"asset-id": aid}) for aid in sorted(collected_asset_ids)]

    # Final report
    final_report = TrustAnalyserReport(
        type="Trust Analyser Report",
        severity=inner_report["system_behaviour"].upper(),
        value=inner_report["system_trust_score_percentage"],
        timestamp=inner_report["report_timestamp"],
        source="Trust Analyser",
        subject=analysis_type + " Analysis Report",
        category_evaluation_report=categories,
        reporting_tools=all_reporting_tools,
        previous_tool_reports=all_previous_tools,
        behaviour_classification_overrides=overrides,
        input_indicators=input_indicators
    )

    return final_report


def generate_TA_report_for_ADI(analysis_type: str):
    if SERVICE_IP == "localhost":
        return {"status": "success", "message": "This is a placeholder response. Implement the actual logic to fetch, transform, and send the TA report to ADI."}
    # TODO: Change This
    resp = requests.get(f"http://{SERVICE_IP}:9001/trust-evaluation-reports?limit=1")
    # resp = requests.get("http://localhost:9001/trust-evaluation-reports?limit=1")

    resp.raise_for_status()  # fail fast if error
    data = resp.json()
    print("Got data")

    # 2. Transform
    report = transform_trust_eval_to_report(analysis_type,data)
    payload = { "payload": report.model_dump(by_alias=True, mode="json")}
    print("report created")
    print(payload)
    # 3. Send to external API
    response = requests.post(
        ADI_SERVICE_URL + "/ta-report",
        json=payload
    )
    print("Report Submited to ADI")
    # print(response.status_code)
    # print(response.text)
    response.raise_for_status()

    return response.json()

def generate_user_action_report_for_ADI(source: str, subject: str, severity: str):
    if SERVICE_IP == "localhost":
        return {"status": "success", "message": "This is a placeholder response. Implement the actual logic to fetch, transform, and send the TA report to ADI."}
    dt = datetime.utcnow().isoformat()
    payload = {
        "payload":{
            "type": "Trust Analyser Action",
            "source": source,
            "timestamp": dt ,
            "subject": subject,
            "severity": severity.upper()
        }
    }

    response = requests.post(
        # "http://localhost:8000/ta-user-action",
        ADI_SERVICE_URL + "/ta-user-action",
        json=payload
    )
    print("Submit")
    # print(response.status_code)
    # print(response.text)
    response.raise_for_status()

    return response.json()