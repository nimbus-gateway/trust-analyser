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
routers/trust_config.py — Trust analyser step 1–5 configuration endpoints.
"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from database import (
    db, MAPPED_COLLECTION,
    TRUST_CONFIG_COLLECTION,
    TRUST_CONFIG_STEP1_COLLECTION,
    TRUST_CONFIG_STEP2_COLLECTION,
    TRUST_CONFIG_STEP3_COLLECTION,
    TRUST_CONFIG_STEP4_COLLECTION,
    TOOL_CONFIG_STEP5_COLLECTION,
    TRUST_SCORE_WEIGHTS_COLLECTION,
)
from fastapi import Body
import traceback

router = APIRouter()


@router.post("/trust-score-weights")
async def save_trust_score_weights(payload: dict = Body(...)):
    try:
        TRUST_SCORE_WEIGHTS_COLLECTION.delete_many({})
        TRUST_SCORE_WEIGHTS_COLLECTION.insert_one(payload)
        return {"status": "success"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.post("/trust-config")
async def save_trust_config(request: Request):
    try:
        config = await request.json()
        TRUST_CONFIG_COLLECTION.delete_many({})
        TRUST_CONFIG_COLLECTION.insert_one({"config": config})
        return {"status": "success"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-config-step2-get")
async def get_trust_config_step2():
    doc = TRUST_CONFIG_STEP2_COLLECTION.find_one({})
    return {"config": doc.get("config", {}) if doc else {}}


@router.post("/trust-config-step1")
async def save_trust_config_step1(request: Request):
    try:
        config = await request.json()
        tool_name = config.get("tool_name")
        if not tool_name:
            return JSONResponse(status_code=400, content={"status": "fail", "error": "Missing tool_name"})
        if not config.get("mapped_request_id"):
            mapped_doc = MAPPED_COLLECTION.find_one({"tool_name": tool_name})
            if mapped_doc:
                config["mapped_request_id"] = str(mapped_doc["_id"])
            else:
                return JSONResponse(status_code=400, content={"status": "fail", "error": "Missing mapped_request_id"})
        trust_evaluation_category = config.get("trust_evaluation_category")
        if not trust_evaluation_category:
            mapped_doc = MAPPED_COLLECTION.find_one({"tool_name": tool_name})
            if mapped_doc:
                trust_evaluation_category = mapped_doc.get("trust_evaluation_category", "")
                config["trust_evaluation_category"] = trust_evaluation_category
        TRUST_CONFIG_STEP1_COLLECTION.update_one(
            {"tool_name": tool_name, "trust_evaluation_category": trust_evaluation_category},
            {"$set": config}, upsert=True,
        )
        return {"status": "success"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-config-step1-get-all")
async def get_trust_config_step1_all():
    return [dict(doc, _id=str(doc["_id"])) for doc in TRUST_CONFIG_STEP1_COLLECTION.find()]


@router.post("/trust-config-step2")
async def save_trust_config_step2(request: Request):
    try:
        config = await request.json()
        tool_name = config.get("tool_name")
        if not tool_name:
            return JSONResponse(status_code=400, content={"status": "fail", "error": "Missing tool_name"})
        trust_evaluation_category = config.get("trust_evaluation_category")
        if not trust_evaluation_category:
            mapped_doc = MAPPED_COLLECTION.find_one({"tool_name": tool_name})
            trust_evaluation_category = mapped_doc.get("trust_evaluation_category", "") if mapped_doc else ""
            config["trust_evaluation_category"] = trust_evaluation_category
        if config.get("override_active") != "true":
            config.pop("override_count", None); config.pop("override_impact", None); config.pop("override_behaviour", None)
            TRUST_CONFIG_STEP2_COLLECTION.update_one(
                {"tool_name": tool_name, "trust_evaluation_category": trust_evaluation_category},
                {"$set": config, "$unset": {"override_count": "", "override_impact": "", "override_behaviour": ""}}, upsert=True,
            )
        else:
            TRUST_CONFIG_STEP2_COLLECTION.update_one(
                {"tool_name": tool_name, "trust_evaluation_category": trust_evaluation_category},
                {"$set": config}, upsert=True,
            )
        return {"status": "success"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-config-step2-get-all")
async def get_trust_config_step2_all():
    return [dict(doc, _id=str(doc["_id"])) for doc in TRUST_CONFIG_STEP2_COLLECTION.find()]


@router.post("/trust-config-step3")
async def save_trust_config_step3(request: Request):
    try:
        config = await request.json()
        cat = config.get("trust_evaluation_category")
        if not cat:
            return JSONResponse(status_code=400, content={"status": "fail", "error": "Missing trust_evaluation_category"})
        config.pop("one_tool_behaviour", None)
        set_fields = dict(config); unset_fields = {}
        if config.get("override_active") == "true":
            allowed = {"trust_evaluation_category", "override_active", "override_count", "override_behaviour", "tool_behaviour"}
            set_fields = {k: v for k, v in config.items() if k in allowed}
            for field in ["final_behaviour", "one_tool_behaviour"]:
                unset_fields[field] = ""
            for field in ["override_count", "override_behaviour", "tool_behaviour"]:
                if field not in set_fields:
                    unset_fields[field] = ""
        else:
            set_fields = {"trust_evaluation_category": cat, "override_active": config.get("override_active")}
            for field in ["override_count", "override_behaviour", "final_behaviour", "one_tool_behaviour", "tool_behaviour"]:
                unset_fields[field] = ""
        TRUST_CONFIG_STEP3_COLLECTION.update_one(
            {"trust_evaluation_category": cat},
            {"$set": set_fields, "$unset": unset_fields}, upsert=True,
        )
        return {"status": "success"}
    except Exception as e:
        print(traceback.format_exc())
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-config-step3-get-all")
async def get_trust_config_step3_all():
    return [dict(doc, _id=str(doc["_id"])) for doc in TRUST_CONFIG_STEP3_COLLECTION.find()]


@router.post("/trust-config-step4")
async def save_trust_config_step4(request: Request):
    try:
        config = await request.json()
        if config.get("override_active") != "true":
            config.pop("override_count", None); config.pop("override_behaviour", None)
            TRUST_CONFIG_STEP4_COLLECTION.delete_many({})
            TRUST_CONFIG_STEP4_COLLECTION.insert_one(config)
            TRUST_CONFIG_STEP4_COLLECTION.update_one({}, {"$unset": {"override_count": "", "override_behaviour": ""}})
        else:
            TRUST_CONFIG_STEP4_COLLECTION.delete_many({})
            TRUST_CONFIG_STEP4_COLLECTION.insert_one(config)
        return {"status": "success"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/trust-config-step4-get")
async def get_trust_config_step4():
    doc = TRUST_CONFIG_STEP4_COLLECTION.find_one({})
    if doc:
        doc["_id"] = str(doc["_id"])
        return doc
    return {}


@router.post("/tool-config-step5")
async def save_tool_config_step5(request: Request):
    try:
        config = await request.json()
        tool_name = config.get("tool_name")
        if not tool_name:
            return JSONResponse(status_code=400, content={"status": "fail", "error": "Missing tool_name"})
        trust_evaluation_category = config.get("trust_evaluation_category")
        if not trust_evaluation_category:
            mapped_doc = MAPPED_COLLECTION.find_one({"tool_name": tool_name})
            trust_evaluation_category = mapped_doc.get("trust_evaluation_category", "") if mapped_doc else ""
            config["trust_evaluation_category"] = trust_evaluation_category
        TOOL_CONFIG_STEP5_COLLECTION.update_one(
            {"tool_name": tool_name, "trust_evaluation_category": trust_evaluation_category},
            {"$set": config}, upsert=True,
        )
        return {"status": "success"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/tool-config-step5-get")
async def get_tool_config_step5_all():
    return [dict(doc, _id=str(doc["_id"])) for doc in TOOL_CONFIG_STEP5_COLLECTION.find()]


@router.post("/value-processing/preview")
async def preview_value_processing(request: Request):
    try:
        data = await request.json()
        value = data.get("value")
        separator = data.get("separator", ",")
        if not value:
            return {"error": "No value provided"}
        if not isinstance(value, str):
            value = str(value)
        parts = value.split(separator)
        return {
            "original_value": value, "separator": separator,
            "parts": parts, "part_count": len(parts),
            "preview": [{"index": i, "value": part.strip()} for i, part in enumerate(parts)],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/value-processing/save")
async def save_value_processing(request: Request):
    try:
        from bson import ObjectId
        data = await request.json()
        mapping_id = data.get("mapping_id")
        processing_steps = data.get("processing_steps", [])
        if not mapping_id:
            return {"error": "No mapping_id provided"}
        from database import MAPPED_COLLECTION as mc
        result = mc.update_one(
            {"_id": ObjectId(mapping_id)},
            {"$set": {"value_processing_required": len(processing_steps) > 0, "value_processing_steps": processing_steps}},
        )
        if result.modified_count > 0:
            return {"status": "success", "message": "Value processing configuration saved"}
        return {"status": "error", "message": "Mapping not found or not updated"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
