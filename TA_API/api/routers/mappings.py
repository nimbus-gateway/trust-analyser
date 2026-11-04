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
routers/mappings.py — Tool mapping management endpoints.
"""
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, Query
from fastapi.responses import JSONResponse
from bson import ObjectId
from database import db, TOOL_DATA_COLLECTION, MAPPED_COLLECTION, REMOVED_MAPPED_COLLECTION
from models import MapRequest
from services import get_by_path

router = APIRouter()


@router.get("/data")
async def get_data(
    response: Response,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: Optional[int] = Query(50, ge=1, le=500, description="Number of records to return"),
):
    """Retrieve raw unmapped tool requests with pagination, sorted newest first."""
    total = TOOL_DATA_COLLECTION.count_documents({})
    response.headers["X-Total-Count"] = str(total)
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"

    cursor = TOOL_DATA_COLLECTION.find().sort("_id", -1).skip(skip)
    if limit is not None and limit > 0:
        cursor = cursor.limit(limit)

    docs = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        docs.append(doc)
    return docs


@router.delete("/data/{request_id}")
async def delete_data(request_id: str):
    try:
        obj_id = ObjectId(request_id)
        result = TOOL_DATA_COLLECTION.delete_one({"_id": obj_id})
        if result.deleted_count == 1:
            return {"status": "success", "message": "Request deleted"}
        raise HTTPException(status_code=404, detail="Request not found")
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/mapped")
async def get_mapped():
    docs = []
    for doc in MAPPED_COLLECTION.find():
        doc["_id"] = str(doc["_id"])
        docs.append(doc)
    return docs


@router.get("/mapped/removed")
async def get_removed_mapped():
    docs = []
    for doc in REMOVED_MAPPED_COLLECTION.find():
        doc["_id"] = str(doc["_id"])
        docs.append(doc)
    return docs


@router.post("/map")
async def map_request(data: MapRequest):
    doc = data.model_dump()
    doc["count"] = 0

    unique_id_path = doc.get("unique_id_path")
    unique_id_value = doc.get("unique_id_value")

    if doc.get("data_type") != "continuous":
        doc.pop("min_value", None)
        doc.pop("max_value", None)
    doc.pop("category", None)

    MAPPED_COLLECTION.insert_one(doc)

    if unique_id_path and unique_id_value:
        for entry in list(TOOL_DATA_COLLECTION.find({})):
            try:
                incoming_uid = get_by_path(entry.get("payload", {}), unique_id_path)
                if incoming_uid is not None and str(incoming_uid) == str(unique_id_value):
                    TOOL_DATA_COLLECTION.delete_one({"_id": entry["_id"]})
            except Exception:
                continue

    return {"status": "saved"}


@router.delete("/mapped/{request_id}")
async def delete_mapped_request(request_id: str):
    try:
        obj_id = ObjectId(request_id)
        result = MAPPED_COLLECTION.delete_one({"_id": obj_id})
        if result.deleted_count == 1:
            return {"status": "success", "message": "Mapped request deleted"}
        raise HTTPException(status_code=404, detail="Mapped request not found")
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "fail", "error": str(e)})


@router.get("/tool-data-type/{tool_name}/{category}")
async def get_tool_data_type(tool_name: str, category: str):
    mapped = MAPPED_COLLECTION.find_one({"tool_name": tool_name, "trust_evaluation_category": category})
    if mapped and "data_type" in mapped:
        return {"data_type": mapped["data_type"], "source": "active_mapping"}
    removed = REMOVED_MAPPED_COLLECTION.find_one({"tool_name": tool_name, "trust_evaluation_category": category})
    if removed and "data_type" in removed:
        return {"data_type": removed["data_type"], "source": "removed_mapping"}
    ts = db["trust_score_results"].find_one({"tool_name": tool_name, "trust_evaluation_category": category})
    if ts and "data_type" in ts:
        return {"data_type": ts["data_type"], "source": "historical"}
    return {"data_type": "categorical", "source": "default"}
