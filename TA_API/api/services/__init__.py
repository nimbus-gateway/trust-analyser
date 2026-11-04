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

def get_by_path(payload: dict, path: str):
    """Extract a value from a nested dict using a dot-separated path string.

    The leading ``payload`` segment is stripped automatically, so both
    ``"payload.data.value"`` and ``"data.value"`` resolve correctly.

    Args:
        payload: The dictionary to traverse.
        path: Dot-separated key path, e.g. ``"payload.id"`` or ``"data.value"``.

    Returns:
        The value at the given path, or ``None`` if any key is missing or
        the path is invalid.
    """
    try:
        parts = path.split(".")
        if parts and parts[0] == "payload":
            parts = parts[1:]
        val = payload
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                return None
        return val
    except Exception:
        return None


from . import rules_engine, trust_calculator, analysis_logger, report_builder

__all__ = [
    "get_by_path",
    "rules_engine",
    "trust_calculator",
    "analysis_logger",
    "report_builder",
]

