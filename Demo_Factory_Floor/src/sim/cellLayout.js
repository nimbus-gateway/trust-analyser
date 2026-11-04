// SPDX-License-Identifier: GPL-3.0-only ( contact authors for upgrade consent )

/*
 * Trust Analyzer - A service to evaluate the trustworthiness of a system
 * using five trust evaluation categories: security, resilience, reliability,
 * threat exposure, and intentions. Output is a trust score (0-100) and a
 * behavior type (normal, suspicious, compromised).
 *
 * Copyright (c) 2026 Pasindu Kurupparachchi <pasindu.kurupparachchi@mtu.ie>, Nimbus Research Centre, Munster Technological University
 *
 * This work is partially supported by the Horizon Europe TELEMETRY project,
 * funded by the European Commission under grant number 101119747, and by the
 * Science Foundation Ireland Centre Advance CRT under grant number 18/CRT/6222.
 *
 * Trust analyzer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (subject to
 * explicit consent) any later version.
 *
 * This tool is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE or SATISFACTORY QUALITY or PERFORMANCE,
 * comply with any description or regulatory standard, or are safe, accurate,
 * up to date or complete. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see [https://www.gnu.org/licenses/.](https://www.gnu.org/licenses/)
 */

// Shared geometry for the palletizing work cell. All positions are in the
// factory-floor frame (the group that Scene offsets by y = -1.5).

// Carton size (square footprint so it can be gripped from either side).
export const BOX = { w: 0.6, h: 0.45, d: 0.6 };

// Robot arm
export const ARM_POS = [-2, 0, 0];
export const ARM = {
    SHOULDER_HEIGHT: 1.1, // shoulder pitch axis above the floor
    UPPER: 1.8, // shoulder -> elbow
    FORE: 1.6, // elbow -> wrist
    TOOL: 0.75, // wrist axis -> grip centre (gripper hangs straight down)
    FINGER_OPEN: 0.42, // inner face of each finger from the gripper centre
    FINGER_CLOSED: BOX.w / 2 - 0.005, // slight squeeze on the carton
    FINGER_THICKNESS: 0.06,
};

// Infeed conveyor: runs along +z, centred on x = 0
export const BELT_POS = [0, 0.5, 0];
export const BELT_LENGTH = 10;
export const BELT_WIDTH = 2;
export const BELT_TOP = BELT_POS[1] + 0.05;
export const BELT_SPEED = 1.2;
export const BELT_BOX_Y = BELT_TOP + BOX.h / 2;
export const STOPPER_Z = 0.33; // stop bar centre (local to belt == floor frame here)
export const STOP_BOX_Z = STOPPER_Z - 0.03 - BOX.d / 2; // where the front carton rests
export const SPAWN_Z = -4.5; // inside the infeed hood
export const QUEUE_SPACING = BOX.d + 0.08;

// Pallet station: pallet sits on a roller bed that carries it away when full
export const PALLET_HOME = [-2, 0, 2];
export const ROLLER_BED_TOP = 0.15;
export const PALLET_TOP = ROLLER_BED_TOP + 0.14;
export const PALLET_EXIT_DISTANCE = 6;
const SLOT_OFFSET = 0.45; // leaves a 0.3 gap between cartons for the gripper fingers
const SLOT_PATTERN = [
    [-SLOT_OFFSET, SLOT_OFFSET],
    [SLOT_OFFSET, SLOT_OFFSET],
    [-SLOT_OFFSET, -SLOT_OFFSET],
    [SLOT_OFFSET, -SLOT_OFFSET],
];
export const PALLET_LAYERS = 2;
export const PALLET_SLOTS = Array.from({ length: PALLET_LAYERS * SLOT_PATTERN.length }, (_, i) => {
    const layer = Math.floor(i / SLOT_PATTERN.length);
    const [x, z] = SLOT_PATTERN[i % SLOT_PATTERN.length];
    return { x, y: PALLET_TOP + BOX.h / 2 + layer * BOX.h, z, yaw: 0 };
});

// Arm motion
export const HOME_POSE = { psi: -Math.PI / 4, r: 1.6, y: 2.2, roll: 0 };
export const TRANSIT_Y = 1.85; // grip-centre height when swinging between belt and pallet
export const PICK_CLEARANCE = 0.55;
