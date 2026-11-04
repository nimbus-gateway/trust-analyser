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

import { ARM, ARM_POS } from './cellLayout';

const { SHOULDER_HEIGHT, UPPER, FORE, TOOL } = ARM;
const HALF_PI = Math.PI / 2;

export const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
export const wrapPi = (a) => Math.atan2(Math.sin(a), Math.cos(a));
// Gripper/carton symmetry: the square carton looks the same every quarter turn
export const wrapQuarter = (a) => a - HALF_PI * Math.round(a / HALF_PI);
export const smootherstep = (t) => t * t * t * (t * (t * 6 - 15) + 10);

// A tool pose in the arm's cylindrical frame: base yaw, horizontal reach,
// grip-centre height and wrist roll (relative to the base yaw).
export const poseAt = (x, y, z, yaw = 0) => {
    const dx = x - ARM_POS[0];
    const dz = z - ARM_POS[2];
    const psi = Math.atan2(-dz, dx);
    return { psi, r: Math.hypot(dx, dz), y, roll: wrapQuarter(yaw - psi) };
};

export const lerpPose = (a, b, t, out) => {
    out.psi = a.psi + wrapPi(b.psi - a.psi) * t;
    out.r = a.r + (b.r - a.r) * t;
    out.y = a.y + (b.y - a.y) * t;
    out.roll = a.roll + (b.roll - a.roll) * t;
    return out;
};

export const poseDistance = (a, b) => {
    const dPsi = Math.abs(wrapPi(b.psi - a.psi)) * (a.r + b.r) * 0.5;
    return Math.hypot(dPsi, b.r - a.r, b.y - a.y) + Math.abs(b.roll - a.roll) * 0.3;
};

// Two-link planar IK (elbow up) with the gripper kept vertical.
// phi1/phi2 are the absolute pitch angles of the upper arm and forearm.
export const solveIK = (pose, out) => {
    let wr = pose.r;
    let wy = pose.y + TOOL - SHOULDER_HEIGHT;
    const d = Math.hypot(wr, wy) || 1e-6;
    const dc = clamp(d, Math.abs(UPPER - FORE) + 1e-3, UPPER + FORE - 1e-3);
    wr *= dc / d;
    wy *= dc / d;

    const cosElbow = clamp((dc * dc - UPPER * UPPER - FORE * FORE) / (2 * UPPER * FORE), -1, 1);
    const elbow = Math.acos(cosElbow);
    out.psi = pose.psi;
    out.phi1 = Math.atan2(wy, wr) + Math.atan2(FORE * Math.sin(elbow), UPPER + FORE * Math.cos(elbow));
    out.phi2 = out.phi1 - elbow;
    out.roll = pose.roll;
    return out;
};

// Forward kinematics: joint angles -> grip centre (floor frame) and cylindrical pose.
export const forwardKinematics = (joints, outPos, outPose) => {
    const wr = UPPER * Math.cos(joints.phi1) + FORE * Math.cos(joints.phi2);
    const tipY = SHOULDER_HEIGHT + UPPER * Math.sin(joints.phi1) + FORE * Math.sin(joints.phi2) - TOOL;
    if (outPos) {
        outPos.set(
            ARM_POS[0] + wr * Math.cos(joints.psi),
            tipY,
            ARM_POS[2] - wr * Math.sin(joints.psi)
        );
    }
    if (outPose) {
        outPose.psi = joints.psi;
        outPose.r = wr;
        outPose.y = tipY;
        outPose.roll = joints.roll;
    }
    return tipY;
};

// Joint angles -> rig transforms. Links are modelled pointing along +y and pitch
// about z; the wrist counter-rotates so the gripper always hangs vertically.
export const applyJointsToRig = (rig, joints, grip) => {
    rig.turret.rotation.y = joints.psi;
    rig.shoulder.rotation.z = joints.phi1 - HALF_PI;
    rig.elbow.rotation.z = joints.phi2 - joints.phi1;
    rig.wrist.rotation.z = HALF_PI - joints.phi2;
    rig.roll.rotation.y = joints.roll;

    const inner = ARM.FINGER_OPEN + (ARM.FINGER_CLOSED - ARM.FINGER_OPEN) * grip;
    const x = inner + ARM.FINGER_THICKNESS / 2;
    rig.fingerLeft.position.x = -x;
    rig.fingerRight.position.x = x;
};
