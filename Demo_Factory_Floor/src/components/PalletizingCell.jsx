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

import React, { useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import useStore from '../store/useStore';
import RoboticArm from './RoboticArm';
import ConveyorBelt from './ConveyorBelt';
import PalletStation, { PALLET_ROLLER_RADIUS } from './PalletStation';
import {
    ARM, ARM_POS, BELT_BOX_Y, BELT_LENGTH, BELT_POS, BELT_SPEED, BELT_WIDTH, BOX, HOME_POSE,
    PALLET_EXIT_DISTANCE, PALLET_HOME, PALLET_SLOTS, PICK_CLEARANCE, QUEUE_SPACING,
    ROLLER_BED_TOP, SPAWN_Z, STOP_BOX_Z, TRANSIT_Y,
} from '../sim/cellLayout';
import {
    applyJointsToRig, clamp, forwardKinematics, lerpPose, poseAt, poseDistance, smootherstep,
    solveIK, wrapPi,
} from '../sim/armKinematics';

const BOX_POOL_SIZE = 20;
const SPAWN_INTERVAL = 2.4;
const MAX_QUEUE = 4;
const GRAVITY = 9.8;
const PALLET_TRAVEL_TIME = 2.8;

// Approach speeds (units/s) for the different move types
const FAST = 2.6;
const APPROACH = 1.4;
const FINE = 0.5;

const damp = THREE.MathUtils.damp;

const createBox = (id) => ({
    id,
    state: 'hidden', // hidden | belt | held | pallet | falling | floor
    pos: new THREE.Vector3(),
    yaw: 0,
    yawOffset: 0,
    reserved: false,
    downstream: false,
    slot: -1,
    vy: 0,
    spin: 0,
});

const PalletizingCell = () => {
    const armRef = useRef();
    const palletRef = useRef();
    const boxMeshesRef = useRef([]);
    const beltSpeedRef = useRef(BELT_SPEED);

    const cartonMaterial = useMemo(() => new THREE.MeshStandardMaterial({ color: '#c49a6c', roughness: 0.85 }), []);
    const cartonAlertMaterial = useMemo(() => new THREE.MeshStandardMaterial({
        color: '#ef4444', emissive: '#7f1d1d', emissiveIntensity: 0.4, roughness: 0.7,
    }), []);

    // All mutable simulation state lives here so the frame loop never re-renders React
    const sim = useMemo(() => {
        const joints = solveIK(HOME_POSE, {});
        return {
            boxes: Array.from({ length: BOX_POOL_SIZE }, (_, i) => createBox(i)),
            spawnTimer: SPAWN_INTERVAL,
            pallet: { phase: 'loading', t: 0, offset: 0, nextSlot: 0 },
            arm: {
                mode: 'normal',
                pose: { ...HOME_POSE }, // commanded tool pose
                joints, // actual (smoothed) joint angles
                desired: { ...joints },
                grip: 0,
                gripTarget: 0,
                steps: [],
                step: null,
                job: null,
                heldBox: null,
            },
            tmpPose: { psi: 0, r: 0, y: 0, roll: 0 },
            tmpTip: new THREE.Vector3(),
        };
    }, []);

    const slotPosition = (slot, offset = 0) => {
        const s = PALLET_SLOTS[slot];
        return [PALLET_HOME[0] + s.x, s.y, PALLET_HOME[2] + s.z + offset];
    };

    const planPick = (box) => {
        const { arm, pallet } = sim;
        const slot = pallet.nextSlot++;
        box.reserved = true;

        const [bx, by, bz] = [box.pos.x, box.pos.y, box.pos.z];
        const [sx, sy, sz] = slotPosition(slot);
        const slotYaw = PALLET_SLOTS[slot].yaw;

        const grip = poseAt(bx, by, bz, box.yaw);
        const place = poseAt(sx, sy, sz, slotYaw);

        arm.job = { box, slot };
        arm.steps = [
            { kind: 'move', to: { ...grip, y: by + PICK_CLEARANCE }, speed: FAST },
            { kind: 'move', to: { ...grip, y: by + 0.12 }, speed: APPROACH },
            { kind: 'move', to: grip, speed: FINE },
            { kind: 'grip', box },
            { kind: 'move', to: { ...grip, y: by + 0.15 }, speed: FINE },
            { kind: 'move', to: { ...grip, y: TRANSIT_Y }, speed: APPROACH },
            { kind: 'move', to: { ...place, y: TRANSIT_Y }, speed: FAST },
            { kind: 'move', to: { ...place, y: sy + 0.18 }, speed: APPROACH },
            { kind: 'move', to: { ...place, y: sy + 0.005 }, speed: FINE },
            { kind: 'release', box, slot },
            { kind: 'move', to: { ...place, y: sy + 0.2 }, speed: FINE },
            { kind: 'move', to: { ...place, y: TRANSIT_Y }, speed: APPROACH },
            { kind: 'done' },
        ];
    };

    const startStep = (step) => {
        const { arm } = sim;
        step.t = 0;
        if (step.kind === 'move') {
            step.from = { ...arm.pose };
            step.duration = Math.max(0.3, poseDistance(step.from, step.to) / step.speed);
        } else if (step.kind === 'grip') {
            arm.gripTarget = 1;
            step.duration = 0.45;
        } else if (step.kind === 'release') {
            arm.gripTarget = 0;
            arm.heldBox = null;
            const { box, slot } = step;
            box.state = 'pallet';
            box.slot = slot;
            box.yaw = PALLET_SLOTS[slot].yaw;
            step.duration = 0.35;
        } else {
            step.duration = 0;
        }
    };

    const finishStep = (step) => {
        const { arm } = sim;
        if (step.kind === 'grip') {
            // Fingers have closed on the carton: it now travels with the tool
            const box = step.box;
            box.state = 'held';
            box.reserved = false;
            box.yawOffset = box.yaw - (arm.joints.psi + arm.joints.roll);
            arm.heldBox = box;
        } else if (step.kind === 'done') {
            arm.job = null;
        }
    };

    const runArmSequence = (dt) => {
        const { arm } = sim;
        let remaining = dt;
        while (remaining > 0) {
            if (!arm.step) {
                arm.step = arm.steps.shift() || null;
                if (!arm.step) return;
                startStep(arm.step);
            }
            const step = arm.step;
            const advance = Math.min(remaining, step.duration - step.t);
            step.t += advance;
            remaining -= advance;

            if (step.kind === 'move') {
                const k = step.duration > 0 ? smootherstep(clamp(step.t / step.duration, 0, 1)) : 1;
                lerpPose(step.from, step.to, k, arm.pose);
            }
            if (step.t >= step.duration) {
                finishStep(step);
                arm.step = null;
            } else {
                return;
            }
        }
    };

    const frontBoxAtStop = () => {
        let front = null;
        for (const box of sim.boxes) {
            if (box.state !== 'belt' || box.downstream) continue;
            if (!front || box.pos.z > front.pos.z) front = box;
        }
        return front && !front.reserved && front.pos.z >= STOP_BOX_Z - 0.005 ? front : null;
    };

    const dropHeldBox = () => {
        const { arm } = sim;
        if (arm.heldBox) {
            arm.heldBox.state = 'falling';
            arm.heldBox.vy = 0;
            arm.heldBox.spin = (Math.random() - 0.5) * 6;
            arm.heldBox = null;
        }
    };

    const abortJob = () => {
        const { arm, pallet } = sim;
        if (arm.job) {
            arm.job.box.reserved = false;
            if (arm.job.box.state !== 'pallet') pallet.nextSlot = arm.job.slot;
        }
        dropHeldBox();
        arm.job = null;
        arm.step = null;
        arm.steps = [];
    };

    const updateBelt = (dt, t, conveyorMalicious) => {
        let speed = BELT_SPEED;
        if (conveyorMalicious) {
            // Erratic drive: surges, stalls and brief reversals
            const noise = Math.sin(t * 10) + Math.cos(t * 4);
            speed = noise > 0.5 ? 6 : noise < -0.5 ? -1.5 : 0;
        }
        beltSpeedRef.current = speed;

        const queue = [];
        for (const box of sim.boxes) {
            if (box.state !== 'belt') continue;
            if (box.downstream) {
                box.pos.z += speed * dt;
                if (box.pos.z > BELT_LENGTH / 2 - 0.1) box.state = 'hidden'; // ran off the end
                continue;
            }
            if (!box.reserved) box.pos.z += speed * dt;
            queue.push(box);
        }

        // Accumulate against the stopper with a fixed gap between cartons
        queue.sort((a, b) => b.pos.z - a.pos.z);
        let limit = STOP_BOX_Z;
        // A carton that is still being lifted off the belt blocks the one behind it
        const held = sim.arm.heldBox;
        if (held && Math.abs(held.pos.x - BELT_POS[0]) < BELT_WIDTH / 2 && held.pos.y < BELT_BOX_Y + BOX.h + 0.05) {
            limit = Math.min(limit, held.pos.z - QUEUE_SPACING);
        }
        for (const box of queue) {
            if (!box.reserved) box.pos.z = Math.min(box.pos.z, limit);
            limit = box.pos.z - QUEUE_SPACING;
        }
        // ...and don't let a reversing belt push them back past the infeed
        limit = SPAWN_Z;
        for (let i = queue.length - 1; i >= 0; i--) {
            const box = queue[i];
            if (!box.reserved) box.pos.z = Math.max(box.pos.z, limit);
            limit = box.pos.z + QUEUE_SPACING;
        }

        sim.spawnTimer += dt;
        const lastZ = queue.length ? queue[queue.length - 1].pos.z : Infinity;
        if (
            sim.spawnTimer >= SPAWN_INTERVAL &&
            speed > 0 &&
            queue.length < MAX_QUEUE &&
            lastZ > SPAWN_Z + QUEUE_SPACING + 0.1
        ) {
            const box = sim.boxes.find((b) => b.state === 'hidden');
            if (box) {
                box.state = 'belt';
                box.pos.set(BELT_POS[0], BELT_BOX_Y, SPAWN_Z);
                box.yaw = 0;
                box.reserved = false;
                box.downstream = false;
                sim.spawnTimer = 0;
            }
        }
    };

    const updatePallet = (dt) => {
        const { pallet, arm } = sim;
        const prevOffset = pallet.offset;

        if (pallet.phase === 'loading') {
            const full = pallet.nextSlot >= PALLET_SLOTS.length;
            if (full && !arm.job && arm.mode === 'normal') {
                pallet.phase = 'out';
                pallet.t = 0;
            }
        } else {
            pallet.t += dt / PALLET_TRAVEL_TIME;
            const k = smootherstep(clamp(pallet.t, 0, 1));
            if (pallet.phase === 'out') {
                pallet.offset = k * PALLET_EXIT_DISTANCE;
                if (pallet.t >= 1) {
                    // Loaded pallet has left the cell; an empty one comes back in
                    sim.boxes.forEach((b) => { if (b.state === 'pallet') b.state = 'hidden'; });
                    pallet.phase = 'in';
                    pallet.t = 0;
                }
            } else {
                pallet.offset = (1 - k) * PALLET_EXIT_DISTANCE;
                if (pallet.t >= 1) {
                    pallet.phase = 'loading';
                    pallet.offset = 0;
                    pallet.nextSlot = 0;
                }
            }
        }

        const station = palletRef.current;
        if (station?.pallet) {
            station.pallet.position.z = pallet.offset;
            const spin = (pallet.offset - prevOffset) / PALLET_ROLLER_RADIUS;
            station.rollers.forEach((r) => { if (r) r.rotation.x += spin; });
        }
    };

    const updateArm = (dt, t, armMalicious) => {
        const { arm, pallet } = sim;

        if (armMalicious && arm.mode === 'normal') {
            abortJob();
            arm.mode = 'malicious';
        } else if (!armMalicious && arm.mode === 'malicious') {
            // Recover: resume from wherever the arm actually is and clean up spilled cartons
            arm.mode = 'normal';
            arm.joints.psi = wrapPi(arm.joints.psi);
            arm.joints.roll -= Math.PI * Math.round(arm.joints.roll / Math.PI);
            forwardKinematics(arm.joints, null, arm.pose);
            arm.gripTarget = 0;
            sim.boxes.forEach((b) => { if (b.state === 'floor') b.state = 'hidden'; });
        }

        let stiffness;
        if (arm.mode === 'malicious') {
            // Erratic, jerky motion with the gripper chattering
            const d = arm.desired;
            d.psi = HOME_POSE.psi + Math.sin(t * 2.3) * 1.6 + Math.sin(t * 7.1) * 0.4 + (Math.random() - 0.5) * 0.3;
            d.phi1 = 1.0 + Math.sin(t * 5.3) * 0.4;
            d.phi2 = d.phi1 - (1.4 + Math.sin(t * 6.7) * 0.5);
            // Keep the tool above the floor
            const minSin = (0.5 + ARM.TOOL - ARM.SHOULDER_HEIGHT - ARM.UPPER * Math.sin(d.phi1)) / ARM.FORE;
            d.phi2 = Math.max(d.phi2, Math.asin(clamp(minSin, -1, 1)));
            d.roll = arm.joints.roll + 8 * dt;
            arm.gripTarget = Math.sin(t * 20) > 0 ? 1 : 0;
            stiffness = 6;
        } else {
            if (!arm.step && arm.steps.length === 0) {
                const box = pallet.phase === 'loading' && pallet.nextSlot < PALLET_SLOTS.length
                    ? frontBoxAtStop()
                    : null;
                if (box) {
                    planPick(box);
                } else if (poseDistance(arm.pose, HOME_POSE) > 0.01) {
                    arm.steps.push({ kind: 'move', to: { ...HOME_POSE }, speed: FAST * 0.7 });
                }
            }
            runArmSequence(dt);
            solveIK(arm.pose, arm.desired);
            stiffness = 22;
        }

        const j = arm.joints;
        const d = arm.desired;
        j.psi = damp(j.psi, j.psi + wrapPi(d.psi - j.psi), stiffness, dt);
        j.phi1 = damp(j.phi1, d.phi1, stiffness, dt);
        j.phi2 = damp(j.phi2, d.phi2, stiffness, dt);
        j.roll = damp(j.roll, d.roll, stiffness, dt);
        arm.grip = damp(arm.grip, arm.gripTarget, 14, dt);

        if (armRef.current?.turret) applyJointsToRig(armRef.current, j, arm.grip);

        // Held carton follows the actual gripper, not the commanded pose
        if (arm.heldBox) {
            forwardKinematics(j, arm.heldBox.pos);
            arm.heldBox.yaw = j.psi + j.roll + arm.heldBox.yawOffset;
        }
    };

    const updateFalling = (dt) => {
        const halfBelt = BELT_WIDTH / 2;
        for (const box of sim.boxes) {
            if (box.state !== 'falling') continue;
            box.vy -= GRAVITY * dt;
            box.pos.y += box.vy * dt;
            box.yaw += box.spin * dt;

            const overBelt = Math.abs(box.pos.x - BELT_POS[0]) < halfBelt &&
                Math.abs(box.pos.z - BELT_POS[2]) < BELT_LENGTH / 2;
            const overBed = Math.abs(box.pos.x - PALLET_HOME[0]) < 0.9 &&
                box.pos.z > PALLET_HOME[2] - 1.1;
            const ground = overBelt ? BELT_BOX_Y : (overBed ? ROLLER_BED_TOP : 0) + BOX.h / 2;

            if (box.pos.y <= ground) {
                box.pos.y = ground;
                if (overBelt) {
                    box.state = 'belt';
                    box.pos.x = BELT_POS[0];
                    box.yaw = 0;
                    box.downstream = box.pos.z > STOP_BOX_Z + 0.05;
                } else {
                    box.state = 'floor';
                }
            }
        }
    };

    const renderBoxes = (conveyorMalicious) => {
        const { pallet } = sim;
        sim.boxes.forEach((box, i) => {
            const mesh = boxMeshesRef.current[i];
            if (!mesh) return;
            mesh.visible = box.state !== 'hidden';
            if (!mesh.visible) return;

            if (box.state === 'pallet') {
                const [x, y, z] = slotPosition(box.slot, pallet.offset);
                mesh.position.set(x, y, z);
            } else {
                mesh.position.copy(box.pos);
            }
            mesh.rotation.set(0, box.yaw, 0);

            const material = conveyorMalicious && box.state === 'belt' ? cartonAlertMaterial : cartonMaterial;
            if (mesh.children[0].material !== material) mesh.children[0].material = material;
        });
    };

    useFrame((state, delta) => {
        const dt = Math.min(delta, 0.05);
        const t = state.clock.getElapsedTime();
        const { roboticArmMalicious, conveyorBeltMalicious } = useStore.getState();

        updateBelt(dt, t, conveyorBeltMalicious);
        updatePallet(dt);
        updateArm(dt, t, roboticArmMalicious);
        updateFalling(dt);
        renderBoxes(conveyorBeltMalicious);
    });

    return (
        <group>
            <RoboticArm ref={armRef} position={ARM_POS} />
            <ConveyorBelt position={BELT_POS} speedRef={beltSpeedRef} />
            <PalletStation ref={palletRef} position={PALLET_HOME} />

            {/* Carton pool */}
            {sim.boxes.map((box, i) => (
                <group key={box.id} ref={el => boxMeshesRef.current[i] = el} visible={false}>
                    <mesh castShadow receiveShadow material={cartonMaterial}>
                        <boxGeometry args={[BOX.w, BOX.h, BOX.d]} />
                    </mesh>
                    {/* Packing tape across the top */}
                    <mesh position={[0, BOX.h / 2 + 0.002, 0]}>
                        <boxGeometry args={[0.14, 0.004, BOX.d + 0.004]} />
                        <meshStandardMaterial color="#a8834f" roughness={0.4} />
                    </mesh>
                </group>
            ))}
        </group>
    );
};

export default PalletizingCell;
