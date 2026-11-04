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

import React, { forwardRef, useImperativeHandle, useRef } from 'react';
import useStore from '../store/useStore';
import { ARM } from '../sim/cellLayout';

// Pure rig: joint groups are exposed through the ref and driven by PalletizingCell.
const RoboticArm = forwardRef(({ position }, ref) => {
    const isMalicious = useStore((state) => state.roboticArmMalicious);

    const turretRef = useRef();
    const shoulderRef = useRef();
    const elbowRef = useRef();
    const wristRef = useRef();
    const rollRef = useRef();
    const fingerLeftRef = useRef();
    const fingerRightRef = useRef();

    useImperativeHandle(ref, () => ({
        get turret() { return turretRef.current; },
        get shoulder() { return shoulderRef.current; },
        get elbow() { return elbowRef.current; },
        get wrist() { return wristRef.current; },
        get roll() { return rollRef.current; },
        get fingerLeft() { return fingerLeftRef.current; },
        get fingerRight() { return fingerRightRef.current; },
    }));

    const materialParams = {
        color: '#e2e8f0',
        metalness: 0.8,
        roughness: 0.2,
    };

    const accentMaterialParams = isMalicious
        ? { color: '#ef4444', emissive: '#ef4444', emissiveIntensity: 0.5 }
        : { color: '#3b82f6', metalness: 0.5, roughness: 0.4 };

    const darkMaterialParams = { color: '#334155', metalness: 0.7, roughness: 0.35 };

    const fingerLength = 0.52;
    const fingerTop = -0.36;

    const finger = (fingerRef, side) => (
        <group ref={fingerRef} position={[side * (ARM.FINGER_OPEN + ARM.FINGER_THICKNESS / 2), fingerTop, 0]}>
            <mesh castShadow receiveShadow position={[0, -fingerLength / 2, 0]}>
                <boxGeometry args={[ARM.FINGER_THICKNESS, fingerLength, 0.2]} />
                <meshStandardMaterial {...materialParams} />
            </mesh>
            {/* Rubber grip pad on the inner face */}
            <mesh position={[-side * (ARM.FINGER_THICKNESS / 2 - 0.005), -fingerLength + 0.17, 0]}>
                <boxGeometry args={[0.012, 0.22, 0.18]} />
                <meshStandardMaterial color="#111827" roughness={0.9} />
            </mesh>
        </group>
    );

    return (
        <group position={position}>
            {/* Pedestal */}
            <mesh castShadow receiveShadow position={[0, 0.175, 0]}>
                <cylinderGeometry args={[0.65, 0.8, 0.35, 32]} />
                <meshStandardMaterial {...darkMaterialParams} />
            </mesh>

            {/* Turret (base yaw) */}
            <group ref={turretRef} position={[0, 0.35, 0]}>
                <mesh castShadow receiveShadow position={[0, 0.2, 0]}>
                    <cylinderGeometry args={[0.55, 0.6, 0.4, 32]} />
                    <meshStandardMaterial {...accentMaterialParams} />
                </mesh>
                {/* Shoulder yoke */}
                {[-0.24, 0.24].map((z) => (
                    <mesh key={z} castShadow receiveShadow position={[0, 0.55, z]}>
                        <boxGeometry args={[0.45, 0.5, 0.08]} />
                        <meshStandardMaterial {...materialParams} />
                    </mesh>
                ))}

                {/* Shoulder pitch */}
                <group ref={shoulderRef} position={[0, ARM.SHOULDER_HEIGHT - 0.35, 0]}>
                    <mesh castShadow receiveShadow rotation={[Math.PI / 2, 0, 0]}>
                        <cylinderGeometry args={[0.24, 0.24, 0.4, 32]} />
                        <meshStandardMaterial {...accentMaterialParams} />
                    </mesh>
                    <mesh castShadow receiveShadow position={[0, ARM.UPPER / 2, 0]}>
                        <boxGeometry args={[0.32, ARM.UPPER, 0.32]} />
                        <meshStandardMaterial {...materialParams} />
                    </mesh>

                    {/* Elbow pitch */}
                    <group ref={elbowRef} position={[0, ARM.UPPER, 0]}>
                        <mesh castShadow receiveShadow rotation={[Math.PI / 2, 0, 0]}>
                            <cylinderGeometry args={[0.2, 0.2, 0.42, 32]} />
                            <meshStandardMaterial {...accentMaterialParams} />
                        </mesh>
                        <mesh castShadow receiveShadow position={[0, ARM.FORE / 2, 0]}>
                            <boxGeometry args={[0.24, ARM.FORE, 0.24]} />
                            <meshStandardMaterial {...materialParams} />
                        </mesh>

                        {/* Wrist pitch keeps the tool vertical */}
                        <group ref={wristRef} position={[0, ARM.FORE, 0]}>
                            <mesh castShadow receiveShadow>
                                <sphereGeometry args={[0.17, 32, 32]} />
                                <meshStandardMaterial {...accentMaterialParams} />
                            </mesh>

                            {/* Wrist roll + parallel-jaw gripper */}
                            <group ref={rollRef}>
                                <mesh castShadow receiveShadow position={[0, -0.14, 0]}>
                                    <cylinderGeometry args={[0.12, 0.12, 0.12, 24]} />
                                    <meshStandardMaterial {...darkMaterialParams} />
                                </mesh>
                                <mesh castShadow receiveShadow position={[0, -0.28, 0]}>
                                    <boxGeometry args={[1.0, 0.16, 0.24]} />
                                    <meshStandardMaterial {...darkMaterialParams} />
                                </mesh>
                                {finger(fingerLeftRef, -1)}
                                {finger(fingerRightRef, 1)}
                            </group>
                        </group>
                    </group>
                </group>
            </group>
        </group>
    );
});

RoboticArm.displayName = 'RoboticArm';

export default RoboticArm;
