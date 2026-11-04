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
import { PALLET_EXIT_DISTANCE, ROLLER_BED_TOP } from '../sim/cellLayout';

export const PALLET_ROLLER_RADIUS = 0.05;
const BED_START = -1.1;
const BED_END = PALLET_EXIT_DISTANCE + 0.9;
const ROLLER_Z = Array.from(
    { length: Math.floor((BED_END - BED_START) / 0.4) },
    (_, i) => BED_START + 0.2 + i * 0.4
);

// Roller bed + wooden pallet. PalletizingCell slides the pallet group out along
// the bed when it is full and brings an empty one back in.
const PalletStation = forwardRef(({ position }, ref) => {
    const palletRef = useRef();
    const rollersRef = useRef([]);

    useImperativeHandle(ref, () => ({
        get pallet() { return palletRef.current; },
        get rollers() { return rollersRef.current; },
    }));

    const bedLength = BED_END - BED_START;
    const bedCenter = (BED_START + BED_END) / 2;
    const rollerY = ROLLER_BED_TOP - PALLET_ROLLER_RADIUS;

    return (
        <group position={position}>
            {/* Roller bed frame */}
            {[-0.85, 0.85].map((x) => (
                <mesh key={x} castShadow receiveShadow position={[x, ROLLER_BED_TOP / 2 + 0.02, bedCenter]}>
                    <boxGeometry args={[0.08, ROLLER_BED_TOP + 0.04, bedLength]} />
                    <meshStandardMaterial color="#3b82f6" metalness={0.8} roughness={0.25} />
                </mesh>
            ))}
            {ROLLER_Z.map((z, i) => (
                <mesh
                    key={z}
                    ref={el => rollersRef.current[i] = el}
                    receiveShadow
                    position={[0, rollerY, z]}
                    rotation={[0, 0, Math.PI / 2]}
                >
                    <cylinderGeometry args={[PALLET_ROLLER_RADIUS, PALLET_ROLLER_RADIUS, 1.62, 12]} />
                    <meshStandardMaterial color="#94a3b8" metalness={0.9} roughness={0.15} />
                </mesh>
            ))}

            {/* Wooden pallet */}
            <group ref={palletRef} position={[0, ROLLER_BED_TOP, 0]}>
                {[-0.7, 0, 0.7].map((z) => (
                    <mesh key={`block-${z}`} castShadow receiveShadow position={[0, 0.05, z]}>
                        <boxGeometry args={[1.6, 0.1, 0.16]} />
                        <meshStandardMaterial color="#7c4a1e" roughness={0.95} />
                    </mesh>
                ))}
                {[-0.68, -0.34, 0, 0.34, 0.68].map((z) => (
                    <mesh key={`slat-${z}`} castShadow receiveShadow position={[0, 0.12, z]}>
                        <boxGeometry args={[1.6, 0.04, 0.24]} />
                        <meshStandardMaterial color="#8b5a2b" roughness={0.9} />
                    </mesh>
                ))}
            </group>
        </group>
    );
});

PalletStation.displayName = 'PalletStation';

export default PalletStation;
