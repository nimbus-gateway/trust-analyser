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

import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { BELT_LENGTH, BELT_TOP, BELT_POS, STOPPER_Z } from '../sim/cellLayout';

const ROLLER_RADIUS = 0.15;

// Visual conveyor. The cartons on it are owned by PalletizingCell, which also
// decides the belt speed and shares it through speedRef.
const ConveyorBelt = ({ position, speedRef }) => {
    const beltMaterialRef = useRef();
    const gearsRef = useRef([]);

    // Creates a simple stripe texture for the belt
    const beltTexture = useMemo(() => {
        const canvas = document.createElement('canvas');
        canvas.width = 256;
        canvas.height = 256;
        const context = canvas.getContext('2d');
        context.fillStyle = '#222';
        context.fillRect(0, 0, 256, 256);
        context.fillStyle = '#333';
        for (let i = 0; i < 256; i += 32) {
            context.fillRect(0, i, 256, 16);
        }
        const tex = new THREE.CanvasTexture(canvas);
        tex.wrapS = THREE.RepeatWrapping;
        tex.wrapT = THREE.RepeatWrapping;
        tex.repeat.set(1, BELT_LENGTH);
        return tex;
    }, []);

    useFrame((state, delta) => {
        const distance = (speedRef?.current ?? 0) * Math.min(delta, 0.05);

        // One texture repeat per world unit, so the stripes move with the cartons
        if (beltMaterialRef.current) {
            beltMaterialRef.current.map.offset.y += distance;
        }

        gearsRef.current.forEach(gear => {
            if (gear) gear.rotation.x += distance / ROLLER_RADIUS;
        });
    });

    const stopperTop = BELT_TOP - BELT_POS[1] + 0.25;

    return (
        <group position={position}>
            {/* Belt Frame */}
            <mesh castShadow receiveShadow position={[0, -0.2, 0]}>
                <boxGeometry args={[2.2, 0.4, BELT_LENGTH + 0.2]} />
                <meshStandardMaterial color="#475569" metalness={0.6} roughness={0.4} />
            </mesh>

            {/* The Belt */}
            <mesh receiveShadow position={[0, 0.05, 0]} rotation={[-Math.PI / 2, 0, 0]}>
                <planeGeometry args={[2, BELT_LENGTH]} />
                <meshStandardMaterial ref={beltMaterialRef} map={beltTexture} roughness={0.8} />
            </mesh>

            {/* Side Rails */}
            <mesh castShadow receiveShadow position={[-1.1, 0.2, 0]}>
                <boxGeometry args={[0.1, 0.4, BELT_LENGTH]} />
                <meshStandardMaterial color="#3b82f6" metalness={0.8} roughness={0.2} />
            </mesh>
            <mesh castShadow receiveShadow position={[1.1, 0.2, 0]}>
                <boxGeometry args={[0.1, 0.4, BELT_LENGTH]} />
                <meshStandardMaterial color="#3b82f6" metalness={0.8} roughness={0.2} />
            </mesh>

            {/* Gears/Rollers */}
            {[-4.8, -2.4, 0, 2.4, 4.8].map((zPos, i) => (
                <mesh
                    key={`gear-${i}`}
                    ref={el => gearsRef.current[i] = el}
                    position={[0, -0.05, zPos]}
                    rotation={[0, 0, Math.PI / 2]}
                >
                    <cylinderGeometry args={[ROLLER_RADIUS, ROLLER_RADIUS, 2.1, 16]} />
                    <meshStandardMaterial color="#94a3b8" metalness={0.9} roughness={0.1} />
                </mesh>
            ))}

            {/* Infeed hood: cartons enter the cell from here */}
            <group position={[0, 0, -BELT_LENGTH / 2 + 0.55]}>
                <mesh castShadow receiveShadow position={[0, 0.85, 0]}>
                    <boxGeometry args={[2.4, 0.1, 1.1]} />
                    <meshStandardMaterial color="#1e293b" metalness={0.6} roughness={0.4} />
                </mesh>
                {[-1.17, 1.17].map((x) => (
                    <mesh key={x} castShadow receiveShadow position={[x, 0.45, 0]}>
                        <boxGeometry args={[0.06, 0.8, 1.1]} />
                        <meshStandardMaterial color="#1e293b" metalness={0.6} roughness={0.4} />
                    </mesh>
                ))}
                <mesh position={[0, 0.79, 0.56]}>
                    <boxGeometry args={[2.4, 0.04, 0.02]} />
                    <meshStandardMaterial color="#f59e0b" emissive="#f59e0b" emissiveIntensity={0.4} />
                </mesh>
            </group>

            {/* Pick-station stopper: cartons accumulate against this bar */}
            <group position={[0, 0, STOPPER_Z]}>
                <mesh castShadow receiveShadow position={[0, stopperTop - 0.04, 0]}>
                    <boxGeometry args={[2.1, 0.08, 0.06]} />
                    <meshStandardMaterial color="#f59e0b" metalness={0.4} roughness={0.5} />
                </mesh>
                {/* Pneumatic actuator housing on the outside of the rail */}
                <mesh castShadow receiveShadow position={[1.24, 0.25, 0]}>
                    <boxGeometry args={[0.16, 0.3, 0.16]} />
                    <meshStandardMaterial color="#64748b" metalness={0.7} roughness={0.3} />
                </mesh>
            </group>
        </group>
    );
};

export default ConveyorBelt;
