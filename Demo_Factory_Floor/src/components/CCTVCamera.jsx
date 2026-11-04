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

import React, { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import useStore from '../store/useStore';
import * as THREE from 'three';

const CCTVCamera = ({ position }) => {
    const isMalicious = useStore((state) => state.cctvCameraMalicious);
    const headRef = useRef();
    const ledRef = useRef();

    useFrame((state, delta) => {
        const t = state.clock.getElapsedTime();

        if (isMalicious) {
            // Erratic twitching
            if (Math.random() > 0.8) {
                headRef.current.rotation.y = THREE.MathUtils.lerp(
                    headRef.current.rotation.y,
                    (Math.random() - 0.5) * Math.PI,
                    0.5
                );
                headRef.current.rotation.x = THREE.MathUtils.lerp(
                    headRef.current.rotation.x,
                    (Math.random() - 0.5) * Math.PI / 4,
                    0.5
                );
            }

            // Blinking red light
            if (ledRef.current) {
                ledRef.current.material.color.setHex(Math.sin(t * 20) > 0 ? 0xef4444 : 0x000000);
                ledRef.current.material.emissive.setHex(Math.sin(t * 20) > 0 ? 0xef4444 : 0x000000);
            }
        } else {
            // Smooth scanning
            headRef.current.rotation.y = Math.sin(t * 0.5) * Math.PI / 4;
            headRef.current.rotation.x = -0.2; // slight downward tilt

            // Steady green light
            if (ledRef.current) {
                ledRef.current.material.color.setHex(0x22c55e);
                ledRef.current.material.emissive.setHex(0x22c55e);
            }
        }
    });

    return (
        <group position={position}>
            {/* Wall/Ceiling Mount */}
            <mesh castShadow receiveShadow position={[0, 0, 0]}>
                <cylinderGeometry args={[0.2, 0.2, 0.5, 16]} />
                <meshStandardMaterial color="#cbd5e1" metalness={0.7} roughness={0.3} />
            </mesh>
            <mesh castShadow receiveShadow position={[0, -0.4, 0]}>
                <sphereGeometry args={[0.2, 16, 16]} />
                <meshStandardMaterial color="#94a3b8" metalness={0.8} roughness={0.2} />
            </mesh>

            {/* Rotating Head */}
            <group ref={headRef} position={[0, -0.4, 0]}>
                {/* Camera Body */}
                <mesh castShadow receiveShadow position={[0, 0, 0.4]}>
                    <boxGeometry args={[0.4, 0.4, 0.8]} />
                    <meshStandardMaterial color="#e2e8f0" metalness={0.3} roughness={0.5} />
                </mesh>

                {/* Lens */}
                <mesh castShadow receiveShadow position={[0, 0, 0.85]} rotation={[Math.PI / 2, 0, 0]}>
                    <cylinderGeometry args={[0.15, 0.15, 0.1, 32]} />
                    <meshStandardMaterial color="#0f172a" metalness={0.9} roughness={0.1} />
                </mesh>

                {/* Status LED */}
                <mesh ref={ledRef} position={[0.15, 0.15, 0.81]}>
                    <sphereGeometry args={[0.03, 8, 8]} />
                    <meshStandardMaterial color="#22c55e" emissive="#22c55e" emissiveIntensity={2} />
                </mesh>

                {/* UI Overlay Label */}
                <Html position={[0, 0.5, 0]} center as="div" className={`cctv-label ${isMalicious ? 'malicious' : ''}`}>
                    CAM-01
                </Html>
            </group>
        </group>
    );
};

export default CCTVCamera;
