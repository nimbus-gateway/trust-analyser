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

import React from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Environment, ContactShadows, Sky } from '@react-three/drei';
import PalletizingCell from './PalletizingCell';
import CCTVCamera from './CCTVCamera';
import Computer from './Computer';
import MobilePhone from './MobilePhone';

const Scene = () => {
    return (
        <Canvas
            camera={{ position: [8, 6, 8], fov: 45 }}
            shadows
            dpr={[1, 2]}
        >
            <color attach="background" args={['#0d0d12']} />

            <ambientLight intensity={0.5} />
            <directionalLight
                position={[10, 10, 5]}
                intensity={1.5}
                castShadow
                shadow-mapSize-width={1024}
                shadow-mapSize-height={1024}
            />
            <pointLight position={[-10, -10, -10]} intensity={0.5} />

            <group position={[0, -1.5, 0]}>
                {/* Factory Floor Grid */}
                <mesh rotation={[-Math.PI / 2, 0, 0]} receiveShadow position={[0, -0.01, 0]}>
                    <planeGeometry args={[30, 30]} />
                    <meshStandardMaterial color="#1f1f2e" metalness={0.5} roughness={0.8} />
                </mesh>
                <gridHelper args={[30, 30, '#3b82f6', '#222233']} position={[0, 0, 0]} />

                {/* 3D Entities */}
                {/* Robot arm, infeed conveyor and pallet station driven as one cell */}
                <PalletizingCell />
                <CCTVCamera position={[4, 4, -4]} />
                <Computer position={[3, 0, 3]} />
                <MobilePhone position={[2.2, 1.0, 3.2]} />

                {/* Shadow Catcher */}
                <ContactShadows resolution={1024} scale={20} blur={2} opacity={0.5} far={10} color="#000000" />
            </group>

            <Environment files="/hdri/dikhololo_night_1k.hdr" />
            <OrbitControls
                makeDefault
                minPolarAngle={0}
                maxPolarAngle={Math.PI / 2 - 0.05}
                minDistance={5}
                maxDistance={25}
            />
        </Canvas>
    );
};

export default Scene;
