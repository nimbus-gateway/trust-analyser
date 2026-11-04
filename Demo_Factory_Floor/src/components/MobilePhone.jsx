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
import { Html } from '@react-three/drei';
import useStore from '../store/useStore';
import { Smartphone } from 'lucide-react';

const MobilePhone = ({ position }) => {
    const isMalicious = useStore((state) => state.mobilePhoneMalicious);

    if (!isMalicious) return null;

    return (
        <group position={position}>
            {/* Phone Body */}
            <mesh castShadow receiveShadow position={[0, 0.4, 0]} rotation={[-0.2, 0, 0]}>
                <boxGeometry args={[0.4, 0.8, 0.05]} />
                <meshStandardMaterial color="#1e293b" metalness={0.8} roughness={0.2} />
            </mesh>
            
            {/* Screen background */}
            <mesh position={[0, 0.4, 0.026]} rotation={[-0.2, 0, 0]}>
                <boxGeometry args={[0.36, 0.74, 0.01]} />
                <meshStandardMaterial color="#000000" emissive="#330000" emissiveIntensity={0.5} />
            </mesh>
            
            {/* Phone Screen HTML */}
            <Html
                position={[0, 0.4, 0.035]}
                rotation={[-0.2, 0, 0]}
                transform
                occlude
                scale={0.06}
            >
                <div style={{
                    width: '120px', 
                    height: '240px', 
                    background: 'rgba(20, 0, 0, 0.85)',
                    color: '#ff4444', 
                    border: '1px solid #ff4444', 
                    borderRadius: '8px',
                    display: 'flex', 
                    flexDirection: 'column', 
                    alignItems: 'center', 
                    justifyContent: 'center',
                    fontFamily: 'monospace', 
                    textAlign: 'center',
                    padding: '8px',
                    boxSizing: 'border-box',
                    boxShadow: '0 0 10px rgba(255, 0, 0, 0.3) inset'
                }}>
                    <Smartphone size={32} style={{ marginBottom: '12px' }} />
                    <p style={{ margin: '0 0 8px 0', fontWeight: 'bold', fontSize: '14px' }}>BREACH</p>
                    <p style={{ margin: 0, fontSize: '10px', wordBreak: 'break-word', color: '#ffaaaa' }}>ATC_NETWORK CONNECTED</p>
                </div>
            </Html>
        </group>
    );
};

export default MobilePhone;
