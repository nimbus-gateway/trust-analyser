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

import React, { useRef, useState, useEffect } from 'react';
import { Html } from '@react-three/drei';
import useStore from '../store/useStore';

const Computer = ({ position }) => {
    const isMalicious = useStore((state) => state.computerMalicious);
    const [graphs, setGraphs] = useState([50, 70, 30, 90, 60, 40, 80, 50, 60, 30]);

    useEffect(() => {
        const interval = setInterval(() => {
            setGraphs(prev => {
                const newGraphs = [...prev];
                newGraphs.shift();
                newGraphs.push(isMalicious ? Math.random() * 100 : 30 + Math.random() * 40);
                return newGraphs;
            });
        }, isMalicious ? 100 : 500);

        return () => clearInterval(interval);
    }, [isMalicious]);

    return (
        <group position={position}>
            {/* Desk */}
            <mesh castShadow receiveShadow position={[0, 0.5, 0]}>
                <boxGeometry args={[3, 1, 1.5]} />
                <meshStandardMaterial color="#334155" />
            </mesh>
            <mesh castShadow receiveShadow position={[-1.4, 0.25, 0]}>
                <boxGeometry args={[0.1, 0.5, 1.4]} />
                <meshStandardMaterial color="#1e293b" />
            </mesh>
            <mesh castShadow receiveShadow position={[1.4, 0.25, 0]}>
                <boxGeometry args={[0.1, 0.5, 1.4]} />
                <meshStandardMaterial color="#1e293b" />
            </mesh>

            {/* Monitor Body */}
            <mesh castShadow receiveShadow position={[0, 1.5, -0.4]} rotation={[-0.1, 0, 0]}>
                <boxGeometry args={[2.2, 1.4, 0.2]} />
                <meshStandardMaterial color="#0f172a" metalness={0.8} roughness={0.2} />
            </mesh>

            {/* Monitor Stand */}
            <mesh castShadow receiveShadow position={[0, 1.2, -0.4]}>
                <cylinderGeometry args={[0.1, 0.2, 0.6, 16]} />
                <meshStandardMaterial color="#475569" />
            </mesh>

            {/* Monitor Screen with HTML Overlay inside the 3D scene */}
            <Html
                position={[0, 1.5, -0.29]}
                rotation={[-0.1, 0, 0]}
                transform
                occlude
                scale={0.1}
            >
                <div className={`computer-screen ${isMalicious ? 'malicious' : ''}`} style={{ width: '800px', height: '500px' }}>
                    {isMalicious && (
                        <div className="hacked-text">SYSTEM HACKED</div>
                    )}

                    <div className="screen-header">
                        <span>{isMalicious ? 'BREACH DETECTED - UNAUTHORIZED ACCESS' : 'TELEMETRY SERVER SECURE'}</span>
                        <span>{new Date().toLocaleTimeString()}</span>
                    </div>

                    <div className="screen-content">
                        {isMalicious ? (
                            <>
                                <p>ERR_CONNECTION_REFUSED</p>
                                <p>DATA EXFILTRATION IN PROGRESS...</p>
                                <p>OVERRIDING COOLING SYSTEMS</p>
                                <p>FIREWALL BREACHED AT PORT 8080</p>
                                <p>OVERLOADING MAINFRAME...</p>
                            </>
                        ) : (
                            <>
                                <p>CPU Usage: 34% - Normal</p>
                                <p>Memory: 16GB / 64GB</p>
                                <p>Conveyor Belt Efficiency: 98%</p>
                                <p>Robotic Arm Calibrated</p>
                                <p>All sensors functioning optimally.</p>
                            </>
                        )}
                    </div>

                    <div className="screen-graph">
                        {graphs.map((val, i) => (
                            <div
                                key={i}
                                className="graph-bar"
                                style={{ height: `${val}%` }}
                            ></div>
                        ))}
                    </div>
                </div>
            </Html>

            {/* Keyboard */}
            <mesh castShadow receiveShadow position={[0, 1.05, 0.2]} rotation={[0.05, 0, 0]}>
                <boxGeometry args={[1, 0.05, 0.4]} />
                <meshStandardMaterial color="#0f172a" />
            </mesh>
        </group>
    );
};

export default Computer;
