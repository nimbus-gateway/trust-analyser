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

import React, { useState } from 'react';
import { Activity, Camera, Cpu, Zap, ShieldAlert, ShieldCheck, Settings, Smartphone } from 'lucide-react';
import useStore from '../store/useStore';
import ConfigPage from './ConfigPage';
import logoTelemetry from '../assets/Logo-Telemetry.png';
import nimbusLogo from '../assets/Nimbus-Logo.png';

const UI = () => {
    const {
        roboticArmMalicious,
        conveyorBeltMalicious,
        cctvCameraMalicious,
        computerMalicious,
        mobilePhoneMalicious,
        toggleRoboticArm,
        toggleConveyorBelt,
        toggleCCTVCamera,
        toggleComputer,
        toggleMobilePhone,
        setAllNormal,
        setAllMalicious,
        activeTab,
        setActiveTab
    } = useStore();

    const [showConfig, setShowConfig] = useState(false);

    const isAnyMalicious = roboticArmMalicious || conveyorBeltMalicious || cctvCameraMalicious || computerMalicious || mobilePhoneMalicious;

    return (
        <div className="ui-container">
            <header className="ui-header glass-panel">
                <div className="title-container" style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
                        <img src={logoTelemetry} alt="Telemetry Logo" style={{ height: '42px', objectFit: 'contain' }} />
                        <img src={nimbusLogo} alt="Nimbus Logo" style={{ height: '32px', objectFit: 'contain' }} />
                        <div>
                            <h1 className="app-title">FACTORY_FLOOR</h1>
                            <div className="app-subtitle">
                                <div className={`status-dot ${isAnyMalicious ? 'malicious' : ''}`}></div>
                                <span>{isAnyMalicious ? 'SYSTEM COMPROMISED' : 'SYSTEM OPERATIONAL'}</span>
                                <span className="text-muted" style={{ marginLeft: '12px', fontSize: '12px' }}>v2.4.1</span>
                            </div>
                        </div>
                    </div>
                    
                    <div className="tab-navigation" style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(0,0,0,0.5)', padding: '4px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                        <button 
                            style={{ 
                                padding: '8px 16px', 
                                border: 'none', 
                                borderRadius: '4px', 
                                cursor: 'pointer',
                                fontWeight: '600',
                                transition: 'all 0.2s',
                                background: activeTab === 'simulator' ? '#4fc3f7' : 'transparent',
                                color: activeTab === 'simulator' ? '#000' : '#888'
                            }} 
                            onClick={() => setActiveTab('simulator')}
                        >
                            Simulator
                        </button>
                        <button 
                            style={{ 
                                padding: '8px 16px', 
                                border: 'none', 
                                borderRadius: '4px', 
                                cursor: 'pointer',
                                fontWeight: '600',
                                transition: 'all 0.2s',
                                background: activeTab === 'presentation' ? '#4fc3f7' : 'transparent',
                                color: activeTab === 'presentation' ? '#000' : '#888'
                            }} 
                            onClick={() => setActiveTab('presentation')}
                        >
                            Presentation
                        </button>
                    </div>

                    <button
                        className="btn btn-normal settings-btn"
                        onClick={() => setShowConfig(true)}
                        title="Configuration"
                    >
                        <Settings size={24} />
                    </button>
                </div>
            </header>

            {activeTab === 'simulator' && (
            <div className="controls-panel glass-panel">
                <h2 className="controls-header">
                    <Activity size={20} />
                    Factory Controls
                </h2>

                <div className="controls-list">
                    <ControlItem
                        icon={<Zap size={18} />}
                        label="Robotic Arm"
                        isMalicious={roboticArmMalicious}
                        onToggle={toggleRoboticArm}
                    />
                    <ControlItem
                        icon={<Activity size={18} />}
                        label="Conveyor Belt"
                        isMalicious={conveyorBeltMalicious}
                        onToggle={toggleConveyorBelt}
                    />
                    <ControlItem
                        icon={<Camera size={18} />}
                        label="CCTV Camera"
                        isMalicious={cctvCameraMalicious}
                        onToggle={toggleCCTVCamera}
                    />
                    <ControlItem
                        icon={<Cpu size={18} />}
                        label="Mainframe"
                        isMalicious={computerMalicious}
                        onToggle={toggleComputer}
                    />
                    <ControlItem
                        icon={<Smartphone size={18} />}
                        label="Mobile Phone"
                        isMalicious={mobilePhoneMalicious}
                        onToggle={toggleMobilePhone}
                    />
                </div>

                <div className="master-controls">
                    <button className="btn btn-normal" onClick={setAllNormal}>
                        <ShieldCheck size={16} /> Override
                    </button>
                    <button className="btn btn-malicious" onClick={setAllMalicious}>
                        <ShieldAlert size={16} /> Breach
                    </button>
                </div>
            </div>
            )}

            {showConfig && <ConfigPage onClose={() => setShowConfig(false)} />}

            <style>{`
                .settings-btn {
                    background: transparent !important;
                    border: none !important;
                    padding: 4px !important;
                    width: 32px !important;
                    height: 32px !important;
                    min-width: unset !important;
                    flex: none !important;
                }
                .settings-btn:hover {
                    background: rgba(255,255,255,0.05) !important;
                }
            `}</style>
        </div>
    );
};

const ControlItem = ({ icon, label, isMalicious, onToggle }) => {
    return (
        <div className={`control-item ${isMalicious ? 'malicious-active' : ''}`} style={{ marginBottom: '8px' }}>
            <div className="control-label">
                <div className="control-icon">
                    {icon}
                </div>
                <span>{label}</span>
            </div>
            <div className={`toggle-switch ${isMalicious ? 'active' : ''}`} onClick={onToggle}>
                <div className="toggle-slider"></div>
            </div>
        </div>
    );
};

export default UI;
