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
import ReactDOM from 'react-dom';
import { Settings, X, Send } from 'lucide-react';
import useStore from '../store/useStore';

const JSON_FILES = [
    'acram.json',
    'atc_network.json',
    'bacon.json',
    'i4ri.json',
    'nad.json',
    'rad.json',
    'sbom.json',
    'ssm.json'
];

const jsonModules = import.meta.glob('../assets/tool_jsons/*.json');

const ConfigPage = ({ onClose }) => {
    const { serverUrl, mappings, setConfig } = useStore();

    // Local state for manual trigger
    const [manualJson, setManualJson] = useState(JSON_FILES[0]);
    const [manualSeverity, setManualSeverity] = useState('OFF');
    const [manualStatus, setManualStatus] = useState('');

    const handleUrlChange = (e) => {
        setConfig({ serverUrl: e.target.value });
    };

    const handleMappingChange = (component, file) => {
        setConfig({ mappings: { ...mappings, [component]: file } });
    };

    const handleManualSend = async () => {
        setManualStatus('Sending...');
        if (!serverUrl) {
            setManualStatus('Error: Server URL is required');
            return;
        }

        try {
            const loader = jsonModules[`../assets/tool_jsons/${manualJson}`];
            if (!loader) throw new Error("JSON payload not found in assets");

            const module = await loader();
            const payload = JSON.parse(JSON.stringify(module.default || module));

            if (payload.data && payload.data.severity !== undefined) {
                payload.data.severity = manualSeverity;
            }

            const wrapper = {
                tool_name: manualJson.replace('.json', ''),
                time_stamp: new Date().toISOString(),
                payload: payload
            };

            const response = await fetch(serverUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(wrapper)
            });

            if (response.ok) {
                setManualStatus('Success!');
            } else {
                setManualStatus(`Failed: ${response.statusText}`);
            }
        } catch (error) {
            setManualStatus(`Error: ${error.message}`);
        }
    };

    return ReactDOM.createPortal(
        <div className="config-overlay" onClick={onClose}>
            <div className="config-modal glass-panel" onClick={(e) => e.stopPropagation()}>
                <div className="config-header">
                    <h2><Settings size={20} style={{ marginRight: '8px', verticalAlign: 'middle' }} /> Configuration</h2>
                    <button className="close-btn" onClick={onClose}><X size={20} /></button>
                </div>

                <div className="config-section">
                    <h3>Server Settings</h3>
                    <div className="form-group">
                        <label>Server POST URL</label>
                        <input
                            type="text"
                            className="text-input"
                            value={serverUrl}
                            onChange={handleUrlChange}
                            placeholder="http://localhost:8001/submit"
                        />
                    </div>
                </div>

                <div className="config-section">
                    <h3>Anomaly Mapping</h3>
                    <p className="help-text">Select which JSON payload should be sent when a component's status changes.</p>

                    <div className="mapping-grid">
                        <div className="form-group">
                            <label>Robotic Arm</label>
                            <select value={mappings.roboticArm} onChange={(e) => handleMappingChange('roboticArm', e.target.value)}>
                                <option value="">-- Select JSON --</option>
                                {JSON_FILES.map(file => <option key={file} value={file}>{file}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Conveyor Belt</label>
                            <select value={mappings.conveyorBelt} onChange={(e) => handleMappingChange('conveyorBelt', e.target.value)}>
                                <option value="">-- Select JSON --</option>
                                {JSON_FILES.map(file => <option key={file} value={file}>{file}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>CCTV Camera</label>
                            <select value={mappings.cctvCamera} onChange={(e) => handleMappingChange('cctvCamera', e.target.value)}>
                                <option value="">-- Select JSON --</option>
                                {JSON_FILES.map(file => <option key={file} value={file}>{file}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Mainframe (Computer)</label>
                            <select value={mappings.computer} onChange={(e) => handleMappingChange('computer', e.target.value)}>
                                <option value="">-- Select JSON --</option>
                                {JSON_FILES.map(file => <option key={file} value={file}>{file}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Mobile Phone</label>
                            <select value={mappings.mobilePhone} onChange={(e) => handleMappingChange('mobilePhone', e.target.value)}>
                                <option value="">-- Select JSON --</option>
                                {JSON_FILES.map(file => <option key={file} value={file}>{file}</option>)}
                            </select>
                        </div>
                    </div>
                </div>

                <div className="config-section">
                    <h3>Manual Trigger</h3>
                    <p className="help-text">Test payloads manually</p>
                    <div className="manual-trigger-box">
                        <select value={manualJson} onChange={(e) => setManualJson(e.target.value)}>
                            {JSON_FILES.map(file => <option key={file} value={file}>{file}</option>)}
                        </select>
                        <select value={manualSeverity} onChange={(e) => setManualSeverity(e.target.value)}>
                            <option value="OFF">Severity: OFF (Normal)</option>
                            <option value="ON">Severity: ON (Anomaly)</option>
                        </select>
                        <button className="btn btn-primary" onClick={handleManualSend}>
                            <Send size={16} /> Send
                        </button>
                    </div>
                    {manualStatus && <div className="status-msg">{manualStatus}</div>}
                </div>
            </div>

            <style>{`
                .config-overlay {
                    position: fixed;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background: rgba(0,0,0,0.85);
                    z-index: 2147483647;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    backdrop-filter: blur(10px);
                    pointer-events: auto;
                }
                .config-modal {
                    width: 600px;
                    max-width: 90%;
                    max-height: 90vh;
                    overflow-y: auto;
                    padding: 24px;
                    background: #18181b;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.5);
                }
                .config-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 24px;
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                    padding-bottom: 12px;
                }
                .config-header h2 { margin: 0; display: flex; align-items: center; color: white; }
                .close-btn { background: none; border: none; color: white; cursor: pointer; }
                .close-btn:hover { color: #ff4444; }
                .config-section { margin-bottom: 24px; }
                .config-section h3 { margin-top: 0; margin-bottom: 8px; font-size: 16px; color: #4fc3f7; }
                .help-text { color: #aaa; font-size: 14px; margin-bottom: 12px; margin-top: 0; }
                .form-group { display: flex; flex-direction: column; margin-bottom: 12px; }
                .form-group label { margin-bottom: 6px; font-size: 14px; color: #ddd; }
                .text-input, select {
                    background: rgba(0,0,0,0.4);
                    border: 1px solid rgba(255,255,255,0.2);
                    color: white;
                    padding: 8px 12px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                .text-input:focus, select:focus {
                    outline: none;
                    border-color: #4fc3f7;
                }
                .mapping-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 16px;
                }
                .manual-trigger-box {
                    display: flex;
                    gap: 12px;
                    align-items: center;
                }
                .btn-primary {
                    background: #4fc3f7;
                    color: black;
                    border: none;
                    padding: 8px 16px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    cursor: pointer;
                    border-radius: 4px;
                    font-weight: 600;
                }
                .btn-primary:hover { background: #29b6f6; }
                .status-msg { margin-top: 8px; font-size: 14px; color: #ffcc00; }
                select option { background: #222; color: white; }
            `}</style>
        </div>,
        document.body
    );
};

export default ConfigPage;
