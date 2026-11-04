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

import { create } from 'zustand';

const jsonModules = import.meta.glob('../assets/tool_jsons/*.json');

const useStore = create((set, get) => ({
    roboticArmMalicious: false,
    conveyorBeltMalicious: false,
    cctvCameraMalicious: false,
    computerMalicious: false,
    mobilePhoneMalicious: false,

    // UI state
    activeTab: 'simulator',
    setActiveTab: (tab) => set({ activeTab: tab }),

    // Configuration state
    serverUrl: 'http://localhost:8001/submit',
    mappings: {
        roboticArm: '',
        conveyorBelt: '',
        cctvCamera: '',
        computer: '',
        mobilePhone: 'atc_network.json'
    },

    setConfig: (newConfig) => set((state) => ({ ...state, ...newConfig })),

    sendPayload: async (componentKey, isMalicious, overrides = {}) => {
        const state = get();
        const url = state.serverUrl;
        const jsonFile = state.mappings[componentKey];

        if (!url || !jsonFile) {
            console.log(`Skipping payload for ${componentKey}: Server URL or mapping not set.`);
            return;
        }

        try {
            const loader = jsonModules[`../assets/tool_jsons/${jsonFile}`];
            if (!loader) throw new Error("JSON payload not found in assets");

            const module = await loader();
            const payload = JSON.parse(JSON.stringify(module.default || module));

            if (payload.data && payload.data.severity !== undefined) {
                payload.data.severity = isMalicious ? "ON" : "OFF";
            }

            if (jsonFile === 'atc_network.json' && payload.data && payload.data['supplementary-details']) {
                if (overrides.destination_ip) {
                    payload.data['supplementary-details'].destination_ip = overrides.destination_ip;
                } else {
                    payload.data['supplementary-details'].destination_ip = '192.168.179.108';
                }
            }

            const wrapper = {
                tool_name: jsonFile.replace('.json', ''),
                time_stamp: new Date().toISOString(),
                payload: payload
            };

            console.log(`Sending payload to ${url}...`, wrapper);

            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(wrapper)
            });

            if (!response.ok) {
                console.error(`Failed to send payload to ${url}:`, response.statusText);
            }
        } catch (error) {
            console.error(`Error sending payload for ${componentKey}:`, error);
        }
    },

    toggleRoboticArm: () => {
        set((state) => {
            const nextState = !state.roboticArmMalicious;
            get().sendPayload('roboticArm', nextState);
            return { roboticArmMalicious: nextState };
        });
    },
    toggleConveyorBelt: () => {
        set((state) => {
            const nextState = !state.conveyorBeltMalicious;
            get().sendPayload('conveyorBelt', nextState);
            return { conveyorBeltMalicious: nextState };
        });
    },
    toggleCCTVCamera: () => {
        set((state) => {
            const nextState = !state.cctvCameraMalicious;
            get().sendPayload('cctvCamera', nextState);
            return { cctvCameraMalicious: nextState };
        });
    },
    toggleComputer: () => {
        set((state) => {
            const nextState = !state.computerMalicious;
            get().sendPayload('computer', nextState);
            return { computerMalicious: nextState };
        });
    },
    toggleMobilePhone: () => {
        set((state) => {
            const nextState = !state.mobilePhoneMalicious;
            get().sendPayload('mobilePhone', nextState);
            return { mobilePhoneMalicious: nextState };
        });
    },

    setAllNormal: () => {
        set({
            roboticArmMalicious: false,
            conveyorBeltMalicious: false,
            cctvCameraMalicious: false,
            computerMalicious: false,
            mobilePhoneMalicious: false,
        });
        get().sendPayload('roboticArm', false, { destination_ip: '192.168.10.10' });
        get().sendPayload('conveyorBelt', false, { destination_ip: '192.168.10.10' });
        get().sendPayload('cctvCamera', false, { destination_ip: '192.168.10.10' });
        get().sendPayload('computer', false, { destination_ip: '192.168.10.10' });
        get().sendPayload('mobilePhone', false, { destination_ip: '192.168.10.10' });
    },

    setAllMalicious: () => {
        set({
            roboticArmMalicious: true,
            conveyorBeltMalicious: true,
            cctvCameraMalicious: true,
            computerMalicious: true,
            mobilePhoneMalicious: true,
        });
        get().sendPayload('roboticArm', true, { destination_ip: '90.90.90.90' });
        get().sendPayload('conveyorBelt', true, { destination_ip: '90.90.90.90' });
        get().sendPayload('cctvCamera', true, { destination_ip: '90.90.90.90' });
        get().sendPayload('computer', true, { destination_ip: '90.90.90.90' });
        get().sendPayload('mobilePhone', true, { destination_ip: '90.90.90.90' });
    },
}));

export default useStore;
