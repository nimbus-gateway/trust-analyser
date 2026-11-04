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

import React, { useState, useEffect } from 'react';
import img4 from '../assets/presentation/Slide4.jpg';
import img5 from '../assets/presentation/Slide5.jpg';
import img6 from '../assets/presentation/Slide6.jpg';
import img7 from '../assets/presentation/Slide7.jpg';
import img8 from '../assets/presentation/Slide8.jpg';

const slides = [img4, img5, img6, img7, img8];

const Presentation = () => {
    const [currentIndex, setCurrentIndex] = useState(0);

    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'ArrowRight') {
                setCurrentIndex((prev) => Math.min(prev + 1, slides.length - 1));
            } else if (e.key === 'ArrowLeft') {
                setCurrentIndex((prev) => Math.max(prev - 1, 0));
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    return (
        <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            backgroundColor: '#0d0d12',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 10
        }}>
            <img 
                src={slides[currentIndex]} 
                alt={`Slide ${currentIndex + 1}`} 
                style={{
                    maxWidth: '100%',
                    maxHeight: '100%',
                    objectFit: 'contain'
                }}
            />
            
            <div style={{
                position: 'absolute',
                bottom: '24px',
                color: 'rgba(255, 255, 255, 0.7)',
                background: 'rgba(0,0,0,0.6)',
                padding: '6px 16px',
                borderRadius: '16px',
                fontFamily: 'monospace',
                fontSize: '14px',
                border: '1px solid rgba(255, 255, 255, 0.1)'
            }}>
                {currentIndex + 1} / {slides.length}
            </div>
            
            <div style={{
                position: 'absolute',
                top: '50%',
                left: '20px',
                transform: 'translateY(-50%)',
                color: 'rgba(255, 255, 255, 0.3)',
                fontSize: '24px',
                cursor: 'pointer',
                userSelect: 'none'
            }} onClick={() => setCurrentIndex((prev) => Math.max(prev - 1, 0))}>
                &#10094;
            </div>
            
            <div style={{
                position: 'absolute',
                top: '50%',
                right: '20px',
                transform: 'translateY(-50%)',
                color: 'rgba(255, 255, 255, 0.3)',
                fontSize: '24px',
                cursor: 'pointer',
                userSelect: 'none'
            }} onClick={() => setCurrentIndex((prev) => Math.min(prev + 1, slides.length - 1))}>
                &#10095;
            </div>
        </div>
    );
};

export default Presentation;
