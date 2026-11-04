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


        let showAllTrustHistory = false;
        // --- Main Dashboard Logic ---
        async function renderTrustScoreDashboard() {
            const resp = await fetch('/dashboard/trust-scores');
            const data = await resp.json();
            const sysResp = await fetch('/dashboard/system-behaviour');
            const sysData = await sysResp.json();
            const trustScores = data.trust_scores || [];
            const toolBehaviours = data.tool_behaviours || [];
            const categoryBehaviours = data.category_behaviours || [];
            const systemBehaviour = sysData.system_behaviour || 'normal';
            // Prepare category-wise trust scores
            let catScores = {};
            trustScores.forEach(ts => {
                const cat = (ts.trust_evaluation_category || 'Uncategorized').trim();
                if (!catScores[cat]) catScores[cat] = [];
                catScores[cat].push(ts);
            });
            // Prepare tool behaviour map
            let toolBehMap = {};
            toolBehaviours.forEach(tb => {
                const key = `${tb.tool_name}|||${tb.trust_evaluation_category}`;
                toolBehMap[key] = tb.behaviour;
            });
            // Prepare category behaviour map
            let catBehMap = {};
            categoryBehaviours.forEach(cb => {
                catBehMap[cb.trust_evaluation_category] = cb.behaviour;
                console.log('Category Behaviour:', cb.trust_evaluation_category, cb.behaviour); // Debug log
            });
            // ── UI ──────────────────────────────────────────────────────
            const tooltips = {
                "Security": "Assesses how well an IoT entity protects data, communications, and operations against unauthorized access and attacks.",
                "Reliability": "Measures the consistency and correctness of an IoT entity’s behavior in delivering expected services over time.",
                "Resilience": "Evaluates the ability of an IoT entity to withstand, recover from, and adapt to faults or adverse conditions.",
                "Threat Exposure": "Indicates the level of risk an IoT entity faces based on its vulnerabilities, attack surface, and environmental context.",
                "Intentions": "Estimates the likelihood that an IoT entity will act in a trustworthy, compliant, or malicious manner based on observed behavior."
            };
            // Display order only — unknown categories keep their data order after the known ones
            const catOrder = ['Security', 'Threat Exposure', 'Intentions', 'Resilience', 'Reliability'];
            const catEntries = Object.entries(catScores).map(([cat, scores], idx) => ({ cat, scores, idx }));
            catEntries.sort((a, b) => {
                const ia = catOrder.indexOf(a.cat), ib = catOrder.indexOf(b.cat);
                return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.idx - b.idx;
            });

            const toolBeh = (tool, cat) => toolBehMap[`${tool}|||${cat}`] || 'normal';
            const totalTools = catEntries.reduce((n, e) => n + e.scores.length, 0);
            const flaggedTools = catEntries.reduce((n, e) => n + e.scores.filter(ts => toolBeh(ts.tool_name, e.cat) !== 'normal').length, 0);
            const flaggedCats = catEntries.filter(e => (catBehMap[e.cat] || 'normal') !== 'normal').length;

            // System overview
            let html = `
            <section class="ta-panel ta-overview mb-4">
                <div class="ta-panel-head">
                    <div>
                        <h2 class="ta-panel-title">System Overview</h2>
                        <div class="ta-panel-sub">Aggregated trust posture across all ${catEntries.length} categories and ${totalTools} evaluation tools</div>
                    </div>
                    ${taLegend()}
                </div>
                <div class="row g-3">
                    <div class="col-lg-3 col-md-6">
                        <div id="systemStatusHero" class="ta-hero ta-unknown">
                            <div class="ta-hero-label">Current system behaviour</div>
                            <div class="ta-hero-value"><span class="spinner-border spinner-border-sm"></span></div>
                            <div class="ta-hero-foot">
                                <span class="text-muted">Most frequent</span>
                                <span id="systemOverallBehaviourLabel"></span>
                            </div>
                        </div>
                        <div class="ta-kpis">
                            <div class="ta-kpi">
                                <div class="ta-kpi-label">Latest trust score</div>
                                <div class="ta-kpi-value" id="systemLatestScore">–</div>
                                <div class="ta-kpi-delta" id="systemScoreDelta"></div>
                            </div>
                            <div class="ta-kpi">
                                <div class="ta-kpi-label">Needs attention</div>
                                <div class="ta-kpi-value">${flaggedCats}<span class="ta-kpi-of">/${catEntries.length}</span></div>
                                <div class="ta-kpi-delta text-muted">categories · ${flaggedTools} tool${flaggedTools === 1 ? '' : 's'} flagged</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-4 col-md-6">
                        <div class="ta-block">
                            <div class="ta-section-label">Behaviour history <span class="ta-hint">all evaluations</span></div>
                            <div id="systemBehaviourDist"><div class="ta-placeholder">Loading…</div></div>
                        </div>
                        <div class="ta-block">
                            <div class="ta-section-label">Recent 10 evaluations <span class="ta-hint">older → latest</span></div>
                            <div id="systemRecentIndicators"><div class="ta-placeholder">Loading…</div></div>
                        </div>
                    </div>
                    <div class="col-lg-5">
                        <div class="ta-block h-100 d-flex flex-column">
                            <div class="ta-section-label d-flex justify-content-between align-items-center">
                                <span>Trust score trend <span class="ta-hint">last 10 evaluations</span></span>
                                <a href="#" id="show-full-history-link" class="ta-link">Full history <i class="bi bi-arrow-right"></i></a>
                            </div>
                            <div class="ta-chart-box"><canvas id="systemScoreChart"></canvas></div>
                        </div>
                    </div>
                </div>
                <div class="ta-section-label mt-3">Category health <span class="ta-hint">click to open details</span></div>
                <div class="ta-cat-strip">`;
            catEntries.forEach(({ cat, scores, idx }) => {
                const beh = catBehMap[cat] || 'normal';
                const flagged = scores.filter(ts => toolBeh(ts.tool_name, cat) !== 'normal').length;
                html += `
                    <a href="#catCard${idx}" class="ta-cat-chip ta-edge-${taStatus(beh).cls}">
                        <span class="ta-cat-chip-name">${cat}</span>
                        ${taPill(beh, 'sm')}
                        <span class="ta-cat-chip-meta">${scores.length} tool${scores.length === 1 ? '' : 's'}${flagged ? ` · <b>${flagged} flagged</b>` : ''}</span>
                    </a>`;
            });
            html += `</div></section>`;

            // Category cards
            html += `
            <section class="ta-panel mb-4">
            <div class="ta-panel-head">
                <div>
                    <h2 class="ta-panel-title">Trust Categories</h2>
                    <div class="ta-panel-sub">Behaviour of each category and the evaluation tools that feed it. Click a tool for its value history.</div>
                </div>
                <div class="ta-scroll-btns">
                    <button type="button" class="btn btn-sm btn-outline-secondary" data-ta-scroll="-1" aria-label="Scroll categories left"><i class="bi bi-chevron-left"></i></button>
                    <button type="button" class="btn btn-sm btn-outline-secondary" data-ta-scroll="1" aria-label="Scroll categories right"><i class="bi bi-chevron-right"></i></button>
                </div>
            </div>
            <div class="ta-cat-grid" id="taCatScroller" tabindex="0" aria-label="Trust categories">`;
            catEntries.forEach(({ cat, scores, idx }) => {
                const beh = catBehMap[cat] || 'normal';
                html += `
                <div class="ta-cat-card ta-edge-${taStatus(beh).cls}" id="catCard${idx}">
                    <div class="ta-cat-head">
                        <div>
                            <h3 class="ta-cat-title">${cat}
                                <i class="bi bi-info-circle ta-info" data-bs-toggle="tooltip" data-bs-placement="top" title="${tooltips[cat] || ''}"></i>
                            </h3>
                            <div class="ta-cat-meta">${scores.length} evaluation tool${scores.length === 1 ? '' : 's'}</div>
                        </div>
                        <div class="text-end">
                            <div class="ta-cat-meta mb-1">Current</div>
                            ${taPill(beh)}
                        </div>
                    </div>
                    <div class="ta-section-label">Behaviour history</div>
                    <div id="catPie${idx}"><div class="ta-placeholder">Loading…</div></div>
                    <div class="ta-section-label mt-3">Recent 10 evaluations <span class="ta-hint">older → latest</span></div>
                    <div id="catRecent${idx}"><div class="ta-placeholder">Loading…</div></div>
                    <div class="ta-section-label mt-3">Evaluation tools</div>
                    <ul class="ta-tool-list">`;
                scores.forEach(ts => {
                    const tb = toolBeh(ts.tool_name, cat);
                    html += `
                        <li class="ta-tool" role="button" tabindex="0" title="View value history"
                            onclick="showToolInfoModal('${ts.tool_name}','${cat}')"
                            onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();this.click();}">
                            <span class="ta-dot ta-bg-${taStatus(tb).cls}"></span>
                            <span class="ta-tool-name">${ts.tool_name}</span>
                            ${taPill(tb, 'sm')}
                            <i class="bi bi-chevron-right ta-chev"></i>
                        </li>`;
                });
                html += `</ul></div>`;
            });
            html += '</div></section>';

            document.getElementById('trust-score-dashboard').innerHTML = html;

            // Category behaviour history distributions
            fetch('/category-behaviour-history-frequencies').then(resp => resp.json()).then(catHist => {
                catEntries.forEach(({ cat, idx }) => {
                    const freq = catHist[cat] || { normal: 0, suspicious: 0, compromised: 0 };
                    const el = document.getElementById(`catPie${idx}`);
                    if (el) el.innerHTML = taDistribution(freq);
                });
                taInitTooltips();
            });

            // Recent 10 behaviours per category
            fetch('/category-behaviour-recent').then(resp => resp.json()).then(recentData => {
                catEntries.forEach(({ cat, idx }) => {
                    const container = document.getElementById(`catRecent${idx}`);
                    if (container) container.innerHTML = taTimeline(recentData[cat] || []);
                });
                taInitTooltips();
            });

            // System behaviour distribution, overall (most frequent) and current behaviour
            fetch('/system-behaviour-history-frequencies').then(resp => resp.json()).then(freqs => {
                const keys = ['normal', 'suspicious', 'compromised'];
                const data = [freqs.normal, freqs.suspicious, freqs.compromised];
                document.getElementById('systemBehaviourDist').innerHTML = taDistribution(freqs);
                // Overall behaviour = most frequent
                const maxCount = Math.max(...data);
                const overallIdx = data.findIndex(v => v === maxCount);
                const overall = keys[overallIdx] || 'normal';
                document.getElementById('systemOverallBehaviourLabel').innerHTML = taPill(overall, 'sm');

                fetch('/dashboard/system-behaviour').then(r => r.json()).then(sysData => {
                    const recent = (sysData.system_behaviour || 'normal').toLowerCase();
                    const m = taStatus(recent);
                    const hero = document.getElementById('systemStatusHero');
                    hero.className = `ta-hero ta-${m.cls}`;
                    hero.querySelector('.ta-hero-value').innerHTML = `<i class="bi ${m.icon}"></i>${m.label}`;
                    document.getElementById('systemRecentIndicators').innerHTML = taTimeline(sysData.recent_behaviour || [], true);
                    taInitTooltips();
                });
            });

            // System trust score history (last 10)
            fetch('/system-trust-score-history').then(resp => resp.json()).then(scores => {
                if (scores.length > 10) {
                    scores = scores.slice(-10); // Keep only the 10 most recent scores
                }
                const latestEl = document.getElementById('systemLatestScore');
                const deltaEl = document.getElementById('systemScoreDelta');
                if (scores.length && latestEl) {
                    const last = Number(scores[scores.length - 1]);
                    latestEl.innerHTML = `${last.toFixed(1)}<span class="ta-kpi-of">%</span>`;
                    if (scores.length > 1) {
                        const diff = last - Number(scores[scores.length - 2]);
                        const dir = diff > 0 ? 'up' : diff < 0 ? 'down' : 'flat';
                        const icon = dir === 'up' ? 'bi-arrow-up-right' : dir === 'down' ? 'bi-arrow-down-right' : 'bi-dash';
                        deltaEl.innerHTML = `<span class="ta-delta-${dir}"><i class="bi ${icon}"></i> ${Math.abs(diff).toFixed(1)} pts</span> <span class="text-muted">vs previous</span>`;
                    }
                } else if (deltaEl) {
                    deltaEl.innerHTML = '<span class="text-muted">No scores yet</span>';
                }

                const labels = scores.map((_, i) => `Eval ${i + 1}`);
                const chartCanvas = document.getElementById('systemScoreChart');
                if (!chartCanvas) return;
                const ctx = chartCanvas.getContext('2d');
                if (window.recentScoreChart) {
                    window.recentScoreChart.destroy();
                    window.recentScoreChart = null;
                }
                const grad = ctx.createLinearGradient(0, 0, 0, 220);
                grad.addColorStop(0, 'rgba(13,110,253,0.18)');
                grad.addColorStop(1, 'rgba(13,110,253,0)');
                window.recentScoreChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Trust Score (%)',
                            data: scores,
                            borderColor: '#0d6efd',
                            backgroundColor: grad,
                            borderWidth: 2,
                            pointRadius: 3,
                            pointHoverRadius: 6,
                            pointBackgroundColor: '#fff',
                            pointBorderWidth: 2,
                            tension: 0.3,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: { mode: 'index', intersect: false },
                        plugins: {
                            legend: { display: false },
                            tooltip: { callbacks: { label: c => ` Trust score: ${Number(c.parsed.y).toFixed(1)}%` } }
                        },
                        scales: {
                            y: { beginAtZero: true, suggestedMax: 100, ticks: { callback: v => v + '%', color: '#6c757d' }, grid: { color: '#eef0f3' }, border: { display: false } },
                            x: { ticks: { color: '#6c757d', maxRotation: 0 }, grid: { display: false } }
                        }
                    }
                });
            });

            // Handle "Full history" link
            const fullHistoryLink = document.getElementById('show-full-history-link');
            if (fullHistoryLink) {
                fullHistoryLink.addEventListener('click', function(e) {
                    e.preventDefault();
                    loadAndRenderFullTrustHistory();
                });
            }

            // Horizontal scrolling of category cards
            const scroller = document.getElementById('taCatScroller');
            const scrollBtns = document.querySelectorAll('[data-ta-scroll]');
            const updateScrollBtns = () => {
                const max = scroller.scrollWidth - scroller.clientWidth;
                scrollBtns[0].disabled = scroller.scrollLeft <= 1;
                scrollBtns[1].disabled = scroller.scrollLeft >= max - 1;
                document.querySelector('.ta-scroll-btns').classList.toggle('d-none', max <= 1);
            };
            scrollBtns.forEach(b => b.addEventListener('click', () => {
                const step = (scroller.querySelector('.ta-cat-card')?.offsetWidth || 340) + 16;
                scroller.scrollBy({ left: Number(b.dataset.taScroll) * step, behavior: 'smooth' });
            }));
            scroller.addEventListener('scroll', updateScrollBtns, { passive: true });
            window.addEventListener('resize', updateScrollBtns);
            updateScrollBtns();

            // Category chips open their card in a pop-up
            document.querySelectorAll('.ta-cat-chip').forEach(a => a.addEventListener('click', e => {
                e.preventDefault();
                taOpenCategoryModal(a.getAttribute('href').slice(1));
            }));

            taInitTooltips();
        }

        // ── Main dashboard presentation helpers ─────────────────────────
        const TA_STATUS = {
            normal:      { label: 'Normal',      icon: 'bi-check-circle-fill',         cls: 'normal' },
            suspicious:  { label: 'Suspicious',  icon: 'bi-exclamation-triangle-fill', cls: 'suspicious' },
            compromised: { label: 'Compromised', icon: 'bi-x-octagon-fill',            cls: 'compromised' }
        };
        function taStatus(beh) {
            const key = String(beh || 'normal').toLowerCase();
            if (TA_STATUS[key]) return TA_STATUS[key];
            return { label: key.charAt(0).toUpperCase() + key.slice(1), icon: 'bi-question-circle-fill', cls: 'unknown' };
        }
        function taPill(beh, size) {
            const m = taStatus(beh);
            return `<span class="ta-pill ta-${m.cls}${size ? ' ta-pill-' + size : ''}"><i class="bi ${m.icon}"></i>${m.label}</span>`;
        }
        function taLegend() {
            return `<div class="ta-legend">${Object.keys(TA_STATUS).map(k =>
                `<span><span class="ta-dot ta-bg-${k}"></span>${TA_STATUS[k].label}</span>`).join('')}</div>`;
        }
        // Proportional bar + counts for a {normal, suspicious, compromised} frequency map
        function taDistribution(freq) {
            const keys = ['normal', 'suspicious', 'compromised'];
            const total = keys.reduce((n, k) => n + (freq[k] || 0), 0);
            if (!total) return '<div class="ta-placeholder">No evaluation history yet</div>';
            let bar = '<div class="ta-dist-bar">';
            let legend = '<div class="ta-dist-legend">';
            keys.forEach(k => {
                const c = freq[k] || 0;
                const pct = (c / total) * 100;
                if (c) bar += `<span class="ta-bg-${k}" style="flex:${c}" data-bs-toggle="tooltip" title="${TA_STATUS[k].label}: ${c} (${pct.toFixed(0)}%)"></span>`;
                legend += `<span class="${c ? '' : 'ta-zero'}"><span class="ta-dot ta-bg-${k}"></span>${TA_STATUS[k].label} <b>${pct.toFixed(0)}%</b> <span class="text-muted">(${c})</span></span>`;
            });
            return bar + '</div>' + legend + `</div><div class="ta-dist-total">${total} evaluation${total === 1 ? '' : 's'} recorded</div>`;
        }
        // Chronological strip of behaviours (oldest → latest); latest is highlighted
        function taTimeline(list, large) {
            if (!list.length) return '<div class="ta-placeholder">No evaluations yet</div>';
            return `<div class="ta-timeline${large ? ' ta-timeline-lg' : ''}">${list.map((beh, i) => {
                const m = taStatus(beh);
                const isLast = i === list.length - 1;
                const label = isLast ? `Latest: ${m.label}` : `${list.length - 1 - i} evaluation${list.length - 1 - i === 1 ? '' : 's'} ago: ${m.label}`;
                return `<span class="ta-tick ta-bg-${m.cls}${isLast ? ' ta-tick-last' : ''}" data-bs-toggle="tooltip" title="${label}" aria-label="${label}"></span>`;
            }).join('')}</div>`;
        }
        // Shows a copy of a category card in #categoryDetailModal
        function taOpenCategoryModal(cardId) {
            const card = document.getElementById(cardId);
            const modalEl = document.getElementById('categoryDetailModal');
            if (!card || !modalEl) return;
            const body = document.getElementById('categoryDetailModalBody');
            const clone = card.cloneNode(true);
            clone.removeAttribute('id');
            clone.classList.remove('ta-flash');
            clone.querySelectorAll('[id]').forEach(el => el.removeAttribute('id'));
            body.innerHTML = '';
            body.appendChild(clone);
            body.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => bootstrap.Tooltip.getOrCreateInstance(el));
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
            modal.show();
        }
        // A tool clicked inside the category pop-up closes it first, then opens the tool modal
        document.getElementById('categoryDetailModal')?.addEventListener('click', function (e) {
            const tool = e.target.closest('.ta-tool');
            if (!tool) return;
            e.stopImmediatePropagation();
            this.addEventListener('hidden.bs.modal', () => tool.onclick && tool.onclick(), { once: true });
            bootstrap.Modal.getInstance(this)?.hide();
        }, true);
        function taInitTooltips() {
            document.querySelectorAll('#trust-score-dashboard [data-bs-toggle="tooltip"]').forEach(el => {
                bootstrap.Tooltip.getOrCreateInstance(el);
            });
        }

        function renderDial(ctx, percent, label) {
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: [label, ''],
                    datasets: [{
                        data: [percent, 100-percent],
                        backgroundColor: [percent>66?'#198754':percent>33?'#ffc107':'#dc3545', '#e9ecef'],
                        borderWidth: 0
                    }]
                },
                options: {
                    cutout: '80%',
                    plugins: {
                        legend: {display: false},
                        tooltip: {enabled: false},
                        title: {display: true, text: `${label}: ${percent.toFixed(1)}%`}
                    }
                }
            });
        }

        function loadAndRenderFullTrustHistory() {
            const modalEl = document.getElementById('trustHistoryModal');
            if (!modalEl) return;
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);

            let canvas = document.getElementById('fullTrustScoreGraph');
            const body = modalEl.querySelector('.modal-body');
            if (!canvas || !body.contains(canvas)) {
                body.innerHTML = `
                    <div id="fullHistoryLoading" class="text-center py-5 d-none">
                        <div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>
                        <div class="mt-2 text-muted small">Loading trust score history...</div>
                    </div>
                    <div id="fullHistoryEmpty" class="alert alert-info d-none">No trust score history found.</div>
                    <div id="fullHistoryWrapper" style="position: relative; height: 400px; width: 100%;">
                        <canvas id="fullTrustScoreGraph"></canvas>
                    </div>
                `;
                canvas = document.getElementById('fullTrustScoreGraph');
            }

            const loadingEl = document.getElementById('fullHistoryLoading');
            const emptyEl = document.getElementById('fullHistoryEmpty');
            const wrapperEl = document.getElementById('fullHistoryWrapper');

            if (loadingEl) loadingEl.classList.remove('d-none');
            if (emptyEl) emptyEl.classList.add('d-none');
            if (wrapperEl) wrapperEl.classList.add('d-none');

            modal.show();

            fetch('/system-trust-score-history')
                .then(resp => {
                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                    return resp.json();
                })
                .then(scores => {
                    if (loadingEl) loadingEl.classList.add('d-none');

                    if (!Array.isArray(scores) || scores.length === 0) {
                        if (emptyEl) emptyEl.classList.remove('d-none');
                        return;
                    }

                    if (wrapperEl) wrapperEl.classList.remove('d-none');

                    if (window.fullHistoryChart) {
                        window.fullHistoryChart.destroy();
                        window.fullHistoryChart = null;
                    }

                    const labels = scores.map((_, i) => i + 1);
                    const ctx = canvas.getContext('2d');

                    window.fullHistoryChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Trust Score (%)',
                                data: scores,
                                borderColor: '#007bff',
                                backgroundColor: 'rgba(0, 123, 255, 0.15)',
                                fill: true,
                                tension: 0.2,
                                pointRadius: scores.length > 100 ? (scores.length > 500 ? 0 : 1) : 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            animation: false,
                            plugins: {
                                title: {
                                    display: true,
                                    text: `Complete Trust Score History (${scores.length} Evaluations)`
                                },
                                tooltip: {
                                    callbacks: {
                                        title: function(items) {
                                            return items.length ? `Evaluation #${items[0].label}` : '';
                                        },
                                        label: function(context) {
                                            return `Trust Score: ${Number(context.raw).toFixed(2)}%`;
                                        }
                                    }
                                }
                            },
                            scales: {
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Evaluation Number'
                                    },
                                    ticks: {
                                        maxTicksLimit: 20
                                    }
                                },
                                y: {
                                    beginAtZero: true,
                                    max: 100,
                                    title: {
                                        display: true,
                                        text: 'Trust Score (%)'
                                    }
                                }
                            }
                        }
                    });

                    setTimeout(() => {
                        if (window.fullHistoryChart) {
                            window.fullHistoryChart.resize();
                        }
                    }, 200);
                })
                .catch(err => {
                    console.error('Error fetching full trust score history:', err);
                    if (loadingEl) loadingEl.classList.add('d-none');
                    if (body) {
                        body.innerHTML = `<div class="alert alert-danger">Failed to load trust score history: ${err.message}</div>`;
                    }
                });
        }

        // Auto-resize full history chart on modal show
        document.getElementById('trustHistoryModal')?.addEventListener('shown.bs.modal', function () {
            if (window.fullHistoryChart) {
                window.fullHistoryChart.resize();
            }
        });

        // Tab event for main dashboard
        document.getElementById('main-dashboard-tab').addEventListener('shown.bs.tab', function () {
            renderTrustScoreDashboard();
        });
        // Initial load
        document.addEventListener('DOMContentLoaded', function() {
            renderTrustScoreDashboard();
        });
        // ...other JS functions...
    
        async function renderTrustConfigStep2() {
            // Fetch mapped requests to get tool names
            const [mappedResp, configResp] = await Promise.all([
                fetch('/mapped'),
                fetch('/trust-config-step2-get-all')
            ]);
            const mapped = await mappedResp.json();
            const configs = await configResp.json();
            // Build a lookup for (tool_name, category) => config
            const configMap = {};
            configs.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                configMap[`${cfg.tool_name}|||${cat}`] = cfg;
            });
            // Group tools by category
            const byCategory = {};
            mapped.forEach(item => {
                let cat = (item.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                if (!byCategory[cat]) byCategory[cat] = [];
                byCategory[cat].push(item);
            });
            function capitalizeWords(str) {
                return str.replace(/\b\w/g, c => c.toUpperCase());
            }
            let html = '';
            Object.entries(byCategory).forEach(([cat, tools]) => {
                html += `<h5 class="mt-4">Category: <b>${capitalizeWords(cat)}</b></h5>`;
                html += '<div class="table-responsive"><table class="table table-bordered"><thead><tr><th>Tool Name</th><th>Override Active</th><th>Count</th><th>Impact</th><th>Behaviour</th></tr></thead><tbody>';
                tools.forEach(tool => {
                    const toolName = tool.tool_name;
                    const cfg = configMap[`${toolName}|||${cat}`] || {};
                    const countVal = cfg.override_count || '';
                    const impactVal = cfg.override_impact || 'low';
                    const behaviourVal = cfg.override_behaviour || 'normal';
                    const overrideActive = cfg.override_active === 'true';
                    html += `<tr><td>${toolName}</td>
                        <td><input type="checkbox" name="${toolName}_${cat}_override_active" value="true" ${overrideActive ? 'checked' : ''}></td>
                        <td><input type="number" min="1" class="form-control w-auto d-inline" name="${toolName}_${cat}_override_count" value="${countVal}"></td>
                        <td><select class="form-select w-auto d-inline" name="${toolName}_${cat}_override_impact">
                            <option value="low" ${impactVal === 'low' ? 'selected' : ''}>Low</option>
                            <option value="mid" ${impactVal === 'mid' ? 'selected' : ''}>Mid</option>
                            <option value="high" ${impactVal === 'high' ? 'selected' : ''}>High</option>
                        </select></td>
                        <td><select class="form-select w-auto d-inline" name="${toolName}_${cat}_override_behaviour">
                            <option value="normal" ${behaviourVal === 'normal' ? 'selected' : ''}>Normal</option>
                            <option value="suspicious" ${behaviourVal === 'suspicious' ? 'selected' : ''}>Suspicious</option>
                            <option value="compromised" ${behaviourVal === 'compromised' ? 'selected' : ''}>Compromised</option>
                        </select></td></tr>`;
                });
                html += '</tbody></table></div>';
            });
            document.getElementById('trust-config-step2').innerHTML = html;
        }
        // Render step 2 on tab show
        document.getElementById('trust-config-tab').addEventListener('shown.bs.tab', function () {
            renderTrustConfigStep1();
            renderTrustConfigStep2();
            renderTrustConfigStep3();
            renderTrustConfigStep4();
            renderTrustCycleConfig();
        });

        // --- Trust Analysis Cycle ---
        async function renderTrustCycleConfig() {
            const response = await fetch('/trust-cycle/config');
            const config = await response.json();
            document.getElementById('cycle-enabled-switch').checked = config.enabled;
            document.getElementById('cycle-duration-input').value = config.duration;
            document.getElementById('cycle-time-unit-select').value = config.time_unit || 'minutes';
            updateEffectiveDuration();
            updateCycleStatus();
        }

        function updateEffectiveDuration() {
            const duration = parseInt(document.getElementById('cycle-duration-input').value) || 0;
            const timeUnit = document.getElementById('cycle-time-unit-select').value;
            let seconds = 0;
            if (timeUnit === 'seconds') {
                seconds = duration;
            } else if (timeUnit === 'minutes') {
                seconds = duration * 60;
            } else if (timeUnit === 'hours') {
                seconds = duration * 3600;
            }
            document.getElementById('effective-duration-display').textContent = seconds + ' seconds';
        }

        async function saveTrustCycleConfig() {
            const enabled = document.getElementById('cycle-enabled-switch').checked;
            const duration = document.getElementById('cycle-duration-input').value;
            const time_unit = document.getElementById('cycle-time-unit-select').value;
            const response = await fetch('/trust-cycle/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled, duration, time_unit })
            });
            const msgDiv = document.getElementById('cycle-config-save-msg');
            if (response.ok) {
                msgDiv.innerHTML = '<span class="text-success">Cycle configuration saved!</span>';
            } else {
                msgDiv.innerHTML = '<span class="text-danger">Failed to save configuration.</span>';
            }
        }

        async function startCycle() {
            const response = await fetch('/trust-cycle/start', { method: 'POST' });
            if (response.ok) {
                updateCycleStatus();
            } else {
                alert('Failed to start cycle.');
            }
        }

        async function stopCycle() {
            const response = await fetch('/trust-cycle/stop', { method: 'POST' });
            if (response.ok) {
                updateCycleStatus();
            } else {
                alert('Failed to stop cycle.');
            }
        }
        let eventSource = null;

        async function updateCycleStatus() {
            const response = await fetch('/trust-cycle/status');
            const status = await response.json();
            const statusDiv = document.getElementById('cycle-status');
            if (status.is_running) {
                const endTime = new Date(status.end_time + 'Z'); // Append Z for UTC
                statusDiv.innerHTML = `Status: <span class="text-success">Running</span>. Ends at: ${endTime.toLocaleTimeString()}. Submissions: ${status.submissions_count}`;
                document.getElementById('start-cycle-btn').disabled = true;
                document.getElementById('stop-cycle-btn').disabled = false;
            } else {
                statusDiv.innerHTML = 'Status: <span class="text-danger">Inactive</span>';
                document.getElementById('start-cycle-btn').disabled = false;
                document.getElementById('stop-cycle-btn').disabled = true;
            }
        }

        function connectCycleStatusStream() {
            if (eventSource) {
                eventSource.close();
            }
            eventSource = new EventSource('/trust-cycle/stream');
            
            eventSource.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    console.log('Cycle update:', data);
                    
                    const statusDiv = document.getElementById('cycle-status');
                    
                    if (data.status === 'started') {
                        const endTime = new Date(data.cycle_state.end_time + 'Z');
                        statusDiv.innerHTML = `Status: <span class="text-success">Running</span>. Ends at: ${endTime.toLocaleTimeString()}. Submissions: ${data.cycle_state.submissions_count}`;
                        document.getElementById('start-cycle-btn').disabled = true;
                        document.getElementById('stop-cycle-btn').disabled = false;
                    } else if (data.status === 'stopped') {
                        statusDiv.innerHTML = 'Status: <span class="text-danger">Inactive</span> - Stopped by user. Analyzed ' + (data.submissions_analyzed || 0) + ' submissions.';
                        document.getElementById('start-cycle-btn').disabled = false;
                        document.getElementById('stop-cycle-btn').disabled = true;
                    } else if (data.status === 'analysis_complete') {
                        // Batch cycle finished — show banner immediately
                        statusDiv.innerHTML = 'Status: <span class="text-warning">Analyzing</span> - Analysis complete. Waiting to restart...';
                        showNewEvalBanner();
                        refreshDashboardStatusBar(); // sync status bar text right away
                    } else if (data.status === 'evaluation_complete') {
                        // Immediate or manual evaluation finished — show banner immediately
                        showNewEvalBanner();
                        refreshDashboardStatusBar(); // sync status bar text right away
                    } else if (data.status === 'restarted') {
                        const endTime = new Date(data.new_end_time + 'Z');
                        statusDiv.innerHTML = `Status: <span class="text-success">Running</span> (Auto-restarted). Ends at: ${endTime.toLocaleTimeString()}. Submissions: ${data.cycle_state.submissions_count}`;
                        document.getElementById('start-cycle-btn').disabled = true;
                        document.getElementById('stop-cycle-btn').disabled = false;
                    }
                } catch (e) {
                    console.error('Error parsing SSE data:', e);
                }
            };
            
            eventSource.onerror = function(error) {
                console.error('SSE connection error:', error);
                eventSource.close();
                // Reconnect after 3 seconds
                setTimeout(connectCycleStatusStream, 3000);
            };
        }

        // Add event listeners for cycle buttons
        document.getElementById('save-cycle-config-btn').addEventListener('click', saveTrustCycleConfig);
        document.getElementById('start-cycle-btn').addEventListener('click', startCycle);
        document.getElementById('stop-cycle-btn').addEventListener('click', stopCycle);
        
        // Add event listeners for duration and time unit changes
        document.getElementById('cycle-duration-input').addEventListener('change', updateEffectiveDuration);
        document.getElementById('cycle-duration-input').addEventListener('input', updateEffectiveDuration);
        document.getElementById('cycle-time-unit-select').addEventListener('change', updateEffectiveDuration);

        // Connect to SSE stream for real-time updates
        connectCycleStatusStream();
        
        // Periodically update cycle status as fallback
        setInterval(updateCycleStatus, 30000); // every 30 seconds


        async function saveTrustConfigStep2() {
            const container = document.getElementById('trust-config-step2');
            const rows = container.querySelectorAll('tbody tr');
            // Get mapped requests for tool_name/category to _id mapping
            const mappedResp = await fetch('/mapped');
            const mapped = await mappedResp.json();
            const toolCatIdMap = {};
            mapped.forEach(m => {
                const cat = (m.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                toolCatIdMap[`${m.tool_name}|||${cat}`] = m._id;
            });
            let saveCount = 0;
            let configsToSave = [];
            rows.forEach(row => {
                const toolName = row.querySelector('td').textContent;
                let cat = row.closest('table').parentElement.previousSibling.textContent.replace('Category:', '').trim().toLowerCase();
                let overrideActive = row.querySelector(`input[name="${toolName}_${cat}_override_active"]`).checked ? 'true' : 'false';
                let config = { tool_name: toolName, trust_evaluation_category: cat, mapped_request_id: toolCatIdMap[`${toolName}|||${cat}`] || '', override_active: overrideActive };
                if (overrideActive === 'true') {
                    config.override_count = row.querySelector(`input[name="${toolName}_${cat}_override_count"]`).value;
                    config.override_impact = row.querySelector(`select[name="${toolName}_${cat}_override_impact"]`).value;
                    config.override_behaviour = row.querySelector(`select[name="${toolName}_${cat}_override_behaviour"]`).value;
                }
                // If override is not active, do NOT send override fields (they will be removed in backend, but this is safer)
                configsToSave.push(config);
            });
            // Save all configs
            let completed = 0;
            configsToSave.forEach(async config => {
                const resp = await fetch('/trust-config-step2', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                completed++;
                if (completed === configsToSave.length) {
                    const msgDiv = document.getElementById('trust-config-step2-msg');
                    if (resp.ok) {
                        msgDiv.innerHTML = '<span class="text-success">Step 2 configuration saved!</span>';
                    } else {
                        msgDiv.innerHTML = '<span class="text-danger">Failed to save step 2 configuration.</span>';
                    }
                }
            });
        }
        document.getElementById('trust-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'saveTrustConfigStep2Btn') {
                saveTrustConfigStep2();
            }
        });
        async function saveTrustConfig() {
            const container = document.getElementById('trust-config-step1');
            const rows = container.querySelectorAll('tbody tr');
            let saveCount = 0;
            // Get mapped requests for tool_name to _id mapping
            const mappedResp = await fetch('/mapped');
            const mappedRespJson = await mappedResp.json();
            // Build a map for (tool_name, category) to mapped_request_id
            const toolCatIdMap = {};
            mappedRespJson.forEach(m => {
                const cat = (m.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                toolCatIdMap[`${m.tool_name}|||${cat}`] = m._id;
            });
            rows.forEach(async row => {
                const toolName = row.querySelector('td').textContent;
                // Find category from parent table
                let cat = row.closest('table').parentElement.previousSibling.textContent.replace('Category:', '').trim().toLowerCase();
                let config = { tool_name: toolName, trust_evaluation_category: cat };
                // Add mapped_request_id
                config.mapped_request_id = toolCatIdMap[`${toolName}|||${cat}`] || '';
                // Collect all selects and ranges in this row
                row.querySelectorAll('select').forEach(sel => {
                    config[sel.name] = sel.value;
                });
                row.querySelectorAll('input[type=range]').forEach(rng => {
                    config[rng.id] = rng.value;
                });
                // POST to backend
                const resp = await fetch('/trust-config-step1', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                saveCount++;
                if (saveCount === rows.length) {
                    const msgDiv = document.getElementById('trust-config-save-msg');
                    if (resp.ok) {
                        msgDiv.innerHTML = '<span class="text-success">Configuration saved!</span>';
                    } else {
                        msgDiv.innerHTML = '<span class="text-danger">Failed to save configuration.</span>';
                    }
                }
            });
        }
        document.getElementById('trust-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'saveTrustConfigBtn') {
                saveTrustConfig();
            }
        });
        async function renderTrustConfigStep1() {
            // Fetch mapped requests and step 1 configs
            const [mappedResp, configResp] = await Promise.all([
                fetch('/mapped'),
                fetch('/trust-config-step1-get-all')
            ]);
            const mapped = await mappedResp.json();
            const configs = await configResp.json();
            // Build a lookup for (tool_name, category) => config
            const configMap = {};
            configs.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                configMap[`${cfg.tool_name}|||${cat}`] = cfg;
            });
            // Group by trust_evaluation_category, then by tool_name
            const byCategory = {};
            mapped.forEach(item => {
                const cat = (item.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                if (!byCategory[cat]) byCategory[cat] = [];
                byCategory[cat].push(item);
            });
            let html = '';
            Object.entries(byCategory).forEach(([cat, tools]) => {
                html += `<h5 class="mt-4">Category: <b>${cat}</b></h5>`;
                html += '<div class="table-responsive"><table class="table table-bordered"><thead><tr><th>Tool Name</th><th>Data Type</th><th>Configuration</th></tr></thead><tbody>';
                tools.forEach(tool => {
                    const toolName = tool.tool_name;
                    const cfg = configMap[`${toolName}|||${cat}`] || {};
                    html += `<tr><td>${toolName}</td><td>${tool.data_type}</td><td>`;
                    if (tool.data_type === 'binary') {
                        const onVal = cfg[`${toolName}_${cat}_on`] || 'Low';
                        const offVal = cfg[`${toolName}_${cat}_off`] || 'Low';
                        html += `<div>On: <select class="form-select d-inline w-auto" name="${toolName}_${cat}_on"><option${onVal === 'Low' ? ' selected' : ''}>Low</option><option${onVal === 'Mid' ? ' selected' : ''}>Mid</option><option${onVal === 'High' ? ' selected' : ''}>High</option></select> &nbsp; Off: <select class="form-select d-inline w-auto" name="${toolName}_${cat}_off"><option${offVal === 'Low' ? ' selected' : ''}>Low</option><option${offVal === 'Mid' ? ' selected' : ''}>Mid</option><option${offVal === 'High' ? ' selected' : ''}>High</option></select></div>`;
                    } else if (tool.data_type === 'categorical') {
                        const cats = (tool.categories || '').split(',').map(x => x.trim()).filter(Boolean);
                        cats.forEach(c => {
                            const catVal = cfg[`${toolName}_${cat}_${c}`] || 'Low';
                            html += `<div>${c}: <select class="form-select d-inline w-auto" name="${toolName}_${cat}_${c}"><option${catVal === 'Low' ? ' selected' : ''}>Low</option><option${catVal === 'Mid' ? ' selected' : ''}>Mid</option><option${catVal === 'High' ? ' selected' : ''}>High</option></select></div>`;
                        });
                    } else if (tool.data_type === 'continuous') {
                        const min = tool.min_value !== undefined ? tool.min_value : 0;
                        const max = tool.max_value !== undefined ? tool.max_value : 100;
                        const sliderId1 = `${toolName}_${cat}_slider_lower`;
                        const sliderId2 = `${toolName}_${cat}_slider_upper`;
                        const impactDivId = `${toolName}_${cat}_impact_ranges`;
                        const lowerVal = cfg[sliderId1] || min;
                        const upperVal = cfg[sliderId2] || max;
                        html += `<div>Min: <b>${min}</b> &nbsp; Max: <b>${max}</b></div>`;
                        html += `<div class="mb-2">Lower Bound: <input type="range" min="${min}" max="${max}" value="${lowerVal}" id="${sliderId1}" style="width:150px;"> <span id="${sliderId1}_val">${lowerVal}</span></div>`;
                        html += `<div class="mb-2">Upper Bound: <input type="range" min="${min}" max="${max}" value="${upperVal}" id="${sliderId2}" style="width:150px;"> <span id="${sliderId2}_val">${upperVal}</span></div>`;
                        html += `<div class="mb-2" id="${impactDivId}"></div>`;
                        setTimeout(() => {
                            var lower = document.getElementById(sliderId1);
                            var upper = document.getElementById(sliderId2);
                            var lowerValSpan = document.getElementById(sliderId1 + '_val');
                            var upperValSpan = document.getElementById(sliderId2 + '_val');
                            var impactDiv = document.getElementById(impactDivId);
                            function update() {
                                var l = parseFloat(lower.value);
                                var u = parseFloat(upper.value);
                                if (l > u) { var t = l; l = u; u = t; }
                                lowerValSpan.textContent = l;
                                upperValSpan.textContent = u;
                                impactDiv.innerHTML = '<b>Impact Ranges:</b><br>Low: ' + min + ' to ' + l + '<br>Mid: ' + (l + 1) + ' to ' + u + '<br>High: Above ' + u;
                            }
                            lower.addEventListener('input', update);
                            upper.addEventListener('input', update);
                            update();
                        }, 0);
                    }
                    html += `</td></tr>`;
                });
                html += '</tbody></table></div>';
            });
            document.getElementById('trust-config-step1').innerHTML = html;
        }
        // Render on tab show
        document.getElementById('trust-config-tab').addEventListener('shown.bs.tab', renderTrustConfigStep1);
        let mappedList = [];
        async function fetchMapped() {
            const response = await fetch('/mapped');
            const data = await response.json();
            
            // Also fetch removed mappings
            const removedResp = await fetch('/mapped/removed');
            const removedData = await removedResp.json();
            
            // Combine both active and removed with a marker
            const allData = [
                ...data.map(item => ({...item, is_removed: false})),
                ...removedData.map(item => ({...item, is_removed: true}))
            ];
            
            mappedList = data;
            const table = document.getElementById('mapped-table');
            table.innerHTML = '';
            allData.forEach(item => {
                const statusBadge = item.is_removed ? '<span class="badge bg-warning ms-2">Previous</span>' : '';
                const row = `<tr>
                    <td>${item.tool_name}${statusBadge}</td>
                    <td>${item.description || ''}</td>
                    <td>${item.data_type}</td>
                    <td>${item.trust_evaluation_category || ''}</td>
                    <td>${item.unique_id_path}</td>
                    <td>${item.unique_id_value || ''}</td>
                    <td>${item.value_path}</td>
                    <td>${item.categories || ''}</td>
                    <td>${item.supplement || ''}</td>
                    <td>${item.count || 0}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteMappedRequest('${item._id}')">Delete</button>
                    </td>
                </tr>`;
                table.innerHTML += row;
            });
        }
        function getByPath(payload, path) {
            try {
                const parts = path.split('.').slice(1); // remove 'payload'
                let val = payload;
                for (const p of parts) {
                    if (typeof val === 'object' && val !== null) {
                        val = val[p];
                    } else {
                        return undefined;
                    }
                }
                return val;
            } catch { return undefined; }
        }
        async function deleteMappedRequest(requestId) {
            if (confirm('Are you sure you want to delete this mapped request? This action cannot be undone.')) {
                try {
                    const response = await fetch(`/mapped/${requestId}`, { method: 'DELETE' });
                    const data = await response.json();
                    if (data.status === 'success') {
                        fetchMapped(); // Refresh the table
                        alert('Mapped request deleted successfully');
                    } else {
                        alert('Error: ' + (data.error || 'Failed to delete mapped request'));
                    }
                } catch (error) {
                    alert('Error deleting mapped request: ' + error.message);
                }
            }
        }
        // ── Requests Tab Pagination & Infinite Scroll ───────────────────────
        let _requestsSkip = 0;
        const _requestsLimit = 30;
        let _requestsLoading = false;
        let _requestsHasMore = true;
        let _requestsTotal = 0;
        let _requestsLoadedCount = 0;
        let _requestsItemsMap = {};
        let _requestsObserver = null;
        let _requestsScrollListenerAttached = false;

        function _reqEscapeHtml(str) {
            if (str == null) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function updateRequestsCounter() {
            const badge = document.getElementById('requests-count-badge');
            if (!badge) return;
            if (_requestsLoading && _requestsLoadedCount === 0) {
                badge.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span> Loading requests...';
            } else if (_requestsLoadedCount === 0 && !_requestsHasMore) {
                badge.textContent = 'No unmapped requests';
            } else {
                const totalDisplay = _requestsTotal > 0 ? ` of ${_requestsTotal}` : '';
                badge.textContent = `Showing ${_requestsLoadedCount}${totalDisplay} unmapped requests`;
            }
        }

        function filterUnmapped(items) {
            if (!mappedList || mappedList.length === 0) return items;
            return items.filter(item => {
                for (const m of mappedList) {
                    if (m.unique_id_path && m.unique_id_value !== undefined) {
                        const val = getByPath(item.payload, m.unique_id_path);
                        if (val !== undefined && String(val) === String(m.unique_id_value)) {
                            return false;
                        }
                    }
                }
                return true;
            });
        }

        function buildRequestRowHtml(item) {
            _requestsItemsMap[item._id] = item;
            const payloadId = `payload-${item._id}`;
            const safeToolName = _reqEscapeHtml(item.tool_name || 'Unknown');
            const safeTimestamp = _reqEscapeHtml(item.time_stamp || '—');
            const prettyJson = _reqEscapeHtml(JSON.stringify(item.payload, null, 2));

            return `<tr id="request-row-${item._id}">
                <td><strong>${safeToolName}</strong></td>
                <td><small class="text-muted">${safeTimestamp}</small></td>
                <td>
                    <button class="btn btn-sm btn-outline-secondary py-0 px-2 mb-1" onclick="toggleJson('${payloadId}')">Toggle</button>
                    <pre id="${payloadId}" class="json-collapsed bg-light p-2 rounded border" style="max-height: 300px; overflow: auto; font-size: 0.85em;">${prettyJson}</pre>
                </td>
                <td style="white-space: nowrap;">
                    <button class="btn btn-primary btn-sm" onclick="openMapWindowById('${item._id}')"><i class="bi bi-link-45deg me-1"></i>Map</button>
                    <button class="btn btn-danger btn-sm ms-1" onclick="removeRequest('${item._id}')"><i class="bi bi-trash me-1"></i>Remove</button>
                </td>
            </tr>`;
        }

        window.openMapWindowById = function(itemId) {
            const item = _requestsItemsMap[itemId];
            if (item) {
                openMapWindow(item);
            } else {
                alert('Request details not found.');
            }
        };

        window.loadMoreRequests = async function() {
            if (_requestsLoading || !_requestsHasMore) return;
            _requestsLoading = true;

            const table = document.getElementById('data-table');
            const sentinel = document.getElementById('requests-scroll-sentinel');
            const spinner = document.getElementById('requests-loading-spinner');
            const loadMoreBtn = document.getElementById('requests-load-more-btn-container');
            const endMsg = document.getElementById('requests-end-message');

            if (spinner) spinner.style.display = 'block';
            if (loadMoreBtn) loadMoreBtn.style.display = 'none';
            if (endMsg) endMsg.style.display = 'none';

            _requestsSkip += _requestsLimit;

            try {
                const response = await fetch(`/data?skip=${_requestsSkip}&limit=${_requestsLimit}`);
                if (!response.ok) throw new Error(`HTTP error ${response.status}`);

                const totalHdr = response.headers.get('X-Total-Count');
                if (totalHdr) {
                    _requestsTotal = parseInt(totalHdr, 10);
                }

                const data = await response.json();
                if (!Array.isArray(data) || data.length < _requestsLimit) {
                    _requestsHasMore = false;
                }

                const filtered = filterUnmapped(data);

                if (filtered.length > 0) {
                    const rowsHtml = filtered.map(buildRequestRowHtml).join('');
                    if (table) {
                        table.insertAdjacentHTML('beforeend', rowsHtml);
                    }
                    _requestsLoadedCount += filtered.length;
                }

                updateRequestsCounter();

                if (!_requestsHasMore) {
                    if (spinner) spinner.style.display = 'none';
                    if (loadMoreBtn) loadMoreBtn.style.display = 'none';
                    if (endMsg && _requestsLoadedCount > 0) endMsg.style.display = 'block';
                } else {
                    if (spinner) spinner.style.display = 'none';
                    if (loadMoreBtn) loadMoreBtn.style.display = 'block';
                }

                if (filtered.length === 0 && _requestsHasMore) {
                    _requestsLoading = false;
                    window.loadMoreRequests();
                    return;
                }
            } catch (err) {
                console.error('Error loading more requests:', err);
                if (spinner) spinner.style.display = 'none';
                if (loadMoreBtn) loadMoreBtn.style.display = 'block';
            } finally {
                _requestsLoading = false;
            }
        };

        async function fetchData(reset = true) {
            if (_requestsLoading) return;
            _requestsLoading = true;

            const table = document.getElementById('data-table');
            const refreshBtn = document.getElementById('requests-refresh-btn');
            const spinner = document.getElementById('requests-loading-spinner');
            const loadMoreBtn = document.getElementById('requests-load-more-btn-container');
            const endMsg = document.getElementById('requests-end-message');

            if (reset) {
                _requestsSkip = 0;
                _requestsHasMore = true;
                _requestsLoadedCount = 0;
                _requestsItemsMap = {};
                if (table) {
                    table.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-muted"><div class="spinner-border spinner-border-sm text-primary me-2"></div>Loading requests...</td></tr>';
                }
                if (refreshBtn) {
                    refreshBtn.disabled = true;
                    refreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Refreshing...';
                }
                if (endMsg) endMsg.style.display = 'none';
                if (spinner) spinner.style.display = 'none';
                if (loadMoreBtn) loadMoreBtn.style.display = 'none';
                updateRequestsCounter();
            }

            try {
                const response = await fetch(`/data?skip=${_requestsSkip}&limit=${_requestsLimit}`);
                if (!response.ok) throw new Error(`HTTP error ${response.status}`);

                const totalHdr = response.headers.get('X-Total-Count');
                if (totalHdr) {
                    _requestsTotal = parseInt(totalHdr, 10);
                }

                const data = await response.json();
                if (!Array.isArray(data) || data.length < _requestsLimit) {
                    _requestsHasMore = false;
                }

                if (reset && table) {
                    table.innerHTML = '';
                }

                const filtered = filterUnmapped(data);

                if (filtered.length > 0) {
                    const rowsHtml = filtered.map(buildRequestRowHtml).join('');
                    if (table) {
                        table.insertAdjacentHTML('beforeend', rowsHtml);
                    }
                    _requestsLoadedCount += filtered.length;
                } else if (_requestsLoadedCount === 0 && !_requestsHasMore) {
                    if (table) {
                        table.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-muted fst-italic">No unmapped requests found.</td></tr>';
                    }
                }

                updateRequestsCounter();

                if (!_requestsHasMore) {
                    if (spinner) spinner.style.display = 'none';
                    if (loadMoreBtn) loadMoreBtn.style.display = 'none';
                    if (endMsg && _requestsLoadedCount > 0) endMsg.style.display = 'block';
                } else {
                    if (spinner) spinner.style.display = 'none';
                    if (loadMoreBtn) loadMoreBtn.style.display = 'block';
                }

                if (filtered.length === 0 && _requestsHasMore) {
                    _requestsLoading = false;
                    window.loadMoreRequests();
                    return;
                }

            } catch (err) {
                console.error('Error fetching data:', err);
                if (reset && table && _requestsLoadedCount === 0) {
                    table.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-danger">Failed to load requests: ${_reqEscapeHtml(err.message)}</td></tr>`;
                }
            } finally {
                _requestsLoading = false;
                if (refreshBtn) {
                    refreshBtn.disabled = false;
                    refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Refresh';
                }
                setupRequestsScrollObserver();
            }
        }

        function setupRequestsScrollObserver() {
            const sentinel = document.getElementById('requests-scroll-sentinel');
            if (sentinel && window.IntersectionObserver) {
                if (_requestsObserver) _requestsObserver.disconnect();

                _requestsObserver = new IntersectionObserver((entries) => {
                    const entry = entries[0];
                    if (entry.isIntersecting && !_requestsLoading && _requestsHasMore) {
                        const tabPane = document.getElementById('requests');
                        if (tabPane && (tabPane.classList.contains('active') || tabPane.classList.contains('show') || tabPane.offsetParent !== null)) {
                            window.loadMoreRequests();
                        }
                    }
                }, {
                    rootMargin: '400px',
                    threshold: 0.01
                });
                _requestsObserver.observe(sentinel);
            }

            if (!_requestsScrollListenerAttached) {
                _requestsScrollListenerAttached = true;
                const checkAndLoad = () => {
                    if (_requestsLoading || !_requestsHasMore) return;
                    const tabPane = document.getElementById('requests');
                    if (!tabPane || tabPane.offsetParent === null) return;

                    const sentinelEl = document.getElementById('requests-scroll-sentinel');
                    if (!sentinelEl) return;
                    const rect = sentinelEl.getBoundingClientRect();
                    if (rect.top <= window.innerHeight + 500) {
                        window.loadMoreRequests();
                    }
                };

                window.addEventListener('scroll', checkAndLoad, { passive: true });
                document.addEventListener('scroll', checkAndLoad, { passive: true });
            }
        }

        async function removeRequest(requestId) {
            if (!confirm('Are you sure you want to delete this request?')) {
                return;
            }
            try {
                const response = await fetch(`/data/${requestId}`, {
                    method: 'DELETE'
                });
                if (response.ok) {
                    const row = document.getElementById(`request-row-${requestId}`);
                    if (row) {
                        row.remove();
                        delete _requestsItemsMap[requestId];
                        _requestsLoadedCount = Math.max(0, _requestsLoadedCount - 1);
                        _requestsTotal = Math.max(0, _requestsTotal - 1);
                        updateRequestsCounter();

                        const table = document.getElementById('data-table');
                        if (table && table.children.length === 0 && !_requestsHasMore) {
                            table.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-muted fst-italic">No unmapped requests found.</td></tr>';
                        }
                    } else {
                        manualRefresh();
                    }
                } else {
                    alert('Failed to delete request.');
                }
            } catch (err) {
                alert('Error deleting request: ' + err.message);
            }
        }

        function manualRefresh() {
            fetchMapped().then(() => fetchData(true));
            refreshDashboardStatusBar();
        }

        // Attach tab-shown listener for Requests tab
        document.addEventListener('DOMContentLoaded', () => {
            const reqTabBtn = document.getElementById('requests-tab');
            if (reqTabBtn) {
                reqTabBtn.addEventListener('shown.bs.tab', () => {
                    if (_requestsLoadedCount === 0 && _requestsHasMore && !_requestsLoading) {
                        fetchData(true);
                    }
                });
            }
        });

        // ── Dashboard Status Bar ──────────────────────────────────────────
        let _prevCycleRunning = null;   // track cycle state for auto-refresh
        let _statusBarScheduled = false; // prevent duplicate polling chains
        let _lastSeenEvalId    = null;   // track newest report to detect new evaluations

        // ── New-evaluation banner helpers ─────────────────────────────────
        function showNewEvalBanner() {
            const banner = document.getElementById('newEvalBanner');
            if (banner) {
                // Reset animation so it plays again even if already visible
                banner.style.display = 'none';
                void banner.offsetWidth; // force reflow
                banner.style.display = 'block';
            }
        }
        function dismissBanner() {
            const banner = document.getElementById('newEvalBanner');
            if (banner) banner.style.display = 'none';
        }
        function dismissBannerAndRefresh() {
            dismissBanner();
            location.reload();
        }

        async function refreshDashboardStatusBar() {
            _statusBarScheduled = false;
            try {
                const [evalResp, cycleResp] = await Promise.all([
                    fetch('/trust-evaluation-reports?limit=1'),
                    fetch('/trust-cycle/status')
                ]);
                const evalData  = await evalResp.json();
                const cycleData = await cycleResp.json();

                // ── Detect cycle completion → auto-refresh dashboard ────
                const nowRunning = cycleData.is_running === true;
                if (_prevCycleRunning === true && nowRunning === false) {
                    // Cycle just finished — refresh all dashboard panels
                    fetchData();
                }
                _prevCycleRunning = nowRunning;

                // ── Latest evaluation pill + new-eval detection ─────────
                const reports = evalData.reports || [];
                const evalText = document.getElementById('latestEvalText');
                if (reports.length > 0) {
                    const r = reports[0];
                    const raw   = r.analysis_type || r.evaluation_mode || 'batch';
                    const label = raw === 'manual' ? 'Manual' : raw === 'immediate' ? 'Immediate' : 'Batch';
                    const cls   = raw === 'manual' ? 'text-warning' : raw === 'immediate' ? 'text-info' : 'text-success';
                    const dt    = new Date(r.timestamp).toLocaleString();
                    evalText.innerHTML = `Last evaluation: <strong class="${cls}">${label}</strong> &mdash; ${dt}`;

                    // Show banner when a new report appears (skip on first load)
                    const newId = r._id || r.id || null;
                    if (_lastSeenEvalId !== null && newId && newId !== _lastSeenEvalId) {
                        showNewEvalBanner();
                    }
                    _lastSeenEvalId = newId;
                } else {
                    evalText.textContent = 'No evaluations yet';
                    _lastSeenEvalId = null;
                }

                // ── Cycle status badge ──────────────────────────────────
                const badge = document.getElementById('cycleStatusBadge');
                const isRunning = cycleData.is_running === true;
                const isEnabled = cycleData.enabled === true;

                if (isRunning && cycleData.end_time) {
                    // Cycle actively running
                    const endStr = new Date(cycleData.end_time).toLocaleString();
                    badge.innerHTML = `
                        <span class="badge bg-success d-flex align-items-center gap-1" style="font-size:0.8em;">
                            <span class="spinner-grow spinner-grow-sm" role="status" style="width:.55rem;height:.55rem;"></span>
                            Cycle running &mdash; ends ${endStr}
                        </span>`;
                } else if (!isRunning && isEnabled) {
                    // Cycle just finished, will automatically restart
                    badge.innerHTML = `
                        <span class="badge bg-warning text-dark d-flex align-items-center gap-1" style="font-size:0.8em;">
                            <span class="spinner-border spinner-border-sm" role="status" style="width:.55rem;height:.55rem;border-width:2px;"></span>
                            Cycle finished &mdash; restarting…
                        </span>`;
                } else {
                    // No cycle scheduled or started
                    badge.innerHTML = `<span class="badge bg-secondary" style="font-size:0.8em;"><i class="bi bi-stop-circle me-1"></i>Cycle inactive</span>`;
                }
            } catch (e) {
                console.warn('Status bar update failed:', e);
            } finally {
                // Poll every 1 s while a cycle is running, 15 s when idle
                // Guard against duplicate chains (e.g. manualRefresh also calls this)
                if (!_statusBarScheduled) {
                    _statusBarScheduled = true;
                    const delay = (_prevCycleRunning === true) ? 1000 : 15000;
                    setTimeout(refreshDashboardStatusBar, delay);
                }
            }
        }

        // Kick off the first poll immediately on load
        refreshDashboardStatusBar();
        function toggleJson(id) {
            const el = document.getElementById(id);
            if (el.classList.contains('json-collapsed')) {
                el.classList.remove('json-collapsed');
                el.classList.add('json-expanded');
            } else {
                el.classList.remove('json-expanded');
                el.classList.add('json-collapsed');
            }
        }
        function openMapWindow(item) {
            const win = window.open('', '_blank', 'width=1000,height=900');
            win.document.write('<!DOCTYPE html><html><head><title>Map Payload</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head><body>');
            win.document.write('<div class="container mt-4"><h2>Map Payload</h2>');
            win.document.write('<form id="mapForm">');
            win.document.write(`<div class="mb-2"><label>Tool Name</label><input class="form-control" name="tool_name" value="${item.tool_name}" required></div>`);
            win.document.write('<div class="mb-2"><label>Description</label><input class="form-control" name="description"></div>');
            win.document.write('<div class="mb-2"><label>Trust Evaluation Category</label><select class="form-control" name="trust_evaluation_category" required><option value="">Select...</option><option value="Security">Security</option><option value="Reliability">Reliability</option><option value="Resilience">Resilience</option><option value="Threat Exposure">Threat Exposure</option><option value="Intentions">Intentions</option></select></div>');
            win.document.write('<div class="mb-2"><label>Data Type</label><select class="form-control" name="data_type" id="dataTypeSelect"><option value="binary">Binary</option><option value="categorical">Categorical</option><option value="continuous">Continuous</option></select></div>');
            win.document.write('<div class="mb-2" id="categoriesDiv" style="display:none;"><label>Categories (comma separated)</label><input class="form-control" name="categories"></div>');
            win.document.write('<div class="mb-2" id="continuousDiv" style="display:none;">' +
                '<label>Min Value</label><input class="form-control mb-1" name="min_value" id="minValueBox" type="number" step="any" disabled>' +
                '<label>Max Value</label><input class="form-control" name="max_value" id="maxValueBox" type="number" step="any" disabled>' +
                '</div>');
            win.document.write('<div class="mb-2"><label>Unique ID Path</label><input class="form-control" name="unique_id_path" id="uniqueIdPath" placeholder="e.g. payload.id"></div>');
            win.document.write('<div class="mb-2"><label>Unique ID Value</label><input class="form-control" name="unique_id_value" id="uniqueIdValue" readonly></div>');
            win.document.write('<div class="mb-2"><label>Value Path</label><input class="form-control" name="value_path" id="valuePath" placeholder="e.g. payload.value"></div>');
            win.document.write('<div class="mb-2"><label>Supplement Info Path</label><input class="form-control" name="supplement" id="supplementPath" placeholder="e.g. payload.location"></div>');
            
            // Value processing section
            win.document.write('<hr><h5>Value Processing (Optional)</h5>');
            win.document.write('<div class="mb-2">');
            win.document.write('  <div class="form-check form-switch">');
            win.document.write('    <input class="form-check-input" type="checkbox" id="valueProcessingCheckbox">');
            win.document.write('    <label class="form-check-label" for="valueProcessingCheckbox">');
            win.document.write('      Special processing needed (substring, JSON key extraction, etc.)');
            win.document.write('    </label>');
            win.document.write('  </div>');
            win.document.write('</div>');
            
            win.document.write('<div id="valueProcessingPanel" style="display:none;" class="card p-3 mb-3">');
            win.document.write('  <div class="mb-3">');
            win.document.write('    <label>Processing Type</label>');
            win.document.write('    <select id="processingType" class="form-select">');
            win.document.write('      <option value="">Select Processing Type</option>');
            win.document.write('      <option value="substring">Substring (Split String)</option>');
            win.document.write('      <option value="json_key">JSON Key Extraction</option>');
            win.document.write('    </select>');
            win.document.write('  </div>');
            
            // Substring Section
            win.document.write('  <div id="substringSection" style="display:none;">');
            win.document.write('    <div class="mb-2">');
            win.document.write('      <label>Separator</label>');
            win.document.write('      <input type="text" class="form-control" id="separator" placeholder="e.g., ,  :  _">');
            win.document.write('    </div>');
            win.document.write('    <div class="mb-2">');
            win.document.write('      <label>Test Value</label>');
            win.document.write('      <input type="text" class="form-control" id="testValue" placeholder="Enter a sample value to test">');
            win.document.write('      <button type="button" class="btn btn-sm btn-info mt-2">Preview</button>');
            win.document.write('    </div>');
            win.document.write('    <div id="previewResult" class="alert alert-secondary mt-2" style="display:none;"></div>');
            win.document.write('    <div class="mb-2">');
            win.document.write('      <label>Select Index</label>');
            win.document.write('      <select id="selectedIndex" class="form-select"></select>');
            win.document.write('    </div>');
            win.document.write('  </div>');
            
            // JSON Key Section
            win.document.write('  <div id="jsonKeySection" style="display:none;">');
            win.document.write('    <div class="mb-2">');
            win.document.write('      <label>JSON Key</label>');
            win.document.write('      <input type="text" class="form-control" id="jsonKey" placeholder="e.g., temperature, sensor_id">');
            win.document.write('    </div>');
            win.document.write('  </div>');
            
            win.document.write('  <div id="processingStepsList"></div>');
            win.document.write('  <button type="button" class="btn btn-sm btn-primary" id="addStepBtn">Add Step</button>');
            win.document.write('  <button type="button" class="btn btn-sm btn-secondary" id="clearStepsBtn">Clear All</button>');
            win.document.write('</div>');
            
            // Evaluation mode selector
            win.document.write('<hr><h5>Evaluation Mode</h5>');
            win.document.write('<div class="mb-3">');
            win.document.write('  <div class="form-check">');
            win.document.write('    <input class="form-check-input" type="radio" name="evaluation_mode" value="simple" id="modeSimple" checked>');
            win.document.write('    <label class="form-check-label" for="modeSimple">Simple (Value Path Only)</label>');
            win.document.write('  </div>');
            win.document.write('  <div class="form-check">');
            win.document.write('    <input class="form-check-input" type="radio" name="evaluation_mode" value="advanced" id="modeAdvanced">');
            win.document.write('    <label class="form-check-label" for="modeAdvanced">Advanced (Multi-Field Evaluation)</label>');
            win.document.write('  </div>');
            win.document.write('</div>');
            
            // Advanced rules panel - STEP 1: Select Secondary Fields
            win.document.write('<div id="advancedRulesPanel" style="display:none;" class="card p-3 mb-3 border-info">');
            win.document.write('  <div class="card-header bg-info text-white"><strong>Step 1: Select Secondary Value Fields</strong></div>');
            win.document.write('  <div class="card-body">');
            win.document.write('    <p class="text-muted small mb-3">Primary Value: <strong id="primaryValueDisplay">Value Path</strong></p>');
            win.document.write('    <p class="text-muted small mb-3">Select additional fields to use in evaluation rules:</p>');
            win.document.write('    <div id="secondaryFieldsList" class="mb-3"></div>');
            win.document.write('    <button type="button" class="btn btn-sm btn-success" id="addSecondaryFieldBtn">+ Add Secondary Field</button>');
            win.document.write('  </div>');
            win.document.write('</div>');
            
            // Advanced rules panel - STEP 2: Define Rules
            win.document.write('<div id="defineRulesPanel" style="display:none;" class="card p-3 mb-3 border-success">');
            win.document.write('  <div class="card-header bg-success text-white"><strong>Step 2: Define Evaluation Rules</strong></div>');
            win.document.write('  <div class="card-body">');
            win.document.write('    <p class="text-muted small mb-3">Create evaluation rules combining primary and secondary fields:</p>');
            win.document.write('    <div id="rulesList" class="mb-3"></div>');
            win.document.write('    <button type="button" class="btn btn-sm btn-primary" id="addRuleBtn">+ Add Rule</button>');
            win.document.write('    <button type="button" class="btn btn-sm btn-secondary" id="clearRulesBtn" style="display:none;">Clear All Rules</button>');
            win.document.write('    <hr id="rulesSeparator" style="display:none;">');
            win.document.write('    <div id="betweenRulesConnectorPanel" style="display:none;" class="mt-4 pt-3 border-top">');
            win.document.write('      <h6 class="text-warning mb-3"><i class="bi bi-diagram-3"></i> Between-Rules Connector</h6>');
            win.document.write('      <p class="text-muted small mb-3">When multiple rules are defined, select how to combine their outcomes:</p>');
            win.document.write('      <div class="mb-3">');
            win.document.write('        <label class="form-label"><strong>Combine Multiple Rules With:</strong></label>');
            win.document.write('        <select class="form-select" id="betweenRulesConnectorSelect">');
            win.document.write('          <option value="AND">AND - All rules must match</option>');
            win.document.write('          <option value="OR">OR - At least one rule must match</option>');
            win.document.write('        </select>');
            win.document.write('        <small class="text-muted d-block mt-2"><strong>Impact Level:</strong> Selected from all matched rules (high > medium > low)</small>');
            win.document.write('      </div>');
            win.document.write('    </div>');
            win.document.write('  </div>');
            win.document.write('</div>');
            
            win.document.write('<div class="mb-2"><label>Payload (click a field to select its path):</label><div id="jsonTree" class="json-tree"></div></div>');
            win.document.write('<button type="submit" class="btn btn-success">Save Mapping</button>');
            win.document.write('</form></div>');
            win.document.write(`<script>
                var dataTypeSelect = document.getElementById('dataTypeSelect');
                var categoriesDiv = document.getElementById('categoriesDiv');
                var continuousDiv = document.getElementById('continuousDiv');
                var minValueBox = document.getElementById('minValueBox');
                var maxValueBox = document.getElementById('maxValueBox');
                function updateTypeDisplays() {
                    categoriesDiv.style.display = dataTypeSelect.value === 'categorical' ? 'block' : 'none';
                    if (dataTypeSelect.value === 'continuous') {
                        continuousDiv.style.display = 'block';
                        minValueBox.disabled = false;
                        maxValueBox.disabled = false;
                    } else {
                        continuousDiv.style.display = 'none';
                        minValueBox.disabled = true;
                        maxValueBox.disabled = true;
                        minValueBox.value = '';
                        maxValueBox.value = '';
                    }
                }
                dataTypeSelect.addEventListener('change', updateTypeDisplays);
                // Set initial state
                updateTypeDisplays();
            <\/script>`);
            win.document.write(`<script>
                function renderTree(obj, path) {
                    let html = '<ul style="list-style:none;padding-left:1em;">';
                    for (const key in obj) {
                        const newPath = path ? path + '.' + key : key;
                        const val = obj[key];
                        let typeLabel = '';
                        
                        // Determine data type
                        if (typeof val === 'object' && val !== null) {
                            if (Array.isArray(val)) {
                                typeLabel = ' <span class="badge bg-info" style="font-size:0.75em;">array</span>';
                            } else {
                                typeLabel = ' <span class="badge bg-secondary" style="font-size:0.75em;">object</span>';
                            }
                            html += \`<li><span class='json-key' onclick="selectPath('\${newPath}')" title="Click to select">\${key}\${typeLabel}</span>: <span class='json-branch'>\` + renderTree(val, newPath) + '</span></li>';
                        } else {
                            // Leaf node - show type
                            if (typeof val === 'number') {
                                typeLabel = ' <span class="badge bg-warning text-dark" style="font-size:0.75em;">number</span>';
                            } else if (typeof val === 'boolean') {
                                typeLabel = ' <span class="badge bg-danger" style="font-size:0.75em;">boolean</span>';
                            } else {
                                typeLabel = ' <span class="badge bg-success" style="font-size:0.75em;">string</span>';
                            }
                            html += \`<li><span class='json-key' onclick="selectPath('\${newPath}')" title="Click to select">\${key}\${typeLabel}</span>: <span class='json-leaf' onclick="selectPath('\${newPath}')" title="Click to select">\${val}</span></li>\`;
                        }
                    }
                    html += '</ul>';
                    return html;
                }
                function getByPath(obj, path) {
                    try {
                        const parts = path.split('.').slice(1); // remove 'payload'
                        let val = obj;
                        for (const p of parts) {
                            if (typeof val === 'object' && val !== null) {
                                val = val[p];
                            } else {
                                return undefined;
                            }
                        }
                        return val;
                    } catch { return undefined; }
                }
                function selectPath(path) {
                    const field = window.selectedField || 'uniqueIdPath';
                    const payload = ${JSON.stringify(item.payload)};
                    const val = getByPath(payload, path);
                    
                    if (field === 'addSecondaryField') {
                        // Adding a secondary field - detect data type
                        let dataType = 'string';
                        if (typeof val === 'number') {
                            dataType = 'int';
                        } else if (typeof val === 'boolean') {
                            dataType = 'boolean';
                        }
                        
                        // Add to secondary fields
                        if (window.addSecondaryField) {
                            window.addSecondaryField(path, dataType);
                        }
                    } else {
                        // Regular path selection
                        document.getElementById(field).value = path;
                        if(field === 'uniqueIdPath') {
                            // Set the unique id value automatically
                            document.getElementById('uniqueIdValue').value = val !== undefined ? val : '';
                        }
                    }
                }
                window.selectedField = 'uniqueIdPath';
                document.getElementById('uniqueIdPath').onclick = function() { window.selectedField = 'uniqueIdPath'; };
                document.getElementById('valuePath').onclick = function() { window.selectedField = 'valuePath'; };
                document.getElementById('supplementPath').onclick = function() { window.selectedField = 'supplementPath'; };
                document.getElementById('jsonTree').innerHTML = renderTree(${JSON.stringify(item.payload)}, 'payload');
                // Set initial unique id value if path is prefilled
                document.getElementById('uniqueIdPath').addEventListener('input', function() {
                    const val = getByPath(${JSON.stringify(item.payload)}, this.value);
                    document.getElementById('uniqueIdValue').value = val !== undefined ? val : '';
                });
            <\/script>`);
            win.document.write(`<script>
                // Value processing state
                let processingSteps = [];
                
                // Checkbox toggle
                document.getElementById('valueProcessingCheckbox').addEventListener('change', function() {
                    document.getElementById('valueProcessingPanel').style.display = this.checked ? 'block' : 'none';
                });
                
                // Processing type selector
                document.getElementById('processingType').addEventListener('change', function() {
                    document.getElementById('substringSection').style.display = this.value === 'substring' ? 'block' : 'none';
                    document.getElementById('jsonKeySection').style.display = this.value === 'json_key' ? 'block' : 'none';
                });
                
                // Preview button
                document.querySelector('#substringSection .btn-info').addEventListener('click', async function() {
                    const testValue = document.getElementById('testValue').value;
                    const separator = document.getElementById('separator').value;
                    if (!testValue || !separator) {
                        alert('Please enter both test value and separator');
                        return;
                    }
                    try {
                        const response = await fetch('/value-processing/preview', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({value: testValue, separator: separator})
                        });
                        const data = await response.json();
                        const resultDiv = document.getElementById('previewResult');
                        if (data.preview && data.preview.length > 0) {
                            let html = '<strong>Split Results:</strong><ul>';
                            data.preview.forEach(p => {
                                html += '<li>Index ' + p.index + ': ' + p.value + '</li>';
                            });
                            html += '</ul>';
                            resultDiv.innerHTML = html;
                            resultDiv.style.display = 'block';
                            
                            // Populate index selector
                            const indexSelect = document.getElementById('selectedIndex');
                            indexSelect.innerHTML = '';
                            data.preview.forEach(p => {
                                const option = document.createElement('option');
                                option.value = p.index;
                                option.text = 'Index ' + p.index + ': ' + p.value;
                                indexSelect.appendChild(option);
                            });
                        }
                    } catch(err) {
                        alert('Error previewing: ' + err.message);
                    }
                });
                
                // Add step button
                document.getElementById('addStepBtn').addEventListener('click', function() {
                    const processingType = document.getElementById('processingType').value;
                    if (!processingType) {
                        alert('Please select a processing type');
                        return;
                    }
                    
                    let step = { type: processingType };
                    
                    if (processingType === 'substring') {
                        const separator = document.getElementById('separator').value;
                        const index = document.getElementById('selectedIndex').value;
                        if (!separator || index === '' || index === undefined) {
                            alert('Please fill in separator and select an index');
                            return;
                        }
                        step = {
                            type: 'substring',
                            separator: separator,
                            index: parseInt(index)
                        };
                    } else if (processingType === 'json_key') {
                        const key = document.getElementById('jsonKey').value;
                        if (!key) {
                            alert('Please enter a JSON key');
                            return;
                        }
                        step = {
                            type: 'json_key',
                            key: key
                        };
                    }
                    
                    processingSteps.push(step);
                    updateStepsDisplay();
                    
                    // Clear form
                    document.getElementById('processingType').value = '';
                    document.getElementById('separator').value = '';
                    document.getElementById('testValue').value = '';
                    document.getElementById('jsonKey').value = '';
                    document.getElementById('selectedIndex').innerHTML = '';
                    document.getElementById('previewResult').style.display = 'none';
                    document.getElementById('substringSection').style.display = 'none';
                    document.getElementById('jsonKeySection').style.display = 'none';
                });
                
                // Clear steps button
                document.getElementById('clearStepsBtn').addEventListener('click', function() {
                    processingSteps = [];
                    updateStepsDisplay();
                });
                
                // Update steps display
                function updateStepsDisplay() {
                    const stepsList = document.getElementById('processingStepsList');
                    if (processingSteps.length === 0) {
                        stepsList.innerHTML = '<p class="text-muted">No steps added yet</p>';
                        return;
                    }
                    let html = '<p><strong>Processing Steps:</strong></p>';
                    processingSteps.forEach((step, idx) => {
                        if (step.type === 'substring') {
                            html += '<span class="badge bg-primary me-2">Step ' + (idx+1) + ': Split by "' + step.separator + '" → Index ' + step.index + '</span>';
                        } else if (step.type === 'json_key') {
                            html += '<span class="badge bg-info me-2">Step ' + (idx+1) + ': Extract key "' + step.key + '"</span>';
                        }
                    });
                    stepsList.innerHTML = html;
                }
                
                // Advanced rules system
                let advancedRules = [];
                const availableOperators = {
                    string: ['equals', 'not_equals', 'contains', 'not_contains', 'starts_with', 'ends_with', 'regex_match', 'length_equals', 'length_greater_than'],
                    numeric: ['equals', 'not_equals', 'greater_than', 'less_than', 'between', 'greater_equal', 'less_equal', 'divisible_by'],
                    boolean: ['is_true', 'is_false', 'equals']
                };
                
                // Add rule button
                document.getElementById('addRuleBtn').addEventListener('click', function() {
                    showRuleModal(null);
                });
                
                // Secondary fields management
                let secondaryFields = [];
                
                // Update primary value display
                document.getElementById('valuePath').addEventListener('change', function() {
                    document.getElementById('primaryValueDisplay').textContent = this.value || 'Value Path';
                });
                
                // Evaluation mode toggle
                document.getElementById('modeSimple').addEventListener('change', function() {
                    document.getElementById('advancedRulesPanel').style.display = 'none';
                    document.getElementById('defineRulesPanel').style.display = 'none';
                });
                document.getElementById('modeAdvanced').addEventListener('change', function() {
                    document.getElementById('advancedRulesPanel').style.display = 'block';
                    if (secondaryFields.length > 0) {
                        document.getElementById('defineRulesPanel').style.display = 'block';
                    }
                });
                
                // Add secondary field button
                document.getElementById('addSecondaryFieldBtn').addEventListener('click', function() {
                    // Set mode to pick from tree
                    window.selectedField = 'addSecondaryField';
                    alert('Click on a field in the JSON tree below to add it as a secondary field');
                });
                
                function updateSecondaryFieldsList() {
                    const list = document.getElementById('secondaryFieldsList');
                    list.innerHTML = '';
                    
                    if (secondaryFields.length === 0) {
                        list.innerHTML = '<p class="text-muted small">No secondary fields selected yet</p>';
                        document.getElementById('defineRulesPanel').style.display = 'none';
                        return;
                    }
                    
                    secondaryFields.forEach((field, index) => {
                        const fieldDiv = document.createElement('div');
                        fieldDiv.className = 'badge bg-info me-2 mb-2 p-2';
                        fieldDiv.innerHTML = '<span><strong>' + field.path + '</strong> <span class="badge bg-secondary">' + field.dataType + '</span></span> <button type="button" class="btn btn-sm btn-link text-white ms-2" onclick="removeSecondaryField(' + index + ')">×</button>';
                        list.appendChild(fieldDiv);
                    });
                    
                    // Show rules panel if advanced mode is selected
                    if (secondaryFields.length > 0 && document.getElementById('modeAdvanced').checked) {
                        document.getElementById('defineRulesPanel').style.display = 'block';
                    }
                }
                
                window.removeSecondaryField = function(index) {
                    secondaryFields.splice(index, 1);
                    updateSecondaryFieldsList();
                };
                
                window.addSecondaryField = function(path, dataType) {
                    if (!secondaryFields.some(f => f.path === path)) {
                        secondaryFields.push({ path, dataType });
                        updateSecondaryFieldsList();
                        // Clear the mode after adding
                        window.selectedField = 'uniqueIdPath';
                    } else {
                        alert('This field is already selected');
                    }
                };
                
                // Clear rules button
                document.getElementById('clearRulesBtn').addEventListener('click', function() {
                    if (confirm('Clear all rules?')) {
                        advancedRules = [];
                        updateRulesDisplay();
                    }
                });
                
                function updateRulesDisplay() {
                    const rulesList = document.getElementById('rulesList');
                    const betweenRulesPanel = document.getElementById('betweenRulesConnectorPanel');
                    const rulesSeparator = document.getElementById('rulesSeparator');
                    
                    if (advancedRules.length === 0) {
                        rulesList.innerHTML = '<p class="text-muted">No rules defined yet. Click "Add Rule" to create one.</p>';
                        if (betweenRulesPanel) betweenRulesPanel.style.display = 'none';
                        if (rulesSeparator) rulesSeparator.style.display = 'none';
                        return;
                    }
                    
                    // Show between-rules connector and separator only if 2+ rules
                    if (betweenRulesPanel) {
                        betweenRulesPanel.style.display = advancedRules.length >= 2 ? 'block' : 'none';
                    }
                    if (rulesSeparator) {
                        rulesSeparator.style.display = advancedRules.length >= 2 ? 'block' : 'none';
                    }
                    
                    let html = '<div class="mb-3"><strong>Rules (' + advancedRules.length + '):</strong></div>';
                    advancedRules.forEach((rule, idx) => {
                        html += '<div class="card mb-2 p-2"><div class="d-flex justify-content-between align-items-center">';
                        html += '<div><strong>' + rule.name + '</strong><br>';
                        html += '<span class="text-secondary small">';
                        html += 'Primary: ' + rule.primary_field_path + ' = ' + rule.primary_value + ' | ';
                        html += 'Within-Rule: ' + (rule.within_rule_connector || rule.conditions_connector || 'AND') + ' | ';
                        html += 'Impact: ' + rule.impact_level + ' | ';
                        html += 'Status: ' + (rule.enabled ? '✓ Enabled' : '✗ Disabled') + '';
                        html += '</span></div>';
                        html += '<div><button type="button" class="btn btn-sm btn-warning" data-rule-idx="' + idx + '" onclick="editRule(this)">Edit</button> ';
                        html += '<button type="button" class="btn btn-sm btn-danger" data-rule-idx="' + idx + '" onclick="deleteRule(this)">Delete</button></div>';
                        html += '</div></div>';
                    });
                    rulesList.innerHTML = html;
                }
                
                function editRule(btn) {
                    const idx = parseInt(btn.getAttribute('data-rule-idx'));
                    showRuleModal(idx);
                }
                
                function deleteRule(btn) {
                    const idx = parseInt(btn.getAttribute('data-rule-idx'));
                    if (confirm('Delete rule: ' + advancedRules[idx].name + '?')) {
                        advancedRules.splice(idx, 1);
                        updateRulesDisplay();
                    }
                }
                
                function showRuleModal(editIdx) {
                    const isEdit = editIdx !== null;
                    const rule = isEdit ? advancedRules[editIdx] : { name: '', condition_groups: [], group_connector: 'AND', impact_level: 'medium', enabled: true };
                    
                    // Create modal HTML
                    let modalHtml = '<div class="modal fade" id="ruleModal"><div class="modal-dialog modal-lg"><div class="modal-content">';
                    modalHtml += '<div class="modal-header"><h5>' + (isEdit ? 'Edit' : 'Add New') + ' Rule</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>';
                    modalHtml += '<div class="modal-body">';
                    
                    // Rule name
                    modalHtml += '<div class="mb-3"><label class="form-label">Rule Name</label><input type="text" class="form-control" id="ruleName" value="' + (rule.name || '') + '" placeholder="e.g., Admin User Check"></div>';
                    
                    // Impact level
                    modalHtml += '<div class="mb-3"><label class="form-label">Impact Level</label>';
                    modalHtml += '<select class="form-select" id="ruleImpactLevel">';
                    ['low', 'medium', 'high'].forEach(lvl => {
                        modalHtml += '<option value="' + lvl + '" ' + (rule.impact_level === lvl ? 'selected' : '') + '>' + lvl.charAt(0).toUpperCase() + lvl.slice(1) + '</option>';
                    });
                    modalHtml += '</select></div>';
                    
                    // Enabled toggle
                    modalHtml += '<div class="mb-3"><div class="form-check"><input class="form-check-input" type="checkbox" id="ruleEnabled" ' + (rule.enabled ? 'checked' : '') + '><label class="form-check-label" for="ruleEnabled">Enable this rule</label></div></div>';
                    
                    // ========== WITHIN-RULE CONNECTOR ==========
                    modalHtml += '<hr><h6 class="text-primary"><i class="bi bi-diagram-2"></i> Within-Rule Connector</h6>';
                    modalHtml += '<p class="text-muted small mb-3">How to combine the primary field with secondary conditions inside this rule:</p>';
                    
                    // Simple condition builder
                    modalHtml += '<hr><h6>Rule Conditions</h6>';
                    modalHtml += '<p class="text-muted small">Define a primary field match and add secondary field conditions:</p>';
                    
                    // Get primary value field path and payload data
                    const primaryValuePath = document.getElementById('valuePath') ? document.getElementById('valuePath').value : 'value_path';
                    const payloadData = ${JSON.stringify(item.payload)};
                    
                    // Helper function to get value from path
                    function getValueFromPath(obj, path) {
                        const parts = path.split('.');
                        let val = obj;
                        for (const p of parts) {
                            if (val && typeof val === 'object' && p in val) {
                                val = val[p];
                            } else {
                                return null;
                            }
                        }
                        return val;
                    }
                    
                    const primaryFieldValue = getValueFromPath(payloadData, primaryValuePath);
                    const dataType = document.getElementById('dataTypeSelect') ? document.getElementById('dataTypeSelect').value : 'categorical';
                    
                    // Primary field info (read-only)
                    modalHtml += '<div class="card mb-3 p-3 bg-light"><h6>Primary Field</h6>';
                    modalHtml += '<div class="mb-2"><label class="form-label">Field Path</label>';
                    modalHtml += '<input type="text" class="form-control" readonly value="' + primaryValuePath + '"></div>';
                    
                    // Show input based on data type
                    if (dataType === 'continuous') {
                        modalHtml += '<div class="mb-2"><label class="form-label">Value (Number)</label>';
                        modalHtml += '<input type="number" class="form-control" id="conditionPrimaryValue" placeholder="Enter numeric value" value="' + (primaryFieldValue || '') + '"></div>';
                    } else if (dataType === 'binary') {
                        modalHtml += '<div class="mb-2"><label class="form-label">Value (Binary)</label>';
                        modalHtml += '<select class="form-select" id="conditionPrimaryValue">';
                        modalHtml += '<option value="">-- Select value --</option>';
                        modalHtml += '<option value="true">True</option>';
                        modalHtml += '<option value="false">False</option>';
                        modalHtml += '</select></div>';
                    } else {
                        modalHtml += '<div class="mb-2"><label class="form-label">Value (Categorical)</label>';
                        modalHtml += '<input type="text" class="form-control" id="conditionPrimaryValue" placeholder="Enter value" value="' + (primaryFieldValue || '') + '"></div>';
                    }
                    modalHtml += '</div>';
                    
                    // Secondary fields conditions builder
                    modalHtml += '<div class="card mb-3 p-3"><h6>Secondary Field Conditions</h6>';
                    modalHtml += '<p class="text-muted small mb-3">Add one or more secondary field evaluations:</p>';
                    
                    // Secondary fields list
                    modalHtml += '<div id="secondaryConditionsList" class="mb-3"></div>';
                    
                    // Add secondary condition button
                    modalHtml += '<button type="button" class="btn btn-sm btn-success" id="addSecondaryConditionBtn">+ Add Secondary Field Condition</button>';
                    
                    // Within-rule connector selector (for secondary conditions)
                    modalHtml += '<div class="mt-3 p-3 bg-light border-left-primary">';
                    modalHtml += '<label class="form-label"><strong>Primary Field + Secondary Conditions:</strong></label>';
                    modalHtml += '<p class="text-muted small mb-2">The primary field must always match. Secondary conditions are combined with:</p>';
                    modalHtml += '<select class="form-select" id="secondaryConditionsConnector">';
                    modalHtml += '<option value="AND">AND - Primary must match AND all secondary conditions must match</option>';
                    modalHtml += '<option value="OR">OR - Primary must match AND at least one secondary condition must match</option>';
                    modalHtml += '</select>';
                    modalHtml += '</div>';
                    modalHtml += '</div>';
                    
                    modalHtml += '</div>';
                    modalHtml += '<div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>';
                    modalHtml += '<button type="button" class="btn btn-primary" id="saveRuleBtn">Save Rule</button></div>';
                    modalHtml += '</div></div></div>';
                    
                    // Create and show modal
                    const modalDiv = document.createElement('div');
                    modalDiv.innerHTML = modalHtml;
                    document.body.appendChild(modalDiv);
                    
                    const modalEl = modalDiv.querySelector('#ruleModal');
                    const modal = new bootstrap.Modal(modalEl);
                    
                    // Use modalDiv for scoped queries
                    const ruleName = modalDiv.querySelector('#ruleName');
                    const ruleImpactLevel = modalDiv.querySelector('#ruleImpactLevel');
                    const ruleEnabled = modalDiv.querySelector('#ruleEnabled');
                    const saveRuleBtn = modalDiv.querySelector('#saveRuleBtn');
                    const conditionPrimaryValue = modalDiv.querySelector('#conditionPrimaryValue');
                    const secondaryConditionsList = modalDiv.querySelector('#secondaryConditionsList');
                    const addSecondaryConditionBtn = modalDiv.querySelector('#addSecondaryConditionBtn');
                    const secondaryConditionsConnector = modalDiv.querySelector('#secondaryConditionsConnector');
                    
                    // Store secondary conditions for this rule
                    let secondaryConditions = [];
                    
                    // Update secondary conditions list display
                    function updateSecondaryConditionsList() {
                        if (secondaryConditions.length === 0) {
                            secondaryConditionsList.innerHTML = '<p class="text-muted small">No conditions added yet</p>';
                            return;
                        }
                        
                        let html = '<div class="list-group">';
                        secondaryConditions.forEach((cond, idx) => {
                            html += '<div class="list-group-item p-2">';
                            html += '<div class="d-flex justify-content-between align-items-start">';
                            html += '<small><strong>' + cond.secondary_field + '</strong> ' + cond.operator + ' ' + cond.secondary_value + '</small>';
                            html += '<button type="button" class="btn btn-sm btn-danger" onclick="removeSecondaryCondition(' + idx + ')">Remove</button>';
                            html += '</div>';
                            html += '</div>';
                        });
                        html += '</div>';
                        secondaryConditionsList.innerHTML = html;
                    }
                    
                    // Add secondary condition
                    window.removeSecondaryCondition = function(idx) {
                        secondaryConditions.splice(idx, 1);
                        updateSecondaryConditionsList();
                    };
                    
                    addSecondaryConditionBtn.addEventListener('click', function() {
                        // Create form for adding new secondary condition
                        let condHtml = '<div class="card p-3 mt-3 bg-light">';
                        condHtml += '<h6>New Secondary Condition</h6>';
                        
                        // Secondary field selector
                        condHtml += '<div class="mb-3"><label class="form-label">Secondary Field</label>';
                        condHtml += '<select id="tempSecondaryField" class="form-select"><option value="">-- Select field --</option>';
                        if (secondaryFields && secondaryFields.length > 0) {
                            secondaryFields.forEach(field => {
                                condHtml += '<option value="' + field.path + '" data-type="' + field.dataType + '">' + field.path + ' (' + field.dataType + ')</option>';
                            });
                        }
                        condHtml += '</select></div>';
                        
                        // Operator selector
                        condHtml += '<div class="mb-3"><label class="form-label">Operator</label>';
                        condHtml += '<select id="tempOperator" class="form-select"><option value="">-- Select operator --</option>';
                        const stringOps = ['equals', 'not_equals', 'contains', 'not_contains', 'starts_with', 'ends_with'];
                        stringOps.forEach(op => {
                            condHtml += '<option value="' + op + '" data-type="string">' + op.replace(/_/g, ' ') + '</option>';
                        });
                        const numericOps = ['greater_than', 'less_than', 'greater_equal', 'less_equal', 'between'];
                        numericOps.forEach(op => {
                            condHtml += '<option value="' + op + '" data-type="numeric">' + op.replace(/_/g, ' ') + '</option>';
                        });
                        condHtml += '</select></div>';
                        
                        // Value input
                        condHtml += '<div class="mb-3"><label class="form-label">Value to Evaluate</label>';
                        condHtml += '<input type="text" id="tempValue" class="form-control" placeholder="Enter value"></div>';
                        
                        // Buttons
                        condHtml += '<button type="button" class="btn btn-sm btn-primary" id="confirmConditionBtn">Add Condition</button>';
                        condHtml += '<button type="button" class="btn btn-sm btn-secondary" id="cancelConditionBtn">Cancel</button>';
                        condHtml += '</div>';
                        
                        // Insert temp form
                        addSecondaryConditionBtn.insertAdjacentHTML('beforebegin', condHtml);
                        addSecondaryConditionBtn.style.display = 'none';
                        
                        const tempField = modalDiv.querySelector('#tempSecondaryField');
                        const tempOperator = modalDiv.querySelector('#tempOperator');
                        const tempValue = modalDiv.querySelector('#tempValue');
                        const confirmBtn = modalDiv.querySelector('#confirmConditionBtn');
                        const cancelBtn = modalDiv.querySelector('#cancelConditionBtn');
                        
                        // Filter operators based on field type
                        tempField.addEventListener('change', function() {
                            const fieldType = this.options[this.selectedIndex].getAttribute('data-type');
                            Array.from(tempOperator.querySelectorAll('option')).forEach(opt => {
                                if (opt.value === '') {
                                    opt.style.display = '';
                                } else {
                                    opt.style.display = (opt.getAttribute('data-type') === fieldType) ? '' : 'none';
                                }
                            });
                            tempOperator.value = '';
                        });
                        
                        confirmBtn.addEventListener('click', function() {
                            const field = tempField.value;
                            const op = tempOperator.value;
                            const val = tempValue.value.trim();
                            
                            if (!field || !op || !val) {
                                alert('Please fill in all fields');
                                return;
                            }
                            
                            secondaryConditions.push({
                                secondary_field: field,
                                operator: op,
                                secondary_value: val
                            });
                            
                            // Remove temp form
                            modalDiv.querySelector('.card.p-3.mt-3.bg-light').remove();
                            addSecondaryConditionBtn.style.display = 'inline-block';
                            updateSecondaryConditionsList();
                        });
                        
                        cancelBtn.addEventListener('click', function() {
                            modalDiv.querySelector('.card.p-3.mt-3.bg-light').remove();
                            addSecondaryConditionBtn.style.display = 'inline-block';
                        });
                    });
                    
                    // Save rule button
                    saveRuleBtn.addEventListener('click', function() {
                        const name = ruleName.value.trim();
                        if (!name) {
                            alert('Please enter a rule name');
                            return;
                        }
                        
                        const primaryValue = conditionPrimaryValue.value.trim();
                        if (!primaryValue) {
                            alert('Please enter primary field value');
                            return;
                        }
                        
                        if (secondaryConditions.length === 0) {
                            alert('Please add at least one secondary field condition');
                            return;
                        }
                        
                        // Create rule with primary value and multiple secondary conditions
                        rule.primary_field_path = primaryValuePath;
                        rule.primary_value = primaryValue;
                        rule.secondary_conditions = secondaryConditions;
                        rule.within_rule_connector = secondaryConditionsConnector.value;  // New: within-rule connector
                        rule.name = name;
                        rule.impact_level = ruleImpactLevel.value;
                        rule.enabled = ruleEnabled.checked;
                        
                        if (isEdit) {
                            advancedRules[editIdx] = rule;
                        } else {
                            advancedRules.push(rule);
                        }
                        
                        updateRulesDisplay();
                        modal.hide();
                        setTimeout(() => modalDiv.remove(), 300);
                    });
                    
                    // Close modal cleanup
                    modalEl.addEventListener('hidden.bs.modal', () => {
                        setTimeout(() => modalDiv.remove(), 10);
                    });
                    
                    modal.show();
                }
                
                function updateConditionGroupsDisplay(groups, container) {
                    if (!container) {
                        container = document.getElementById('conditionGroupsList');
                    }
                    if (!groups || groups.length === 0) {
                        container.innerHTML = '<p class="text-muted small">No condition groups yet</p>';
                        return;
                    }
                    let html = '';
                    groups.forEach((grp, gIdx) => {
                        html += '<div class="card mb-2 p-2"><div class="d-flex justify-content-between align-items-start">';
                        html += '<div class="flex-grow-1">';
                        html += '<small><strong>Group ' + (gIdx + 1) + ':</strong> ' + (grp.conditions ? grp.conditions.length : 0) + ' condition(s), Connector: <strong>' + grp.connector + '</strong></small>';
                        html += '</div>';
                        html += '<button type="button" class="btn btn-sm btn-warning ms-2" onclick="editConditionGroup(' + gIdx + ')">Edit</button> ';
                        html += '<button type="button" class="btn btn-sm btn-danger" onclick="deleteConditionGroup(' + gIdx + ')">Delete</button>';
                        html += '</div></div>';
                    });
                    container.innerHTML = html;
                }
                
                function editConditionGroup(gIdx) {
                    alert('Condition group editing not yet implemented in demo. You can manually add conditions via the API.');
                }
                function deleteConditionGroup(gIdx) {
                    const modalBody = document.querySelector('.modal-body');
                    const rule = { condition_groups: [] };
                    // This would need proper implementation to access the rule from modal
                    alert('Deletion in demo view - use API for full management');
                }
                
                // Form submission with value processing
                document.getElementById('mapForm').onsubmit = async function(e) {
                    e.preventDefault();
                    const form = e.target;
                    const data = Object.fromEntries(new FormData(form));
                    
                    // Add processing steps
                    data.value_processing_required = processingSteps.length > 0;
                    data.value_processing_steps = processingSteps;
                    
                    // Add secondary fields if in advanced mode
                    const evaluationMode = document.querySelector('input[name="evaluation_mode"]:checked').value;
                    data.evaluation_mode = evaluationMode;
                    data.secondary_value_fields = secondaryFields;
                    
                    // Add advanced rules if in advanced mode
                    if (evaluationMode === 'advanced' && advancedRules.length > 0) {
                        data.advanced_rules = advancedRules;
                        // Add between-rules connector
                        const betweenRulesConnectorSelect = document.getElementById('betweenRulesConnectorSelect');
                        data.between_rules_connector = betweenRulesConnectorSelect ? betweenRulesConnectorSelect.value : 'AND';
                    } else {
                        data.advanced_rules = null;
                        data.between_rules_connector = 'AND';
                    }
                    
                    await fetch('/map', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    
                    if(window.opener && window.opener.switchToMappedTab){
                        window.opener.switchToMappedTab();
                    }
                    window.close();
                };
                
                // Initialize rules display on form load
                updateRulesDisplay();
            <\/script>`)
            win.document.write('<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"><\/script>');
            win.document.write('</body></html>');
        }
        function switchToMappedTab() {
            var mappedTab = document.getElementById('mapped-tab');
            if (mappedTab) {
                var tab = new bootstrap.Tab(mappedTab);
                tab.show();
            }
            fetchMapped();
            fetchData();
        }
        async function renderTrustConfigStep3() {
            // Fetch mapped requests and step 3 configs
            const [mappedResp, configResp] = await Promise.all([
                fetch('/mapped'),
                fetch('/trust-config-step3-get-all')
            ]);
            const mapped = await mappedResp.json();
            const configs = await configResp.json();
            // Build a lookup for category => config
            const configMap = {};
            configs.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                configMap[cat] = cfg;
            });
            // Group tools by category
            const byCategory = {};
            mapped.forEach(item => {
                let cat = (item.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                if (!byCategory[cat]) byCategory[cat] = [];
                byCategory[cat].push(item);
            });
            function capitalizeWords(str) {
                return str.replace(/\b\w/g, c => c.toUpperCase());
            }
            let html = '';
            Object.entries(byCategory).forEach(([cat, tools]) => {
                const cfg = configMap[cat] || {};
                const overrideActive = cfg.override_active === 'true';
                const overrideCount = cfg.override_count || '';
                const overrideBehaviour = cfg.override_behaviour || 'normal';
                const toolBehaviour = cfg.tool_behaviour || 'normal';
                const finalBehaviour = cfg.final_behaviour || 'normal';
                html += `<div class="mb-4 p-3 border rounded">
                    <h5>Category: <b>${capitalizeWords(cat)}</b></h5>
                    <div>Number of tools registered: <b>${tools.length}</b></div>
                    <div>Default: Majority behaviour for this category will be selected.<br>
                        <span class="text-secondary">Majority Low = Normal, Majority Mid = Suspicious, Majority High = Compromised</span>
                    </div>
                    <div class="mt-2">Override rule:
                        <label class="form-check-label ms-2">
                            <input type="checkbox" class="form-check-input" name="${cat}_override_active" value="true" ${overrideActive ? 'checked' : ''}> Activate Override
                        </label><br>
                        <input type="number" min="1" class="form-control d-inline w-auto" style="width:80px;" name="${cat}_override_count" placeholder="Number of tools" value="${overrideCount}">
                        <select class="form-select w-auto d-inline" name="${cat}_tool_behaviour">
                            <option value="normal" ${toolBehaviour === 'normal' ? 'selected' : ''}>Normal</option>
                            <option value="suspicious" ${toolBehaviour === 'suspicious' ? 'selected' : ''}>Suspicious</option>
                            <option value="compromised" ${toolBehaviour === 'compromised' ? 'selected' : ''}>Compromised</option>
                        </select>
                        <span class="text-secondary ms-2">(If at least <b>number of tools</b> then <b>behaviour</b>)</span>
                    </div>
                    <div class="mt-2">If at least one tool with this behaviour:
                        <select class="form-select w-auto d-inline" name="${cat}_override_behaviour">
                            <option value="normal" ${overrideBehaviour === 'normal' ? 'selected' : ''}>Normal</option>
                            <option value="suspicious" ${overrideBehaviour === 'suspicious' ? 'selected' : ''}>Suspicious</option>
                            <option value="compromised" ${overrideBehaviour === 'compromised' ? 'selected' : ''}>Compromised</option>
                        </select>
                        <span class="text-secondary ms-2">(Result in this behaviour)</span>
                    </div>
                    <div class="mt-2">Final Behaviour Categorisation: <b>${capitalizeWords(finalBehaviour)}</b></div>
                </div>`;
            });
            document.getElementById('trust-config-step3').innerHTML = html;
        }
        // Render step 3 on tab show
        document.getElementById('trust-config-tab').addEventListener('shown.bs.tab', function () {
            renderTrustConfigStep3();
        });
        async function saveTrustConfigStep3() {
            const container = document.getElementById('trust-config-step3');
            const blocks = container.querySelectorAll('.mb-4.p-3.border.rounded');
            let configsToSave = [];
            blocks.forEach(block => {
                const cat = block.querySelector('h5 b').textContent.trim().toLowerCase();
                const overrideActive = block.querySelector(`input[name="${cat}_override_active"]`).checked ? 'true' : 'false';
                let config = {
                    trust_evaluation_category: cat,
                    override_active: overrideActive
                };
                if (overrideActive === 'true') {
                    config.override_count = block.querySelector(`input[name="${cat}_override_count"]`).value;
                    // Assign override_behaviour from its own dropdown
                    config.override_behaviour = block.querySelector(`select[name="${cat}_override_behaviour"]`).value;
                }
                // Always get tool_behaviour from its own dropdown
                config.tool_behaviour = block.querySelector(`select[name="${cat}_tool_behaviour"]`).value;
                configsToSave.push(config);
            });
            let completed = 0;
            configsToSave.forEach(async config => {
                const resp = await fetch('/trust-config-step3', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                completed++;
                if (completed === configsToSave.length) {
                    const msgDiv = document.getElementById('trust-config-step3-msg');
                    if (resp.ok) {
                        msgDiv.innerHTML = '<span class="text-success">Step 3 configuration saved!</span>';
                    } else {
                        msgDiv.innerHTML = '<span class="text-danger">Failed to save step 3 configuration.</span>';
                    }
                }
            });
        }
        document.getElementById('trust-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'saveTrustConfigStep3Btn') {
                saveTrustConfigStep3();
            }
        });
        async function renderTrustConfigStep4() {
            // Fetch step 4 config
            const resp = await fetch('/trust-config-step4-get');
            const cfg = await resp.json();
            const overrideActive = cfg.override_active === 'true';
            const overrideCount = cfg.override_count || '';
            const overrideBehaviour = cfg.override_behaviour || 'normal';
            const finalBehaviour = cfg.final_behaviour || 'normal';
            let html = '';
            html += `<div class="mb-4 p-3 border rounded">
        <div>Default: Majority of category behaviour will determine system behaviour.</div>
        <div class="mt-2">Override rule:
            <label class="form-check-label ms-2">
                <input type="checkbox" class="form-check-input" name="system_override_active" value="true" ${overrideActive ? 'checked' : ''}> Activate Override
            </label><br>
            <input type="number" min="1" class="form-control d-inline w-auto" style="width:80px;" name="system_override_count" placeholder="Number of categories" value="${overrideCount}">
            <select class="form-select w-auto d-inline" name="system_override_behaviour">
                <option value="normal" ${overrideBehaviour === 'normal' ? 'selected' : ''}>Normal</option>
                <option value="suspicious" ${overrideBehaviour === 'suspicious' ? 'selected' : ''}>Suspicious</option>
                <option value="compromised" ${overrideBehaviour === 'compromised' ? 'selected' : ''}>Compromised</option>
            </select>
            <span class="text-secondary ms-2">(If at least <b>number of categories</b> then <b>behaviour</b>)</span>
        </div>
        <div class="mt-2">Final System Behaviour: <select class="form-select w-auto d-inline" name="system_final_behaviour">
            <option value="normal" ${finalBehaviour === 'normal' ? 'selected' : ''}>Normal</option>
            <option value="suspicious" ${finalBehaviour === 'suspicious' ? 'selected' : ''}>Suspicious</option>
            <option value="compromised" ${finalBehaviour === 'compromised' ? 'selected' : ''}>Compromised</option>
        </select></div>
    </div>`;
            document.getElementById('trust-config-step4').innerHTML = html;
        }
        // Render step 4 on tab show
        document.getElementById('trust-config-tab').addEventListener('shown.bs.tab', function () {
            renderTrustConfigStep4();
        });
        async function saveTrustConfigStep4() {
            const container = document.getElementById('trust-config-step4');
            const block = container.querySelector('.mb-4.p-3.border.rounded');
            const overrideActive = block.querySelector('input[name="system_override_active"]').checked ? 'true' : 'false';
            const overrideCount = block.querySelector('input[name="system_override_count"]').value;
            const overrideBehaviour = block.querySelector('select[name="system_override_behaviour"]').value;
            const finalBehaviour = block.querySelector('select[name="system_final_behaviour"]').value;
            let config = {
                override_active: overrideActive,
                override_count: overrideActive === 'true' ? overrideCount : '',
                override_behaviour: overrideActive === 'true' ? overrideBehaviour : 'normal',
                final_behaviour: finalBehaviour
            };
            const resp = await fetch('/trust-config-step4', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            const msgDiv = document.getElementById('trust-config-step4-msg');
            if (resp.ok) {
                msgDiv.innerHTML = '<span class="text-success">Step 4 configuration saved!</span>';
            } else {
                msgDiv.innerHTML = '<span class="text-danger">Failed to save step 4 configuration.</span>';
            }
        }
        document.getElementById('trust-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'saveTrustConfigStep4Btn') {
                saveTrustConfigStep4();
            }
        });
        async function renderToolConfigStep5() {
            // Fetch mapped requests and step 5 configs
            const [mappedResp, configResp] = await Promise.all([
                fetch('/mapped'),
                fetch('/tool-config-step5-get')
            ]);
            const mapped = await mappedResp.json();
            const configs = await configResp.json();
            // Build a lookup for (tool_name, category) => config
            const configMap = {};
            configs.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                configMap[`${cfg.tool_name}|||${cat}`] = cfg;
            });
            // Group by trust_evaluation_category, then by tool_name
            const byCategory = {};
            mapped.forEach(item => {
                const cat = (item.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                if (!byCategory[cat]) byCategory[cat] = [];
                byCategory[cat].push(item);
            });
            let html = '';
            Object.entries(byCategory).forEach(([cat, tools]) => {
                html += `<h5 class="mt-4">Category: <b>${cat}</b></h5>`;
                html += '<div class="table-responsive"><table class="table table-bordered"><thead><tr><th>Tool Name</th><th>Data Type</th><th>Value</th><th>Count</th></tr></thead><tbody>';
                tools.forEach(tool => {
                    const toolName = tool.tool_name;
                    const cfg = configMap[`${toolName}|||${cat}`] || {};
                    html += `<tr><td>${toolName}</td><td>${tool.data_type}</td><td>`;
                    if (tool.data_type === 'binary') {
                        const val = cfg.value || 'true';
                        html += `<select class="form-select w-auto d-inline" name="${toolName}_${cat}_value">
                    <option value="true" ${val === 'true' ? 'selected' : ''}>True</option>
                    <option value="false" ${val === 'false' ? 'selected' : ''}>False</option>
                </select>`;
                    } else if (tool.data_type === 'categorical') {
                        const cats = (tool.categories || '').split(',').map(x => x.trim()).filter(Boolean);
                        const val = cfg.value || (cats.length ? cats[0] : '');
                        html += `<select class="form-select w-auto d-inline" name="${toolName}_${cat}_value">`;
                        cats.forEach(c => {
                            html += `<option value="${c}" ${val === c ? 'selected' : ''}>${c}</option>`;
                        });
                        html += `</select>`;
                    } else if (tool.data_type === 'continuous') {
                        const min = tool.min_value !== undefined ? tool.min_value : 0;
                        const max = tool.max_value !== undefined ? tool.max_value : 100;
                        const val = cfg.value !== undefined ? cfg.value : min;
                        html += `<div style="display:flex;align-items:center;gap:10px;">
                    <span>Min: <b>${min}</b></span>
                    <input type="range" min="${min}" max="${max}" value="${val}" name="${toolName}_${cat}_value" style="width:150px;" oninput="this.nextElementSibling.textContent=this.value">
                    <span>${val}</span>
                    <span>Max: <b>${max}</b></span>
                </div>`;
                    }
                    // Add count textbox
                    const countVal = cfg.count !== undefined ? cfg.count : 1;
                    html += `</td><td><input type="number" min="1" value="${countVal}" name="${toolName}_${cat}_count" class="form-control w-auto d-inline"></td></tr>`;
                });
                html += '</tbody></table></div>';
            });
            document.getElementById('trust-score-step5').innerHTML = html;
        }

        document.getElementById('tool-config-tab').addEventListener('shown.bs.tab', function () {
            renderToolConfigStep5();
        });

        async function saveToolConfigStep5() {
            const container = document.getElementById('trust-score-step5');
            const rows = container.querySelectorAll('tbody tr');
            let configsToSave = [];
            rows.forEach (row => {
                const toolName = row.querySelector('td').textContent;
                let cat = row.closest('table').parentElement.previousSibling.textContent.replace('Category:', '').trim().toLowerCase();
                let valueInput = row.querySelector(`[name="${toolName}_${cat}_value"]`);
                let value = valueInput.value;
                configsToSave.push({ tool_name: toolName, trust_evaluation_category: cat, value });
            });
            console.log(configsToSave);
            let completed = 0;
            for (const config of configsToSave) {
                const resp = await fetch('/tool-config-step5', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                completed++;
                if (completed === configsToSave.length) {
                    const msgDiv = document.getElementById('trust-score-step5-msg');
                    if (resp.ok) {
                        msgDiv.innerHTML = '<span class="text-success">Step 5 configuration saved!</span>';
                    } else {
                        msgDiv.innerHTML = '<span class="text-danger">Failed to save step 5 configuration.</span>';
                    }
                }
            }
        }
        document.getElementById('trust-score-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'saveTrustScoreStep5Btn') {
                saveToolConfigStep5();
                saveTrustScoreWeights();
            }
            async function saveTrustScoreWeights() {
                // Get and normalise category weights
                const categories = [
                    'Security',
                    'Reliability',
                    'Resilience',
                    'Threat Exposure',
                    'Intentions'
                ];
                let catWeights = {};
                let total = 0;
                categories.forEach(cat => {
                    let val = parseInt(document.querySelector(`[name='cat_weight_${cat}']`).value) || 0;
                    catWeights[cat] = val;
                    total += val;
                });
                if (total === 0) total = 1;
                Object.keys(catWeights).forEach(cat => {
                    catWeights[cat] = Math.round((catWeights[cat] / total) * 100);
                });
                // Get and normalise behaviour weights
                let behaviourWeights = {
                    normal: parseInt(document.getElementById('behaviour_weight_normal').value) || 0,
                    suspicious: parseInt(document.getElementById('behaviour_weight_suspicious').value) || 0,
                    compromised: parseInt(document.getElementById('behaviour_weight_compromised').value) || 0
                };
                // Do NOT normalise behaviour weights, save as entered
                // Save to DB
                const resp = await fetch('/trust-score-weights', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ category_weights: catWeights, behaviour_weights: behaviourWeights })
                });
                const msgDiv = document.getElementById('trust-score-step5-msg');
                if (resp.ok) {
                    msgDiv.innerHTML += '<br><span class="text-success">Trust score weights saved!</span>';
                } else {
                    msgDiv.innerHTML += '<br><span class="text-danger">Failed to save trust score weights.</span>';
                }
            }
        });
        async function simulateTrustAnalyser() {
            // Always fetch all configs fresh
            const [mappedResp, step1Resp, step2Resp, step3Resp, step4Resp] = await Promise.all([
                fetch('/mapped'),
                fetch('/trust-config-step1-get-all'),
                fetch('/trust-config-step2-get-all'),
                fetch('/trust-config-step3-get-all'),
                fetch('/trust-config-step4-get')
            ]);
            const mapped = await mappedResp.json();
            const step1 = await step1Resp.json();
            const step2 = await step2Resp.json();
            const step3 = await step3Resp.json();
            const step4 = await step4Resp.json();
            // Get tool values and counts from UI
            const toolInputs = {};
            const rows = document.querySelectorAll('#trust-score-step5 tbody tr');
            rows.forEach(row => {
                const toolName = row.querySelector('td').textContent;
                let cat = row.closest('table').parentElement.previousSibling.textContent.replace('Category:', '').trim();
                let valueInput = row.querySelector(`[name="${toolName}_${cat}_value"]`);
                let countInput = row.querySelector(`[name="${toolName}_${cat}_count"]`);
                let value = valueInput.value;
                let count = parseInt(countInput.value) || 1;
                toolInputs[`${toolName}|||${cat}`] = { value, count };
            });
            // Build lookup maps
            const step1Map = {};
            step1.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                step1Map[`${cfg.tool_name}|||${cat}`] = cfg;
            });
            const step2Map = {};
            step2.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                step2Map[`${cfg.tool_name}|||${cat}`] = cfg;
            });
            const step3Map = {};
            step3.forEach(cfg => {
                const cat = (cfg.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                step3Map[cat] = cfg;
            });
            // 1. Tool Impact Categorisation (consider count and override)
            let toolImpacts = {};
            mapped.forEach(tool => {
                const toolName = tool.tool_name;
                const cat = (tool.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                               const key = `${toolName}|||${cat}`;
                const step1Cfg = step1Map[key] || {};
                const step2Cfg = step2Map[key] || {};
                const input = toolInputs[key] || { value: '', count: 1 };
                let impact = 'Low';
                // If override rule in step 2 and count >= override_count, apply override impact
                if (step2Cfg.override_active === 'true' && input.count >= parseInt(step2Cfg.override_count || '0')) {
                    impact = step2Cfg.override_impact || 'Low';
                } else {
                    if (tool.data_type === 'binary') {
                        impact = input.value === 'true' ? (step1Cfg[`${toolName}_${cat}_on`] || 'Low') : (step1Cfg[`${toolName}_${cat}_off`] || 'Low');
                    } else if (tool.data_type === 'categorical') {
                        impact = step1Cfg[`${toolName}_${cat}_${input.value}`] || 'Low';
                    } else if (tool.data_type === 'continuous') {
                        const val = parseFloat(input.value || tool.min_value || 0);
                        const lower = parseFloat(step1Cfg[`${toolName}_${cat}_slider_lower`] || tool.min_value || 0);
                        const upper = parseFloat(step1Cfg[`${toolName}_${cat}_slider_upper`] || tool.max_value || 100);
                        if (val <= lower) impact = 'Low';
                        else if (val <= upper) impact = 'Mid';
                        else impact = 'High';
                    }
                }
                toolImpacts[key] = impact;
            });
            // 2. Tool Behaviour (consider count and override)
            let toolBehaviours = {};
            mapped.forEach(tool => {
                const toolName = tool.tool_name;
                const cat = (tool.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                const key = `${toolName}|||${cat}`;
                const step2Cfg = step2Map[key] || {};
                const input = toolInputs[key] || { value: '', count: 1 };
                let behaviour = 'normal';
                if (step2Cfg.override_active === 'true' && input.count >= parseInt(step2Cfg.override_count || '0')) {
                    behaviour = step2Cfg.override_behaviour || 'normal';
                } else {
                    const impact = toolImpacts[key];
                    if (impact === 'Low') behaviour = 'normal';
                    else if (impact === 'Mid') behaviour = 'suspicious';
                    else behaviour = 'compromised';
                }
                toolBehaviours[key] = behaviour;
            });
            // 3. Category Behaviour
            let categoryBehaviours = {};
            const byCategory = {};
            mapped.forEach(tool => {
                const cat = (tool.trust_evaluation_category || 'Uncategorized').trim().toLowerCase();
                if (!byCategory[cat]) byCategory[cat] = [];
                byCategory[cat].push(tool);
            });
            Object.entries(byCategory).forEach(([cat, tools]) => {
                const step3Cfg = step3Map[cat] || {};
                let behaviours = tools.map(tool => toolBehaviours[`${tool.tool_name}|||${cat}`]);
                let finalCatBehaviour = 'normal';
                if (step3Cfg.override_active === 'true') {
                    // Count number of tools whose behaviour matches the override behaviour
                    const count = parseInt(step3Cfg.override_count || '0');
                    const target = step3Cfg.override_behaviour || 'normal';
                    const tool_behaviour = step3Cfg.tool_behaviour || 'normal';
                    let num = 0;
                    tools.forEach(tool => {
                        const key = `${tool.tool_name}|||${cat}`;
                        if (toolBehaviours[key] === tool_behaviour) {
                            num++;
                            // console.log('hello '+num+tool_behaviour);
                        }

                    });
                    if (num >= count) {
                        finalCatBehaviour = target;
                    } else {
                        // If not enough for override, use majority rule
                        const counts = { normal: 0, suspicious: 0, compromised: 0 };
                        behaviours.forEach(b => { counts[b] = (counts[b] || 0) + 1; });
                        let max = 'normal';
                        if (counts.compromised > counts.normal && counts.compromised > counts.suspicious) max = 'compromised';
                        else if (counts.suspicious > counts.normal && counts.suspicious > counts.compromised) max = 'suspicious';
                        else if (counts.normal > counts.suspicious && counts.normal > counts.compromised) max = 'normal';
                        else if (counts.normal === counts.suspicious || counts.normal === counts.compromised || counts.suspicious === counts.compromised) max = 'suspicious';
                        finalCatBehaviour = max;
                    }
                    // if (cat === "security"){
                    //     console.log('hello '+num+step3Cfg.override_behaviour);
                    // }
                } else {
                    // Default: majority rule
                    const counts = { normal: 0, suspicious: 0, compromised: 0 };
                    behaviours.forEach(b => { counts[b] = (counts[b] || 0) + 1; });
                    let max = 'normal';
                    if (counts.compromised > counts.normal && counts.compromised > counts.suspicious) max = 'compromised';
                    else if (counts.suspicious > counts.normal && counts.suspicious > counts.compromised) max = 'suspicious';
                    else if (counts.normal > counts.suspicious && counts.normal > counts.compromised) max = 'normal';
                    else if (counts.normal === counts.suspicious || counts.normal === counts.compromised || counts.suspicious === counts.compromised) max = 'suspicious';
                    finalCatBehaviour = max;
                }
                // If at least one tool with one_tool_behaviour, set to that behaviour
                if (step3Cfg.one_tool_behaviour) {
                    if (behaviours.includes(step3Cfg.one_tool_behaviour)) finalCatBehaviour = step3Cfg.one_tool_behaviour;
                }
                categoryBehaviours[cat] = finalCatBehaviour;
            });
            // 4. System Behaviour (step 4)
            let systemBehaviour = 'normal';
            const step4Cfg = step4 || {};
            const catBehaviours = Object.values(categoryBehaviours);
            if (step4Cfg.override_active === 'true') {
                const count = parseInt(step4Cfg.override_count || '0');
                const target = step4Cfg.final_behaviour || 'normal';
                const category_behaviour = step4Cfg.override_behaviour || 'normal';
                const num = catBehaviours.filter(b => b === category_behaviour).length;
                if (num >= count) {
                    systemBehaviour = target;
                } else {
                    // If override not applicable, use majority behaviour
                    const counts = { normal: 0, suspicious: 0, compromised: 0 };
                    catBehaviours.forEach(b => { counts[b] = (counts[b] || 0) + 1; });
                    let max = 'normal';
                    if (counts.compromised > counts.normal && counts.compromised > counts.suspicious) max = 'compromised';
                    else if (counts.suspicious > counts.normal && counts.suspicious > counts.compromised) max = 'suspicious';
                    else if (counts.normal > counts.suspicious && counts.normal > counts.compromised) max = 'normal';
                    else if (counts.normal === counts.suspicious || counts.normal === counts.compromised || counts.suspicious === counts.compromised) max = 'suspicious';
                    systemBehaviour = max;
                }
            } else {
                // No override, use majority behaviour
                const counts = { normal: 0, suspicious: 0, compromised: 0 };
                catBehaviours.forEach(b => { counts[b] = (counts[b] || 0) + 1; });
                let max = 'normal';
                if (counts.compromised > counts.normal && counts.compromised > counts.suspicious) max = 'compromised';
                else if (counts.suspicious > counts.normal && counts.suspicious > counts.compromised) max = 'suspicious';
                else if (counts.normal > counts.suspicious && counts.normal > counts.compromised) max = 'normal';
                else if (counts.normal === counts.suspicious || counts.normal === counts.compromised || counts.suspicious === counts.compromised) max = 'suspicious';
                systemBehaviour = max;
            }
            // Show results
            let html = '<h5>Simulation Results</h5>';
            html += '<b>Tool Impact Categorisation:</b><ul>';
            Object.entries(toolImpacts).forEach(([key, impact]) => {
                html += `<li>${key}: <b>${impact}</b></li>`;
            });
            html += '</ul><b>Tool Behaviour:</b><ul>';
            Object.entries(toolBehaviours).forEach(([key, behaviour]) => {
                html += `<li>${key}: <b>${behaviour}</b></li>`;
            });
            html += '</ul><b>Category Behaviour:</b><ul>';
            Object.entries(categoryBehaviours).forEach(([cat, behaviour]) => {
                html += `<li>${cat}: <b>${behaviour}</b></li>`;
            });
            window.simulatedCategoryBehaviours = categoryBehaviours;
            window.simulatedToolBehaviours = toolBehaviours;
            html += `</ul><b>System Behaviour (Step 4):</b> <span class="badge bg-${systemBehaviour === 'normal' ? 'success' : systemBehaviour === 'suspicious' ? 'warning' : 'danger'}">${systemBehaviour.toUpperCase()}</span>`;
            document.getElementById('trust-simulation-result').innerHTML = html;
        }
        document.getElementById('trust-score-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'simulateTrustBtn') {
                document.getElementById('trust-simulation-result').innerHTML = '';
                simulateTrustAnalyser();
            }
        });
        async function renderTrustScoreConfig() {
            // Categories
            const categories = [
                'Security',
                'Reliability',
                'Resilience',
                'Threat Exposure',
                'Intentions'
            ];
            let html = '<b>Assign weights to each category (total = 100):</b><br>';
            categories.forEach(cat => {
                html += `<div class="mb-2">${cat}: <input type="range" min="0" max="100" value="20" name="cat_weight_${cat}" style="width:150px;" oninput="document.getElementById('cat_weight_${cat}_val').textContent=this.value"> <span id="cat_weight_${cat}_val">20</span></div>`;
            });
            html += '<button class="btn btn-secondary mt-2" id="normaliseWeightsBtn">Normalise Weights</button>';
            html += '<hr><h5>Tool Inputs for Simulation</h5>';
            html += '<div id="tool-inputs-panel"></div>';
            document.getElementById('trust-score-config-weights').addEventListener('click', function (e) {
                if (e.target && e.target.id === 'normaliseWeightsBtn') {
                    normaliseCategoryWeights();
                }
            });

            function normaliseCategoryWeights() {
                const categories = [
                    'Security',
                    'Reliability',
                    'Resilience',
                    'Threat Exposure',
                    'Intentions'
                ];
                let total = 0;
                let weights = {};
                categories.forEach(cat => {
                    let val = parseInt(document.querySelector(`[name='cat_weight_${cat}']`).value) || 0;
                    weights[cat] = val;
                    total += val;
                });
                if (total === 0) total = 1;
                categories.forEach(cat => {
                    let norm = Math.round((weights[cat] / total) * 100);
                    document.querySelector(`[name='cat_weight_${cat}']`).value = norm;
                    document.getElementById(`cat_weight_${cat}_val`).textContent = norm;
                });
            }
            html += '<b>Assign weights for behaviour types:</b><br>';
            html += `<div class="mb-2">Normal: <input type="number" min="0" max="100" value="100" name="behaviour_weight_normal" id="behaviour_weight_normal" class="form-control d-inline w-auto" oninput="window.behaviourWeightNormal=this.value"></div>`;
            html += `<div class="mb-2">Suspicious: <input type="number" min="0" max="100" value="50" name="behaviour_weight_suspicious" id="behaviour_weight_suspicious" class="form-control d-inline w-auto" oninput="window.behaviourWeightSuspiciousdictable=this.value"></div>`;
            html += `<div class="mb-2">Compromised: <input type="number" min="0" max="100" value="0" name="behaviour_weight_compromised" id="behaviour_weight_compromised" class="form-control d-inline w-auto" oninput="window.behaviourWeightCompromised=this.value"></div>`;
            document.getElementById('trust-score-config-weights').innerHTML = html;
        }
        document.getElementById('tool-config-tab').addEventListener('shown.bs.tab', function () {
            renderToolConfigStep5();
            renderTrustScoreConfig();
            setupToolInputPanel();
            function setupToolInputPanel() {
                const panel = document.getElementById('tool-inputs-panel');
                panel.innerHTML = '';
                let toolInputs = [];
                function renderInputs() {
                    panel.innerHTML = '';
                    toolInputs.forEach((input, idx) => {
                        panel.innerHTML += `<div class="mb-2 border p-2 rounded">
                        <label>Tool Name:</label> <input type="text" class="form-control d-inline w-auto" value="${input.tool_name || ''}" onchange="this.parentElement.parentElement.toolInputs[${idx}].tool_name=this.value">
                        <label>Category:</label> <input type="text" class="form-control d-inline w-auto" value="${input.category || ''}" onchange="this.parentElement.parentElement.toolInputs[${idx}].category=this.value">
                        <label>Value:</label> <input type="text" class="form-control d-inline w-auto" value="${input.value || ''}" onchange="this.parentElement.parentElement.toolInputs[${idx}].value=this.value">
                        <label>Count:</label> <input type="number" min="1" class="form-control d-inline w-auto" value="${input.count || 1}" onchange="this.parentElement.parentElement.toolInputs[${idx}].count=this.value">
                        <button class="btn btn-sm btn-danger ms-2" onclick="this.parentElement.parentElement.toolInputs.splice(${idx},1);this.parentElement.parentElement.renderInputs();">Remove</button>
                    </div>`;
                    });
                    panel.toolInputs = toolInputs;
                    panel.renderInputs = renderInputs;
                }
                panel.toolInputs = toolInputs;
                panel.renderInputs = renderInputs;
                renderInputs();
                // Removed 'Add Tool Input' button logic to prevent error
            }
        });
        async function calcTrustScore() {
            // Get category weights
            const categories = [
                'Security',
                'Reliability',
                'Resilience',
                'Threat Exposure',
                'Intentions'
            ];
            let catWeights = {};
            let total = 0;
            categories.forEach(cat => {
                let val = parseInt(document.querySelector(`[name='cat_weight_${cat}']`).value) || 0;
                catWeights[cat] = val;
                total += val;
            });
            // Normalise
            if (total === 0) total = 1;
            Object.keys(catWeights).forEach(cat => {
                catWeights[cat] = Math.round((catWeights[cat] / total) * 100);
            });
            // Get behaviour weights
            let behaviourWeights = {
                normal: parseInt(document.querySelector('[name="behaviour_weight_normal"]').value) || 0,
                suspicious: parseInt(document.querySelector('[name="behaviour_weight_suspicious"]').value) || 0,
                compromised: parseInt(document.querySelector('[name="behaviour_weight_compromised"]').value) || 0
            };
            // Use previously simulated categoryBehaviours if available
            let categoryBehaviours = window.simulatedCategoryBehaviours || {};
            // 4. Trust Score Calculation
            // TODO: Normalize behaviour weights if sum > 100
            // let behTotal = behaviourWeights.normal + behaviourWeights.suspicious + behaviourWeights.compromised;
            // if (behTotal > 100) {
            //     Object.keys(behaviourWeights).forEach(b => {
            //         behaviourWeights[b] = Math.round((behaviourWeights[b] / behTotal) * 100);
            //     });
            // }
            // Get mapped tools for each category
            let mapped = window.simulatedMappedTools || [];
            if (!mapped.length && window.lastSimulatedMapped) mapped = window.lastSimulatedMapped;
            // If not available, fetch from simulation panel
            if (!mapped.length) {
                mapped = [];
                const rows = document.querySelectorAll('#trust-score-step5 tbody tr');
                rows.forEach(row => {
                    const toolName = row.querySelector('td').textContent;
                    let cat = row.closest('table').parentElement.previousSibling.textContent.replace('Category:', '').trim();
                    mapped.push({ tool_name: toolName, trust_evaluation_category: cat });
                });
            }
            // Calculate max possible score
            let maxScore = 0;
            let realScore = 0;
            let details = '<b>Trust Score Calculation:</b><ul>';
            categories.forEach(cat => {
                let catKey = cat.trim().toLowerCase();
                let catWeight = catWeights[cat];
                // Get all tools in this category
                let toolsInCat = mapped.filter(t => (t.trust_evaluation_category || '').trim().toLowerCase() === catKey);
                let numTools = toolsInCat.length;
                // Find highest behaviour weight
                let maxBehWeight = Math.max(...Object.values(behaviourWeights));
                let catMax = numTools * maxBehWeight * catWeight;
                maxScore += catMax;
                // Calculate real score for this category by summing individual tool behaviour weights
                let partial = 0;
                toolsInCat.forEach(tool => {
                    let key = `${tool.tool_name}|||${catKey}`;
                    let behaviour = (window.simulatedToolBehaviours && window.simulatedToolBehaviours[key]) || 'normal';
                    let behWeight = behaviourWeights[behaviour];
                    if (behWeight === undefined) {
                        details += `<li class='text-danger'>${cat}: Tool ${tool.tool_name} behaviour '${behaviour}' not found in weights! Using 0.</li>`;
                        behWeight = 0;
                    }
                    partial += behWeight * catWeight;
                    details += `<li>${cat}: Tool=${tool.tool_name}, CatWeight=${catWeight}, Behaviour=${behaviour}, Behaviour Weight=${behWeight}, Partial=${(behWeight * catWeight).toFixed(2)}</li>`;
                });
                realScore += partial;
                details += `<li><b>${cat} Total: ${partial.toFixed(2)} / Max: ${catMax}</b></li>`;
            });
            let percent = maxScore > 0 ? (realScore / maxScore) * 100 : 0;
            details += `</ul><b>Final Trust Score: <span class="badge bg-info">${realScore.toFixed(2)}</span> / Max: <span class="badge bg-secondary">${maxScore.toFixed(2)}</span> (<span class="badge bg-success">${percent.toFixed(2)}%</span>)</b>`;
            document.getElementById('trust-score-result').innerHTML = details;

            await fetch('/trust-score-weights', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ category_weights: catWeights, behaviour_weights: behaviourWeights })
            });
        }
        document.getElementById('trust-config').addEventListener('click', function (e) {
            if (e.target && e.target.id === 'calcTrustScoreBtn') {
                calcTrustScore();
            }
        });
        // Also connect button directly in case it's outside trust-config
        document.getElementById('calcTrustScoreBtn').addEventListener('click', function () {
            calcTrustScore();
        });
        function renderMappedRequestsTable(mappedRequests) {
            const tableBody = document.getElementById('mapped-requests-table-body');
            tableBody.innerHTML = '';
            if (mappedRequests.length === 0) {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.className = 'text-center text-muted';
                cell.innerText = 'No mapped requests found.';
                row.appendChild(cell);
                tableBody.appendChild(row);
                return;
            }
            mappedRequests.forEach((req, idx) => {
                const row = `<tr>
                    <td>${req.tool_name}</td>
                    <td>${req.description || ''}</td>
                    <td>${req.data_type}</td>
                    <td>${req.trust_evaluation_category || ''}</td>
                    <td>${req.unique_id_path}</td>
                    <td>${req.unique_id_value || ''}</td>
                    <td>${req.value_path}</td>
                    <td>${req.categories || ''}</td>
                    <td>${req.supplement || ''}</td>
                    <td>${req.count || 0}</td>
                </tr>`;
                tableBody.innerHTML += row;
            });
        }
    

// ──────────────────────────────────────────────────────────


    // Show tool info modal with value frequency/history graphs
    async function showToolInfoModal(toolName, category) {
        const modal = new bootstrap.Modal(document.getElementById('toolInfoModal'));
        const contentDiv = document.getElementById('toolInfoModalContent');
        contentDiv.innerHTML = `<div class='text-center'><div class='spinner-border'></div> Loading...</div>`;
        
        // Fetch active mapped requests
        let mappedResp = await fetch('/mapped');
        let mapped = await mappedResp.json();
        
        // Fetch removed mapped requests
        let removedResp = await fetch('/mapped/removed');
        let removedMapped = await removedResp.json();
        
        // Look for tool in active mappings
        let tool = mapped.find(t => t.tool_name === toolName && (t.trust_evaluation_category||'').trim().toLowerCase() === category.trim().toLowerCase());
        
        // If not found in active, check removed mappings
        let isRemoved = false;
        if (!tool) {
            tool = removedMapped.find(t => t.tool_name === toolName && (t.trust_evaluation_category||'').trim().toLowerCase() === category.trim().toLowerCase());
            if (tool) {
                isRemoved = true;
            }
        }
        
        // Get data type from endpoint (works for both active and removed)
        let dataTypeResp = await fetch(`/tool-data-type/${encodeURIComponent(toolName)}/${encodeURIComponent(category)}`);
        let dataTypeData = await dataTypeResp.json();
        let dataType = dataTypeData.data_type || 'continuous';
        let dataSource = dataTypeData.source || 'default';
        console.log(dataTypeData)
        // Determine alert message
        let alertHtml = '';
        if (!tool) {
            // No mapping found at all - show historical data if available
            alertHtml = `<div class='alert alert-info'><strong>Historical Data:</strong> This tool was previously evaluated in this category. Showing historical analysis data.</div>`;
        } else if (isRemoved) {
            // Mapping was removed/reassigned
            alertHtml = `<div class='alert alert-warning'><strong>Note:</strong> This tool has been reassigned to another category. Showing historical data for this previous mapping.</div>`;
        }
        
        let html = `<h5>${toolName} (${dataType}) - ${category}</h5>${alertHtml}`;
        
        if (dataType === 'binary' || dataType === 'categorical') {
            let freqResp = await fetch(`/tool-value-frequency/${encodeURIComponent(toolName)}/${encodeURIComponent(category)}`);
            let freqData = await freqResp.json();
            
            if (Object.keys(freqData).length > 0) {
                let labels = Object.keys(freqData);
                let values = Object.values(freqData);
                html += `<canvas id='toolFreqChart' width='400' height='200'></canvas>`;
                contentDiv.innerHTML = html;
                setTimeout(() => {
                    let ctxFreq = document.getElementById('toolFreqChart').getContext('2d');
                    new Chart(ctxFreq, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Value Frequency',
                                data: values,
                                backgroundColor: '#0d6efd'
                            }]
                        },
                        options: {
                            plugins: { title: { display: true, text: 'Value Frequency' } },
                            scales: { y: { beginAtZero: true } }
                        }
                    });
                }, 100);
            } else {
                html += `<div class='alert alert-secondary mt-3'>No frequency data available.</div>`;
                contentDiv.innerHTML = html;
            }
        } else if (dataType === 'continuous') {
            let histResp = await fetch(`/tool-value-history/${encodeURIComponent(toolName)}/${encodeURIComponent(category)}`);
            let histData = await histResp.json();
            
            if (histData && histData.length > 0) {
                let labels = histData.map((_,i) => i+1);
                let values = histData;
                html += `<canvas id='toolHistChart' width='400' height='200'></canvas>`;
                contentDiv.innerHTML = html;
                setTimeout(() => {
                    let ctxHist = document.getElementById('toolHistChart').getContext('2d');
                    new Chart(ctxHist, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Value History',
                                data: values,
                                borderColor: '#198754',
                                backgroundColor: 'rgba(25,135,84,0.2)',
                                fill: true
                            }]
                        },
                        options: {
                            plugins: { title: { display: true, text: 'Value History' } },
                            scales: { y: { beginAtZero: true } }
                        }
                    });
                }, 100);
            } else {
                html += `<div class='alert alert-secondary mt-3'>No value history data available.</div>`;
                contentDiv.innerHTML = html;
            }
        } else {
            html += `<div class='alert alert-warning mt-3'>Unknown data type: ${dataType}</div>`;
            contentDiv.innerHTML = html;
        }
        modal.show();
    }
    
    // ============ EVALUATION REPORTS FUNCTIONS ============
    
    async function loadLatestEvaluationReport() {
        try {
            const spinner = document.getElementById('reportLoadingSpinner');
            const container = document.getElementById('evaluationReportContainer');
            
            spinner.classList.remove('d-none');
            container.innerHTML = '';
            
            const response = await fetch('/trust-evaluation-reports/latest');
            if (!response.ok) {
                spinner.classList.add('d-none');
                container.innerHTML = '<div class="alert alert-info">No evaluation reports found. Submit data to generate reports.</div>';
                return;
            }
            
            const data = await response.json();
            const report = data.report;
            
            spinner.classList.add('d-none');
            renderEvaluationReport(report);
        } catch (error) {
            console.error('Error loading report:', error);
            document.getElementById('reportLoadingSpinner').classList.add('d-none');
            document.getElementById('evaluationReportContainer').innerHTML = 
                '<div class="alert alert-danger">Error loading report: ' + error.message + '</div>';
        }
    }
    
    function renderEvaluationReport(report) {
        const container = document.getElementById('evaluationReportContainer');
        let html = '';

        const sysPct = Number(report.system_trust_score_percentage ?? report.system_trust_percent ?? report.system_trust_score ?? 0);
        const sysPctStr = (!isNaN(sysPct) ? sysPct : 0).toFixed(2);
        const sysBeh = report.system_behaviour || 'normal';
        
        // Header with metadata
        html += `
            <div class="card mb-3">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">
                        <i class="bi bi-file-earmark-text"></i> Trust Evaluation Report
                    </h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <small class="text-muted">Report Generated</small>
                            <p class="mb-0"><strong>${new Date(report.timestamp).toLocaleString()}</strong></p>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Evaluation Mode</small>
                            <p class="mb-0">
                                ${(() => {
                                    const raw = report.analysis_type || report.evaluation_mode || 'batch';
                                    const label = raw === 'manual' ? 'Manual' : raw === 'immediate' ? 'Immediate' : 'Batch';
                                    const cls   = raw === 'manual' ? 'bg-warning text-dark' : raw === 'immediate' ? 'bg-info' : 'bg-success';
                                    return `<span class="badge ${cls}">${label}</span>`;
                                })()}
                            </p>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Submissions Analyzed</small>
                            <p class="mb-0"><strong>${report.cycle_submissions_count || 1}</strong></p>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">System Behaviour</small>
                            <p class="mb-0">
                                <span class="badge ${getBehaviourBadgeClass(sysBeh)}">
                                    ${sysBeh}
                                </span>
                            </p>
                        </div>
                    </div>
                    <div class="mt-3">
                        <div class="progress" style="height: 25px;">
                            <div class="progress-bar" role="progressbar" 
                                style="width: ${sysPct}%; background-color: ${getTrustScoreColor(sysPct)};"
                                aria-valuenow="${sysPct}" aria-valuemin="0" aria-valuemax="100">
                                <small style="color: white; font-weight: bold;">System Trust Score: ${sysPctStr}%</small>
                            </div>
                        </div>
                    </div>
                    <div class="mt-3">
                        <button class="btn btn-outline-primary btn-sm" onclick="loadAndShowAnalysisDetails('${report._id}')">
                            <i class="bi bi-graph-up"></i> View Detailed Analysis
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Analysis Details Section (will be loaded dynamically)
        html += `<div id="analysisDetailsSection-${report._id}" class="d-none mt-4"></div>`;
        
        // Categories section
        const trustReport = report.report || {};
        const categories = trustReport.trust_evaluation_report || [];
       
        html += `<h5 class="mt-4 mb-3"><i class="bi bi-diagram-2"></i> Categories Analysis</h5>`;
        
        if (categories.length === 0) {
            html += '<div class="alert alert-info">No categories evaluated in this report.</div>';
        } else {
            categories.forEach((category, idx) => {
                html += renderCategoryCard(category, idx);
            });
        }
        
        // Overrides section
        const overrides = trustReport.behaviour_classification_overrides || [];
        if (overrides.length > 0) {
            html += `
                <h5 class="mt-4 mb-3"><i class="bi bi-exclamation-triangle"></i> Behaviour Classification Overrides</h5>
                <div class="alert alert-warning">
                    <p class="mb-0"><strong>${overrides.length} override(s) applied during this evaluation</strong></p>
                </div>
            `;
            
            overrides.forEach((override, idx) => {
                html += `
                    <div class="card mb-2">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-3">
                                    <small class="text-muted">Category</small>
                                    <p class="mb-0"><strong>${override.category_name}</strong></p>
                                </div>
                                <div class="col-md-2">
                                    <small class="text-muted">Original</small>
                                    <p class="mb-0"><span class="badge bg-light text-dark">${override.original_behaviour_classification}</span></p>
                                </div>
                                <div class="col-md-2">
                                    <small class="text-muted">Overridden To</small>
                                    <p class="mb-0"><span class="badge ${getBehaviourBadgeClass(override.overridden_behaviour_classification)}">${override.overridden_behaviour_classification}</span></p>
                                </div>
                                <div class="col-md-5">
                                    <small class="text-muted">Reason</small>
                                    <p class="mb-0"><small>${override.override_reason}</small></p>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });
        }
        
        container.innerHTML = html;
    }
    
    function renderCategoryCard(category, index) {
        const catPct = Number(category.category_trust_score_percentage ?? category.category_trust_percent ?? 0);
        const catPctStr = (!isNaN(catPct) ? catPct : 0).toFixed(2);
        const catScore = category.category_trust_score ?? 0;
        const catMaxScore = category.category_max_trust_score ?? category.category_max_score ?? 0;
        const catBehaviour = category.category_final_behaviour || category.category_behaviour || 'normal';
        const reportingCount = category.numer_of_tools_reporting ?? (category.reporting_tools ? category.reporting_tools.length : 0);
        const registeredCount = category.number_of_tools_registered ?? ((category.reporting_tools ? category.reporting_tools.length : 0) + (category.previous_value_tools ? category.previous_value_tools.length : 0));

        let html = `
            <div class="card mb-3">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="mb-0">${category.category_name}</h6>
                            <small class="text-muted">${reportingCount} of ${registeredCount} tools reporting</small>
                        </div>
                        <button class="btn btn-sm btn-outline-secondary" type="button" 
                            onclick="toggleCategoryDetails('category-${index}')"
                            id="btn-category-${index}">
                            <i class="bi bi-chevron-down"></i> Show Details
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <small class="text-muted">Behaviour</small>
                            <p class="mb-0">
                                <span class="badge ${getBehaviourBadgeClass(catBehaviour)}">
                                    ${catBehaviour}
                                </span>
                            </p>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Trust Score</small>
                            <p class="mb-0">${catScore}/${catMaxScore}</p>
                        </div>
                        <div class="col-md-6">
                            <small class="text-muted">Trust Score Percentage</small>
                            <div class="progress" style="height: 20px;">
                                <div class="progress-bar" role="progressbar" 
                                    style="width: ${catPct}%; background-color: ${getTrustScoreColor(catPct)};"
                                    aria-valuenow="${catPct}" aria-valuemin="0" aria-valuemax="100">
                                    <small style="color: white; font-size: 0.75rem;">${catPctStr}%</small>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Collapsible Details -->
                    <div id="category-${index}" class="d-none mt-3">
                        <hr>
                        <h6 class="mt-3 mb-2"><i class="bi bi-tools"></i> Reporting Tools</h6>
                        ${renderToolsList(category.reporting_tools, category.category_name)}
                        
                        ${(category.previous_value_tools && category.previous_value_tools.length > 0) 
                            ? `<h6 class="mt-3 mb-2"><i class="bi bi-clock-history"></i> Previous Value Tools</h6>
                               ${renderToolsList(category.previous_value_tools, category.category_name)}`
                            : ''
                        }
                    </div>
                </div>
            </div>
        `;
        
        return html;
    }
    
    function renderToolsList(tools, categoryName) {
        if (!tools || tools.length === 0) {
            return '<p class="text-muted"><small>No tools in this category</small></p>';
        }
        
        let html = '<div class="list-group">';
        
        tools.forEach((tool, idx) => {
            const impactCount = tool.activated_impacts ? tool.activated_impacts.length : 0;
            const toolBeh = tool.tool_final_behaviour || tool.behaviour || 'normal';
            const toolImpact = tool.final_impact || tool.impact || 'mid';
            const reportsCount = tool.tool_reports_submitted ?? tool.count ?? 0;
            html += `
                <div class="list-group-item">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div>
                            <h6 class="mb-1">${tool.tool_name}</h6>
                            <small class="text-muted">${reportsCount} report${reportsCount === 1 ? '' : 's'} submitted</small>
                        </div>
                        <div>
                            <span class="badge ${getBehaviourBadgeClass(toolBeh)}">${toolBeh}</span>
                            <span class="badge bg-secondary ms-1">${toolImpact}</span>
                        </div>
                    </div>
                    
                    ${impactCount > 0 ? `
                        <div class="mb-2 border-top pt-2">
                            <button class="btn btn-sm btn-outline-info w-100" 
                                onclick="toggleToolDetails('tool-${categoryName}-${idx}', 'btn-tool-${categoryName}-${idx}')"
                                id="btn-tool-${categoryName}-${idx}">
                                <i class="bi bi-chevron-down"></i> 
                                <span>${impactCount} supplementary detail(s) - Click to view</span>
                            </button>
                            <div id="tool-${categoryName}-${idx}" class="d-none mt-3 p-3 bg-light rounded">
                                <small class="text-muted d-block mb-2"><strong>📋 Triggered Rules & Impacts:</strong></small>
                                ${tool.activated_impacts.map(impact => `
                                    <div class="ps-3 pb-3 border-bottom" style="margin-bottom: 10px;">
                                        <div class="d-flex gap-2 align-items-start">
                                            <span class="badge bg-info flex-shrink-0">${impact.impact || 'mid'}</span>
                                            <div style="flex: 1;">
                                                <code style="color: #d63384; font-size: 0.85rem;">${impact.rule || impact.value || 'N/A'}</code>
                                                <br><small class="text-muted">⏰ ${impact.tool_report_timestamp || 'N/A'}</small>
                                            </div>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        });
        
        html += '</div>';
        return html;
    }
    
    function toggleCategoryDetails(elementId) {
        const element = document.getElementById(elementId);
        const button = document.getElementById('btn-' + elementId);
        
        if (element.classList.contains('d-none')) {
            element.classList.remove('d-none');
            button.innerHTML = '<i class="bi bi-chevron-up"></i> Hide Details';
        } else {
            element.classList.add('d-none');
            button.innerHTML = '<i class="bi bi-chevron-down"></i> Show Details';
        }
    }
    
    function toggleToolDetails(elementId, buttonId) {
        const element = document.getElementById(elementId);
        const button = document.getElementById(buttonId);
        
        if (element.classList.contains('d-none')) {
            element.classList.remove('d-none');
            if (button) {
                const icon = button.querySelector('i');
                if (icon) icon.className = 'bi bi-chevron-up';
                const span = button.querySelector('span');
                if (span) span.textContent = element.textContent.includes('detail') 
                    ? span.textContent.replace('Click to view', 'Click to hide') 
                    : span.textContent;
            }
        } else {
            element.classList.add('d-none');
            if (button) {
                const icon = button.querySelector('i');
                if (icon) icon.className = 'bi bi-chevron-down';
                const span = button.querySelector('span');
                if (span) span.textContent = element.textContent.includes('detail') 
                    ? span.textContent.replace('Click to hide', 'Click to view') 
                    : span.textContent;
            }
        }
    }
    
    function getBehaviourBadgeClass(behaviour) {
        switch(behaviour) {
            case 'normal': return 'bg-success';
            case 'suspicious': return 'bg-warning';
            case 'compromised': return 'bg-danger';
            default: return 'bg-secondary';
        }
    }
    
    function getTrustScoreColor(percentage) {
        if (percentage >= 75) return '#198754'; // green
        if (percentage >= 50) return '#ffc107'; // yellow
        return '#dc3545'; // red
    }
    
    async function showEvaluationReportHistory() {
        try {
            const response = await fetch('/trust-evaluation-reports');
            const data = await response.json();
            const reports = data.reports || [];
            
            if (reports.length === 0) {
                alert('No evaluation reports found.');
                return;
            }
            
            let historyHtml = `<div class="text-muted small mb-2">${reports.length} report${reports.length !== 1 ? 's' : ''} found</div>`;
            historyHtml += '<div class="list-group" style="max-height:65vh; overflow-y:auto;">';
            
            reports.forEach((report, idx) => {
                const timestamp = new Date(report.timestamp).toLocaleString();
                const analysisType = report.analysis_type || report.evaluation_mode || 'batch';
                const modeLabel = analysisType === 'manual' ? 'Manual' : analysisType === 'immediate' ? 'Immediate' : 'Batch';
                const scoreNum = Number(report.system_trust_score_percentage ?? report.system_trust_percent ?? report.system_trust_score ?? 0);
                const score = (!isNaN(scoreNum) ? scoreNum : 0).toFixed(2);
                const behaviour = report.system_behaviour;
                
                historyHtml += `
                    <button type="button" class="list-group-item list-group-item-action" 
                        onclick="loadReportById('${report._id}')">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-1">${timestamp}</h6>
                                <small class="text-muted">${modeLabel} • ${report.cycle_submissions_count} submission${report.cycle_submissions_count !== 1 ? 's' : ''}</small>
                            </div>
                            <div class="d-flex gap-1">
                                <span class="badge ${getBehaviourBadgeClass(behaviour)}">${behaviour}</span>
                                <span class="badge" style="background-color: ${getTrustScoreColor(score)}">${score}%</span>
                            </div>
                        </div>
                    </button>
                `;
            });
            
            historyHtml += '</div>';
            
            // Create and show modal
            const modalEl = document.getElementById('evaluationReportHistoryModal');
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
            document.getElementById('evalReportHistoryModalBody').innerHTML = historyHtml;
            modal.show();
        } catch (error) {
            alert('Error loading report history: ' + error.message);
        }
    }
    
    async function loadReportById(reportId) {
        try {
            const response = await fetch(`/trust-evaluation-reports/${reportId}`);
            if (!response.ok) {
                alert('Error loading report');
                return;
            }
            
            const data = await response.json();
            const report = data.report;
            
            // Close history modal and show report
            const modalEl = document.getElementById('evaluationReportHistoryModal');
            if (modalEl) {
                const modalInstance = bootstrap.Modal.getInstance(modalEl);
                if (modalInstance) {
                    modalInstance.hide();
                }
            }
            
            setTimeout(() => {
                renderEvaluationReport(report);
            }, 500);
        } catch (error) {
            alert('Error loading report: ' + error.message);
        }
    }
    
    // ==================== Analysis Details Functions ====================
    
    async function loadAndShowAnalysisDetails(reportId) {
        try {
            const section = document.getElementById(`analysisDetailsSection-${reportId}`);
            
            // Show loading
            section.classList.remove('d-none');
            section.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>';
            
            // Fetch analysis data
            const response = await fetch(`/api/analysis-report/${reportId}`);
            if (!response.ok) {
                section.innerHTML = '<div class="alert alert-danger">Error loading analysis details</div>';
                return;
            }
            
            const data = await response.json();
            
            // Render analysis details
            let html = `
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="bi bi-graph-up"></i> Detailed Analysis Breakdown</h5>
                    </div>
                    <div class="card-body">
                        <ul class="nav nav-tabs" role="tablist" id="analysisTabs">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" id="toolReportings-tab" data-bs-toggle="tab" data-bs-target="#toolReportings"
                                    type="button" role="tab">Tool Submissions (${data.tool_reportings.length})</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="behaviorSteps-tab" data-bs-toggle="tab" data-bs-target="#behaviorSteps"
                                    type="button" role="tab">Behavior Steps (${data.behavior_determination_logs.length})</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="scoreSteps-tab" data-bs-toggle="tab" data-bs-target="#scoreSteps"
                                    type="button" role="tab">Score Calculation (${data.trust_score_calculation_logs.length})</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="ruleEvals-tab" data-bs-toggle="tab" data-bs-target="#ruleEvals"
                                    type="button" role="tab">Rule Evaluations (${data.rule_evaluation_logs.length})</button>
                            </li>
                        </ul>
                        
                        <div class="tab-content mt-3" id="analysisTabContent">
                            <!-- Tool Reportings Tab -->
                            <div class="tab-pane fade show active" id="toolReportings" role="tabpanel">
                                ${renderToolReportings(data.tool_reportings)}
                            </div>
                            
                            <!-- Behavior Steps Tab -->
                            <div class="tab-pane fade" id="behaviorSteps" role="tabpanel">
                                ${renderBehaviorSteps(data.behavior_determination_logs)}
                            </div>
                            
                            <!-- Score Steps Tab -->
                            <div class="tab-pane fade" id="scoreSteps" role="tabpanel">
                                ${renderScoreSteps(data.trust_score_calculation_logs)}
                            </div>
                            
                            <!-- Rule Evaluations Tab -->
                            <div class="tab-pane fade" id="ruleEvals" role="tabpanel">
                                ${renderRuleEvaluations(data.rule_evaluation_logs)}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            section.innerHTML = html;
            
            // Load tool reporting actions after rendering
            setTimeout(() => {
                console.log('Loading actions for', data.tool_reportings.length, 'reportings');
                loadToolReportingActions(data.tool_reportings);
                setupActionDropdownListeners();
                setupRecordActionsButton();
            }, 100);
        } catch (error) {
            console.error('Error:', error);
            section.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
        }
    }
    
    function renderToolReportings(reportings) {
        if (!reportings || reportings.length === 0) {
            return '<p class="text-muted">No tool submissions found</p>';
        }
        
        let html = '<div class="table-responsive"><table class="table table-sm">';
        html += '<thead><tr><th>Tool Name</th><th>Unique ID</th><th>Value</th><th>Category</th><th>Impact</th><th>Source</th><th>Action</th><th>Date & Time</th></tr></thead><tbody>';
        
        reportings.forEach(rep => {
            // Use timestamp directly - it's already formatted by backend as 'YYYY-MM-DD HH:MM:SS'
            const time = rep.timestamp || 'N/A';
            const actionId = `action-${rep._id}`;
            html += `
                <tr>
                    <td><strong>${rep.tool_name}</strong></td>
                    <td><code>${rep.unique_id}</code></td>
                    <td>${JSON.stringify(rep.value)}</td>
                    <td>${rep.category}</td>
                    <td><span class="badge bg-${rep.impact === 'High' ? 'danger' : rep.impact === 'Mid' ? 'warning' : 'success'}">${rep.impact}</span></td>
                    <td>${renderValueSourceBadge(rep.value_source)}</td>
                    <td>
                        <select id="${actionId}" 
                                class="form-select form-select-sm tool-action-select" 
                                data-reporting-id="${rep._id}"
                                data-tool-name="${rep.tool_name}"
                                data-category="${rep.category}"
                                data-unique-id="${rep.unique_id}"
                                style="max-width: 140px;">
                            <option value="no action" style="background-color: #d3d3d3;">No Action</option>
                            <option value="reviewing" style="background-color: #ffc107;">Reviewing</option>
                            <option value="resolved" style="background-color: #28a745;">Resolved</option>
                            <option value="dismiss" style="background-color: #ff9800;">Dismiss</option>
                        </select>
                    </td>
                    <td><small>${time}</small></td>
                </tr>
            `;
        });
        
        html += '</tbody></table></div>';
        html += '<div class="mt-3">';
        html += '<button class="btn btn-sm btn-primary" id="recordActionsBtn">Record Actions</button>';
        html += '</div>';
        return html;
    }
    
    function renderValueSourceBadge(source) {
        if (!source) return '';
        if (source === 'new_report') {
            return '<span class="badge" style="background-color:#0d6efd; font-size:0.7rem;"><i class="bi bi-file-earmark-text-fill me-1"></i>New Report</span>';
        } else if (source === 'past_value') {
            return '<span class="badge" style="background-color:#6c757d; font-size:0.7rem;"><i class="bi bi-clock-history me-1"></i>Past Value</span>';
        } else if (source === 'manual_impact') {
            return '<span class="badge" style="background-color:#fd7e14; font-size:0.7rem;"><i class="bi bi-pencil-fill me-1"></i>Manual Impact</span>';
        }
        return '';
    }

    function renderBehaviorSteps(logs) {
        if (!logs || logs.length === 0) {
            return '<p class="text-muted">No behavior determination logs found</p>';
        }
        
        let html = '';
        logs.forEach((log, idx) => {
            let advancedRulesHtml = '';
            if (log.advanced_rules && log.advanced_rules.evaluated) {
                const rulesColor = log.advanced_rules.overall_result ? 'bg-success' : 'bg-secondary';
                advancedRulesHtml = `
                    <div style="margin-top: 10px; padding: 8px; background: #f0f0f0; border-radius: 4px;">
                        <small><strong>Advanced Rules:</strong> ${log.advanced_rules.overall_result ? '✓ Matched' : '✗ Not Matched'} 
                        (${log.advanced_rules.matched_count}/${log.advanced_rules.total_rules} rules matched)
                        <span class="badge ${rulesColor}" style="margin-left: 5px;">${log.advanced_rules.overall_result ? 'Active' : 'Inactive'}</span>
                        </small>
                    </div>
                `;
            }
            
            html += `
                <div class="card mb-3">
                    <div class="card-header cursor-pointer" onclick="toggleCollapse('behaviorLog${idx}')">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6 class="mb-0">${log.tool_name} → ${log.category}</h6>
                            <div class="d-flex align-items-center gap-2">
                                ${renderValueSourceBadge(log.value_source)}
                                <span class="badge ${log.final_behaviour === 'normal' ? 'bg-success' : log.final_behaviour === 'suspicious' ? 'bg-warning' : 'bg-danger'}">${log.final_behaviour}</span>
                            </div>
                        </div>
                    </div>
                    <div class="card-body d-none" id="behaviorLog${idx}">
                        ${advancedRulesHtml}
                        ${renderSteps(log.steps)}
                    </div>
                </div>
            `;
        });
        
        return html;
    }
    
    function renderScoreSteps(logs) {
        if (!logs || logs.length === 0) {
            return '<p class="text-muted">No score calculation logs found</p>';
        }
        
        let html = '';
        logs.forEach((log, idx) => {
            const finalScore = Number(log.final_score ?? 0);
            const finalMax = Number(log.final_max_score ?? 0);
            const finalPct = Number(log.final_percentage ?? 0);
            const finalScoreStr = (!isNaN(finalScore) ? finalScore : 0).toFixed(2);
            const finalMaxStr = (!isNaN(finalMax) ? finalMax : 0).toFixed(2);
            const finalPctStr = (!isNaN(finalPct) ? finalPct : 0).toFixed(2);
            html += `
                <div class="card mb-3">
                    <div class="card-header cursor-pointer" onclick="toggleCollapse('scoreLog${idx}')">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6 class="mb-0">${log.tool_name} → ${log.category}</h6>
                            <div>
                                <span class="badge bg-primary">${finalScoreStr}/${finalMaxStr}</span>
                                <span class="badge" style="background-color: ${getTrustScoreColor(finalPct)}">${finalPctStr}%</span>
                            </div>
                        </div>
                    </div>
                    <div class="card-body d-none" id="scoreLog${idx}">
                        <div class="progress mb-3" style="height: 25px;">
                            <div class="progress-bar" style="width: ${finalPct}%; background-color: ${getTrustScoreColor(finalPct)}">
                                <small style="color: white; font-weight: bold;">${finalPctStr}%</small>
                            </div>
                        </div>
                        ${renderSteps(log.steps)}
                    </div>
                </div>
            `;
        });
        
        return html;
    }
    
    function renderSteps(steps) {
        if (!steps || steps.length === 0) {
            return '<p class="text-muted">No steps recorded</p>';
        }
        
        let html = '';
        steps.forEach((step, idx) => {
            html += `
                <div style="margin: 15px 0; padding: 10px; background: #f8f9fa; border-left: 3px solid #0d6efd; border-radius: 4px;">
                    <h6 class="mb-2">
                        <strong>Step ${step.step}: ${step.name}</strong>
                    </h6>
                    <p class="mb-2 text-muted"><small>${step.description || ''}</small></p>
                    ${step.formula ? `<p class="mb-2"><code style="background: #f5f5f5; padding: 5px;">${step.formula}</code></p>` : ''}
                    ${step.logic ? `<p class="mb-2"><small><strong>Logic:</strong> ${step.logic}</small></p>` : ''}
                    ${step.input ? `<p class="mb-2"><small><strong>Input:</strong> ${JSON.stringify(step.input)}</small></p>` : ''}
                    <p style="color: #198754; font-weight: bold; margin-bottom: 0;">→ Result: ${JSON.stringify(step.result)}</p>
                </div>
            `;
        });
        
        return html;
    }
    
    function renderRuleEvaluations(logs) {
        if (!logs || logs.length === 0) {
            return '<p class="text-muted">No advanced rules were evaluated</p>';
        }
        
        let html = '';
        logs.forEach((log, idx) => {
            const summary = log.summary || {};
            const matched = summary.rules_matched || 0;
            const total = summary.total_rules || 0;
            
            html += `
                <div class="card mb-3">
                    <div class="card-header cursor-pointer" onclick="toggleCollapse('ruleLog${idx}')">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6 class="mb-0">${log.tool_name} → ${log.category}</h6>
                            <span class="badge ${matched === total ? 'bg-danger' : 'bg-warning'}">${matched}/${total} matched</span>
                        </div>
                    </div>
                    <div class="card-body d-none" id="ruleLog${idx}">
                        ${log.rules_evaluated && log.rules_evaluated.length > 0 
                            ? log.rules_evaluated.map(rule => `
                                <div style="margin: 10px 0; padding: 12px; background: ${rule.matched ? '#d4edda' : '#f8d7da'}; border-radius: 4px; border-left: 4px solid ${rule.matched ? '#28a745' : '#dc3545'}">
                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                        <strong style="font-size: 1.05em;">${rule.rule_name || 'Rule'}</strong>
                                        <span class="badge ${rule.matched ? 'bg-success' : 'bg-danger'}">${rule.matched ? '✓ Matched' : '✗ Not Matched'}</span>
                                    </div>
                                    
                                    ${rule.impact_level ? `
                                        <div style="margin: 8px 0;">
                                            <small><strong>Impact Level:</strong> <span style="color: #666;">${rule.impact_level}</span></small>
                                        </div>
                                    ` : ''}
                                    
                                    ${rule.matched_groups && rule.matched_groups.length > 0 ? `
                                        <div style="margin: 8px 0; padding: 8px; background: rgba(255,255,255,0.6); border-radius: 3px;">
                                            <small><strong>Matched Conditions:</strong></small>
                                            <ul style="margin: 5px 0 0 20px; padding: 0;">
                                                ${rule.matched_groups.map(group => `
                                                    <li style="margin: 3px 0;">
                                                        <small>
                                                            <strong>Field:</strong> ${group.field_path || 'N/A'}<br>
                                                            <strong>Operator:</strong> ${group.operator || 'N/A'}<br>
                                                            <strong>Expected:</strong> <code style="background: #f0f0f0; padding: 2px 4px;">${group.expected_value !== undefined ? JSON.stringify(group.expected_value) : 'N/A'}</code><br>
                                                            <strong>Actual:</strong> <code style="background: #f0f0f0; padding: 2px 4px;">${group.actual_value !== undefined ? JSON.stringify(group.actual_value) : 'N/A'}</code>
                                                        </small>
                                                    </li>
                                                `).join('')}
                                            </ul>
                                        </div>
                                    ` : ''}
                                    
                                    ${rule.extracted_values && Object.keys(rule.extracted_values).length > 0 ? `
                                        <div style="margin: 8px 0; padding: 8px; background: rgba(255,255,255,0.6); border-radius: 3px;">
                                            <small><strong>Extracted Values:</strong></small>
                                            <ul style="margin: 5px 0 0 20px; padding: 0;">
                                                ${Object.entries(rule.extracted_values).map(([key, value]) => `
                                                    <li style="margin: 3px 0;">
                                                        <small><strong>${key}:</strong> <code style="background: #f0f0f0; padding: 2px 4px;">${typeof value === 'object' ? JSON.stringify(value) : value}</code></small>
                                                    </li>
                                                `).join('')}
                                            </ul>
                                        </div>
                                    ` : ''}
                                </div>
                            `).join('')
                            : '<p class="text-muted">No rules evaluated</p>'
                        }
                    </div>
                </div>
            `;
        });
        
        return html;
    }
    
    function toggleCollapse(elementId) {
        const el = document.getElementById(elementId);
        if (el) {
            el.classList.toggle('d-none');
        }
    }
    
    // ==================== Tool Reporting Action Management ====================
    
    async function loadToolReportingActions(reportings) {
        if (!reportings || reportings.length === 0) return;
        
        console.log('loadToolReportingActions called with', reportings.length, 'reportings');
        
        for (let rep of reportings) {
            try {
                // First, try to get action for this specific reporting
                const response = await fetch(`/api/tool-reporting-action/${rep._id}`);
                if (response.ok) {
                    const data = await response.json();
                    console.log('Loaded action for reporting', rep._id, ':', data.action_status);
                    const select = document.querySelector(`[data-reporting-id="${rep._id}"]`);
                    
                    if (!select) {
                        console.log('No select element found for', rep._id);
                        continue;
                    }
                    
                    // If action_status is valid and not default, apply it
                    if (data.action_status && data.action_status !== 'no action') {
                        select.value = data.action_status;
                        applyActionStyleToSelect(select, data.action_status);
                        console.log('Applied action', data.action_status, 'to select');
                    } else {
                        // No action or default action, try to carry forward from previous
                        console.log('No previous action for this reporting, checking for carried forward action...');
                        await loadCarriedForwardAction(rep, select);
                    }
                } else {
                    console.log('Error loading action for', rep._id, ':', response.status);
                }
            } catch (error) {
                console.error(`Error loading action for ${rep._id}:`, error);
            }
        }
    }
    
    async function loadCarriedForwardAction(rep, select) {
        if (!select) return;
        
        try {
            // Use data attributes from select if available, otherwise use rep object
            const toolName = select.dataset.toolName || rep.tool_name;
            const category = select.dataset.category || rep.category;
            const uniqueId = select.dataset.uniqueId || rep.unique_id;
            
            console.log('[CARRY-FORWARD] Tool identifier:', {toolName, category, uniqueId});
            console.log('[CARRY-FORWARD] Rep object:', {tool_name: rep.tool_name, category: rep.category, unique_id: rep.unique_id});
            console.log('[CARRY-FORWARD] Data attributes:', {toolName: select.dataset.toolName, category: select.dataset.category, uniqueId: select.dataset.uniqueId});
            
            const url = `/api/tool-action-by-identifier/${encodeURIComponent(toolName)}/${encodeURIComponent(category)}/${encodeURIComponent(uniqueId)}`;
            console.log('[CARRY-FORWARD] Fetching from:', url);
            
            const response = await fetch(url);
            if (response.ok) {
                const data = await response.json();
                console.log('[CARRY-FORWARD] API Response:', data);
                
                if (data.has_previous && data.action_status && data.action_status !== 'no action') {
                    select.value = data.action_status;
                    applyActionStyleToSelect(select, data.action_status);
                    console.log('[CARRY-FORWARD] ✓ Applied action', data.action_status, 'for tool:', toolName);
                    
                    // Add visual indicator that this was carried forward
                    const parent = select.closest('td');
                    if (parent && !parent.querySelector('.carried-forward-badge')) {
                        const badge = document.createElement('small');
                        badge.className = 'carried-forward-badge';
                        badge.style.color = '#666';
                        badge.style.marginLeft = '5px';
                        badge.innerHTML = '(↻ carried)';
                        parent.appendChild(badge);
                    }
                } else {
                    console.log('[CARRY-FORWARD] ✗ No valid carried action available. has_previous:', data.has_previous, 'action_status:', data.action_status);
                }
            } else {
                console.log('[CARRY-FORWARD] ✗ API Error:', response.status);
            }
        } catch (error) {
            console.error('[CARRY-FORWARD] ✗ Exception:', error);
        }
    }
    
    function applyActionStyleToSelect(selectElement, status) {
        const colorMap = {
            'no action': '#d3d3d3',
            'reviewing': '#ffc107',
            'resolved': '#28a745',
            'dismiss': '#ff9800'
        };
        
        selectElement.style.backgroundColor = colorMap[status] || '#d3d3d3';
        selectElement.style.color = (status === 'resolved' || status === 'dismiss') ? 'white' : 'black';
    }
    
    function setupActionDropdownListeners() {
        const selects = document.querySelectorAll('.tool-action-select');
        selects.forEach(select => {
            // Remove any existing listeners
            const newSelect = select.cloneNode(true);
            select.parentNode.replaceChild(newSelect, select);
            
            // Add new listener
            newSelect.addEventListener('change', (e) => {
                applyActionStyleToSelect(e.target, e.target.value);
            });
        });
    }
    
    function setupRecordActionsButton() {
        // Use event delegation on document for dynamically created buttons
        document.removeEventListener('click', handleRecordActionsClick);
        document.addEventListener('click', handleRecordActionsClick);
    }
    
    async function handleRecordActionsClick(e) {
        if (e.target && e.target.id === 'recordActionsBtn') {
            e.preventDefault();
            e.stopPropagation();
            await saveToolReportingActions();
        }
    }
    
    async function saveToolReportingActions() {
        console.log('saveToolReportingActions called');
        const selects = document.querySelectorAll('.tool-action-select');
        console.log('Found selects:', selects.length);
        const actions = [];
        
        selects.forEach(select => {
            const reportingId = select.dataset.reportingId;
            const toolName = select.dataset.toolName;
            const category = select.dataset.category;
            const uniqueId = select.dataset.uniqueId;
            const status = select.value;
            
            console.log('Processing select:', {reportingId, toolName, category, uniqueId, status});
            
            if (status && toolName && category && uniqueId) {
                actions.push({
                    reporting_id: reportingId,
                    tool_name: toolName,
                    category: category,
                    unique_id: uniqueId,
                    status: status
                });
            }
        });
        
        console.log('Actions to save:', actions);
        if (actions.length === 0) {
            alert('No actions to save');
            return;
        }
        
        try {
            const recordBtn = document.getElementById('recordActionsBtn');
            if (recordBtn) {
                recordBtn.disabled = true;
                recordBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';
            }
            
            console.log('Sending to /api/batch-tool-reporting-actions:', actions);
            const response = await fetch('/api/batch-tool-reporting-actions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(actions)
            });
            
            console.log('Response status:', response.status);
            if (response.ok) {
                const result = await response.json();
                console.log('Success response:', result);
                const recordBtn = document.getElementById('recordActionsBtn');
                if (recordBtn) {
                    recordBtn.innerHTML = '<i class="bi bi-check-circle me-2"></i>Actions Saved!';
                    recordBtn.classList.add('btn-success');
                    recordBtn.classList.remove('btn-primary');
                    
                    setTimeout(() => {
                        recordBtn.disabled = false;
                        recordBtn.innerHTML = 'Record Actions';
                        recordBtn.classList.remove('btn-success');
                        recordBtn.classList.add('btn-primary');
                    }, 2000);
                }
            } else {
                const error = await response.json();
                console.error('Error response:', error);
                alert('Error saving actions: ' + (error.detail || error.error || 'Unknown error'));
                const recordBtn = document.getElementById('recordActionsBtn');
                if (recordBtn) {
                    recordBtn.disabled = false;
                    recordBtn.innerHTML = 'Record Actions';
                }
            }
        } catch (error) {
            console.error('Exception during save:', error);
            alert('Error saving actions: ' + error.message);
            const recordBtn = document.getElementById('recordActionsBtn');
            if (recordBtn) {
                recordBtn.disabled = false;
                recordBtn.innerHTML = 'Record Actions';
            }
        }
    }
    
    // Override renderEvaluationReport to add action loading after rendering
    const originalRenderEvaluationReport = renderEvaluationReport;
    renderEvaluationReport = function(report) {
        originalRenderEvaluationReport(report);
        
        // Load actions and setup listeners after a short delay to ensure DOM is ready
        setTimeout(() => {
            const toolReportings = report.tool_reportings || [];
            loadToolReportingActions(toolReportings);
            setupActionDropdownListeners();
            setupRecordActionsButton();
        }, 100);
    };
    
    // Load report when tab is shown
    document.getElementById('evaluation-reports-tab').addEventListener('shown.bs.tab', function() {
        loadLatestEvaluationReport();
    });

    // =====================================================================
    // Tool Report Management Tab
    // =====================================================================

    async function triggerManualAnalysis() {
        const btn = document.getElementById('startTrustAnalysisBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span> Running…';

        try {
            const resp = await fetch('/api/trigger-manual-analysis', { method: 'POST' });
            const data = await resp.json();

            if (!resp.ok) {
                alert('Analysis failed: ' + (data.error || resp.statusText));
                return;
            }

            const behaviour = (data.system_behaviour || '').toUpperCase();
            const score     = data.system_trust_score_percentage ?? '—';
            const tools     = data.tools_analysed ?? '—';

            // Show a small toast-style alert
            const alertHtml = `
                <div class="alert alert-success alert-dismissible fade show d-flex align-items-center gap-2 mt-2" role="alert" id="manualAnalysisAlert">
                    <i class="bi bi-check-circle-fill fs-5"></i>
                    <div>
                        <strong>Trust Analysis Complete</strong> &mdash;
                        System behaviour: <strong>${behaviour}</strong> &nbsp;|&nbsp;
                        Trust score: <strong>${score}%</strong> &nbsp;|&nbsp;
                        Tools analysed: <strong>${tools}</strong>
                    </div>
                    <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>`;
            const container = document.querySelector('#tool-report-management .mt-4');
            // Remove previous alert if any
            const prev = document.getElementById('manualAnalysisAlert');
            if (prev) prev.remove();
            container.insertAdjacentHTML('afterbegin', alertHtml);

            // Refresh the table to show updated statuses
            loadToolReportManagement();
            // Refresh the main dashboard panels and status bar
            fetchData();
            refreshDashboardStatusBar();

        } catch (err) {
            alert('Unexpected error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-play-circle me-1"></i> Start Trust Analysis';
        }
    }

    async function loadToolReportManagement() {
        const spinner = document.getElementById('toolReportLoadingSpinner');
        const tbody = document.getElementById('toolReportTableBody');
        const summaryCards = document.getElementById('toolReportSummaryCards');

        spinner.classList.remove('d-none');
        tbody.innerHTML = '';
        summaryCards.innerHTML = '';

        try {
            const resp = await fetch('/api/tool-report-management');
            if (!resp.ok) {
                const err = await resp.json();
                tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">Error loading data: ${err.error || resp.statusText}</td></tr>`;
                return;
            }
            const data = await resp.json();
            const tools = data.tools || [];

            // --- Summary cards ---
            const totalTools = tools.length;
            const statusCounts = { normal: 0, suspicious: 0, compromised: 0, 'No data': 0 };
            const actionCounts = { 'no action': 0, reviewing: 0, resolved: 0, dismiss: 0 };

            tools.forEach(t => {
                const s = (t.current_status || 'No data').toLowerCase();
                if (s === 'normal') statusCounts.normal++;
                else if (s === 'suspicious') statusCounts.suspicious++;
                else if (s === 'compromised') statusCounts.compromised++;
                else statusCounts['No data']++;

                const a = (t.current_action || 'no action').toLowerCase();
                if (actionCounts[a] !== undefined) actionCounts[a]++;
                else actionCounts['no action']++;
            });

            const statTile = (cls, icon, value, label) => `
                <div class="col-6 col-lg-3">
                    <div class="ta-stat ta-${cls}">
                        <i class="bi ${icon}"></i>
                        <div><div class="ta-stat-value">${value}</div><div class="ta-stat-label">${label}</div></div>
                    </div>
                </div>`;
            summaryCards.innerHTML = `
                <div class="col-12 col-xl-6">
                    <div class="ta-stat-group-label">Current status · ${totalTools} tools</div>
                    <div class="row g-2">
                        ${statTile('unknown', 'bi-tools', totalTools, 'Total Tools')}
                        ${statTile('normal', 'bi-check-circle-fill', statusCounts.normal, 'Normal')}
                        ${statTile('suspicious', 'bi-exclamation-triangle-fill', statusCounts.suspicious, 'Suspicious')}
                        ${statTile('compromised', 'bi-x-octagon-fill', statusCounts.compromised, 'Compromised')}
                    </div>
                </div>
                <div class="col-12 col-xl-6">
                    <div class="ta-stat-group-label">Actions</div>
                    <div class="row g-2">
                        ${statTile('unknown', 'bi-dash-circle', actionCounts['no action'], 'No Action')}
                        ${statTile('info', 'bi-eye', actionCounts.reviewing, 'Reviewing')}
                        ${statTile('normal', 'bi-check2-all', actionCounts.resolved, 'Resolved')}
                        ${statTile('unknown', 'bi-x-circle', actionCounts.dismiss, 'Dismissed')}
                    </div>
                </div>
            `;

            // --- Table rows ---
            if (tools.length === 0) {
                tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted py-4">No mapped tools found.</td></tr>';
                return;
            }

            _batchToolsList = tools; // store for batch mode

            tools.forEach((tool, idx) => {
                const statusBadge = getToolStatusBadge(tool.current_status);
                const actionBadge = getToolActionBadge(tool.current_action);
                const submittedDisplay = tool.most_recent_submitted
                    ? formatToolReportTimestamp(tool.most_recent_submitted)
                    : '<span class="text-muted fst-italic">Never submitted</span>';
                const actionUpdatedDisplay = tool.action_updated_at
                    ? formatToolReportTimestamp(tool.action_updated_at)
                    : '<span class="text-muted fst-italic">—</span>';
                const notesDisplay = tool.action_notes
                    ? `<span title="${escapeHtml(tool.action_notes)}" class="text-truncate d-inline-block" style="max-width:150px;">${escapeHtml(tool.action_notes)}</span>`
                    : '<span class="text-muted fst-italic">—</span>';
                const dataTypeBadge = tool.data_type
                    ? `<span class="badge bg-light text-dark border">${escapeHtml(tool.data_type)}</span>`
                    : '—';
                const manualImpactDisplay = tool.manual_impact
                    ? getManualImpactBadge(tool.manual_impact, tool.manual_impact_reason, tool.manual_impact_custom_reason)
                    : '<span class="text-muted fst-italic small">—</span>';

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="batch-check-col d-none text-center">
                        <input type="checkbox" class="form-check-input batch-tool-checkbox" data-tool-idx="${idx}" onchange="updateBatchCount()">
                    </td>
                    <td class="fw-semibold">${escapeHtml(tool.tool_name)}</td>
                    <td>${escapeHtml(tool.trust_evaluation_category)}</td>
                    <td>${dataTypeBadge}</td>
                    <td>${statusBadge}</td>
                    <td>${manualImpactDisplay}</td>
                    <td>${submittedDisplay}</td>
                    <td>${actionBadge}</td>
                    <td>${notesDisplay}</td>
                    <td>${actionUpdatedDisplay}</td>
                    <td>
                        <button class="btn btn-outline-primary btn-sm" onclick="openManualImpactModal(${JSON.stringify(tool).replace(/"/g, '&quot;')})">
                            <i class="bi bi-pencil-square me-1"></i>Modify
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">Unexpected error: ${e.message}</td></tr>`;
        } finally {
            spinner.classList.add('d-none');
        }
    }

    function getToolStatusBadge(status) {
        const s = (status || 'No data').toLowerCase();
        if (s === 'normal') return '<span class="badge bg-success fs-6 px-3 py-2">Normal</span>';
        if (s === 'suspicious') return '<span class="badge bg-warning text-dark fs-6 px-3 py-2">Suspicious</span>';
        if (s === 'compromised') return '<span class="badge bg-danger fs-6 px-3 py-2">Compromised</span>';
        return '<span class="badge bg-secondary px-3 py-2">No Data</span>';
    }

    function getToolActionBadge(action) {
        const a = (action || 'no action').toLowerCase();
        if (a === 'reviewing') return '<span class="badge bg-primary px-3 py-2">Reviewing</span>';
        if (a === 'resolved') return '<span class="badge bg-success px-3 py-2">Resolved</span>';
        if (a === 'dismiss') return '<span class="badge bg-secondary px-3 py-2">Dismissed</span>';
        return '<span class="badge bg-light text-dark border px-3 py-2">No Action</span>';
    }

    function getManualImpactBadge(impact, reason, customReason) {
        const i = (impact || '').toLowerCase();
        const reasonLabel = reason === 'review_complete' ? 'Review Complete'
                          : reason === 'false_alarm' ? 'False Alarm'
                          : reason === 'other' ? (customReason || 'Other')
                          : reason;
        let badge = '';
        if (i === 'low')  badge = `<span class="badge bg-success me-1">Low</span>`;
        else if (i === 'mid')  badge = `<span class="badge bg-warning text-dark me-1">Mid</span>`;
        else if (i === 'high') badge = `<span class="badge bg-danger me-1">High</span>`;
        return `${badge}<small class="text-muted fst-italic">${escapeHtml(reasonLabel)}</small>`;
    }

    function formatToolReportTimestamp(isoStr) {
        if (!isoStr) return '—';
        try {
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return isoStr;
            return d.toLocaleString('en-GB', {
                year: 'numeric', month: 'short', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        } catch { return isoStr; }
    }

    function escapeHtml(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // ── Manual Impact Modal ───────────────────────────────────────────────────

    let _manualImpactTool = null;  // currently open tool in modal

    // ── Batch Update ─────────────────────────────────────────────────────────

    let _batchMode = false;
    let _batchToolsList = [];

    function toggleBatchMode() {
        _batchMode = !_batchMode;
        const btn = document.getElementById('batchUpdateBtn');
        const batchBar = document.getElementById('batchUpdateBar');
        const checkCols = document.querySelectorAll('.batch-check-col');
        const checkHeader = document.getElementById('batchCheckHeader');
        const selectAll = document.getElementById('batchSelectAll');

        if (_batchMode) {
            btn.innerHTML = '<i class="bi bi-x-circle me-1"></i> Cancel Batch';
            btn.classList.remove('btn-outline-secondary');
            btn.classList.add('btn-outline-danger');
            batchBar.classList.remove('d-none');
            checkCols.forEach(el => el.classList.remove('d-none'));
            checkHeader.classList.remove('d-none');
            // Reset form
            document.querySelectorAll('input[name="batchImpactLevel"]').forEach(r => r.checked = false);
            document.getElementById('batchImpactReason').value = '';
            document.getElementById('batchImpactCustomReason').value = '';
            document.getElementById('batchImpactCustomReasonGroup').classList.add('d-none');
            document.getElementById('batchActionSelect').value = '';
            document.getElementById('batchActionNotes').value = '';
            updateBatchCount();
        } else {
            btn.innerHTML = '<i class="bi bi-check2-square me-1"></i> Batch Update';
            btn.classList.remove('btn-outline-danger');
            btn.classList.add('btn-outline-secondary');
            batchBar.classList.add('d-none');
            checkCols.forEach(el => el.classList.add('d-none'));
            checkHeader.classList.add('d-none');
            document.querySelectorAll('.batch-tool-checkbox').forEach(cb => cb.checked = false);
            if (selectAll) selectAll.checked = false;
            // Remove result alert if present
            const prev = document.getElementById('batchUpdateResult');
            if (prev) prev.remove();
        }
    }

    function selectAllBatchTools(checked) {
        document.querySelectorAll('.batch-tool-checkbox').forEach(cb => cb.checked = checked);
        updateBatchCount();
    }

    function updateBatchCount() {
        const count = document.querySelectorAll('.batch-tool-checkbox:checked').length;
        const badge = document.getElementById('batchSelectedCount');
        if (badge) badge.textContent = count + ' selected';
        // Sync select-all checkbox state
        const total = document.querySelectorAll('.batch-tool-checkbox').length;
        const selectAll = document.getElementById('batchSelectAll');
        if (selectAll) selectAll.checked = total > 0 && count === total;
    }

    document.getElementById('batchImpactReason').addEventListener('change', function() {
        const group = document.getElementById('batchImpactCustomReasonGroup');
        if (this.value === 'other') group.classList.remove('d-none');
        else group.classList.add('d-none');
    });

    async function saveBatchUpdate() {
        const checked = [...document.querySelectorAll('.batch-tool-checkbox:checked')];
        if (checked.length === 0) { alert('Please select at least one tool.'); return; }

        const impactEl = document.querySelector('input[name="batchImpactLevel"]:checked');
        const reason = document.getElementById('batchImpactReason').value;
        const customReason = document.getElementById('batchImpactCustomReason').value.trim();
        const action = document.getElementById('batchActionSelect').value;
        const actionNotes = document.getElementById('batchActionNotes').value.trim();

        if (!impactEl) { alert('Please select an impact level.'); return; }
        if (!reason) { alert('Please select a reason for the impact change.'); return; }
        if (reason === 'other' && !customReason) { alert('Please provide a custom reason.'); return; }

        const btn = document.getElementById('saveBatchUpdateBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Saving…';

        let successCount = 0, failCount = 0;

        for (const cb of checked) {
            const toolIdx = parseInt(cb.dataset.toolIdx);
            const tool = _batchToolsList[toolIdx];
            if (!tool) continue;

            const payload = {
                tool_name: tool.tool_name,
                category: tool.trust_evaluation_category,
                impact: impactEl.value,
                reason: reason,
                custom_reason: customReason
            };
            if (action) {
                payload.action = action;
                payload.action_notes = actionNotes;
            }

            try {
                const resp = await fetch('/api/tool-manual-impact', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                if (resp.ok) successCount++; else failCount++;
            } catch (e) { failCount++; }
        }

        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-save me-1"></i> Apply to Selected';

        // Show result banner above the batch bar
        const prev = document.getElementById('batchUpdateResult');
        if (prev) prev.remove();
        const cls = failCount === 0 ? 'alert-success' : 'alert-warning';
        const msg = `Updated <strong>${successCount}</strong> tool(s)${failCount > 0 ? `, <strong>${failCount}</strong> failed` : ''}.`;
        document.getElementById('batchUpdateBar').insertAdjacentHTML('beforebegin',
            `<div id="batchUpdateResult" class="alert ${cls} alert-dismissible py-2 mt-2" role="alert">
                <i class="bi bi-check-circle me-1"></i>${msg}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>`);

        // Exit batch mode and reload table
        _batchMode = true; // trick: toggleBatchMode will flip it to false
        toggleBatchMode();
        await loadToolReportManagement();
    }

    function openManualImpactModal(tool) {
        _manualImpactTool = tool;

        // Populate tool details
        const statusBadge = getToolStatusBadge(tool.current_status);
        const actionBadge = getToolActionBadge(tool.current_action);
        document.getElementById('manualImpactToolDetails').innerHTML = `
            <div class="row g-2 small">
                <div class="col-6"><span class="text-muted">Tool:</span> <strong>${escapeHtml(tool.tool_name)}</strong></div>
                <div class="col-6"><span class="text-muted">Category:</span> ${escapeHtml(tool.trust_evaluation_category)}</div>
                <div class="col-6"><span class="text-muted">Data Type:</span> ${escapeHtml(tool.data_type || '—')}</div>
                <div class="col-6"><span class="text-muted">Current Status:</span> ${statusBadge}</div>
                <div class="col-6"><span class="text-muted">Current Action:</span> ${actionBadge}</div>
                <div class="col-6"><span class="text-muted">Last Submitted:</span> ${tool.most_recent_submitted ? formatToolReportTimestamp(tool.most_recent_submitted) : '<em>Never</em>'}</div>
            </div>
        `;

        // Reset impact fields
        document.querySelectorAll('input[name="manualImpactLevel"]').forEach(r => r.checked = false);
        document.getElementById('manualImpactReason').value = '';
        document.getElementById('manualImpactCustomReason').value = '';
        document.getElementById('manualImpactCustomReasonGroup').classList.add('d-none');

        // Reset action fields
        document.getElementById('manualActionSelect').value = '';
        document.getElementById('manualActionNotes').value = tool.action_notes || '';

        document.getElementById('manualImpactExistingInfo').classList.add('d-none');

        // Pre-fill impact if already has override
        if (tool.manual_impact) {
            const radios = document.querySelectorAll('input[name="manualImpactLevel"]');
            radios.forEach(r => { if (r.value === tool.manual_impact) r.checked = true; });
            document.getElementById('manualImpactReason').value = tool.manual_impact_reason || '';
            if (tool.manual_impact_reason === 'other') {
                document.getElementById('manualImpactCustomReasonGroup').classList.remove('d-none');
                document.getElementById('manualImpactCustomReason').value = tool.manual_impact_custom_reason || '';
            }
            const updAt = tool.manual_impact_updated_at ? formatToolReportTimestamp(tool.manual_impact_updated_at) : '';
            document.getElementById('manualImpactExistingInfo').classList.remove('d-none');
            document.getElementById('manualImpactExistingText').textContent =
                `Existing impact override: ${tool.manual_impact} (${tool.manual_impact_reason})${updAt ? ' — set ' + updAt : ''}`;
        }

        new bootstrap.Modal(document.getElementById('manualImpactModal')).show();
    }

    // Show/hide custom reason textarea
    document.getElementById('manualImpactReason').addEventListener('change', function() {
        const group = document.getElementById('manualImpactCustomReasonGroup');
        if (this.value === 'other') group.classList.remove('d-none');
        else group.classList.add('d-none');
    });

    async function saveManualImpact() {
        if (!_manualImpactTool) return;
        const impactEl = document.querySelector('input[name="manualImpactLevel"]:checked');
        const reason = document.getElementById('manualImpactReason').value;
        const customReason = document.getElementById('manualImpactCustomReason').value.trim();
        const action = document.getElementById('manualActionSelect').value;
        const actionNotes = document.getElementById('manualActionNotes').value.trim();

        if (!impactEl) { alert('Please select an impact level.'); return; }
        if (!reason) { alert('Please select a reason for the impact change.'); return; }
        if (reason === 'other' && !customReason) { alert('Please provide a custom reason.'); return; }

        const btn = document.getElementById('saveManualImpactBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Saving...';

        try {
            const payload = {
                tool_name: _manualImpactTool.tool_name,
                category: _manualImpactTool.trust_evaluation_category,
                impact: impactEl.value,
                reason: reason,
                custom_reason: customReason
            };
            // Only include action fields if user selected an action
            if (action) {
                payload.action = action;
                payload.action_notes = actionNotes;
            }

            const resp = await fetch('/api/tool-manual-impact', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            if (resp.ok) {
                bootstrap.Modal.getInstance(document.getElementById('manualImpactModal')).hide();
                await loadToolReportManagement();
            } else {
                const err = await resp.json();
                alert('Error saving: ' + (err.error || resp.statusText));
            }
        } catch (e) {
            alert('Error: ' + e.message);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-save me-1"></i>Save Changes';
        }
    }

    async function clearManualImpact() {
        if (!_manualImpactTool) return;
        if (!confirm(`Clear manual impact override for "${_manualImpactTool.tool_name}" / "${_manualImpactTool.trust_evaluation_category}"?`)) return;

        const btn = document.getElementById('clearManualImpactBtn');
        btn.disabled = true;

        try {
            const tn = encodeURIComponent(_manualImpactTool.tool_name);
            const cat = encodeURIComponent(_manualImpactTool.trust_evaluation_category);
            const resp = await fetch(`/api/tool-manual-impact/${tn}/${cat}`, { method: 'DELETE' });
            if (resp.ok) {
                bootstrap.Modal.getInstance(document.getElementById('manualImpactModal')).hide();
                await loadToolReportManagement();
            } else {
                const err = await resp.json();
                alert('Error clearing override: ' + (err.error || resp.statusText));
            }
        } catch (e) {
            alert('Error: ' + e.message);
        } finally {
            btn.disabled = false;
        }
    }

    // Load when tab is shown
    document.getElementById('tool-report-management-tab').addEventListener('shown.bs.tab', function() {
        loadToolReportManagement();
    });
    