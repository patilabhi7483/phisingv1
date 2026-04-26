// PhishForensics AI - Live Backend

// --- Client-Side Pre-Analysis Engine ---
async function runPreAnalysis(text) {
    const findings = {
        urls: [],
        homographs: [],
        rawSignals: ''
    };

    // 1. URL Extraction
    const urlRegex = /(https?:\/\/[^\s>"]+)/gi;
    let urls = text.match(urlRegex) || [];
    urls = [...new Set(urls)];

    for (let u of urls) {
        let urlObj;
        try { urlObj = new URL(u); } catch(e) { continue; }
        
        let fetchResult = null;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3500);
            // safe fetch
            const resp = await fetch(u, { method: 'GET', mode: 'cors', signal: controller.signal });
            clearTimeout(timeoutId);
            
            let title = null;
            const contentType = resp.headers.get('content-type') || '';
            if (contentType.includes('text/html')) {
                const textChunk = await resp.text();
                const titleMatch = textChunk.match(/<title>([^<]*)<\/title>/i);
                if (titleMatch) title = titleMatch[1].trim();
            }
            
            fetchResult = {
                status: resp.status,
                contentType: contentType,
                finalUrl: resp.url,
                title: title
            };
        } catch (err) {
            fetchResult = { error: err.message };
        }
        
        findings.urls.push({
            original: u,
            domain: urlObj.hostname,
            fetchResult: fetchResult
        });
    }

    // 2. Homograph Detection
    const domainRegex = /@([a-zA-Z0-9.-]+)/gi;
    let domains = [...text.matchAll(domainRegex)].map(m => m[1]);
    findings.urls.forEach(u => domains.push(u.domain));
    domains = [...new Set(domains)];

    for (let d of domains) {
        let suspicious = false;
        let charMap = [];
        
        if (d.includes('1')) { suspicious = true; charMap.push({ char: '1', cp: 'U+0031', likely: 'l' }); }
        if (d.includes('0')) { suspicious = true; charMap.push({ char: '0', cp: 'U+0030', likely: 'o' }); }
        if (d.startsWith('xn--')) { suspicious = true; charMap.push({ char: 'xn--', cp: 'PUNYCODE', likely: 'punycode' }); }
        
        for(let i=0; i<d.length; i++) {
            const cp = d.charCodeAt(i);
            if (cp > 127) {
                suspicious = true;
                charMap.push({ char: d[i], cp: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'), likely: 'unicode' });
            }
        }
        
        if (suspicious) {
            findings.homographs.push({ domain: d, charMap: charMap });
        }
    }

    let signals = `\n--- CLIENT PRE-ANALYSIS SIGNALS ---\n`;
    findings.urls.forEach(u => {
        signals += `URL: ${u.original}\n`;
        if (u.fetchResult && !u.fetchResult.error) {
            signals += `  -> VERIFIED DESTINATION: ${u.fetchResult.finalUrl}\n`;
            signals += `  -> STATUS: ${u.fetchResult.status}\n`;
            signals += `  -> CONTENT: ${u.fetchResult.contentType}\n`;
            if (u.fetchResult.title) signals += `  -> TITLE: ${u.fetchResult.title}\n`;
        } else {
            signals += `  -> FETCH FAILED (CORS/Network)\n`;
        }
    });
    findings.homographs.forEach(h => {
        signals += `HOMOGRAPH DETECTED: ${h.domain}\n`;
        h.charMap.forEach(c => signals += `  -> Char '${c.char}' (${c.cp}) replacing '${c.likely}'\n`);
    });
    
    findings.rawSignals = signals;
    return findings;
}
document.addEventListener('DOMContentLoaded', () => {
    console.log("PhishForensics AI Core Initialized.");

    // Add glowing hover effects to buttons dynamically if needed
    const buttons = document.querySelectorAll('.btn-primary');
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', (e) => {
            // Optional: add cursor tracking glow effect later
        });
    });

    // Extension install helper
    const extensionInstallConfig = {
        chromeWebStoreUrl: '',
        edgeAddonsUrl: '',
        extensionsManagerUrl: 'chrome://extensions/',
        downloadUrl: 'https://drive.usercontent.google.com/u/0/uc?id=1BDF3C4prpToasjHHokAMbeBDNciG1pCC&export=download'
    };

    const downloadExtensionBtn = document.getElementById('downloadExtensionBtn');
    const extensionInstallModal = document.getElementById('extensionInstallModal');
    const closeInstallModalBtn = document.getElementById('closeInstallModalBtn');
    const installIntroText = document.getElementById('installIntroText');
    const installStepsList = document.getElementById('installStepsList');
    const openExtensionsPageBtn = document.getElementById('openExtensionsPageBtn');

    function detectBrowser() {
        const ua = navigator.userAgent || '';
        if (ua.includes('Edg/')) return 'edge';
        if (ua.includes('Chrome/') && !ua.includes('Edg/') && !ua.includes('OPR/')) return 'chrome';
        if (ua.includes('Firefox/')) return 'firefox';
        return 'other';
    }

    function getInstallContent(browserName) {
        if (browserName === 'edge') {
            return {
                intro: 'Edge does not allow silent local installs from websites. Use these steps once:',
                managerUrl: 'edge://extensions/',
                steps: [
                    'Click "Open Extensions Page".',
                    'Turn ON "Developer mode".',
                    'Click "Load unpacked".',
                    'Select the folder named "phish-forensics-extension".',
                    'Pin the extension from the toolbar menu (optional).'
                ]
            };
        }

        if (browserName === 'chrome') {
            return {
                intro: 'Chrome blocks silent local installs from websites. Use these quick steps:',
                managerUrl: 'chrome://extensions/',
                steps: [
                    'Click "Open Extensions Page".',
                    'Turn ON "Developer mode" (top-right).',
                    'Click "Load unpacked".',
                    'Select the folder named "phish-forensics-extension".',
                    'Enable "Allow in incognito" if you need private-window scanning.'
                ]
            };
        }

        if (browserName === 'firefox') {
            return {
                intro: 'Firefox cannot auto-install unpacked add-ons from normal websites.',
                managerUrl: 'about:debugging#/runtime/this-firefox',
                steps: [
                    'Open the Add-ons debug page.',
                    'Click "This Firefox".',
                    'Choose "Load Temporary Add-on".',
                    'Pick a manifest file from "phish-forensics-extension".',
                    'For permanent install, package and sign the add-on.'
                ]
            };
        }

        return {
            intro: 'Your browser does not allow direct extension install from websites. Use manual install:',
            managerUrl: extensionInstallConfig.extensionsManagerUrl,
            steps: [
                'Open your browser extension manager page.',
                'Enable developer mode.',
                'Choose "Load unpacked".',
                'Select the folder named "phish-forensics-extension".'
            ]
        };
    }

    function renderInstallModal(content) {
        if (!extensionInstallModal || !installIntroText || !installStepsList) return;
        installIntroText.textContent = content.intro;
        installStepsList.innerHTML = content.steps.map(step => `<li>${step}</li>`).join('');
        extensionInstallModal.dataset.managerUrl = content.managerUrl;
        extensionInstallModal.classList.remove('hidden');
        extensionInstallModal.setAttribute('aria-hidden', 'false');
    }

    function closeInstallModal() {
        if (!extensionInstallModal) return;
        extensionInstallModal.classList.add('hidden');
        extensionInstallModal.setAttribute('aria-hidden', 'true');
    }

    if (downloadExtensionBtn) {
        downloadExtensionBtn.addEventListener('click', (e) => {
            e.preventDefault();
            window.open(extensionInstallConfig.downloadUrl, '_blank', 'noopener');
        });
    }

    if (closeInstallModalBtn) {
        closeInstallModalBtn.addEventListener('click', closeInstallModal);
    }

    if (extensionInstallModal) {
        extensionInstallModal.addEventListener('click', (e) => {
            if (e.target === extensionInstallModal) closeInstallModal();
        });
    }

    if (openExtensionsPageBtn) {
        openExtensionsPageBtn.addEventListener('click', () => {
            window.open(extensionInstallConfig.downloadUrl, '_blank', 'noopener');
        });
    }

    // ── LANDING PAGE (index.html) ──────────────────────────────
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    // Render History
    const historyCards = document.getElementById('historyCards');
    const historySection = document.getElementById('historySection');
    if (historyCards && historySection) {
        const history = JSON.parse(localStorage.getItem('phishHistory') || '[]');
        if (history.length > 0) {
            historySection.classList.remove('hidden');
            historyCards.innerHTML = history.map((item, index) => {
                const hColor = item.riskScore >= 60 ? 'var(--accent-red)' : item.riskScore >= 40 ? 'var(--accent-yellow)' : 'var(--accent-green)';
                return `
                <div class="history-card" data-index="${index}">
                    <div class="history-card-left">
                        <span style="color:${hColor}; font-weight:bold; font-size:1.1rem">${item.verdict}</span>
                        <span class="history-input">${item.input.replace(/</g, '&lt;')}</span>
                    </div>
                    <div class="history-card-right">
                        <span class="tag" style="border-color:${hColor}; color:${hColor}">${item.riskScore}</span>
                        <span style="font-size:0.8rem; color:var(--text-muted)">${item.timestamp}</span>
                    </div>
                </div>
                `;
            }).join('');
            
            document.querySelectorAll('.history-card').forEach(card => {
                card.addEventListener('click', (e) => {
                    const idx = e.currentTarget.getAttribute('data-index');
                    sessionStorage.setItem('phishResult', JSON.stringify(history[idx].fullResult));
                    window.location.href = 'analysis.html';
                });
            });
        }
    }

    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            const input = document.getElementById('inputBox').value.trim();
            if (!input) return;

            const originalText = analyzeBtn.innerText;
            analyzeBtn.innerText = '⚡ Analyzing...';
            analyzeBtn.style.opacity = '0.8';
            analyzeBtn.disabled = true;

            try {
                // Feature 4: Improved Pre-Analysis Engine
                analyzeBtn.innerText = '⚡ Pre-Analyzing...';
                const preAnalysis = await runPreAnalysis(input);
                sessionStorage.setItem('clientSignals', JSON.stringify(preAnalysis));
                
                const finalInputPayload = input + preAnalysis.rawSignals;
                
                analyzeBtn.innerText = '⚡ AI Forensics...';
                const response = await fetch('http://127.0.0.1:3000/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ input: finalInputPayload })
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }

                const result = await response.json();

                sessionStorage.setItem('phishResult', JSON.stringify(result));
                
                // History Update
                let history = JSON.parse(localStorage.getItem('phishHistory') || '[]');
                history.unshift({
                    timestamp: new Date().toLocaleString(),
                    riskScore: result.riskScore,
                    verdict: result.verdict,
                    input: input.substring(0, 60) + (input.length > 60 ? '...' : ''),
                    fullResult: result
                });
                if (history.length > 5) history = history.slice(0, 5);
                localStorage.setItem('phishHistory', JSON.stringify(history));

                // Scanning Animation Overlay
                const overlay = document.getElementById('scanningOverlay');
                const stepsContainer = document.getElementById('scanSteps');
                if (overlay && stepsContainer) {
                    overlay.classList.remove('hidden');
                    const steps = [
                        "Extracting email headers...",
                        "Unshortening URLs...",
                        "Running homograph detection...",
                        "Querying AI forensic engine...",
                        "Generating threat report..."
                    ];
                    stepsContainer.innerHTML = '';
                    
                    for (let i = 0; i < steps.length; i++) {
                        setTimeout(() => {
                            const stepEl = document.createElement('div');
                            stepEl.className = 'scan-step';
                            stepEl.innerHTML = `<span style="color:var(--accent-cyan)">[✓]</span> ${steps[i]}`;
                            stepsContainer.appendChild(stepEl);
                            document.querySelector('.loader-fill').style.width = `${((i+1)/steps.length)*100}%`;
                        }, i * 600);
                    }
                    
                    setTimeout(() => {
                        window.location.href = 'analysis.html';
                    }, steps.length * 600 + 400);
                } else {
                    window.location.href = 'analysis.html';
                }

            } catch (err) {
                console.error('Analysis failed:', err);
                analyzeBtn.innerText = '⚠ Error: ' + err.message;
                analyzeBtn.style.opacity = '1';
                analyzeBtn.disabled = false;
            }
        });
    }

    // ── ANALYSIS DASHBOARD (analysis.html) ────────────────────
    const dashboard = document.querySelector('.dashboard-container');
    if (dashboard) {
        const raw = sessionStorage.getItem('phishResult');
        if (!raw) return;

        const d = JSON.parse(raw);

        const colorVar = d.riskScore >= 60
            ? 'var(--accent-red)'
            : d.riskScore >= 40
                ? 'var(--accent-yellow)'
                : 'var(--accent-green)';

        // Risk Score circle
        const scoreEl = document.getElementById('riskScore');
        if (scoreEl) {
            scoreEl.style.color = colorVar;
            let current = 0;
            const target = d.riskScore;
            const duration = 1500;
            const stepTime = Math.max(15, duration / (target || 1));
            const timer = setInterval(() => {
                current += 1;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                scoreEl.textContent = current;
            }, stepTime);
        }
        const container = document.getElementById('riskScore-container');
        if (container) {
            const deg = (d.riskScore / 100) * 360;
            container.style.background = `conic-gradient(${colorVar} ${deg}deg, rgba(255,255,255,0.05) 0)`;
            container.style.boxShadow = `inset 0 0 20px rgba(0,0,0,0.8), 0 0 15px ${colorVar}55`;
            if (d.riskScore >= 60) {
                container.style.animation = 'pulseRed 2s infinite';
            }
        }
        
        // Top Risk Factors
        if (d.threatVectors) {
            const topRiskPills = document.getElementById('top-risk-pills');
            if (topRiskPills) {
                const vectorLabelsMap = {
                    headerAnomaly: 'Header', domainSpoof: 'Spoofing', contentUrgency: 'Urgency', urlRisk: 'URL', ipReputation: 'IP', homographRisk: 'Homograph'
                };
                const sorted = Object.entries(d.threatVectors).sort((a, b) => b[1] - a[1]).slice(0, 3);
                topRiskPills.innerHTML = sorted.map(([k, v]) => {
                    const c = v >= 60 ? 'var(--accent-red)' : v >= 40 ? 'var(--accent-yellow)' : 'var(--accent-green)';
                    return `<span class="tag" style="border-color:${c}55; color:${c}; background:${c}15">${vectorLabelsMap[k] || k}: ${v}%</span>`;
                }).join('');
            }
        }

        // Verdict
        const verdictEl = document.getElementById('verdict');
        if (verdictEl) {
            verdictEl.textContent = d.verdict;
            verdictEl.style.color = colorVar;
        }

        // Reasoning (Typing Effect)
        const reasoningEl = document.getElementById('reasoning');
        if (reasoningEl && d.reasoning) {
            reasoningEl.textContent = '';
            let i = 0;
            const typing = setInterval(() => {
                reasoningEl.textContent += d.reasoning.charAt(i);
                i++;
                if (i >= d.reasoning.length) clearInterval(typing);
            }, 18);
        }

        // Confidence
        const confidenceEl = document.getElementById('confidence');
        if (confidenceEl) confidenceEl.textContent = d.confidence;

        // Tags
        const tagsEl = document.querySelector('.tags-container');
        if (tagsEl && d.tags) {
            tagsEl.innerHTML = d.tags.map(t =>
                `<span class="tag" style="border-color:${colorVar}55;color:${colorVar};background:${colorVar}15">${t}</span>`
            ).join('');
        }

        // Advanced Forensics
        if (d.headerAnalysis) {
            const getBadgeColor = status => (status || '').toLowerCase() === 'pass' ? 'var(--accent-green)' : (status || '').toLowerCase() === 'fail' ? 'var(--accent-red)' : 'var(--text-dim)';
            
            const el1 = document.getElementById('ha-senderDomain'); if(el1) el1.textContent = d.headerAnalysis.senderDomain || 'N/A';
            const el2 = document.getElementById('ha-returnDomain'); if(el2) el2.textContent = d.headerAnalysis.returnPathDomain || 'N/A';
            
            const matchBadge = document.getElementById('ha-matchBadge');
            if (matchBadge) {
                matchBadge.textContent = d.headerAnalysis.domainMatch ? '→ MATCH →' : '⤬ MISMATCH ⤬';
                matchBadge.style.backgroundColor = d.headerAnalysis.domainMatch ? 'var(--accent-green)' : 'var(--accent-red)';
                matchBadge.style.color = '#000';
            }

            const spfBadge = document.getElementById('ha-spfBadge');
            if (spfBadge) {
                spfBadge.textContent = d.headerAnalysis.spfStatus.toUpperCase();
                spfBadge.style.backgroundColor = getBadgeColor(d.headerAnalysis.spfStatus);
                spfBadge.style.color = '#000';
            }

            const dkimBadge = document.getElementById('ha-dkimBadge');
            if (dkimBadge) {
                dkimBadge.textContent = d.headerAnalysis.dkimStatus.toUpperCase();
                dkimBadge.style.backgroundColor = getBadgeColor(d.headerAnalysis.dkimStatus);
                dkimBadge.style.color = '#000';
            }

            const el3 = document.getElementById('ha-displayName'); if(el3) el3.textContent = d.headerAnalysis.displayNameTrick || 'None';
            
            const spoofingEl = document.getElementById('ha-spoofing');
            if (spoofingEl) {
                spoofingEl.textContent = d.headerAnalysis.spoofingDetected ? '⚠ WARNING: Spoofing Detected' : 'No Spoofing Detected';
                spoofingEl.style.color = d.headerAnalysis.spoofingDetected ? 'var(--accent-red)' : 'var(--accent-green)';
            }
        }
        
        if (d.urlAnalysis) {
            const el1 = document.getElementById('ua-originalUrl'); if(el1) el1.textContent = d.urlAnalysis.originalUrl || 'N/A';
            const el2 = document.getElementById('ua-realDestination'); if(el2) el2.textContent = d.urlAnalysis.realDestination || 'N/A';
            
            // Client-Side Safe Fetch verified signals
            const clientSignalsStr = sessionStorage.getItem('clientSignals');
            if (clientSignalsStr) {
                const clientSignals = JSON.parse(clientSignalsStr);
                if (clientSignals.urls && clientSignals.urls.length > 0) {
                    const primaryUrlData = clientSignals.urls[0]; // fallback to first
                    if (primaryUrlData && primaryUrlData.fetchResult && !primaryUrlData.fetchResult.error) {
                        const verifiedBadge = document.getElementById('ua-httpVerifiedBadge');
                        if (verifiedBadge) verifiedBadge.classList.remove('hidden');
                        
                        const safeFetchData = document.getElementById('ua-safeFetchData');
                        if (safeFetchData) safeFetchData.classList.remove('hidden');
                        
                        if (el2) el2.textContent = primaryUrlData.fetchResult.finalUrl;
                        
                        const statusCodeEl = document.getElementById('ua-statusCode');
                        if (statusCodeEl) {
                            statusCodeEl.textContent = primaryUrlData.fetchResult.status;
                            statusCodeEl.style.color = primaryUrlData.fetchResult.status >= 200 && primaryUrlData.fetchResult.status < 300 ? 'var(--accent-green)' : 'var(--accent-red)';
                        }
                        
                        const contentTypeEl = document.getElementById('ua-contentType');
                        if (contentTypeEl) contentTypeEl.textContent = primaryUrlData.fetchResult.contentType || 'unknown';
                        
                        const pageTitleEl = document.getElementById('ua-pageTitle');
                        if (pageTitleEl) pageTitleEl.textContent = primaryUrlData.fetchResult.title || 'N/A';
                    }
                }
            }
            
            const shortenedBadge = document.getElementById('ua-shortenedBadge');
            if (shortenedBadge) {
                shortenedBadge.textContent = d.urlAnalysis.isShortened ? 'SHORTENED' : 'DIRECT';
                shortenedBadge.style.backgroundColor = d.urlAnalysis.isShortened ? 'var(--accent-yellow)' : 'var(--accent-green)';
                shortenedBadge.style.color = '#000';
            }

            const tldBadge = document.getElementById('ua-tldBadge');
            if (tldBadge) {
                tldBadge.textContent = d.urlAnalysis.suspiciousTld ? '⚠ SUSPICIOUS TLD' : 'SAFE TLD';
                tldBadge.style.backgroundColor = d.urlAnalysis.suspiciousTld ? 'var(--accent-red)' : 'var(--accent-green)';
                tldBadge.style.color = '#000';
            }

            const el3 = document.getElementById('ua-preview'); if(el3) el3.textContent = d.urlAnalysis.destinationPreview || 'N/A';
        }

        if (d.homographAnalysis) {
            const statusBadge = document.getElementById('ho-statusBadge');
            if (statusBadge) {
                statusBadge.textContent = d.homographAnalysis.detected ? '⚠ WARNING' : 'SAFE';
                statusBadge.style.backgroundColor = d.homographAnalysis.detected ? 'var(--accent-red)' : 'var(--accent-green)';
                statusBadge.style.color = '#000';
            }

            const chars = document.getElementById('ho-suspiciousChars');
            if (chars) chars.textContent = (d.homographAnalysis.suspiciousChars || []).join(', ') || 'None';
            
            const el2 = document.getElementById('ho-legitimateDomain'); if(el2) el2.textContent = d.homographAnalysis.legitimateDomain || 'N/A';
            const el3 = document.getElementById('ho-explanation'); if(el3) el3.textContent = d.homographAnalysis.explanation || 'None detected.';
            
            // Client-Side Homograph Visualizer
            const clientSignalsStr = sessionStorage.getItem('clientSignals');
            if (clientSignalsStr) {
                const clientSignals = JSON.parse(clientSignalsStr);
                if (clientSignals.homographs && clientSignals.homographs.length > 0) {
                    const primaryHomo = clientSignals.homographs[0];
                    const hoVisualizer = document.getElementById('ho-visualizer');
                    if (hoVisualizer) {
                        hoVisualizer.classList.remove('hidden');
                        
                        const suspVisualEl = document.getElementById('ho-suspiciousVisual');
                        if (suspVisualEl) {
                            let coloredStr = primaryHomo.domain;
                            primaryHomo.charMap.forEach(cm => {
                                if (cm.char.length === 1) {
                                    coloredStr = coloredStr.split(cm.char).join(`<span style="color:var(--accent-red); background:rgba(255,0,0,0.2); padding:0 2px;">${cm.char}</span>`);
                                } else if (cm.char === 'xn--') {
                                    coloredStr = coloredStr.replace('xn--', '<span style="color:var(--accent-red); background:rgba(255,0,0,0.2); padding:0 2px;">xn--</span>');
                                }
                            });
                            suspVisualEl.innerHTML = coloredStr;
                        }
                        
                        const realVisualEl = document.getElementById('ho-realVisual');
                        if (realVisualEl) {
                            let cleanStr = primaryHomo.domain;
                            primaryHomo.charMap.forEach(cm => {
                                if (cm.char.length === 1 && cm.likely && cm.likely !== 'unicode' && cm.likely !== 'punycode') {
                                    cleanStr = cleanStr.split(cm.char).join(`<span style="color:var(--accent-green); background:rgba(0,255,0,0.1); padding:0 2px;">${cm.likely}</span>`);
                                }
                            });
                            realVisualEl.innerHTML = cleanStr;
                        }
                        
                        const codepointsContainer = document.getElementById('ho-codepoints');
                        if (codepointsContainer) {
                            codepointsContainer.innerHTML = primaryHomo.charMap.map(cm => 
                                `<span class="tag" style="background: rgba(255,255,255,0.05); color: var(--text-main); font-family: var(--font-mono); font-size: 0.7rem; border-color: var(--border-subtle);">
                                    <span style="color:var(--accent-red); font-weight:bold">${cm.char}</span> 
                                    <span style="color:var(--text-muted)">(${cm.cp})</span>
                                </span>`
                            ).join('');
                        }
                    }
                }
            }
        }

        // Threat Vectors
        const vectorLabels = {
            headerAnomaly: 'Header Anomaly',
            domainSpoof: 'Domain Spoof',
            contentUrgency: 'Content Urgency',
            urlRisk: 'URL Risk',
            ipReputation: 'IP Reputation',
            homographRisk: 'Homograph Risk'
        };
        const vectorsContainer = document.querySelector('.glass-panel .vector-item')?.parentElement;
        if (vectorsContainer && d.threatVectors) {
            vectorsContainer.innerHTML = `<h3 class="section-title">Threat Vector Analysis</h3>` + Object.entries(d.threatVectors).map(([key, val]) => {
                const fc = val >= 60 ? 'fill-red' : val >= 40 ? 'fill-yellow' : 'fill-green';
                return `
                    <div class="vector-item">
                        <div class="vector-header"><span>${vectorLabels[key] || key}</span><span>${val}%</span></div>
                        <div class="vector-bar-bg"><div class="vector-bar-fill ${fc}" style="width:0%" data-target="${val}"></div></div>
                    </div>`;
            }).join('');
            
            setTimeout(() => {
                document.querySelectorAll('.vector-bar-fill').forEach((bar, idx) => {
                    setTimeout(() => {
                        bar.style.width = bar.getAttribute('data-target') + '%';
                    }, idx * 100);
                });
            }, 100);
        }

        // AI Insights
        const insightLabels = {
            primaryThreat: 'Primary Threat',
            attackType: 'Attack Type',
            targetedBrand: 'Targeted Brand',
            evasionTechnique: 'Evasion Technique'
        };
        const insightsContainer = document.querySelector('.insight-row')?.parentElement;
        if (insightsContainer && d.aiInsights) {
            insightsContainer.innerHTML = `<h3 class="section-title">AI Insights</h3>` + Object.entries(d.aiInsights).map(([key, val]) =>
                `<div class="insight-row">
                    <span class="insight-label">${insightLabels[key] || key}</span>
                    <span class="insight-value">${val}</span>
                </div>`
            ).join('');
        }

        // Forensic Findings
        const findingsEl = document.querySelector('.findings-grid');
        if (findingsEl && d.forensicFindings) {
            findingsEl.innerHTML = d.forensicFindings.map(f =>
                `<div class="finding-card ${f.severity === 'high' ? 'high-risk' : ''}">
                    <div class="finding-title">${f.title}</div>
                    <div class="finding-desc">${f.description}</div>
                </div>`
            ).join('');
        }

        // Attack Simulation Timeline
        const timelineEl = document.querySelector('.timeline');
        if (timelineEl && d.attackSimulation) {
            timelineEl.innerHTML = d.attackSimulation.map(s =>
                `<div class="timeline-step ${s.danger ? 'step-danger' : ''} step-active">
                    <div class="step-icon">${s.step}</div>
                    <div class="step-title">${s.title}</div>
                    <div class="step-desc">${s.description}</div>
                </div>`
            ).join('');
        }
        
        // Export PDF
        const exportPdfBtn = document.getElementById('exportPdfBtn');
        if (exportPdfBtn) exportPdfBtn.addEventListener('click', () => window.print());

        // Raw JSON Modal
        const rawJsonBtn = document.getElementById('rawJsonBtn');
        const jsonModal = document.getElementById('jsonModal');
        const closeJsonBtn = document.getElementById('closeJsonBtn');
        if (rawJsonBtn && jsonModal) {
            rawJsonBtn.addEventListener('click', () => {
                document.getElementById('rawJsonOutput').textContent = JSON.stringify(d, null, 2);
                jsonModal.classList.remove('hidden');
            });
            closeJsonBtn.addEventListener('click', () => jsonModal.classList.add('hidden'));
            jsonModal.addEventListener('click', (e) => {
                if (e.target === jsonModal) jsonModal.classList.add('hidden');
            });
        }

        // Share Button
        const shareBtn = document.getElementById('shareBtn');
        const shareToast = document.getElementById('shareToast');
        if (shareBtn && shareToast) {
            shareBtn.addEventListener('click', () => {
                const summary = `PhishForensics AI Report\nTime: ${new Date().toLocaleString()}\nVerdict: ${d.verdict}\nRisk Score: ${d.riskScore}/100\nConfidence: ${d.confidence}\n\nTop Findings:\n` + (d.forensicFindings || []).slice(0,3).map(f => `- ${f.title}`).join('\n') + `\n\nReasoning: ${d.reasoning}`;
                navigator.clipboard.writeText(summary).then(() => {
                    shareToast.classList.remove('hidden');
                    setTimeout(() => shareToast.classList.add('hidden'), 2500);
                }).catch(err => {
                    console.error('Clipboard error:', err);
                    alert('Clipboard access denied.');
                });
            });
        }
    }
});