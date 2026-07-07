// Tab Switching Logic
function switchTab(tabId, btnElement) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    btnElement.classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

async function analyzeEmail() {
    const emailText = document.getElementById('email-content').value;
    const btn = document.getElementById('analyze-btn');
    const loader = document.getElementById('loader');
    const resultsPanel = document.getElementById('results-panel');
    
    if (!emailText.trim()) {
        alert("Please paste the RAW email to analyze.");
        return;
    }

    // UI Loading State
    btn.disabled = true;
    btn.innerText = "Executing Scan...";
    resultsPanel.style.display = 'none';
    loader.style.display = 'block';
    
    try {
      //  CORRECT: Includes the full path
        const response = await fetch(`https://email-analyzer-yzh1.onrender.com/analyze-full-email/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_content: emailText })
        });
        if (!response.ok) throw new Error(`Server Error: ${response.status}`);

        const data = await response.json();
        
        // Build the Live Dashboard with Real Data
        buildLiveDashboard(data, emailText);

    } catch (error) {
        console.error("System Failure:", error);
        alert(`Backend Error: Ensure your Python server is running. ${error.message}`);
    } finally {
        btn.disabled = false;
        btn.innerText = "Execute Full Scan";
        loader.style.display = 'none';
        resultsPanel.style.display = 'block';
    }
}

function buildLiveDashboard(data, rawText) {
    // 1. Calculate Multi-Vector Scores
    let authScore = data.metadata.auth_status === "FAILED" ? 100 : 0;
    let payloadScore = data.threat_intel.status === "malicious" ? 100 : 0;
    
    // Heuristic Intent Score (Offline text analysis)
    let intentScore = 0;
    const lowerText = rawText.toLowerCase();
    if (lowerText.includes('urgent') || lowerText.includes('immediate')) intentScore += 40;
    if (lowerText.includes('password') || lowerText.includes('login')) intentScore += 40;
    if (lowerText.includes('wire') || lowerText.includes('invoice')) intentScore += 30;
    if (intentScore > 100) intentScore = 100;

    // Master Severity (Highest risk vector dictates overall severity)
    let severityScore = Math.max(authScore, payloadScore, intentScore);

    // 2. Update Gauges UI
    updateGauge('val-severity', severityScore);
    updateGauge('val-auth', authScore);
    updateGauge('val-payload', payloadScore);
    updateGauge('val-intent', intentScore);

    // 3. Populate Overview Tab
    const summaryEl = document.getElementById('summary-text');
    const flagsEl = document.getElementById('red-flags-list');
    let flagsHtml = `<li><span style="color:var(--text-muted)">Sender:</span> ${data.metadata.sender}</li>`;
    
    if (severityScore >= 70) {
        summaryEl.innerText = "CRITICAL THREAT: This email triggers high-risk indicators across multiple vectors. Do not interact.";
        if (authScore > 0) flagsHtml += `<li style="color:var(--risk-high)">🚨 SPF/DKIM Authentication FAILED (Spoofed Identity).</li>`;
        if (payloadScore > 0) flagsHtml += `<li style="color:var(--risk-high)">🔥 Payload flagged as malicious by live threat intelligence.</li>`;
        if (intentScore > 50) flagsHtml += `<li style="color:var(--risk-med)">⚠️ Highly manipulative language detected (Urgency/Credentials).</li>`;
    } else {
        summaryEl.innerText = "Analysis Complete: No critical threats identified, but rely on standard operational security.";
        flagsHtml += `<li style="color:var(--risk-low)">✅ Authentication passed.</li>`;
        flagsHtml += `<li style="color:var(--risk-low)">✅ No malicious payloads found on primary scan.</li>`;
    }
    flagsEl.innerHTML = flagsHtml;

    // 4. Populate Deep Headers Tab
    const headerTable = document.getElementById('header-table-body');
    // Extracting basic info from the raw auth header the backend sends
    let authOutput = data.metadata.raw_auth_header || "No Authentication-Results header found.";
    let statusColor = authScore > 0 ? "var(--risk-high)" : "var(--risk-low)";
    
    headerTable.innerHTML = `
        <tr>
            <td style="font-weight: 600;">Auth-Results</td>
            <td class="code-text" style="font-size: 12px;">${authOutput}</td>
            <td style="color: ${statusColor}; font-weight:bold;">${data.metadata.auth_status}</td>
        </tr>
    `;

    // 5. Populate Payload Registry Tab
    const payloadTable = document.getElementById('payload-table-body');
    if (data.links_found.length === 0) {
        payloadTable.innerHTML = `<tr><td colspan="2" style="color:var(--text-muted)">No payloads detected in this email.</td></tr>`;
    } else {
        payloadTable.innerHTML = data.links_found.map((url, index) => {
            // Apply VT result to the first URL (as our backend currently checks the first one)
            let vtStatus = (index === 0) ? data.threat_intel.details : "Not scanned in quick-triage mode.";
            let vtColor = (index === 0 && payloadScore === 100) ? "var(--risk-high)" : "var(--text-muted)";
            if (index === 0 && payloadScore === 0) vtColor = "var(--risk-low)";

            return `
                <tr>
                    <td class="code-text">${url}</td>
                    <td style="color: ${vtColor}">${vtStatus}</td>
                </tr>
            `;
        }).join('');
    }
}

function updateGauge(elementId, score) {
    const el = document.getElementById(elementId);
    el.innerText = `${score}%`;
    if (score >= 70) el.style.color = "var(--risk-high)";
    else if (score >= 40) el.style.color = "var(--risk-med)";
    else el.style.color = "var(--risk-low)";
}