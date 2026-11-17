// app.js - SSLGuard Pro Modern Frontend Logic

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const scanBtn = document.getElementById("scanBtn");
    const domainInput = document.getElementById("domain");
    const clearBtn = document.getElementById("clearBtn");
    const loadingSection = document.getElementById("loading");
    const errorCard = document.getElementById("errorCard");
    const errorMessage = document.getElementById("errorMessage");
    const errorTitle = document.getElementById("errorTitle");
    const retryBtn = document.getElementById("retryBtn");
    const dashboard = document.getElementById("dashboard");
    const recentTray = document.getElementById("recentTray");
    const recentTags = document.getElementById("recentTags");
    const clearHistoryBtn = document.getElementById("clearHistoryBtn");
    const toastContainer = document.getElementById("toastContainer");

    // Stepper elements
    const steps = [
        document.getElementById("step1"),
        document.getElementById("step2"),
        document.getElementById("step3"),
        document.getElementById("step4")
    ];
    const loadingStatusText = document.getElementById("loadingStatusText");

    // Executive Banner Elements
    const overallStatusBadge = document.getElementById("overallStatusBadge");
    const overallStatusText = document.getElementById("overallStatusText");
    const scanTimestamp = document.getElementById("scanTimestamp");
    const statusTargetTitle = document.getElementById("statusTargetTitle");
    const statusDescriptionText = document.getElementById("statusDescriptionText");
    const gradeCircle = document.getElementById("gradeCircle");
    const gradeLetter = document.getElementById("gradeLetter");
    const gradeScore = document.getElementById("gradeScore");
    const gradeSubtext = document.getElementById("gradeSubtext");

    // Metric Cards Elements
    const metricDaysRemaining = document.getElementById("metricDaysRemaining");
    const metricExpiryDate = document.getElementById("metricExpiryDate");
    const expiryProgressBar = document.getElementById("expiryProgressBar");
    const validityTag = document.getElementById("validityTag");

    const metricProtocol = document.getElementById("metricProtocol");
    const metricCipher = document.getElementById("metricCipher");
    const metricAlpn = document.getElementById("metricAlpn");
    const tlsTag = document.getElementById("tlsTag");

    const metricKeyType = document.getElementById("metricKeyType");
    const metricSigAlg = document.getElementById("metricSigAlg");
    const metricKeyUsage = document.getElementById("metricKeyUsage");
    const keyTag = document.getElementById("keyTag");

    const metricIssuer = document.getElementById("metricIssuer");
    const metricResolvedIp = document.getElementById("metricResolvedIp");
    const metricSanCount = document.getElementById("metricSanCount");
    const trustTag = document.getElementById("trustTag");

    // Tab Elements
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    // Audit Tab Elements
    const checklistContainer = document.getElementById("checklistContainer");
    const recommendationsContainer = document.getElementById("recommendationsContainer");

    // Details Tab Elements
    const detailCommonName = document.getElementById("detailCommonName");
    const detailOrganization = document.getElementById("detailOrganization");
    const detailIssuerO = document.getElementById("detailIssuerO");
    const detailIssuerCN = document.getElementById("detailIssuerCN");
    const detailValidFrom = document.getElementById("detailValidFrom");
    const detailValidFromUTC = document.getElementById("detailValidFromUTC");
    const detailValidTo = document.getElementById("detailValidTo");
    const detailValidToUTC = document.getElementById("detailValidToUTC");
    const detailSerialNumber = document.getElementById("detailSerialNumber");
    const detailSha256 = document.getElementById("detailSha256");
    const detailPublicKey = document.getElementById("detailPublicKey");
    const detailSignatureAlgorithm = document.getElementById("detailSignatureAlgorithm");
    const detailKeyUsage = document.getElementById("detailKeyUsage");
    const detailEphemeralKey = document.getElementById("detailEphemeralKey");

    // Chain Tab Elements
    const chainContainer = document.getElementById("chainContainer");
    const chainCount = document.getElementById("chainCount");

    // SAN Tab Elements
    const sanCloud = document.getElementById("sanCloud");
    const sanBadgeCount = document.getElementById("sanBadgeCount");
    const sanFilter = document.getElementById("sanFilter");
    const detailOcsp = document.getElementById("detailOcsp");
    const detailCaIssuers = document.getElementById("detailCaIssuers");

    // Raw PEM Elements
    const pemDisplay = document.getElementById("pemDisplay");
    const copyPemBtn = document.getElementById("copyPemBtn");
    const downloadCrtBtn = document.getElementById("downloadCrtBtn");

    // Action Buttons
    const copyDetailsBtn = document.getElementById("copyDetailsBtn");
    const jsonBtn = document.getElementById("jsonBtn");
    const pdfBtn = document.getElementById("pdfBtn");
    const shareBtn = document.getElementById("shareBtn");

    // State
    let currentResult = null;
    let stepTimer = null;
    let currentSans = [];

    // History Storage Key
    const HISTORY_KEY = "sslguard_recent_scans";

    // Initialize
    loadRecentSearches();

    // Event Listeners
    scanBtn.addEventListener("click", () => handleScan());
    domainInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") handleScan();
    });

    domainInput.addEventListener("input", () => {
        if (domainInput.value.trim().length > 0) {
            clearBtn.classList.remove("hidden");
        } else {
            clearBtn.classList.add("hidden");
        }
    });

    clearBtn.addEventListener("click", () => {
        domainInput.value = "";
        clearBtn.classList.add("hidden");
        domainInput.focus();
    });

    retryBtn.addEventListener("click", () => handleScan());

    // Sample Chips Click
    document.querySelectorAll(".chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const domain = chip.getAttribute("data-domain");
            if (domain) {
                domainInput.value = domain;
                clearBtn.classList.remove("hidden");
                handleScan(domain);
            }
        });
    });

    // Clear History Click
    clearHistoryBtn.addEventListener("click", () => {
        localStorage.removeItem(HISTORY_KEY);
        loadRecentSearches();
        showToast("Search history cleared", "info");
    });

    // Tab Switching
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            tabButtons.forEach(b => b.classList.remove("active"));
            tabPanes.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            const targetPane = document.getElementById(targetId);
            if (targetPane) targetPane.classList.add("active");
        });
    });

    // SAN Filter
    sanFilter.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        filterSans(query);
    });

    // Raw PEM Actions
    copyPemBtn.addEventListener("click", () => {
        if (!currentResult || !currentResult.certificate?.rawPEM) return;
        navigator.clipboard.writeText(currentResult.certificate.rawPEM);
        showToast("PEM Certificate copied to clipboard", "success");
    });

    downloadCrtBtn.addEventListener("click", () => {
        if (!currentResult || !currentResult.certificate?.rawPEM) return;
        downloadBlob(currentResult.certificate.rawPEM, `${currentResult.target.host}.crt`, "application/x-x509-ca-cert");
        showToast("Certificate (.crt) downloaded", "success");
    });

    // Global Actions
    copyDetailsBtn.addEventListener("click", () => {
        if (!currentResult) return;
        navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2));
        showToast("Full scan JSON copied to clipboard", "success");
    });

    jsonBtn.addEventListener("click", () => {
        if (!currentResult) return;
        downloadBlob(JSON.stringify(currentResult, null, 2), `ssl-report-${currentResult.target.host}.json`, "application/json");
        showToast("JSON report downloaded", "success");
    });

    pdfBtn.addEventListener("click", () => {
        generatePdfReport();
    });

    shareBtn.addEventListener("click", () => {
        if (!currentResult) return;
        const url = `${window.location.origin}${window.location.pathname}?domain=${encodeURIComponent(currentResult.target.host)}`;
        navigator.clipboard.writeText(url);
        showToast("Shareable link copied to clipboard", "success");
    });

    // Auto-scan from URL Query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const domainParam = urlParams.get("domain");
    if (domainParam) {
        domainInput.value = domainParam;
        clearBtn.classList.remove("hidden");
        handleScan(domainParam);
    }

    function getApiUrl() {
        // If opened as a local file (file:///...) or empty hostname, target localhost:5000
        if (window.location.protocol === "file:" || !window.location.hostname) {
            return "http://localhost:5000/api/scan";
        }
        // If served directly by the backend server
        if (window.location.port === "5000") {
            return "/api/scan";
        }
        // If served via VS Code Live Server or another port (e.g. 5500, 3000)
        if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
            return "http://localhost:5000/api/scan";
        }
        return "/api/scan";
    }

    // Main Scan Function
    async function handleScan(manualDomain) {
        const domain = (manualDomain || domainInput.value).trim();

        if (!domain) {
            showToast("Please enter a domain or hostname", "error");
            domainInput.focus();
            return;
        }

        // Save to Recent Searches
        saveRecentSearch(domain);

        // UI Reset
        errorCard.classList.add("hidden");
        dashboard.classList.add("hidden");
        loadingSection.classList.remove("hidden");
        setScanButtonLoading(true);

        // Animate radar steps
        startStepAnimation();

        try {
            const apiUrl = getApiUrl();

            const response = await fetch(apiUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ domain })
            });

            const data = await response.json();
            stopStepAnimation();
            setScanButtonLoading(false);
            loadingSection.classList.add("hidden");

            if (!response.ok) {
                showError(data.error || "Unable to inspect certificate for this host.", "Scan Failed");
                return;
            }

            currentResult = data;
            renderDashboard(data);
            showToast(`Scan completed for ${data.target.host}`, "success");

            // Smooth scroll to results
            dashboard.scrollIntoView({ behavior: "smooth", block: "start" });

        } catch (err) {
            stopStepAnimation();
            setScanButtonLoading(false);
            loadingSection.classList.add("hidden");
            const targetUrl = getApiUrl();
            showError(
                `Could not reach backend service at ${targetUrl}. Please ensure the Node.js server is running by executing "npm start" or "node server.js" in your terminal.`,
                "Backend Server Offline"
            );
            console.error("Scan error:", err);
        }
    }

    // Step animation in loading state
    function startStepAnimation() {
        let currentStep = 0;
        steps.forEach((s, idx) => {
            s.className = idx === 0 ? "step step-active" : "step";
        });
        loadingStatusText.textContent = "Resolving host & DNS records...";

        const statusMessages = [
            "Resolving host & DNS records...",
            "Negotiating TLS 1.3/1.2 handshake...",
            "Validating Certificate Chain & Trust Store...",
            "Analyzing Cryptographic Parameters & Expiration..."
        ];

        clearInterval(stepTimer);
        stepTimer = setInterval(() => {
            if (currentStep < steps.length - 1) {
                currentStep++;
                steps.forEach((s, idx) => {
                    s.className = idx <= currentStep ? "step step-active" : "step";
                });
                loadingStatusText.textContent = statusMessages[currentStep];
            }
        }, 650);
    }

    function stopStepAnimation() {
        clearInterval(stepTimer);
    }

    function setScanButtonLoading(isLoading) {
        const text = scanBtn.querySelector(".btn-text");
        const loader = scanBtn.querySelector(".btn-loader");
        if (isLoading) {
            text.classList.add("hidden");
            loader.classList.remove("hidden");
            scanBtn.disabled = true;
        } else {
            text.classList.remove("hidden");
            loader.classList.add("hidden");
            scanBtn.disabled = false;
        }
    }

    function showError(msg, title = "Scan Failed") {
        errorTitle.textContent = title;
        errorMessage.textContent = msg;
        errorCard.classList.remove("hidden");
        errorCard.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    // Render Dashboard
    function renderDashboard(data) {
        dashboard.classList.remove("hidden");

        const target = data.target;
        const status = data.status;
        const cert = data.certificate;
        const audit = data.audit;
        const tls = data.tls;
        const chain = data.chain || [];

        // 1. Executive Banner
        statusTargetTitle.textContent = target.port === 443 ? target.host : `${target.host}:${target.port}`;
        statusDescriptionText.textContent = status.description;
        scanTimestamp.textContent = `Scanned ${new Date(data.scannedAt).toLocaleTimeString()}`;

        // Status pill
        overallStatusBadge.className = "status-pill";
        if (status.code === "VALID") {
            overallStatusBadge.classList.add("status-valid");
            overallStatusBadge.innerHTML = `<i class="fa-solid fa-circle-check"></i> <span>VALID & TRUSTED</span>`;
        } else if (status.code === "EXPIRING_SOON" || status.code === "EXPIRING_CRITICAL") {
            overallStatusBadge.classList.add("status-warning");
            overallStatusBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <span>EXPIRING SOON</span>`;
        } else {
            overallStatusBadge.classList.add("status-invalid");
            const label = status.code.replace(/_/g, " ");
            overallStatusBadge.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> <span>${label}</span>`;
        }

        // Grade Badge
        gradeLetter.textContent = audit.grade;
        gradeScore.textContent = `${audit.score}%`;
        gradeCircle.className = "grade-circle";
        if (audit.grade.startsWith("A")) {
            gradeCircle.classList.add("grade-a");
            gradeSubtext.textContent = audit.grade === "A+" ? "Industry Leading" : "High Security";
        } else if (audit.grade.startsWith("B")) {
            gradeCircle.classList.add("grade-b");
            gradeSubtext.textContent = "Adequate Standard";
        } else if (audit.grade.startsWith("C")) {
            gradeCircle.classList.add("grade-c");
            gradeSubtext.textContent = "Needs Attention";
        } else {
            gradeCircle.classList.add("grade-f");
            gradeSubtext.textContent = "High Risk / Invalid";
        }

        // 2. Metrics Cards
        // Card 1: Expiry
        if (status.expired) {
            metricDaysRemaining.textContent = "Expired";
            metricDaysRemaining.style.color = "var(--danger)";
            validityTag.className = "metric-tag fail";
            validityTag.textContent = "Expired";
            expiryProgressBar.style.width = "100%";
            expiryProgressBar.style.background = "var(--danger)";
        } else if (status.notYetValid) {
            metricDaysRemaining.textContent = "Not Active";
            validityTag.className = "metric-tag warn";
            validityTag.textContent = "Future Date";
            expiryProgressBar.style.width = "0%";
        } else {
            metricDaysRemaining.textContent = `${status.daysRemaining} Days`;
            metricDaysRemaining.style.color = status.daysRemaining <= 14 ? "var(--danger)" : (status.daysRemaining <= 30 ? "var(--warning)" : "var(--success)");
            validityTag.className = `metric-tag ${status.daysRemaining <= 14 ? 'fail' : (status.daysRemaining <= 30 ? 'warn' : 'pass')}`;
            validityTag.textContent = status.daysRemaining <= 30 ? "Expiring Soon" : "Active";
            expiryProgressBar.style.width = `${status.expiryPercentage || 50}%`;
            expiryProgressBar.style.background = status.daysRemaining <= 30 ? "var(--warning)" : "linear-gradient(90deg, var(--primary), var(--success))";
        }
        metricExpiryDate.textContent = `Valid Until: ${new Date(cert.validTo).toLocaleDateString()}`;

        // Card 2: TLS Protocol
        metricProtocol.textContent = tls.version;
        metricCipher.textContent = tls.cipherStandardName || tls.cipherName;
        metricCipher.title = tls.cipherName;
        metricAlpn.textContent = `ALPN: ${target.alpnProtocol || "None negotiated"}`;
        tlsTag.className = `metric-tag ${tls.version === "TLSv1.3" ? "info" : (tls.version === "TLSv1.2" ? "pass" : "fail")}`;
        tlsTag.textContent = tls.version;

        // Card 3: Cryptographic Key
        metricKeyType.textContent = `${cert.publicKeyAlgorithm} ${cert.keySize}`;
        metricSigAlg.textContent = cert.signatureAlgorithm;
        metricSigAlg.title = cert.signatureAlgorithm;
        metricKeyUsage.textContent = Array.isArray(cert.keyUsage) ? cert.keyUsage.slice(0, 2).join(", ") : cert.keyUsage;
        keyTag.className = "metric-tag pass";
        keyTag.textContent = cert.keySize;

        // Card 4: Trust Authority
        metricIssuer.textContent = cert.issuerO && cert.issuerO !== "-" ? cert.issuerO : cert.issuerCN;
        metricIssuer.title = cert.issuerCN;
        if (target.resolvedIps && target.resolvedIps.length > 0) {
            metricResolvedIp.textContent = `Server IP: ${target.resolvedIps[0].address} (${target.resolvedIps[0].family})`;
        } else {
            metricResolvedIp.textContent = "IP: Connected";
        }
        currentSans = cert.subjectAltNames || [];
        metricSanCount.textContent = `${currentSans.length} Subject Alternative Names`;
        trustTag.className = `metric-tag ${status.isAuthorized ? "pass" : "fail"}`;
        trustTag.textContent = status.isAuthorized ? "Trusted CA" : (status.isSelfSigned ? "Self-Signed" : "Untrusted");

        // 3. Tab 1: Security Audit
        renderAuditTab(audit);

        // 4. Tab 2: Certificate Details
        renderDetailsTab(cert, tls);

        // 5. Tab 3: Certificate Trust Chain
        renderChainTab(chain);

        // 6. Tab 4: SANs & AIA
        renderSansTab(cert);

        // 7. Tab 5: Raw PEM
        pemDisplay.textContent = cert.rawPEM || "No PEM certificate available.";
    }

    // Render Security Audit Checklist & Recommendations
    function renderAuditTab(audit) {
        checklistContainer.innerHTML = "";
        (audit.checklist || []).forEach(item => {
            const div = document.createElement("div");
            div.className = "check-item";

            let iconHtml = '<i class="fa-solid fa-circle-check check-icon pass"></i>';
            if (item.status === "warning") {
                iconHtml = '<i class="fa-solid fa-triangle-exclamation check-icon warning"></i>';
            } else if (item.status === "fail") {
                iconHtml = '<i class="fa-solid fa-circle-xmark check-icon fail"></i>';
            }

            div.innerHTML = `
                ${iconHtml}
                <div class="check-text">
                    <h6>${escapeHtml(item.title)}</h6>
                    <p>${escapeHtml(item.message)}</p>
                </div>
            `;
            checklistContainer.appendChild(div);
        });

        recommendationsContainer.innerHTML = "";
        const recs = audit.recommendations || [];
        if (recs.length === 0) {
            recommendationsContainer.innerHTML = `
                <div class="rec-item" style="border-left-color: var(--success);">
                    <i class="fa-solid fa-circle-check" style="color: var(--success);"></i>
                    <span>All automated security checks passed. Certificate, cipher suite, and trust chain meet current industry best practices.</span>
                </div>
            `;
        } else {
            recs.forEach(rec => {
                const div = document.createElement("div");
                div.className = "rec-item";
                div.innerHTML = `
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <span>${escapeHtml(rec)}</span>
                `;
                recommendationsContainer.appendChild(div);
            });
        }
    }

    // Render Certificate Details Tab
    function renderDetailsTab(cert, tls) {
        detailCommonName.textContent = cert.commonName || "-";
        detailOrganization.textContent = cert.organization && cert.organization !== "-" ? `${cert.organization} (${cert.country || "-"})` : (cert.country || "-");
        detailIssuerO.textContent = cert.issuerO || "-";
        detailIssuerCN.textContent = cert.issuerCN || "-";

        detailValidFrom.textContent = new Date(cert.validFrom).toLocaleString();
        detailValidFromUTC.textContent = `UTC: ${cert.validFromUTC}`;

        detailValidTo.textContent = new Date(cert.validTo).toLocaleString();
        detailValidToUTC.textContent = `UTC: ${cert.validToUTC}`;

        detailSerialNumber.textContent = cert.serialNumber || "-";
        detailSha256.textContent = cert.sha256Fingerprint || "-";

        detailPublicKey.textContent = `${cert.publicKeyAlgorithm} (${cert.keySize})`;
        detailSignatureAlgorithm.textContent = cert.signatureAlgorithm || "-";

        detailKeyUsage.textContent = Array.isArray(cert.keyUsage) ? cert.keyUsage.join(", ") : (cert.keyUsage || "-");
        detailEphemeralKey.textContent = tls.ephemeralKey || "Standard / None";
    }

    // Render Trust Chain Tab
    function renderChainTab(chain) {
        chainContainer.innerHTML = "";
        chainCount.textContent = chain.length;

        if (chain.length === 0) {
            chainContainer.innerHTML = '<p class="chain-intro">Trust chain hierarchy details unavailable.</p>';
            return;
        }

        chain.forEach((node, index) => {
            const isRoot = index === chain.length - 1 && (node.isSelfSigned || node.role.includes("Root"));
            const nodeDiv = document.createElement("div");
            nodeDiv.className = `chain-node ${isRoot ? "root" : ""}`;

            let iconClass = "fa-certificate";
            if (node.level === 0) iconClass = "fa-server";
            else if (isRoot) iconClass = "fa-building-shield";

            nodeDiv.innerHTML = `
                <div class="chain-node-badge">
                    <i class="fa-solid ${iconClass}"></i>
                </div>
                <div class="chain-node-info">
                    <span class="chain-role-tag">${escapeHtml(node.role)}</span>
                    <h5 class="chain-cn">${escapeHtml(node.commonName)}</h5>
                    <div class="chain-details">
                        <span><strong>Org:</strong> ${escapeHtml(node.organization || node.issuerO || "-")}</span> &bull; 
                        <span><strong>Valid To:</strong> ${new Date(node.validTo).toLocaleDateString()}</span> &bull; 
                        <span><strong>Serial:</strong> <span class="font-mono">${escapeHtml(node.serialNumber.slice(0, 16))}...</span></span>
                    </div>
                </div>
            `;
            chainContainer.appendChild(nodeDiv);
        });
    }

    // Render SANs Tab
    function renderSansTab(cert) {
        sanBadgeCount.textContent = currentSans.length;
        detailOcsp.textContent = cert.ocspUri || "None specified";
        detailCaIssuers.textContent = cert.caIssuersUri || "None specified";

        filterSans("");
    }

    function filterSans(query) {
        sanCloud.innerHTML = "";
        const filtered = currentSans.filter(san => san.toLowerCase().includes(query));

        if (filtered.length === 0) {
            sanCloud.innerHTML = '<span style="color: var(--text-muted); font-size: 13px;">No matching Subject Alternative Names found.</span>';
            return;
        }

        filtered.forEach(san => {
            const badge = document.createElement("span");
            badge.className = "san-badge selectable";
            badge.textContent = san;
            sanCloud.appendChild(badge);
        });
    }

    // PDF Report Generator using jsPDF
    function generatePdfReport() {
        if (!currentResult) {
            showToast("No scan data to export", "error");
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            const res = currentResult;

            // Brand Header Banner
            doc.setFillColor(7, 10, 20);
            doc.rect(0, 0, 210, 38, "F");

            doc.setTextColor(0, 240, 255);
            doc.setFontSize(20);
            doc.setFont("helvetica", "bold");
            doc.text("SSLGuard Pro", 14, 18);

            doc.setFontSize(10);
            doc.setTextColor(148, 163, 184);
            doc.setFont("helvetica", "normal");
            doc.text("SSL/TLS Certificate Validity & Security Audit Report", 14, 26);

            doc.setFontSize(9);
            doc.text(`Generated: ${new Date().toUTCString()}`, 14, 32);

            // Target & Status Block
            doc.setTextColor(15, 23, 42);
            doc.setFontSize(14);
            doc.setFont("helvetica", "bold");
            doc.text(`Target Host: ${res.target.host}:${res.target.port}`, 14, 48);

            doc.setFontSize(11);
            doc.setFont("helvetica", "normal");
            doc.text(`Overall Status: ${res.status.code}`, 14, 56);
            doc.text(`Security Grade: ${res.audit.grade} (${res.audit.score}%)`, 14, 63);
            doc.text(`Days Remaining: ${res.status.daysRemaining} days`, 14, 70);
            doc.text(`TLS Protocol: ${res.tls.version}`, 14, 77);
            doc.text(`Cipher Suite: ${res.tls.cipherStandardName || res.tls.cipherName}`, 14, 84);

            // Divider Line
            doc.setDrawColor(203, 213, 225);
            doc.line(14, 90, 196, 90);

            // Certificate Details Table
            doc.setFontSize(12);
            doc.setFont("helvetica", "bold");
            doc.text("Certificate Specification", 14, 98);

            const details = [
                ["Common Name (CN)", res.certificate.commonName],
                ["Subject Organization", res.certificate.organization],
                ["Issuer (CA)", res.certificate.issuerCN],
                ["Issuer Organization", res.certificate.issuerO],
                ["Valid From", res.certificate.validFrom],
                ["Valid To", res.certificate.validTo],
                ["Public Key", `${res.certificate.publicKeyAlgorithm} (${res.certificate.keySize})`],
                ["Signature Algorithm", res.certificate.signatureAlgorithm],
                ["Serial Number", res.certificate.serialNumber],
                ["SHA-256 Fingerprint", res.certificate.sha256Fingerprint]
            ];

            doc.setFontSize(9);
            let y = 106;
            details.forEach(([key, val]) => {
                doc.setFont("helvetica", "bold");
                doc.text(`${key}:`, 14, y);
                doc.setFont("helvetica", "normal");
                const cleanVal = (val || "-").toString();
                doc.text(cleanVal.length > 70 ? cleanVal.slice(0, 68) + "..." : cleanVal, 60, y);
                y += 7;
            });

            // Divider Line
            doc.line(14, y + 2, 196, y + 2);
            y += 10;

            // Security Checklist
            doc.setFontSize(12);
            doc.setFont("helvetica", "bold");
            doc.text("Automated Security Checklist", 14, y);
            y += 8;

            doc.setFontSize(9);
            (res.audit.checklist || []).slice(0, 6).forEach(chk => {
                const mark = chk.status === "pass" ? "[PASS]" : (chk.status === "warning" ? "[WARN]" : "[FAIL]");
                doc.setFont("helvetica", "bold");
                doc.text(`${mark} ${chk.title}:`, 14, y);
                doc.setFont("helvetica", "normal");
                doc.text(chk.message, 60, y);
                y += 6.5;
            });

            // Footer
            doc.setFontSize(8);
            doc.setTextColor(148, 163, 184);
            doc.text("Generated by SSLGuard Pro - Next-Generation SSL/TLS Certificate Scanner", 14, 285);

            doc.save(`ssl-report-${res.target.host}.pdf`);
            showToast("PDF report downloaded successfully", "success");

        } catch (err) {
            console.error("PDF generation failed:", err);
            showToast("Failed to generate PDF", "error");
        }
    }

    // Helper: Download Blob
    function downloadBlob(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Recent Searches Helper
    function saveRecentSearch(domain) {
        try {
            let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
            history = history.filter(d => d.toLowerCase() !== domain.toLowerCase());
            history.unshift(domain);
            if (history.length > 6) history = history.slice(0, 6);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
            loadRecentSearches();
        } catch {
            // Storage might be restricted
        }
    }

    function loadRecentSearches() {
        try {
            const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
            if (history.length === 0) {
                recentTray.classList.add("hidden");
                return;
            }

            recentTray.classList.remove("hidden");
            recentTags.innerHTML = "";
            history.forEach(domain => {
                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "recent-tag";
                btn.textContent = domain;
                btn.addEventListener("click", () => {
                    domainInput.value = domain;
                    clearBtn.classList.remove("hidden");
                    handleScan(domain);
                });
                recentTags.appendChild(btn);
            });
        } catch {
            recentTray.classList.add("hidden");
        }
    }

    // Toast Notification System
    function showToast(message, type = "info") {
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;

        let icon = "fa-circle-info";
        if (type === "success") icon = "fa-circle-check";
        else if (type === "error") icon = "fa-circle-exclamation";

        toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateX(40px)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
