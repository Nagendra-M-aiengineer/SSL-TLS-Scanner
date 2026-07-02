// app.js

const scanBtn = document.getElementById("scanBtn");
const domainInput = document.getElementById("domain");

const loading = document.getElementById("loading");
const dashboard = document.getElementById("dashboard");

const status = document.getElementById("status");
const score = document.getElementById("score");
const daysRemaining = document.getElementById("daysRemaining");
const tlsVersion = document.getElementById("tlsVersion");

const commonName = document.getElementById("commonName");
const organization = document.getElementById("organization");
const issuer = document.getElementById("issuer");
const validFrom = document.getElementById("validFrom");
const validTo = document.getElementById("validTo");
const serialNumber = document.getElementById("serialNumber");
const fingerprint = document.getElementById("fingerprint");
const signatureAlgorithm = document.getElementById("signatureAlgorithm");
const publicKeyAlgorithm = document.getElementById("publicKeyAlgorithm");
const subject = document.getElementById("subject");
const issuerDetails = document.getElementById("issuerDetails");
const certificateState = document.getElementById("certificateState");

let lastResult = null;

scanBtn.addEventListener("click", scanCertificate);

document.getElementById("pdfBtn").addEventListener("click", downloadPdf);

domainInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
        scanCertificate();
    }
});

async function scanCertificate() {

    const domain = domainInput.value.trim();

    if (!domain) {
        alert("Enter a domain name");
        return;
    }

    lastResult = null;
    resetDashboard();

    loading.classList.remove("hidden");
    dashboard.classList.add("hidden");

    try {

        const response = await fetch("http://localhost:5000/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                domain: domain
            })
        });

        const data = await response.json();

        loading.classList.add("hidden");

        if (!response.ok) {
            alert(data.error || "Scan Failed");
            return;
        }

        lastResult = data;

        fillDashboard(data);

    } catch (err) {

        loading.classList.add("hidden");
        resetDashboard();

        alert("Unable to connect to backend server.");

        console.error(err);

    }

}

function resetDashboard() {

    commonName.textContent = "-";
    organization.textContent = "-";
    issuer.textContent = "-";
    validFrom.textContent = "-";
    validTo.textContent = "-";
    serialNumber.textContent = "-";
    fingerprint.textContent = "-";
    signatureAlgorithm.textContent = "-";
    publicKeyAlgorithm.textContent = "-";
    tlsVersion.textContent = "-";
    subject.textContent = "-";
    issuerDetails.textContent = "-";
    daysRemaining.textContent = "-";
    status.textContent = "Not Scanned";
    certificateState.textContent = "Not Scanned";
    score.textContent = "0%";
    dashboard.classList.add("hidden");

}

function fillDashboard(data) {

    dashboard.classList.remove("hidden");

    commonName.textContent = data.commonName || "-";
    organization.textContent = data.organization || "-";
    issuer.textContent = data.issuer || "-";

    validFrom.textContent = data.validFrom || "-";
    validTo.textContent = data.validTo || "-";

    serialNumber.textContent = data.serialNumber || "-";

    fingerprint.textContent = data.sha256Fingerprint || "-";

    signatureAlgorithm.textContent =
        data.signatureAlgorithm || "-";

    publicKeyAlgorithm.textContent =
        data.publicKeyAlgorithm || "-";

    tlsVersion.textContent =
        data.tlsVersion || "-";

    subject.textContent =
        data.subject || "-";

    issuerDetails.textContent =
        data.issuerDetails || "-";

    daysRemaining.textContent =
        data.daysRemaining ?? "-";

    if (data.expired) {

        status.textContent = "Expired";
        certificateState.textContent = "Expired";

    } else {

        status.textContent = "Valid";
        certificateState.textContent = "Valid";

    }

    score.textContent =
        calculateScore(data) + "%";

}

function calculateScore(data) {

    let total = 100;

    if (data.expired)
        total = 20;

    if (data.daysRemaining < 30)
        total -= 25;

    if (data.daysRemaining < 90)
        total -= 10;

    if (data.tlsVersion &&
        data.tlsVersion.includes("1.2"))
        total -= 5;

    if (data.tlsVersion &&
        data.tlsVersion.includes("1.1"))
        total -= 20;

    if (total < 0)
        total = 0;

    return total;

}

document.getElementById("copyBtn").addEventListener("click", () => {

    if (!lastResult) return;

    navigator.clipboard.writeText(
        JSON.stringify(lastResult, null, 2)
    );

    alert("Certificate details copied.");

});

const jsonBtn = document.getElementById("jsonBtn");

if (jsonBtn) {

    jsonBtn.addEventListener("click", () => {

        if (!lastResult) return;

        const blob = new Blob(
            [JSON.stringify(lastResult, null, 2)],
            {
                type: "application/json"
            }
        );

        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");

        a.href = url;
        a.download = "ssl-report.json";

        a.click();

        URL.revokeObjectURL(url);

    });

}

function downloadPdf() {

    if (!lastResult) return;

    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF();
    const lines = [
        "SSL/TLS Certificate Report",
        "",
        `Domain: ${domainInput.value.trim() || "Unknown"}`,
        `Status: ${status.textContent}`,
        `Security Score: ${score.textContent}`,
        `Days Remaining: ${daysRemaining.textContent}`,
        `TLS Version: ${tlsVersion.textContent}`,
        `Common Name: ${commonName.textContent}`,
        `Organization: ${organization.textContent}`,
        `Issuer: ${issuer.textContent}`,
        `Valid From: ${validFrom.textContent}`,
        `Valid Until: ${validTo.textContent}`,
        `Serial Number: ${serialNumber.textContent}`,
        `Fingerprint SHA256: ${fingerprint.textContent}`,
        `Signature Algorithm: ${signatureAlgorithm.textContent}`,
        `Public Key Algorithm: ${publicKeyAlgorithm.textContent}`,
        `Subject: ${subject.textContent}`,
        `Issuer Details: ${issuerDetails.textContent}`,
        `Certificate State: ${certificateState.textContent}`
    ];

    pdf.setFontSize(18);
    pdf.text(lines[0], 14, 20);

    pdf.setFontSize(11);

    lines.slice(1).forEach((line, index) => {
        const y = 32 + index * 8;
        pdf.text(line, 14, y > 280 ? 280 : y);
    });

    pdf.save("ssl-report.pdf");

}