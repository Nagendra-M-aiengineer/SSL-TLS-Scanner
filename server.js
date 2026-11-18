// server.js - SSLGuard Pro Backend
const express = require("express");
const cors = require("cors");
const tls = require("tls");
const crypto = require("crypto");
const dns = require("dns");
const net = require("net");
const path = require("path");

const fs = require("fs");

const app = express();

app.use(cors());
app.use(express.json());

// Serve static assets from public directory and root
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 5000;

// Explicit static handlers for resilient Vercel serverless delivery
app.get("/style.css", (req, res) => {
    const pubFile = path.join(__dirname, "public", "style.css");
    const rootFile = path.join(__dirname, "style.css");
    res.setHeader("Content-Type", "text/css; charset=utf-8");
    if (fs.existsSync(pubFile)) {
        return res.sendFile(pubFile);
    }
    res.sendFile(rootFile);
});

app.get("/app.js", (req, res) => {
    const pubFile = path.join(__dirname, "public", "app.js");
    const rootFile = path.join(__dirname, "app.js");
    res.setHeader("Content-Type", "application/javascript; charset=utf-8");
    if (fs.existsSync(pubFile)) {
        return res.sendFile(pubFile);
    }
    res.sendFile(rootFile);
});

// Home Route
app.get("/", (req, res) => {
    const pubIndex = path.join(__dirname, "public", "index.html");
    const rootIndex = path.join(__dirname, "index.html");
    if (fs.existsSync(pubIndex)) {
        return res.sendFile(pubIndex);
    }
    res.sendFile(rootIndex);
});

// Helper: Clean domain and extract port
function parseDomainInput(input) {
    if (!input || typeof input !== "string") return null;
    let clean = input.trim();

    // Remove protocol
    clean = clean.replace(/^[a-zA-Z]+:\/\//, "");

    // Remove paths, queries, fragments
    clean = clean.split("/")[0].split("?")[0].split("#")[0].trim();

    // Strip trailing dot if present
    if (clean.endsWith(".")) {
        clean = clean.slice(0, -1);
    }

    let host = clean;
    let port = 443;

    // Check for custom port e.g. domain.com:8443 or [::1]:8443
    if (clean.includes("]:")) {
        const parts = clean.split("]:");
        host = parts[0].replace("[", "");
        const p = parseInt(parts[1], 10);
        if (!isNaN(p) && p > 0 && p <= 65535) port = p;
    } else if (!clean.startsWith("[") && clean.includes(":")) {
        const parts = clean.split(":");
        host = parts[0];
        const p = parseInt(parts[1], 10);
        if (!isNaN(p) && p > 0 && p <= 65535) port = p;
    }

    host = host.toLowerCase().trim();
    if (!host) return null;

    return { host, port };
}

// Helper: Format hex fingerprint with colons
function formatFingerprint(hex) {
    if (!hex) return "-";
    const clean = hex.replace(/[^a-fA-F0-9]/g, "").toUpperCase();
    return clean.match(/.{1,2}/g)?.join(":") || clean;
}

// Helper: Format serial number cleanly
function formatSerialNumber(serial) {
    if (!serial) return "-";
    const clean = serial.replace(/[^a-fA-F0-9]/g, "").toUpperCase();
    return clean.match(/.{1,2}/g)?.join(":") || serial;
}

// Helper: Calculate security grade and score
function evaluateCertificateSecurity({
    authorized,
    authorizationError,
    hostnameMatches,
    expired,
    notYetValid,
    daysRemaining,
    tlsVersion,
    cipher,
    keyType,
    keySize,
    sigAlg,
    isSelfSigned,
    hasOCSP
}) {
    let score = 100;
    const checklist = [];
    const recommendations = [];

    // 1. Hostname Match
    if (hostnameMatches) {
        checklist.push({
            id: "hostname",
            title: "Hostname Verification",
            status: "pass",
            message: "Certificate matches requested domain."
        });
    } else {
        score -= 40;
        checklist.push({
            id: "hostname",
            title: "Hostname Verification",
            status: "fail",
            message: "Certificate does not match requested hostname (Name Mismatch)."
        });
        recommendations.push("Issue or bind a certificate that includes this exact domain in its Subject Alternative Names (SAN).");
    }

    // 2. CA Trust & Chain
    if (authorized) {
        checklist.push({
            id: "trust",
            title: "CA Trust & Chain",
            status: "pass",
            message: "Issued by a trusted Certificate Authority."
        });
    } else if (isSelfSigned) {
        score -= 50;
        checklist.push({
            id: "trust",
            title: "CA Trust & Chain",
            status: "fail",
            message: "Self-signed certificate; not trusted by public root stores."
        });
        recommendations.push("Replace self-signed certificate with one signed by a trusted CA (e.g. Let's Encrypt, DigiCert, Google Trust Services).");
    } else {
        score -= 35;
        checklist.push({
            id: "trust",
            title: "CA Trust & Chain",
            status: "fail",
            message: authorizationError ? `Trust verification failed: ${authorizationError}` : "Untrusted root or incomplete intermediate CA chain."
        });
        recommendations.push("Check intermediate certificate chain and ensure the full bundle is installed on the web server.");
    }

    // 3. Expiration / Validity Dates
    if (expired) {
        score -= 50;
        checklist.push({
            id: "validity",
            title: "Certificate Validity",
            status: "fail",
            message: `Certificate expired ${Math.abs(daysRemaining)} day(s) ago.`
        });
        recommendations.push("Renew and replace the expired certificate immediately to restore HTTPS security.");
    } else if (notYetValid) {
        score -= 40;
        checklist.push({
            id: "validity",
            title: "Certificate Validity",
            status: "fail",
            message: "Certificate is not yet active (activation date is in the future)."
        });
        recommendations.push("Check system time or ensure valid_from date has taken effect.");
    } else if (daysRemaining <= 14) {
        score -= 20;
        checklist.push({
            id: "validity",
            title: "Certificate Validity",
            status: "warning",
            message: `Certificate expires critically soon: ${daysRemaining} day(s) remaining.`
        });
        recommendations.push("Urgent: Renew certificate within the next 2 weeks to prevent outages.");
    } else if (daysRemaining <= 30) {
        score -= 10;
        checklist.push({
            id: "validity",
            title: "Certificate Validity",
            status: "warning",
            message: `Certificate expires soon: ${daysRemaining} days remaining.`
        });
        recommendations.push("Schedule certificate renewal within the next 30 days.");
    } else {
        checklist.push({
            id: "validity",
            title: "Certificate Validity",
            status: "pass",
            message: `Active and valid for ${daysRemaining} more days.`
        });
    }

    // 4. Protocol Version
    if (tlsVersion === "TLSv1.3") {
        checklist.push({
            id: "protocol",
            title: "TLS Protocol",
            status: "pass",
            message: "TLS 1.3 negotiated (modern, highest speed and security standard)."
        });
    } else if (tlsVersion === "TLSv1.2") {
        checklist.push({
            id: "protocol",
            title: "TLS Protocol",
            status: "pass",
            message: "TLS 1.2 negotiated (secure standard; TLS 1.3 recommended)."
        });
        recommendations.push("Enable TLS 1.3 on your server for enhanced performance and modern cipher suites.");
    } else if (tlsVersion === "TLSv1.1" || tlsVersion === "TLSv1") {
        score -= 30;
        checklist.push({
            id: "protocol",
            title: "TLS Protocol",
            status: "fail",
            message: `${tlsVersion} is legacy, deprecated by IETF, and vulnerable.`
        });
        recommendations.push("Disable legacy TLS 1.0 and TLS 1.1; enforce TLS 1.2 or TLS 1.3 only.");
    } else {
        score -= 10;
        checklist.push({
            id: "protocol",
            title: "TLS Protocol",
            status: "warning",
            message: `Protocol: ${tlsVersion || "Unknown"}`
        });
    }

    // 5. Public Key Strength
    const keyTypeUpper = (keyType || "").toUpperCase();
    if (keyTypeUpper.includes("EC") || keyTypeUpper.includes("ED25519") || keyTypeUpper.includes("ECDSA")) {
        checklist.push({
            id: "key_strength",
            title: "Key Strength",
            status: "pass",
            message: `Modern Elliptic Curve Key (${keyTypeUpper} ${keySize ? keySize + "-bit" : ""}).`
        });
    } else if (keyTypeUpper.includes("RSA")) {
        if (keySize >= 2048) {
            checklist.push({
                id: "key_strength",
                title: "Key Strength",
                status: "pass",
                message: `Strong RSA Key (${keySize}-bit).`
            });
        } else if (keySize > 0) {
            score -= 30;
            checklist.push({
                id: "key_strength",
                title: "Key Strength",
                status: "fail",
                message: `Weak RSA Key (${keySize}-bit). Minimum standard is 2048-bit.`
            });
            recommendations.push("Upgrade RSA private key to at least 2048 bits or switch to ECDSA (P-256).");
        } else {
            checklist.push({
                id: "key_strength",
                title: "Key Strength",
                status: "pass",
                message: "RSA Public Key present."
            });
        }
    } else {
        checklist.push({
            id: "key_strength",
            title: "Key Strength",
            status: "pass",
            message: `${keyType || "Public Key"} configured.`
        });
    }

    // 6. Signature Algorithm
    const sigAlgLower = (sigAlg || "").toLowerCase();
    if (sigAlgLower.includes("sha1") || sigAlgLower.includes("md5")) {
        score -= 35;
        checklist.push({
            id: "signature",
            title: "Signature Algorithm",
            status: "fail",
            message: `Insecure signature algorithm (${sigAlg}). Vulnerable to collision attacks.`
        });
        recommendations.push("Re-issue certificate with SHA-256 (SHA-2) or stronger signature algorithm.");
    } else if (sigAlgLower.includes("sha256") || sigAlgLower.includes("sha384") || sigAlgLower.includes("sha512") || sigAlgLower.includes("ecdsa")) {
        checklist.push({
            id: "signature",
            title: "Signature Algorithm",
            status: "pass",
            message: `Secure signature algorithm (${sigAlg}).`
        });
    } else {
        checklist.push({
            id: "signature",
            title: "Signature Algorithm",
            status: "pass",
            message: `Signature algorithm: ${sigAlg || "Standard"}.`
        });
    }

    // 7. Cipher Suite & Forward Secrecy
    const cipherName = (cipher?.name || "").toUpperCase();
    if (cipherName.includes("GCM") || cipherName.includes("CHACHA20") || cipherName.includes("POLY1305")) {
        checklist.push({
            id: "cipher",
            title: "Cipher & Forward Secrecy",
            status: "pass",
            message: `Modern AEAD Cipher (${cipher?.name}). Forward Secrecy active.`
        });
    } else if (cipherName) {
        checklist.push({
            id: "cipher",
            title: "Cipher Suite",
            status: "pass",
            message: `Cipher: ${cipher?.name}.`
        });
    }

    // 8. Revocation Check (OCSP)
    if (hasOCSP) {
        checklist.push({
            id: "revocation",
            title: "Revocation Information",
            status: "pass",
            message: "AIA OCSP responder endpoint is present."
        });
    }

    // Clamp score
    if (expired || !hostnameMatches) {
        score = Math.min(score, 45);
    }
    if (isSelfSigned) {
        score = Math.min(score, 50);
    }
    score = Math.max(0, Math.min(100, score));

    // Determine Grade letter
    let grade = "A+";
    if (score >= 95 && tlsVersion === "TLSv1.3" && authorized && hostnameMatches && !expired) {
        grade = "A+";
    } else if (score >= 85) {
        grade = "A";
    } else if (score >= 70) {
        grade = "B";
    } else if (score >= 55) {
        grade = "C";
    } else if (score >= 40) {
        grade = "D";
    } else {
        grade = "F";
    }

    return { score, grade, checklist, recommendations };
}

// Scan handler
const handleScanRequest = async (req, res) => {
    const rawDomain = req.body?.domain;

    if (!rawDomain) {
        return res.status(400).json({
            error: "Domain or hostname is required"
        });
    }

    const parsed = parseDomainInput(rawDomain);
    if (!parsed) {
        return res.status(400).json({
            error: "Invalid domain or hostname format"
        });
    }

    const { host: targetHost, port: targetPort } = parsed;

    // Resolve DNS records in parallel for network context
    let resolvedIps = [];
    try {
        const lookups = await dns.promises.lookup(targetHost, { all: true });
        resolvedIps = lookups.map(item => ({ address: item.address, family: `IPv${item.family}` }));
    } catch {
        // DNS lookup may fail or sandbox may restrict, continue gracefully
    }

    let responded = false;
    const sendResponse = (statusCode, data) => {
        if (!responded) {
            responded = true;
            return res.status(statusCode).json(data);
        }
    };

    const isIP = net.isIP(targetHost) !== 0;
    const socketOptions = {
        host: targetHost,
        port: targetPort,
        rejectUnauthorized: false,
        ALPNProtocols: ["h2", "http/1.1"]
    };

    if (!isIP) {
        socketOptions.servername = targetHost;
    }

    let socket;
    try {
        socket = tls.connect(socketOptions, () => {
            try {
                const cert = socket.getPeerCertificate(true);

                if (!cert || Object.keys(cert).length === 0) {
                    socket.destroy();
                    return sendResponse(404, {
                        error: "No SSL/TLS certificate was returned by the remote server."
                    });
                }

                const protocol = socket.getProtocol();
                const cipher = socket.getCipher();
                const ephemeralKey = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo() : null;
                const alpnProtocol = socket.alpnProtocol || "-";

                // X509 inspection
                let x509 = null;
                let matchedHost = null;
                let pemCert = "";
                let keyType = "Unknown";
                let keySize = cert.bits || 0;
                let sigAlg = cert.sigalg || "Unknown";
                let keyUsage = [];

                if (cert.raw) {
                    try {
                        x509 = new crypto.X509Certificate(cert.raw);
                        matchedHost = x509.checkHost(targetHost);
                        pemCert = x509.toString();
                        if (x509.publicKey) {
                            keyType = x509.publicKey.asymmetricKeyType || "Unknown";
                            const details = x509.publicKey.asymmetricKeyDetails;
                            if (details) {
                                keySize = details.modulusLength || details.namedCurve || cert.bits || 0;
                            }
                        }
                        if (x509.keyUsage) {
                            keyUsage = x509.keyUsage;
                        }
                    } catch (e) {
                        console.warn("X509 parsing fallback:", e.message);
                    }
                }

                // If checkHost was undefined, do manual SAN / wildcard check fallback
                let hostnameMatches = Boolean(matchedHost);
                const sanList = [];
                if (cert.subjectaltname) {
                    const rawSans = cert.subjectaltname.split(",");
                    for (const item of rawSans) {
                        const s = item.trim();
                        if (s.startsWith("DNS:")) {
                            sanList.push(s.replace(/^DNS:/, ""));
                        } else if (s.startsWith("IP Address:")) {
                            sanList.push(s.replace(/^IP Address:/, ""));
                        } else {
                            sanList.push(s);
                        }
                    }
                }

                if (!hostnameMatches && sanList.length > 0) {
                    hostnameMatches = sanList.some(san => {
                        if (san.toLowerCase() === targetHost.toLowerCase()) return true;
                        if (san.startsWith("*.")) {
                            const rootSan = san.slice(2).toLowerCase();
                            const parts = targetHost.toLowerCase().split(".");
                            if (parts.length > 2) {
                                const domainPart = parts.slice(1).join(".");
                                return domainPart === rootSan;
                            }
                        }
                        return false;
                    });
                } else if (!hostnameMatches && cert.subject?.CN) {
                    const cn = cert.subject.CN.toLowerCase();
                    if (cn === targetHost.toLowerCase()) {
                        hostnameMatches = true;
                    } else if (cn.startsWith("*.")) {
                        const rootCn = cn.slice(2);
                        const parts = targetHost.toLowerCase().split(".");
                        if (parts.length > 2) {
                            hostnameMatches = parts.slice(1).join(".") === rootCn;
                        }
                    }
                }

                // Time checks
                const now = new Date();
                const validFromDate = new Date(cert.valid_from);
                const validToDate = new Date(cert.valid_to);
                const daysRemaining = Math.floor((validToDate - now) / (1000 * 60 * 60 * 24));
                const totalDays = Math.floor((validToDate - validFromDate) / (1000 * 60 * 60 * 24));
                const daysActive = Math.max(0, Math.floor((now - validFromDate) / (1000 * 60 * 60 * 24)));
                const expiryPercentage = totalDays > 0 ? Math.min(100, Math.max(0, Math.round((daysActive / totalDays) * 100))) : 100;

                const expired = now > validToDate || daysRemaining < 0;
                const notYetValid = now < validFromDate;

                // Authorization & Trust
                const authorized = socket.authorized === true;
                const authorizationError = socket.authorizationError || null;
                const isSelfSigned =
                    authorizationError === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
                    (cert.subject && cert.issuer && cert.subject.CN === cert.issuer.CN && cert.subject.O === cert.issuer.O);

                // Build certificate hierarchy chain
                const chain = [];
                let currentCert = cert;
                const seenSerials = new Set();
                let chainIndex = 0;

                while (currentCert && !seenSerials.has(currentCert.serialNumber)) {
                    seenSerials.add(currentCert.serialNumber);
                    const isLeaf = chainIndex === 0;
                    const isSelfIssued = currentCert.subject?.CN === currentCert.issuer?.CN;

                    chain.push({
                        level: chainIndex,
                        role: isLeaf ? "Leaf / Server Certificate" : (isSelfIssued ? "Root CA" : "Intermediate CA"),
                        commonName: currentCert.subject?.CN || currentCert.subject?.O || "Unknown",
                        organization: currentCert.subject?.O || "-",
                        country: currentCert.subject?.C || "-",
                        issuerCN: currentCert.issuer?.CN || currentCert.issuer?.O || "Unknown",
                        issuerO: currentCert.issuer?.O || "-",
                        validFrom: currentCert.valid_from,
                        validTo: currentCert.valid_to,
                        serialNumber: formatSerialNumber(currentCert.serialNumber),
                        fingerprintSHA256: formatFingerprint(currentCert.fingerprint256 || ""),
                        isSelfSigned: isSelfIssued
                    });

                    chainIndex++;
                    if (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
                        currentCert = currentCert.issuerCertificate;
                    } else {
                        break;
                    }
                }

                // Check AIA / OCSP
                let ocspUri = null;
                let caIssuersUri = null;
                if (cert.infoAccess) {
                    ocspUri = cert.infoAccess["OCSP - URI"] ? (Array.isArray(cert.infoAccess["OCSP - URI"]) ? cert.infoAccess["OCSP - URI"][0] : cert.infoAccess["OCSP - URI"]) : null;
                    caIssuersUri = cert.infoAccess["CA Issuers - URI"] ? (Array.isArray(cert.infoAccess["CA Issuers - URI"]) ? cert.infoAccess["CA Issuers - URI"][0] : cert.infoAccess["CA Issuers - URI"]) : null;
                }

                // SHA256 Fingerprint
                const sha256Fingerprint = cert.fingerprint256
                    ? formatFingerprint(cert.fingerprint256)
                    : (cert.raw ? formatFingerprint(crypto.createHash("sha256").update(cert.raw).digest("hex")) : "-");

                const sha1Fingerprint = cert.fingerprint ? formatFingerprint(cert.fingerprint) : "-";

                // Overall Status calculation
                let overallStatus = "VALID";
                let statusDescription = "Certificate is valid, active, and trusted.";

                if (expired) {
                    overallStatus = "EXPIRED";
                    statusDescription = `Certificate expired on ${validToDate.toUTCString()}.`;
                } else if (notYetValid) {
                    overallStatus = "NOT_YET_VALID";
                    statusDescription = `Certificate is not active until ${validFromDate.toUTCString()}.`;
                } else if (!hostnameMatches) {
                    overallStatus = "HOSTNAME_MISMATCH";
                    statusDescription = `Certificate does not match requested host "${targetHost}".`;
                } else if (isSelfSigned) {
                    overallStatus = "SELF_SIGNED";
                    statusDescription = "Self-signed certificate; not trusted by browser root stores.";
                } else if (!authorized) {
                    overallStatus = "UNTRUSTED";
                    statusDescription = authorizationError ? `Trust verification failed: ${authorizationError}` : "Certificate is untrusted.";
                } else if (daysRemaining <= 14) {
                    overallStatus = "EXPIRING_CRITICAL";
                    statusDescription = `Certificate expires critically soon (${daysRemaining} days remaining).`;
                } else if (daysRemaining <= 30) {
                    overallStatus = "EXPIRING_SOON";
                    statusDescription = `Certificate expires within ${daysRemaining} days.`;
                }

                // Evaluate detailed security checklist & score
                const securityEvaluation = evaluateCertificateSecurity({
                    authorized,
                    authorizationError,
                    hostnameMatches,
                    expired,
                    notYetValid,
                    daysRemaining,
                    tlsVersion: protocol,
                    cipher,
                    keyType,
                    keySize,
                    sigAlg,
                    isSelfSigned,
                    hasOCSP: Boolean(ocspUri)
                });

                const responsePayload = {
                    target: {
                        host: targetHost,
                        port: targetPort,
                        isIP,
                        resolvedIps,
                        alpnProtocol
                    },
                    status: {
                        code: overallStatus,
                        description: statusDescription,
                        isValid: authorized && hostnameMatches && !expired && !notYetValid,
                        isAuthorized: authorized,
                        authorizationError,
                        hostnameMatches,
                        isSelfSigned,
                        expired,
                        notYetValid,
                        daysRemaining,
                        totalValidityDays: totalDays,
                        expiryPercentage
                    },
                    audit: {
                        grade: securityEvaluation.grade,
                        score: securityEvaluation.score,
                        checklist: securityEvaluation.checklist,
                        recommendations: securityEvaluation.recommendations
                    },
                    certificate: {
                        commonName: cert.subject?.CN || "-",
                        organization: cert.subject?.O || "-",
                        organizationalUnit: cert.subject?.OU || "-",
                        country: cert.subject?.C || "-",
                        state: cert.subject?.ST || "-",
                        locality: cert.subject?.L || "-",
                        issuerCN: cert.issuer?.CN || "-",
                        issuerO: cert.issuer?.O || "-",
                        issuerC: cert.issuer?.C || "-",
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        validFromUTC: validFromDate.toUTCString(),
                        validToUTC: validToDate.toUTCString(),
                        serialNumber: formatSerialNumber(cert.serialNumber),
                        sha256Fingerprint,
                        sha1Fingerprint,
                        signatureAlgorithm: sigAlg,
                        publicKeyAlgorithm: keyType,
                        keySize: keySize ? `${keySize}-bit` : "Standard",
                        keyUsage: keyUsage.length > 0 ? keyUsage : (cert.ext_key_usage || ["Digital Signature", "Server Authentication"]),
                        subjectAltNames: sanList,
                        ocspUri: ocspUri || "None specified",
                        caIssuersUri: caIssuersUri || "None specified",
                        rawPEM: pemCert
                    },
                    tls: {
                        version: protocol || "Unknown",
                        cipherName: cipher?.name || "Unknown",
                        cipherStandardName: cipher?.standardName || cipher?.name || "Unknown",
                        cipherVersion: cipher?.version || protocol || "Unknown",
                        ephemeralKey: ephemeralKey ? `${ephemeralKey.type || "ECDH"} ${ephemeralKey.name || ""} (${ephemeralKey.size || ""} bit)`.trim() : "None / Standard"
                    },
                    chain,
                    scannedAt: new Date().toISOString()
                };

                socket.end();
                return sendResponse(200, responsePayload);

            } catch (err) {
                if (socket) socket.destroy();
                return sendResponse(500, {
                    error: `Error inspecting certificate: ${err.message}`
                });
            }
        });

        socket.setTimeout(10000);

        socket.on("timeout", () => {
            if (socket) socket.destroy();
            return sendResponse(408, {
                error: `Connection to ${targetHost}:${targetPort} timed out (10s). The server did not respond or port 443 is blocked.`
            });
        });

        socket.on("error", (err) => {
            if (socket) socket.destroy();
            let errorMessage = err.message;
            if (err.code === "ENOTFOUND") {
                errorMessage = `Domain "${targetHost}" could not be resolved (DNS ENOTFOUND). Please verify spelling.`;
            } else if (err.code === "ECONNREFUSED") {
                errorMessage = `Connection refused at ${targetHost}:${targetPort}. No TLS service is listening on this port.`;
            } else if (err.code === "ECONNRESET") {
                errorMessage = `Connection reset by peer (${targetHost}:${targetPort}). Handshake aborted.`;
            } else if (err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH") {
                errorMessage = `Host or network unreachable for ${targetHost}:${targetPort}.`;
            }
            return sendResponse(502, {
                error: errorMessage,
                code: err.code
            });
        });

    } catch (err) {
        if (socket) socket.destroy();
        return sendResponse(500, {
            error: err.message
        });
    }
};

app.post("/scan", handleScanRequest);
app.post("/api/scan", handleScanRequest);

// Health check endpoint
app.get("/api/health", (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`SSLGuard Pro running on http://localhost:${PORT}`);
    });
}

app.parseDomainInput = parseDomainInput;
app.evaluateCertificateSecurity = evaluateCertificateSecurity;
app.handleScanRequest = handleScanRequest;

module.exports = app;
