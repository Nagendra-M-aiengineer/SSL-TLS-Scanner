// server.js

const express = require("express");
const cors = require("cors");
const tls = require("tls");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 5000;

// Home Route
app.get("/", (req, res) => {
    res.send("SSLGuard Pro Backend Running...");
});

// Scan Route
app.post("/scan", async (req, res) => {

    const { domain } = req.body;

    if (!domain) {
        return res.status(400).json({
            error: "Domain is required"
        });
    }

    const cleanDomain = domain
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0];

    const socket = tls.connect(
        {
            host: cleanDomain,
            port: 443,
            servername: cleanDomain,
            rejectUnauthorized: false
        },
        () => {

            try {

                const cert = socket.getPeerCertificate(true);

                if (!cert || Object.keys(cert).length === 0) {
                    socket.end();

                    return res.status(404).json({
                        error: "Certificate not found"
                    });
                }

                const protocol = socket.getProtocol();

                const now = new Date();
                const expiry = new Date(cert.valid_to);

                const daysRemaining =
                    Math.ceil(
                        (expiry - now) /
                        (1000 * 60 * 60 * 24)
                    );

                const sha256 =
                    crypto
                        .createHash("sha256")
                        .update(cert.raw)
                        .digest("hex")
                        .match(/.{2}/g)
                        .join(":")
                        .toUpperCase();

                res.json({

                    commonName:
                        cert.subject.CN || "-",

                    organization:
                        cert.subject.O || "-",

                    issuer:
                        cert.issuer.O ||
                        cert.issuer.CN ||
                        "-",

                    validFrom:
                        cert.valid_from,

                    validTo:
                        cert.valid_to,

                    serialNumber:
                        cert.serialNumber,

                    sha256Fingerprint:
                        sha256,

                    signatureAlgorithm:
                        "Unavailable",

                    publicKeyAlgorithm:
                        "Unavailable",

                    tlsVersion:
                        protocol,

                    subject:
                        JSON.stringify(cert.subject),

                    issuerDetails:
                        JSON.stringify(cert.issuer),

                    daysRemaining,

                    expired:
                        daysRemaining < 0

                });

                socket.end();

            }
            catch (err) {

                socket.end();

                return res.status(500).json({
                    error: err.message
                });

            }

        }
    );

    socket.setTimeout(10000);

    socket.on("timeout", () => {

        socket.destroy();

        return res.status(408).json({
            error: "Connection Timeout"
        });

    });

    socket.on("error", err => {

        return res.status(500).json({
            error: err.message
        });

    });

});

app.listen(PORT, () => {

    console.log(`SSLGuard Pro running on http://localhost:${PORT}`);

});