// server.js production-ready version for Railway deployment

import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";

dotenv.config();

const app = express();
app.use(express.json());

const AES_KEY = Buffer.from(process.env.AES_KEY, "hex");
const HMAC_KEY = Buffer.from(process.env.HMAC_KEY, "hex");
const IPQS_API_KEY = process.env.IPQS_API_KEY;

const ALIAS_FILE = path.resolve("./aliases.json");

// Load aliases
let aliases = {};
try {
  if (fs.existsSync(ALIAS_FILE)) {
    aliases = JSON.parse(fs.readFileSync(ALIAS_FILE));
  }
} catch (e) {
  console.error("Failed to load aliases.json, starting fresh.");
  aliases = {};
}

function saveAliases() {
  fs.writeFileSync(ALIAS_FILE, JSON.stringify(aliases, null, 2));
}

function encryptURL(url) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
  let encrypted = cipher.update(url, "utf8", "hex");
  encrypted += cipher.final("hex");

  const hmac = crypto.createHmac("sha256", HMAC_KEY);
  hmac.update(iv.toString("hex") + encrypted);
  const digest = hmac.digest("hex");

  return `${encrypted}:${digest}:${iv.toString("hex")}`;
}

function decryptURL(encryptedString) {
  const parts = encryptedString.split(":");
  if (parts.length !== 3) return null;
  const [encrypted, digest, ivHex] = parts;

  const hmac = crypto.createHmac("sha256", HMAC_KEY);
  hmac.update(ivHex + encrypted);
  if (digest !== hmac.digest("hex")) return null;

  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

async function checkIpReputation(ip) {
  if (!IPQS_API_KEY) return false;
  try {
    const res = await fetch(`https://ipqualityscore.com/api/json/ip/${IPQS_API_KEY}/${ip}`);
    const data = await res.json();
    return data && data.fraud_score && data.fraud_score > 80;
  } catch {
    return false;
  }
}

app.get("/create", (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing 'url' parameter");

  try {
    const encrypted = encryptURL(target);
    res.send(`${req.protocol}://${req.get("host")}/r/${encrypted}`);
  } catch (e) {
    res.status(500).send("Encryption error");
  }
});

app.post("/alias/create", (req, res) => {
  const { url, alias } = req.body;
  if (!url) return res.status(400).json({ error: "'url' is required" });

  let encrypted;
  try {
    encrypted = encryptURL(url);
  } catch {
    return res.status(500).json({ error: "Encryption failed" });
  }

  let keyAlias = alias || crypto.randomBytes(3).toString("hex");

  aliases[keyAlias] = encrypted;
  saveAliases();

  const fullUrl = `${req.protocol}://${req.get("host")}/r/${keyAlias}`;
  res.json({ alias: keyAlias, redirectUrl: fullUrl });
});

app.get("/r/:id", async (req, res) => {
  const id = req.params.id;
  const encryptedString = aliases[id] || id;

  const ip = req.ip || req.connection.remoteAddress || "";
  const isBot = await checkIpReputation(ip);
  if (isBot) return res.redirect("https://calendly.com");

  const targetUrl = decryptURL(encryptedString);
  if (!targetUrl) return res.redirect("https://calendly.com");

  res.redirect(targetUrl);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Redirect service running on port ${PORT}`));

// ✅ Ready for Railway deployment with alias, redirect, and bot fallback to Calendly
