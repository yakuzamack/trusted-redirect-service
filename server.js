// server.js - Complete production-ready version for Railway deployment
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";

dotenv.config();

const app = express();

// Trust proxy for Railway deployment
app.set('trust proxy', 1);

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

// ===== SECURITY MIDDLEWARE =====
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  
  // Remove server fingerprinting
  res.removeHeader('X-Powered-By');
  
  next();
});

// Request logging for monitoring
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent') || 'Unknown';
  console.log(`${new Date().toISOString()} - ${ip} - ${req.method} ${req.path} - ${userAgent}`);
  next();
});

// ===== BOT DETECTION FUNCTIONS =====
function detectBotByUserAgent(userAgent) {
  const botPatterns = [
    /bot/i, /crawler/i, /spider/i, /scraper/i,
    /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i,
    /whatsapp/i, /telegram/i, /discord/i,
    /curl/i, /wget/i, /python/i, /requests/i,
    /postman/i, /insomnia/i, /httpie/i,
    /apache-httpclient/i, /java/i, /okhttp/i
  ];
  
  return botPatterns.some(pattern => pattern.test(userAgent || ''));
}

function detectBotByHeaders(headers) {
  // Missing common browser headers
  const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
  const missingHeaders = requiredHeaders.filter(h => !headers[h]);
  
  // Suspicious header combinations
  const hasUserAgent = !!headers['user-agent'];
  const hasAccept = !!headers['accept'];
  
  return missingHeaders.length > 1 || (!hasUserAgent && !hasAccept);
}

// Rate limiting per IP
const ipRequestCounts = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_MINUTE = 10;

function isRateLimited(ip) {
  const now = Date.now();
  const ipData = ipRequestCounts.get(ip) || { count: 0, windowStart: now };
  
  // Reset window if expired
  if (now - ipData.windowStart > RATE_LIMIT_WINDOW) {
    ipData.count = 0;
    ipData.windowStart = now;
  }
  
  ipData.count++;
  ipRequestCounts.set(ip, ipData);
  
  return ipData.count > MAX_REQUESTS_PER_MINUTE;
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

// Comprehensive bot detection
async function isSuspiciousRequest(req) {
  const ip = req.ip || req.connection.remoteAddress || '';
  const userAgent = req.get('User-Agent') || '';
  
  // Multiple detection methods
  const checks = [
    detectBotByUserAgent(userAgent),
    detectBotByHeaders(req.headers),
    isRateLimited(ip),
    await checkIpReputation(ip)
  ];
  
  // If any check fails, it's suspicious
  return checks.some(Boolean);
}

// ===== ENCRYPTION FUNCTIONS =====
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

// ===== ROUTES =====
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
  const ip = req.ip || req.connection.remoteAddress || '';
  const userAgent = req.get('User-Agent') || '';
  
  // Log the attempt
  console.log(`Redirect attempt: ${id} from ${ip} - ${userAgent}`);
  
  // Check if request is suspicious
  if (await isSuspiciousRequest(req)) {
    console.log(`Blocked suspicious request from ${ip}`);
    return res.redirect("https://calendly.com");
  }
  
  // Get encrypted string (from alias or direct)
  const encryptedString = aliases[id] || id;
  
  // Decrypt and validate URL
  const targetUrl = decryptURL(encryptedString);
  if (!targetUrl) {
    console.log(`Invalid/expired link: ${id}`);
    return res.redirect("https://calendly.com");
  }
  
  // Validate URL format
  try {
    new URL(targetUrl);
  } catch {
    console.log(`Invalid URL format: ${targetUrl}`);
    return res.redirect("https://calendly.com");
  }
  
  // Add small delay to slow down automated requests
  await new Promise(resolve => setTimeout(resolve, 100));
  
  console.log(`Redirecting to: ${targetUrl}`);
  res.redirect(targetUrl);
});

// ===== ERROR HANDLING =====
// Global error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).redirect("https://calendly.com");
});

// 404 handler
app.use((req, res) => {
  res.status(404).redirect("https://calendly.com");
});

// ===== SERVER STARTUP =====
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Redirect service running on port ${PORT}`));

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Clean up rate limiting data periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of ipRequestCounts.entries()) {
    if (now - data.windowStart > RATE_LIMIT_WINDOW * 2) {
      ipRequestCounts.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW);

// ✅ Complete production-ready server with aggressive bot protection