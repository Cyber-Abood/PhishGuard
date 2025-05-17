// server/app.js
const path = require('path');
const fetch = require('node-fetch'); // Added for redirect resolution

// Load environment variables from .env file first
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { createCanvas, loadImage } = require('canvas');
const jsQR = require('jsqr');
const fs = require('fs');

// Import custom routes and services
const scanRouter = require('./routes/scan');
const { scanUrl } = require('./services/virusTotal');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// --- Initial Debugging & Environment Checks ---
console.log('Environment Path:', path.resolve(__dirname, '../.env'));
console.log('Node Environment:', process.env.NODE_ENV || 'development (default)');
console.log('VT API Key:', process.env.VIRUSTOTAL_API_KEY ? 'Loaded' : 'MISSING! Check .env file.');
if (isProduction && !process.env.YOUR_PRODUCTION_DOMAIN) {
  console.warn('WARNING: Running in production mode but YOUR_PRODUCTION_DOMAIN environment variable is not set. CORS might block frontend access.');
}

// --- Middleware Setup ---
app.use(
  helmet({
    hsts: {
      maxAge: 60 * 60 * 24 * 365,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://apis.virustotal.com"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'", "https://www.virustotal.com"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

const allowedOrigins = isProduction
  ? (process.env.YOUR_PRODUCTION_DOMAIN ? process.env.YOUR_PRODUCTION_DOMAIN.split(',') : [])
  : '*';

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: allowedOrigins !== '*',
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 100 : 500,
  message: JSON.stringify({ error: 'Too many requests from this IP, please try again after 15 minutes.' }),
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// --- Redirect Resolution Utility ---
async function resolveFinalUrl(initialUrl) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(initialUrl, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
      }
    });
    clearTimeout(timeoutId);
    return response.url;
  } catch (error) {
    console.error('Redirect resolution error:', error.message);
    return initialUrl;
  }
}

// --- File Upload Configuration ---
const upload = multer({
  dest: path.join(__dirname, '../uploads/'),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type: Only image files (PNG, JPG, etc.) are allowed.'), false);
    }
  },
});

// --- API Routes ---
app.use('/api/vt-scan', scanRouter);

app.post('/check-qr', upload.single('qrfile'), async (req, res, next) => {
  let uploadedFilePath = req.file ? req.file.path : null;

  try {
    if (!req.file) {
      const err = new Error('Please upload a valid image file (max 5MB) under field name "qrfile".');
      err.status = 400;
      throw err;
    }

    const image = await loadImage(req.file.path);
    const canvas = createCanvas(image.width, image.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(image, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);

    if (!code || !code.data) {
      throw new Error('No QR code detected in the uploaded image.');
    }

    // --- Modified Validation Section ---
    let urlString = code.data;
    if (!/^https?:\/\//i.test(urlString)) {
      urlString = 'http://' + urlString;
    }

    const initialUrl = new URL(urlString);
    if (!['http:', 'https:'].includes(initialUrl.protocol)) {
      throw new Error('Invalid URL protocol in QR code. Only HTTP/HTTPS URLs allowed.');
    }

    const finalUrlString = await resolveFinalUrl(initialUrl.href);
    const finalUrl = new URL(finalUrlString);

    if (!['http:', 'https:'].includes(finalUrl.protocol)) {
      throw new Error('Resolved URL has invalid protocol.');
    }

    const hostname = finalUrl.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1' ||
        hostname.match(/^10\.\d+\.\d+\.\d+$/) ||
        hostname.match(/^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/) ||
        hostname.match(/^192\.168\.\d+\.\d+$/)) {
      throw new Error('Resolved URL points to a private network.');
    }

    const vtResult = await scanUrl(finalUrl.href);

    res.json({
      result: vtResult.isMalicious ? 'fail' : 'pass',
      originalUrl: initialUrl.href,
      finalUrl: finalUrl.href,
      details: vtResult
    });

  } catch (error) {
    next(error);
  } finally {
    if (uploadedFilePath) {
      fs.unlink(uploadedFilePath, (unlinkErr) => {
        if (unlinkErr) console.error(`Error deleting uploaded file: ${uploadedFilePath}`, unlinkErr);
      });
    }
  }
});

// --- Extension Download Route ---
app.get('/download-extension', (req, res, next) => {
  const extensionPath = path.join(__dirname, '../public/extension/PhishGuardExtension.zip');
  fs.access(extensionPath, fs.constants.R_OK, (err) => {
    if (err) {
      return res.status(404).json({ error: 'Extension file not found.' });
    }
    res.download(extensionPath, 'PhishGuardExtension.zip', (downloadErr) => {
      if (downloadErr && !res.headersSent) next(new Error('Could not download the extension file.'));
    });
  });
});

// --- Final Middleware ---
app.get('/', (req, res) => {
  res.send('API Server is running.');
});

app.use((req, res, next) => {
  res.status(404).json({ error: `Not Found: ${req.method} ${req.originalUrl}` });
});

app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] ERROR: ${err.message}`, isProduction ? '' : err.stack);
  let statusCode = err.status || 500;
  let message = err.message || 'An internal server error occurred.';

  if (err instanceof multer.MulterError) {
    statusCode = 400;
    if (err.code === 'LIMIT_FILE_SIZE') message = 'File too large. Maximum size allowed is 5MB.';
    else if (err.code === 'LIMIT_FILE_COUNT') message = 'Too many files uploaded. Only one file allowed.';
    else message = 'File upload error.';
  }

  if (statusCode === 500 && isProduction) message = 'An internal server error occurred. Please try again later.';

  res.status(statusCode).json({
    error: message,
    ...( !isProduction && err.stack && { stack: err.stack }),
  });
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server listening on port ${PORT}`);
  console.log(`   Mode: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   CORS Allowed Origins: ${allowedOrigins || '(Not Set - Check YOUR_PRODUCTION_DOMAIN in .env for production)'}`);
  console.log(`   Rate Limit: ${isProduction ? 100 : 500} requests/15min per IP`);
  console.log(`   Public files served from: ${path.join(__dirname, '../public')}`);
  console.log(`   Uploads directory: ${path.join(__dirname, '../uploads/')}`);
  console.log(`   Access API root at: http://localhost:${PORT}\n`);
});

module.exports = app;
