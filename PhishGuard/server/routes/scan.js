const express = require('express');
const router = express.Router();
const { scanUrl } = require('../services/virusTotal');
const axios = require('axios');

// Health-check endpoint
router.get('/', (req, res) => {
  res.json({ 
    status: 'Operational',
    components: {
      virusTotal: 'Integrated',
      aiModel: 'Active (Flask API @ 5055)'
    }
  });
});

// URL scan endpoint
router.post('/', async (req, res) => {
  try {
    const { url } = req.body;
    console.log(`[Scan Initiated] ${new Date().toISOString()} - URL: ${url}`);

    // Validate URL format
    if (!isValidUrl(url)) {
      console.error(`[Validation Failed] Invalid URL: ${url}`);
      return res.status(400).json({ 
        error: 'Invalid URL format',
        example: 'http://example.com'
      });
    }

    // Attempt VirusTotal scan
    let vtResult;
    try {
      vtResult = await scanUrl(url);
      console.log('[VirusTotal] Scan completed:', vtResult ? 'Success' : 'No data');
    } catch (vtError) {
      console.error('[VirusTotal] Scan failed:', vtError.message);
      vtResult = null;
    }

    // VirusTotal failure handling → AI fallback
    if (!vtResult || vtResult.error) {
      console.log('[AI Fallback] Initiating AI model analysis');
      try {
        const aiResult = await getAIModelPrediction(url);
        console.log('[AI Success] Prediction:', aiResult.prediction);
        
        return res.json({
          result: aiResult.prediction === 'malicious' ? 'fail' : 'pass',
          details: {
            source: 'AI Model',  // Explicit source identifier
            confidence: aiResult.confidence,
            executionTime: new Date().toISOString()
          },
          aiAnalysis: aiResult
        });
      } catch (aiError) {
        console.error('[AI Failure]', aiError.message);
        throw new Error(`Both scanners failed: ${aiError.message}`);
      }
    }

    // Process VirusTotal results
    const analysis = {
      malicious: vtResult.malicious || 0,
      suspicious: vtResult.suspicious || 0,
      harmless: vtResult.harmless || 0,
      undetected: vtResult.undetected || 0,
      scanDate: vtResult.scan_date || 'N/A'
    };

    console.log('[VirusTotal] Analysis:', analysis);

    // Decision Matrix
    let result, source;
    if (analysis.malicious >= 2 || analysis.suspicious >= 2) {
      result = 'fail';
      source = 'VirusTotal';  // Explicit VirusTotal flag
    } else if (analysis.harmless >= 4) {
      result = 'pass';
      source = 'VirusTotal';
    } else {
      console.log('[AI Activation] Inconclusive results - Using AI model');
      const aiResult = await getAIModelPrediction(url);
      result = aiResult.prediction === 'malicious' ? 'fail' : 'pass';
      source = 'AI Model';  // AI-determined result
    }

    // Final response with source metadata
    res.json({
      result,
      details: {
        source,  // Critical: Pass source to extension
        ...analysis
      },
      supplementary: vtResult.permaLink ? {
        reportUrl: vtResult.permaLink
      } : null
    });

  } catch (error) {
    console.error(`[System Failure] ${error.message}`);
    res.status(500).json({
      error: error.message,
      troubleshooting: {
        step1: 'Verify internet connection',
        step2: 'Check VirusTotal API key',
        step3: 'Validate AI model server on http://localhost:5055'
      },
      timestamp: new Date().toISOString()
    });
  }
});

// AI Model Integration
async function getAIModelPrediction(url) {
  try {
    console.log('[AI HTTP] Sending request to Flask model server');
    const response = await axios.post('http://127.0.0.1:5055/predict', { url });
    return response.data;
  } catch (error) {
    console.error('[AI HTTP Error]', error.message);
    throw new Error('Flask AI model server failed');
  }
}

// URL Validation
function isValidUrl(url) {
  try {
    new URL(url);
    return /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i.test(url);
  } catch {
    return false;
  }
}

module.exports = router;