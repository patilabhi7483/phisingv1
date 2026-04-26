import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const SYSTEM_PROMPT = `You are PhishForensics AI, an elite cybersecurity forensic engine. When given suspicious email content or a URL, perform ALL of the following checks and return ONLY a raw valid JSON object with no markdown, no backticks, no explanation.

FORENSIC CHECKS TO PERFORM:
1. HEADER ANALYSIS: Check if sender email domain matches return-path domain. Flag SPF/DKIM/DMARC failures. Detect display name spoofing where friendly name differs from actual email.
2. URL ANALYSIS: Expand and analyze all URLs. Identify if they use URL shorteners (bit.ly, tinyurl etc). Extract and analyze the real destination domain. Check for suspicious TLDs (.tk .ml .gq .xyz .top .click).
3. HOMOGRAPH DETECTION: Check every domain for unicode lookalike characters. Examples: googIe.com uses capital I not l, paypaI.com, micosoft.com, arnazon.com. Flag any character substitutions.
4. CONTENT ANALYSIS: Detect urgency language, threats, prize claims, account suspension warnings, requests for credentials or personal info.
5. DESTINATION PREVIEW: Analyze where URLs lead without clicking. Describe what the destination domain likely hosts based on its name and structure.
6. BRAND IMPERSONATION: Identify which real brand is being impersonated if any.

Return this exact JSON schema:
{
  "riskScore": <integer 0-100>,
  "verdict": "<string>",
  "confidence": "<string like 97.3%>",
  "reasoning": "<3-4 sentence executive summary covering all forensic findings>",
  "tags": ["<tag1>", "<tag2>", "<tag3>"],
  "headerAnalysis": {
    "senderDomain": "<extracted sender domain or N/A>",
    "returnPathDomain": "<return path domain or N/A>",
    "domainMatch": <boolean>,
    "spfStatus": "<pass/fail/unknown>",
    "dkimStatus": "<pass/fail/unknown>",
    "spoofingDetected": <boolean>,
    "displayNameTrick": "<description or none>"
  },
  "urlAnalysis": {
    "originalUrl": "<the url found>",
    "isShortened": <boolean>,
    "realDestination": "<expanded destination or same as original>",
    "destinationPreview": "<1 sentence describing what this site likely is>",
    "suspiciousTld": <boolean>,
    "tldRisk": "<the TLD and why its suspicious or safe>"
  },
  "homographAnalysis": {
    "detected": <boolean>,
    "suspiciousChars": ["<list of suspicious character substitutions found>"],
    "legitimateDomain": "<what domain it is trying to impersonate or none>",
    "explanation": "<explanation of the trick used or none detected>"
  },
  "threatVectors": {
    "headerAnomaly": <integer 0-100>,
    "domainSpoof": <integer 0-100>,
    "contentUrgency": <integer 0-100>,
    "urlRisk": <integer 0-100>,
    "ipReputation": <integer 0-100>,
    "homographRisk": <integer 0-100>
  },
  "aiInsights": {
    "primaryThreat": "<string>",
    "attackType": "<string>",
    "targetedBrand": "<string or Unknown>",
    "evasionTechnique": "<string or None Detected>"
  },
  "forensicFindings": [
    {
      "title": "<finding title>",
      "description": "<1 sentence>",
      "severity": "<high or medium or low>"
    }
  ],
  "attackSimulation": [
    { "step": 1, "title": "<title>", "description": "<desc>", "danger": false },
    { "step": 2, "title": "<title>", "description": "<desc>", "danger": false },
    { "step": 3, "title": "<title>", "description": "<desc>", "danger": false },
    { "step": 4, "title": "<title>", "description": "<desc>", "danger": true },
    { "step": 5, "title": "<title>", "description": "<desc>", "danger": true }
  ]
}

Rules: Output valid JSON only. riskScore above 60 = threat, 40-60 = suspicious, below 40 = safe. forensicFindings must have 4-6 entries. attackSimulation must have exactly 5 steps.`;

app.get('/', (req, res) => {
    res.json({ status: 'PhishForensics AI backend is running' });
});

app.post('/analyze', async (req, res) => {
    const { input } = req.body;
    console.log('Received:', input);
    console.log('API KEY:', process.env.GROQ_API_KEY ? 'Found ✅' : 'MISSING ❌');

    try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
            },
            body: JSON.stringify({
                model: 'llama-3.3-70b-versatile',
                messages: [
                    { role: 'system', content: SYSTEM_PROMPT },
                    { role: 'user', content: input }
                ]
            })
        });

        const data = await response.json();
        console.log('Groq status:', response.status);
        console.log('Groq response:', JSON.stringify(data));

        if (!response.ok) {
            return res.status(500).json({ error: data });
        }

        const rawContent = data.choices[0].message.content;
        const match = rawContent.match(/\{[\s\S]*\}/);
        const raw = match ? match[0] : rawContent.replace(/```json|```/g, '').trim();
        
        const result = JSON.parse(raw);
        res.json(result);

    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Running on http://127.0.0.1:3000');
});