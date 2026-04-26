import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

const SYSTEM_PROMPT = `You are PhishForensics AI, an expert cybersecurity forensic engine. Analyze the given email or URL and return ONLY a raw valid JSON object with no markdown, no backticks, no explanation. The JSON must have these exact fields: riskScore (integer 0-100), verdict (string), confidence (string like 97.3%), reasoning (2-3 sentences), tags (array of strings), threatVectors (object with headerAnomaly, domainSpoof, contentUrgency, urlRisk, ipReputation, homographRisk — all integers 0-100), aiInsights (object with primaryThreat, attackType, targetedBrand, evasionTechnique — all strings), forensicFindings (array of 3-5 objects each with title, description, severity where severity is high medium or low), attackSimulation (array of exactly 5 objects each with step, title, description, danger where danger is boolean)`;

async function test() {
    const input = 'https://themoviesflix.ngo/';
    console.log('Received input:', input);
    
    const grokApiKey = process.env.GROK_API_KEY;
    if (!grokApiKey || grokApiKey === 'paste_your_key_here') {
        console.error('GROK_API_KEY is missing');
        return;
    }

    console.log(`Analyzing input: ${input.substring(0, 50)}...`);

    try {
        const response = await fetch('https://api.x.ai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${grokApiKey}`
            },
            body: JSON.stringify({
                model: 'grok-3',
                messages: [
                    { role: 'system', content: SYSTEM_PROMPT },
                    { role: 'user', content: input }
                ]
            })
        });

        console.log('Grok API response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Grok API Error:', errorText);
            return;
        }

        const data = await response.json();
        console.log('Grok raw response:', JSON.stringify(data));
        
        const rawText = data.choices[0]?.message?.content || '';
        
        const cleanedText = rawText.replace(/```json|```/g, '').trim();
        const result = JSON.parse(cleanedText);
        
        console.log('Parsed successfully!');
    } catch (error) {
        console.error('Full error:', error);
    }
}

test();
