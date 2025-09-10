// /api/virustotal/check/[hash].js
// This checks if a file hash already exists in VirusTotal database

export default async function handler(req, res) {
    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        // Get the file hash from the URL parameter
        const { hash } = req.query;
        
        // Get API key from environment variables
        const apiKey = process.env.VIRUSTOTAL_API_KEY;
        
        if (!apiKey) {
            return res.status(500).json({ error: 'VirusTotal API key not configured' });
        }

        if (!hash) {
            return res.status(400).json({ error: 'File hash is required' });
        }

        // Call VirusTotal API to check if file exists
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'Content-Type': 'application/json'
            }
        });

        if (response.status === 404) {
            // File doesn't exist in database, need to upload
            return res.status(404).json({ error: 'File not found in database' });
        }

        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const data = await response.json();
        
        // Return the scan results
        return res.status(200).json(data);

    } catch (error) {
        console.error('Error checking file hash:', error);
        return res.status(500).json({ 
            error: 'Failed to check file hash',
            details: error.message 
        });
    }
}
