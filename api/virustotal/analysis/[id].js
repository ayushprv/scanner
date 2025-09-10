// /api/virustotal/analysis/[id].js
// This gets the analysis results from VirusTotal

export default async function handler(req, res) {
    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        // Get the analysis ID from the URL parameter
        const { id } = req.query;
        
        // Get API key from environment variables
        const apiKey = process.env.VIRUSTOTAL_API_KEY;
        
        if (!apiKey) {
            return res.status(500).json({ error: 'VirusTotal API key not configured' });
        }

        if (!id) {
            return res.status(400).json({ error: 'Analysis ID is required' });
        }

        // Call VirusTotal API to get analysis results
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            if (response.status === 404) {
                return res.status(404).json({ error: 'Analysis not found' });
            }
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const data = await response.json();
        
        // Check if analysis is completed
        if (data.data.attributes.status !== 'completed') {
            return res.status(202).json({
                status: 'pending',
                message: 'Analysis still in progress',
                data: data.data
            });
        }

        // Analysis is completed, return results
        return res.status(200).json({
            status: 'completed',
            data: data.data
        });

    } catch (error) {
        console.error('Error getting analysis results:', error);
        return res.status(500).json({ 
            error: 'Failed to get analysis results',
            details: error.message 
        });
    }
}
