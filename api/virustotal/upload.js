// /api/virustotal/upload.js
// This uploads a new APK file to VirusTotal for scanning

import formidable from 'formidable';
import fs from 'fs';

// Disable default body parser to handle file uploads
export const config = {
    api: {
        bodyParser: false,
    },
};

export default async function handler(req, res) {
    // Only allow POST requests
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        // Get API key from environment variables
        const apiKey = process.env.VIRUSTOTAL_API_KEY;
        
        if (!apiKey) {
            return res.status(500).json({ error: 'VirusTotal API key not configured' });
        }

        // Parse the uploaded file
        const form = formidable({
            maxFileSize: 32 * 1024 * 1024, // 32MB limit
            keepExtensions: true,
        });

        const [fields, files] = await form.parse(req);
        
        const file = files.file?.[0];
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Check if file is APK
        if (!file.originalFilename?.toLowerCase().endsWith('.apk')) {
            return res.status(400).json({ error: 'Only APK files are allowed' });
        }

        // Read the file
        const fileBuffer = fs.readFileSync(file.filepath);
        
        // Create FormData for VirusTotal upload
        const formData = new FormData();
        const blob = new Blob([fileBuffer], { type: 'application/vnd.android.package-archive' });
        formData.append('file', blob, file.originalFilename);

        // Upload to VirusTotal
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
            },
            body: formData
        });

        // Clean up temporary file
        fs.unlinkSync(file.filepath);

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`VirusTotal upload failed: ${response.status} - ${errorText}`);
        }

        const data = await response.json();
        
        // Return the analysis ID
        return res.status(200).json({
            success: true,
            data: data.data,
            message: 'File uploaded successfully for analysis'
        });

    } catch (error) {
        console.error('Error uploading file:', error);
        return res.status(500).json({ 
            error: 'Failed to upload file',
            details: error.message 
        });
    }
}
