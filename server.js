const express = require('express');
const axios = require('axios');
const https = require('https');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const url = require('url');
const { JSDOM } = require('jsdom');
const UserAgent = require('user-agents');
const tldRegex = require('./lib/regexp-top-level-domain');

// Load lib/aes.js script
const aesScript = fs.readFileSync(path.join(__dirname, 'lib', 'aes.js'), 'utf-8');

const app = express();
const PORT = process.env.PORT || 3000;
const userAgent = new UserAgent().toString();

const httpsAgent = new https.Agent({
    rejectUnauthorized: false, // Disable SSL verification
});

// https://github.com/Rob--W/cors-anywhere/blob/34ec83b25ccacad5c523e6b0ad2e156d2107c6e6/lib/cors-anywhere.js#L39
function isValidHostName(hostname) {
    return !!(
        tldRegex.test(hostname) ||
        net.isIPv4(hostname) ||
        net.isIPv6(hostname)
    );
}

// https://github.com/Rob--W/cors-anywhere/blob/34ec83b25ccacad5c523e6b0ad2e156d2107c6e6/lib/cors-anywhere.js#L227
function parseURL(req_url) {
    var match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);
    if (!match) {
        return null;
    }
    if (!match[1]) {
        if (/^https?:/i.test(req_url)) {
            return null;
        }
        if (req_url.lastIndexOf('//', 0) === -1) {
            req_url = '//' + req_url;
        }
        req_url = (match[4] === '443' ? 'https:' : 'http:') + req_url;
    }
    var parsed = url.parse(req_url);
    if (!parsed.hostname) {
        return null;
    }
    return parsed;
}

// Middleware to add Access-Control-Allow-Origin header
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow all origins
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS'); // Allowed methods
    if (req.method === 'OPTIONS') {
        if (req.headers['access-control-request-headers']) {
            res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers']);
        }
        return res.status(204).end();
    }
    next();
});

// Serve the "/status" page
app.get('/status', (req, res) => {
    // Equivalent to res.sendStatus(200)
    res.status(200).send('OK');
});

// Dynamic route for all requests
app.get('/:url(*)', async (req, res) => {
    let link = req.originalUrl.substring(1);
    const location = parseURL(link);

    if (!link) {
        return res.status(400).send('URL is required as a path parameter.');
    }

    if (/^https?:\/[^/]/i.test(link)) {
        return res.status(400).send('Invalid URL: Two slashes are needed after http(s):, e.g. "http://example.com".');
        // link = link.replace(/^https?:\/([^/])/i, 'http://$1');
    }

    // Check if the URL is valid
    if (!/^https?:/.test(link) && !isValidHostName(location.hostname)) {
        // If the URL is invalid, check if the file exists in the directory
        const filePath = path.join(__dirname, link);
        if (fs.existsSync(filePath)) {
            return res.sendFile(filePath);
        } else {
            return res.status(404).send('Not Found.');
        }
    } else {
        // Ensure the URL starts with http:// or https://
        if (!/^https?:\/\//i.test(link)) {
            link = `http://${link}`;
        }
    }

    try {
        // Decode the URL (since it might be encoded in the path)
        const decodedUrl = decodeURIComponent(link);
        const urlHostname = new URL(decodedUrl).hostname;

        // Create a temp file to store the cookies
        const tempDir = os.tmpdir();
        const cookieFileName = urlHostname + '_cookies.txt';
        const cookiePath = path.join(tempDir, cookieFileName);

        let response, finalResponse;
        let testcookie_cache = false;

        // Check if cookie file exists
        if (fs.existsSync(cookiePath)) {
            // Read and use the existing cookie
            const existingCookie = fs.readFileSync(cookiePath, 'utf-8').trim();

            // Make the request with the existing cookie
            response = await axios.get(decodedUrl, {
                httpsAgent, // Use the custom HTTPS agent
                headers: {
                    'User-Agent': userAgent,
                    Cookie: existingCookie,
                    Referer: decodedUrl, // Bypass bkmn #1
                    'X-Requested-With': 'XMLHttpRequest', // Bypass bkmn #2
                },
                withCredentials: true, // Send cookies with the request
                responseType: 'arraybuffer', // Handle binary data
            });
        } else {
            response = await axios.get(decodedUrl, {
                httpsAgent, // Use the custom HTTPS agent
                headers: {
                    'User-Agent': userAgent,
                    Referer: decodedUrl, // Bypass bkmn #1
                    'X-Requested-With': 'XMLHttpRequest', // Bypass bkmn #2
                },
                responseType: 'arraybuffer', // Handle binary data
            });
        }

        // Convert response data to string for HTML content
        const responseData = Buffer.isBuffer(response.data)
            ? response.data.toString('utf-8')
            : response.data;

        // If the response does not contain the AES-based challenge, return the response immediately
        if (!responseData.includes('/aes.js')) {
            finalResponse = response;
            testcookie_cache = true;
        } else {
            // Step 1: Extract and evaluate the AES-based challenge
            const dom = new JSDOM(responseData, { runScripts: 'outside-only' });

            // Use XPath to find the script containing "toNumbers("
            const xpath = '//script[contains(text(), "toNumbers(")]';
            const targetScript = dom.window.document.evaluate(xpath, dom.window.document, null, dom.window.XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

            if (!targetScript) {
                throw new Error('Failed to find the script containing "toNumbers(".');
            }

            const scriptContent = targetScript.textContent;

            // Step 2: Extract the "testcookie" name and AES challenge "a,b,c"
            const testcookie_name = scriptContent.match(/document\.cookie\s?=\s?['"]([^'"]+)=/i)[1];
            const testcookie_abc = scriptContent.match(/(toHex\([^\)]+\)\))/i)[1];

            const newScriptContent = scriptContent.replace(
                /document\.cookie[^<]+/i,
                `var tc=document.createElement('testcookie');tc.innerHTML=${testcookie_abc};document.body.appendChild(tc);`
            );
            dom.window.eval(aesScript); // Load lib/aes.js into the DOM
            dom.window.eval(newScriptContent); // Load the modified script into the DOM

            const testcookie = dom.window.document.querySelector('testcookie').innerHTML;

            // Save the cookie to a file
            const cookie = `${testcookie_name}=${testcookie}`;
            fs.writeFileSync(cookiePath, cookie, 'utf-8');

            // Step 3: Make a request with the newly obtained testcookie
            finalResponse = await axios.get(decodedUrl, {
                httpsAgent, // Use the custom HTTPS agent
                headers: {
                    'User-Agent': userAgent,
                    Cookie: cookie,
                    Referer: decodedUrl, // Bypass bkmn #1
                    'X-Requested-With': 'XMLHttpRequest', // Bypass bkmn #2
                },
                withCredentials: true, // Send cookies with the request
                responseType: 'arraybuffer', // Handle binary data
            });
        }

        // Convert finalResponse data to string for HTML content
        const finalResponseData = Buffer.isBuffer(finalResponse.data)
            ? finalResponse.data.toString('utf-8')
            : finalResponse.data;

        // Log request information
        if (finalResponseData.includes('/aes.js')) {
            const logPath = `log_${urlHostname}.txt`;
            const logContent = `${new Date().toISOString()} ${req.ip} ${decodedUrl} ${userAgent}\n`;
            fs.appendFileSync(logPath, logContent, 'utf-8');
        }

        // Set Content-Type and send the response
        const contentType = finalResponse.headers['content-type'];
        if (contentType.includes('/html')) {
            res.json({
                link: finalResponse.request.res.responseUrl,
                testcookie_cache,
                headers: finalResponse.headers,
                body: finalResponseData,
            });
        } else {
            res.set('Content-Type', contentType);
            res.send(finalResponse.data);
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
        console.error('!! Error:', error);
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
