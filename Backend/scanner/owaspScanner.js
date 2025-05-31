const axios = require('axios');

class OWASPScanner {
    constructor() {
        this.vulnerabilities = [];
    }

    async scanUrl(url) {
        try {
            const response = await axios.get(url);
            const html = response.data;
            const headers = response.headers;

            // Run all security checks
            await this.checkBrokenAccessControl(headers);
            await this.checkInjectionVulnerabilities(html);
            await this.checkSensitiveDataExposure(headers);
            await this.checkXXE(html);
            await this.checkBrokenAuthentication(headers);
            await this.checkSecurityMisconfiguration(headers);
            await this.checkXSS(html);
            await this.checkInsecureDeserialization(html);
            await this.checkUsingComponentsWithKnownVulnerabilities(headers);
            await this.checkInsufficientLogging(headers);

            return {
                url,
                timestamp: new Date().toISOString(),
                vulnerabilities: this.vulnerabilities
            };
        } catch (error) {
            throw new Error(`Scan failed: ${error.message}`);
        }
    }

    async checkBrokenAccessControl(headers) {
        // Check for missing security headers
        const securityHeaders = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy'
        ];

        const missingHeaders = securityHeaders.filter(header => !headers[header.toLowerCase()]);
        
        if (missingHeaders.length > 0) {
            this.vulnerabilities.push({
                type: 'Broken Access Control',
                severity: 'High',
                description: 'Missing security headers',
                details: `Missing headers: ${missingHeaders.join(', ')}`
            });
        }
    }

    async checkInjectionVulnerabilities(html) {
        // Check for SQL injection patterns
        const sqlPatterns = [
            /(\b(select|insert|update|delete|drop|union)\b.*\b(from|into|where)\b)/i,
            /(\b(exec|execute)\b.*\b(sp_executesql|xp_cmdshell)\b)/i
        ];

        sqlPatterns.forEach(pattern => {
            if (pattern.test(html)) {
                this.vulnerabilities.push({
                    type: 'Injection',
                    severity: 'Critical',
                    description: 'Potential SQL injection vulnerability detected',
                    details: 'Found SQL-like patterns in the response'
                });
            }
        });
    }

    async checkSensitiveDataExposure(headers) {
        // Check for secure cookie settings
        if (headers['set-cookie'] && !headers['set-cookie'].includes('Secure')) {
            this.vulnerabilities.push({
                type: 'Sensitive Data Exposure',
                severity: 'High',
                description: 'Insecure cookie configuration',
                details: 'Cookies are not set with Secure flag'
            });
        }

        // Check for HTTPS
        if (!headers['strict-transport-security']) {
            this.vulnerabilities.push({
                type: 'Sensitive Data Exposure',
                severity: 'High',
                description: 'Missing HSTS header',
                details: 'HTTP Strict Transport Security not enforced'
            });
        }
    }

    async checkXXE(html) {
        // Check for XML External Entity patterns
        const xxePatterns = [
            /<!ENTITY.*SYSTEM/i,
            /<!DOCTYPE.*\[/i
        ];

        xxePatterns.forEach(pattern => {
            if (pattern.test(html)) {
                this.vulnerabilities.push({
                    type: 'XML External Entities (XXE)',
                    severity: 'High',
                    description: 'Potential XXE vulnerability detected',
                    details: 'Found XML entity declarations in the response'
                });
            }
        });
    }

    async checkBrokenAuthentication(headers) {
        // Check for session management issues
        if (headers['set-cookie'] && !headers['set-cookie'].includes('HttpOnly')) {
            this.vulnerabilities.push({
                type: 'Broken Authentication',
                severity: 'High',
                description: 'Insecure session management',
                details: 'Cookies are not set with HttpOnly flag'
            });
        }
    }

    async checkSecurityMisconfiguration(headers) {
        // Check for server information disclosure
        if (headers['server'] || headers['x-powered-by']) {
            this.vulnerabilities.push({
                type: 'Security Misconfiguration',
                severity: 'Medium',
                description: 'Server information disclosure',
                details: 'Server version information is exposed in headers'
            });
        }
    }

    async checkXSS(html) {
        // Check for potential XSS vulnerabilities
        const xssPatterns = [
            /<script.*>.*<\/script>/i,
            /javascript:/i,
            /on\w+\s*=/i
        ];

        xssPatterns.forEach(pattern => {
            if (pattern.test(html)) {
                this.vulnerabilities.push({
                    type: 'Cross-Site Scripting (XSS)',
                    severity: 'High',
                    description: 'Potential XSS vulnerability detected',
                    details: 'Found potentially unsafe script patterns'
                });
            }
        });
    }

    async checkInsecureDeserialization(html) {
        // Check for common serialization formats
        const serializationPatterns = [
            /application\/json/i,
            /application\/xml/i
        ];

        if (serializationPatterns.some(pattern => pattern.test(html))) {
            this.vulnerabilities.push({
                type: 'Insecure Deserialization',
                severity: 'High',
                description: 'Potential insecure deserialization',
                details: 'Found serialized data without proper validation'
            });
        }
    }

    async checkUsingComponentsWithKnownVulnerabilities(headers) {
        // Check for outdated or vulnerable components
        if (headers['x-aspnet-version'] || headers['x-aspnetmvc-version']) {
            this.vulnerabilities.push({
                type: 'Using Components with Known Vulnerabilities',
                severity: 'Medium',
                description: 'Potentially outdated framework version',
                details: 'ASP.NET version information exposed'
            });
        }
    }

    async checkInsufficientLogging(headers) {
        // Check for logging headers
        if (!headers['x-content-type-options'] || !headers['x-frame-options']) {
            this.vulnerabilities.push({
                type: 'Insufficient Logging & Monitoring',
                severity: 'Medium',
                description: 'Insufficient security logging',
                details: 'Missing security logging headers'
            });
        }
    }
}

module.exports = OWASPScanner; 