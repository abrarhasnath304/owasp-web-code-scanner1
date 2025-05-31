        const vulnerabilityChecks = [
            // A01 - Broken Access Control
            {
                pattern: /window\.location\s*=\s*['"`][^'"`]*\/[^'"`]*\+[^'"`]*['"`]/gi,
                title: "A01 - Insecure Direct Object Reference",
                description: "Direct access to objects using user input without proper authorization checks",
                severity: "high",
                owasp: "A01"
            },
            {
                pattern: /\$_GET\[[^]]+\]|\$_POST\[[^]]+\]/gi,
                title: "A01 - Unvalidated Input Access",
                description: "Direct access to user input without validation or authorization",
                severity: "medium",
                owasp: "A01"
            },
            
            // A02 - Cryptographic Failures
            {
                pattern: /md5\s*\(|sha1\s*\(/gi,
                title: "A02 - Weak Cryptographic Hash",
                description: "Using weak hashing algorithms (MD5, SHA1) for security purposes",
                severity: "high",
                owasp: "A02"
            },
            {
                pattern: /password\s*=\s*['"`][^'"`]+['"`]/gi,
                title: "A02 - Hardcoded Password",
                description: "Hardcoded passwords in source code expose sensitive credentials",
                severity: "critical",
                owasp: "A02"
            },
            
            // A03 - Injection
            {
                pattern: /SELECT\s+.*\+.*['"`]/gi,
                title: "A03 - SQL Injection",
                description: "SQL query constructed with string concatenation - vulnerable to injection",
                severity: "critical",
                owasp: "A03"
            },
            {
                pattern: /innerHTML\s*=.*\+/gi,
                title: "A03 - Cross-Site Scripting (XSS)",
                description: "Direct insertion of user input into HTML without sanitization",
                severity: "high",
                owasp: "A03"
            },
            {
                pattern: /eval\s*\(/gi,
                title: "A03 - Code Injection",
                description: "Use of eval() function can lead to code injection vulnerabilities",
                severity: "critical",
                owasp: "A03"
            },
            {
                pattern: /document\.write\s*\(.*\+/gi,
                title: "A03 - DOM-based XSS",
                description: "Using document.write with user input can lead to XSS",
                severity: "high",
                owasp: "A03"
            },
            
            // A05 - Security Misconfiguration
            {
                pattern: /Access-Control-Allow-Origin:\s*\*/gi,
                title: "A05 - Insecure CORS Configuration",
                description: "Wildcard CORS policy allows any domain to make requests",
                severity: "medium",
                owasp: "A05"
            },
            {
                pattern: /console\.log\s*\(.*password|console\.log\s*\(.*token/gi,
                title: "A05 - Information Disclosure",
                description: "Logging sensitive information to console",
                severity: "medium",
                owasp: "A05"
            },
            
            // A07 - Authentication Failures
            {
                pattern: /if\s*\(\s*password\s*==\s*['"`][^'"`]+['"`]\)|if\s*\(\s*['"`][^'"`]+['"`]\s*==\s*password\)/gi,
                title: "A07 - Weak Authentication",
                description: "Hardcoded password comparison in authentication logic",
                severity: "critical",
                owasp: "A07"
            },
            {
                pattern: /session_start\(\)(?!.*session_regenerate_id)/gi,
                title: "A07 - Session Fixation",
                description: "Session started without regenerating session ID",
                severity: "medium",
                owasp: "A07"
            },
            
            // A09 - Logging Failures
            {
                pattern: /catch\s*\([^)]*\)\s*\{[\s\n]*\}/gi,
                title: "A09 - Silent Error Handling",
                description: "Empty catch blocks hide errors and security events",
                severity: "low",
                owasp: "A09"
            },
            
            // A10 - Server-Side Request Forgery
            {
                pattern: /fetch\s*\(\s*[^)]*\+|XMLHttpRequest.*open.*\+/gi,
                title: "A10 - Potential SSRF",
                description: "HTTP requests with user-controlled URLs can lead to SSRF",
                severity: "high",
                owasp: "A10"
            },
            
            // Additional Security Issues
            {
                pattern: /document\.cookie\s*=(?!.*secure|.*httponly)/gi,
                title: "A05 - Insecure Cookie",
                description: "Cookies set without Secure or HttpOnly flags",
                severity: "medium",
                owasp: "A05"
            },
            {
                pattern: /setTimeout\s*\(.*\+|setInterval\s*\(.*\+/gi,
                title: "A03 - Code Injection via Timer",
                description: "Using user input in setTimeout/setInterval can lead to code injection",
                severity: "high",
                owasp: "A03"
            }
        ];

        function scanCode() {
            const code = document.getElementById('codeInput').value;
            const resultsDiv = document.getElementById('results');
            const statsDiv = document.getElementById('stats');
            
            if (!code.trim()) {
                resultsDiv.innerHTML = '<div class="no-issues">Please enter some code to scan.</div>';
                statsDiv.style.display = 'none';
                return;
            }
            
            const vulnerabilities = [];
            const lines = code.split('\n');
            
            // Check each vulnerability pattern
            vulnerabilityChecks.forEach(check => {
                const matches = code.match(check.pattern);
                if (matches) {
                    matches.forEach(match => {
                        // Find line number
                        let lineNumber = 1;
                        let currentIndex = 0;
                        for (let i = 0; i < lines.length; i++) {
                            if (lines[i].includes(match.replace(/\s+/g, ' ').trim()) || 
                                lines[i].toLowerCase().includes(match.toLowerCase().replace(/\s+/g, ' ').trim())) {
                                lineNumber = i + 1;
                                break;
                            }
                        }
                        
                        vulnerabilities.push({
                            ...check,
                            match: match.trim(),
                            line: lineNumber
                        });
                    });
                }
            });
            
            // Remove duplicates
            const uniqueVulns = vulnerabilities.filter((vuln, index, self) => 
                index === self.findIndex(v => v.title === vuln.title && v.line === vuln.line)
            );
            
            // Count by severity
            const counts = {
                critical: uniqueVulns.filter(v => v.severity === 'critical').length,
                high: uniqueVulns.filter(v => v.severity === 'high').length,
                medium: uniqueVulns.filter(v => v.severity === 'medium').length,
                low: uniqueVulns.filter(v => v.severity === 'low').length
            };
            
            // Update stats
            document.getElementById('criticalCount').textContent = counts.critical;
            document.getElementById('highCount').textContent = counts.high;
            document.getElementById('mediumCount').textContent = counts.medium;
            document.getElementById('lowCount').textContent = counts.low;
            statsDiv.style.display = uniqueVulns.length > 0 ? 'flex' : 'none';
            
            // Display results
            if (uniqueVulns.length === 0) {
                resultsDiv.innerHTML = '<div class="no-issues">✅ No obvious vulnerabilities detected! Remember to also check for business logic flaws and conduct thorough testing.</div>';
            } else {
                // Sort by severity
                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                uniqueVulns.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
                
                resultsDiv.innerHTML = uniqueVulns.map(vuln => `
                    <div class="vulnerability ${vuln.severity}">
                        <div class="vuln-title">${vuln.title}</div>
                        <div class="vuln-description">${vuln.description}</div>
                        <div class="vuln-line">Line ${vuln.line}: ${vuln.match}</div>
                    </div>
                `).join('');
            }
        }

        // Sample vulnerable code for demonstration
        document.getElementById('codeInput').addEventListener('focus', function() {
            if (this.value.includes('Example vulnerable code:')) {
                this.value = `<script>
function login() {
    var username = document.getElementById('user').value;
    var password = document.getElementById('pass').value;
    
    // SQL Injection vulnerability
    var query = 'SELECT * FROM users WHERE username=\\'' + username + '\\' AND password=\\'' + password + '\\'';
    
    // XSS vulnerability
    document.getElementById('welcome').innerHTML = 'Welcome ' + username;
    
    // Insecure direct object reference
    window.location = '/profile/' + username;
}

// Hardcoded password
var adminPassword = 'admin123';

// Weak authentication
if (password == 'secret') {
    console.log('Login successful for: ' + username);
}
</script>

<php>
// More vulnerabilities
$user_id = $_GET['id'];
$password_hash = md5($password);
</php>`;
            }
        });

        // Add URL scanning functionality
        async function scanUrl() {
            const url = document.getElementById('urlInput').value;
            const resultsDiv = document.getElementById('results');
            const statsDiv = document.getElementById('stats');
            
            if (!url.trim()) {
                resultsDiv.innerHTML = '<div class="no-issues">Please enter a URL to scan.</div>';
                statsDiv.style.display = 'none';
                return;
            }

            try {
                resultsDiv.innerHTML = '<div class="scanning">🔍 Scanning URL for vulnerabilities...</div>';
                
                const response = await fetch('http://localhost:3000/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();
                
                if (data.error) {
                    resultsDiv.innerHTML = `<div class="error">❌ Error: ${data.error}</div>`;
                    statsDiv.style.display = 'none';
                    return;
                }

                // Count vulnerabilities by severity
                const counts = {
                    critical: data.vulnerabilities.filter(v => v.severity === 'Critical').length,
                    high: data.vulnerabilities.filter(v => v.severity === 'High').length,
                    medium: data.vulnerabilities.filter(v => v.severity === 'Medium').length,
                    low: data.vulnerabilities.filter(v => v.severity === 'Low').length
                };

                // Update stats
                document.getElementById('criticalCount').textContent = counts.critical;
                document.getElementById('highCount').textContent = counts.high;
                document.getElementById('mediumCount').textContent = counts.medium;
                document.getElementById('lowCount').textContent = counts.low;
                statsDiv.style.display = data.vulnerabilities.length > 0 ? 'flex' : 'none';

                // Display results
                if (data.vulnerabilities.length === 0) {
                    resultsDiv.innerHTML = '<div class="no-issues">✅ No vulnerabilities detected! Remember to also check for business logic flaws and conduct thorough testing.</div>';
                } else {
                    // Sort by severity
                    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
                    data.vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
                    
                    resultsDiv.innerHTML = data.vulnerabilities.map(vuln => `
                        <div class="vulnerability ${vuln.severity.toLowerCase()}">
                            <div class="vuln-title">${vuln.type}</div>
                            <div class="vuln-description">${vuln.description}</div>
                            <div class="vuln-details">${vuln.details}</div>
                        </div>
                    `).join('');
                }
            } catch (error) {
                resultsDiv.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
                statsDiv.style.display = 'none';
            }
        }