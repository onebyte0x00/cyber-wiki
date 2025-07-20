// Main attacks database
const attacks = {
    "sql-injection": {
        title: "SQL Injection",
        description: `<p>One of the most common web hacking techniques where attackers inject malicious SQL commands into an application's database query.</p>
                     <p><strong>Impact:</strong> Data theft, data deletion, unauthorized access</p>`,
        code: `// VULNERABLE CODE
const query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
db.query(query);

// SECURE CODE (Parameterized Query)
const query = "SELECT * FROM users WHERE username=? AND password=?";
db.query(query, [username, password]);`,
        prevention: `<ul>
                       <li>Always use parameterized queries/prepared statements</li>
                       <li>Implement input validation</li>
                       <li>Use ORM frameworks</li>
                       <li>Apply principle of least privilege for database accounts</li>
                    </ul>`,
        visual: `graph LR
                 A[Attacker] -->|' OR '1'='1| B(Web App)
                 B -->|Executes Raw SQL| C[(Database)]
                 C -->|Returns All Data| B
                 B -->|Displays Data| A`
    },
    "xss": {
        title: "Cross-Site Scripting (XSS)",
        description: `<p>Allows attackers to inject client-side scripts into web pages viewed by other users.</p>
                     <p><strong>Types:</strong> Stored, Reflected, DOM-based</p>
                     <p><strong>Impact:</strong> Session hijacking, defacement, malware distribution</p>`,
        code: `// VULNERABLE CODE
document.getElementById('output').innerHTML = userInput;

// SECURE CODE
document.getElementById('output').textContent = userInput;

// OR (if HTML needed)
const clean = DOMPurify.sanitize(userInput);
output.innerHTML = clean;`,
        prevention: `<ul>
                       <li>Escape all untrusted data (HTML, JS, CSS contexts)</li>
                       <li>Implement Content Security Policy (CSP)</li>
                       <li>Use libraries like DOMPurify for HTML sanitization</li>
                       <li>Set HttpOnly flag on cookies</li>
                    </ul>`,
        visual: `sequenceDiagram
                 Attacker->>Website: Injects <script>alert(1)</script>
                 Website->>User: Serves malicious page
                 User->>Attacker: Executes script`
    },
    "csrf": {
        title: "Cross-Site Request Forgery (CSRF)",
        description: `<p>Forces authenticated users to submit unintended requests to a web application.</p>
                     <p><strong>Impact:</strong> Unauthorized actions (transfers, password changes)</p>`,
        code: `<!-- Malicious form on attacker's site -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit();</script>`,
        prevention: `<ul>
                       <li>Implement CSRF tokens</li>
                       <li>Use SameSite cookie attribute</li>
                       <li>Require re-authentication for sensitive actions</li>
                       <li>Check Origin/Referer headers</li>
                    </ul>`,
        visual: `graph TD
                 A[Attacker Site] -->|Tricked User| B[User's Browser]
                 B -->|Authenticated Request| C[Bank Website]
                 C -->|Processes Request| B`
    },
    "clickjacking": {
        title: "Clickjacking",
        description: `<p>Attackers trick users into clicking something different from what they perceive.</p>
                     <p><strong>Impact:</strong> Unauthorized actions, malware download</p>`,
        code: `<!-- Malicious page code -->
<style>
  iframe {
    opacity: 0.5;
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 2;
  }
  button {
    position: absolute;
    top: 300px; left: 500px;
    z-index: 1;
  }
</style>
<button>Free iPhone!</button>
<iframe src="https://bank.com/transfer?to=attacker"></iframe>`,
        prevention: `<ul>
                       <li>Implement X-Frame-Options header</li>
                       <li>Use Content Security Policy frame-ancestors</li>
                       <li>Add frame-busting JavaScript</li>
                       <li>UI confirmation for sensitive actions</li>
                    </ul>`
    },
    "mitm": {
        title: "Man-in-the-Middle (MITM)",
        description: `<p>Attackers secretly intercept and potentially alter communications.</p>
                     <p><strong>Impact:</strong> Data theft, session hijacking, traffic manipulation</p>`,
        code: `// Example of vulnerable communication
// HTTP (not HTTPS) requests are susceptible
fetch('http://bank.com/api/balance');`,
        prevention: `<ul>
                       <li>Always use HTTPS (TLS encryption)</li>
                       <li>Implement HSTS header</li>
                       <li>Certificate pinning for mobile apps</li>
                       <li>Verify certificate validity</li>
                    </ul>`,
        visual: `sequenceDiagram
                 User->>Attacker: Sends request (intercepted)
                 Attacker->>Server: Forwards request
                 Server->>Attacker: Returns response
                 Attacker->>User: Returns modified response`
    },
    "dos": {
        title: "Denial of Service (DoS)",
        description: `<p>Makes a system unavailable to legitimate users by overwhelming resources.</p>
                     <p><strong>DDoS:</strong> Distributed version using multiple systems</p>`,
        code: `// Simple DoS script example (for educational purposes)
const http = require('http');
const target = 'http://victim.com';

setInterval(() => {
  http.get(target); 
}, 10); // Rapid requests`,
        prevention: `<ul>
                       <li>Implement rate limiting</li>
                       <li>Use DDoS protection services (Cloudflare, AWS Shield)</li>
                       <li>Configure firewalls and load balancers</li>
                       <li>Scale resources horizontally</li>
                    </ul>`
    },
    "phishing": {
        title: "Phishing",
        description: `<p>Social engineering attack to steal sensitive information by masquerading as trustworthy.</p>
                     <p><strong>Variants:</strong> Spear phishing, whaling, smishing</p>`,
        prevention: `<ul>
                       <li>User education and awareness</li>
                       <li>Email filtering solutions</li>
                       <li>Multi-factor authentication</li>
                       <li>Verify URLs before clicking</li>
                    </ul>`
    },
    "brute-force": {
        title: "Brute Force",
        description: `<p>Attempting many password combinations to gain access.</p>
                     <p><strong>Variants:</strong> Dictionary attacks, credential stuffing</p>`,
        code: `# Simple brute force script (educational)
import requests

url = 'https://site.com/login'
for password in open('wordlist.txt'):
    data = {'username':'admin', 'password':password.strip()}
    r = requests.post(url, data=data)
    if 'Welcome' in r.text:
        print(f'Password found: {password}')
        break`,
        prevention: `<ul>
                       <li>Account lockout policies</li>
                       <li>Rate limiting login attempts</li>
                       <li>Strong password requirements</li>
                       <li>CAPTCHAs</li>
                    </ul>`
    },
    "session-hijacking": {
        title: "Session Hijacking",
        description: `<p>Stealing or predicting session tokens to impersonate users.</p>`,
        prevention: `<ul>
                       <li>Use secure, HttpOnly cookies</li>
                       <li>Regenerate session IDs after login</li>
                       <li>Implement session timeouts</li>
                       <li>Bind sessions to IP/user-agent</li>
                    </ul>`
    },
    "directory-traversal": {
        title: "Directory Traversal",
        description: `<p>Accessing files outside web root by manipulating file paths.</p>`,
        code: `// Vulnerable code example
app.get('/files', (req, res) => {
    const file = req.query.file;
    res.sendFile(\`/var/www/uploads/\${file}\`);
});

// Exploit: /files?file=../../etc/passwd`,
        prevention: `<ul>
                       <li>Validate user input</li>
                       <li>Use basename() to remove path traversal</li>
                       <li>Store files outside web root</li>
                       <li>Use whitelists for allowed files</li>
                    </ul>`
    },
    "xxe": {
        title: "XML External Entity (XXE)",
        description: `<p>Exploiting XML processors by including external entities.</p>`,
        code: `<!-- Malicious XML -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<user>&xxe;</user>`,
        prevention: `<ul>
                       <li>Disable DTD processing</li>
                       <li>Use JSON instead of XML</li>
                       <li>Patch XML processors</li>
                       <li>Implement input validation</li>
                    </ul>`
    },
    "idor": {
        title: "Insecure Direct Object Reference (IDOR)",
        description: `<p>Accessing objects directly by modifying parameter values.</p>`,
        code: `// Vulnerable endpoint
app.get('/profile/:id', (req, res) => {
    const user = db.getUser(req.params.id);
    res.send(user);
});

// Exploit: Access /profile/123 as regular user`,
        prevention: `<ul>
                       <li>Implement proper authorization checks</li>
                       <li>Use UUIDs instead of sequential IDs</li>
                       <li>Map objects to current user</li>
                       <li>Use access control lists</li>
                    </ul>`
    },
    "ssrf": {
        title: "Server-Side Request Forgery (SSRF)",
        description: `<p>Forcing server to make requests to internal resources.</p>`,
        code: `// Vulnerable code
app.get('/fetch', (req, res) => {
    fetch(req.query.url).then(r => r.text()).then(t => res.send(t));
});

// Exploit: /fetch?url=http://169.254.169.254/latest/meta-data`,
        prevention: `<ul>
                       <li>Validate and sanitize URLs</li>
                       <li>Use allowlists for domains</li>
                       <li>Disable unused URL schemas (file://, ftp://)</li>
                       <li>Implement network segmentation</li>
                    </ul>`
    },
    "command-injection": {
        title: "Command Injection",
        description: `<p>Executing arbitrary OS commands by injecting malicious input.</p>`,
        code: `// Vulnerable PHP code
$email = $_POST['email'];
system("mail -s 'Test' " . $email);

// Exploit: email=attacker@evil.com; rm -rf /`,
        prevention: `<ul>
                       <li>Use built-in functions instead of commands</li>
                       <li>Implement strict input validation</li>
                       <li>Use parameterized APIs</li>
                       <li>Run with least privileges</li>
                    </ul>`
    },
    "insecure-deserialization": {
        title: "Insecure Deserialization",
        description: `<p>Manipulating serialized objects to execute malicious code.</p>`,
        code: `# Python pickle example (vulnerable)
import pickle

data = pickle.loads(user_controlled_input)`,
        prevention: `<ul>
                       <li>Avoid serialization if possible</li>
                       <li>Use digital signatures</li>
                       <li>Validate serialized data</li>
                       <li>Use safe formats like JSON</li>
                    </ul>`
    },
    "zero-day": {
        title: "Zero-Day Exploit",
        description: `<p>Attacks targeting vulnerabilities unknown to vendors.</p>`,
        prevention: `<ul>
                       <li>Keep systems patched and updated</li>
                       <li>Use intrusion detection systems</li>
                       <li>Implement defense in depth</li>
                       <li>Monitor for unusual activity</li>
                    </ul>`
    },
    "api-abuse": {
        title: "API Abuse",
        description: `<p>Exploiting poorly secured APIs through excessive requests or parameter manipulation.</p>`,
        prevention: `<ul>
                       <li>Implement proper authentication</li>
                       <li>Use rate limiting</li>
                       <li>Validate all input</li>
                       <li>Use API gateways</li>
                    </ul>`
    },
    "crypto-failure": {
        title: "Cryptographic Failures",
        description: `<p>Weak or improper use of cryptography leading to data exposure.</p>`,
        code: `// Vulnerable crypto usage
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');`,
        prevention: `<ul>
                       <li>Use strong algorithms (AES, SHA-256, bcrypt)</li>
                       <li>Never implement your own crypto</li>
                       <li>Rotate keys regularly</li>
                       <li>Use TLS everywhere</li>
                    </ul>`
    },
    "misconfiguration": {
        title: "Security Misconfiguration",
        description: `<p>Default configurations, unused pages, unprotected files.</p>`,
        prevention: `<ul>
                       <li>Harden systems according to best practices</li>
                       <li>Automate configuration checks</li>
                       <li>Minimize installed components</li>
                       <li>Regularly audit configurations</li>
                    </ul>`
    },
    "supply-chain": {
        title: "Supply Chain Attacks",
        description: `<p>Compromising software dependencies or vendor systems.</p>`,
        prevention: `<ul>
                       <li>Verify package signatures</li>
                       <li>Monitor for suspicious updates</li>
                       <li>Use dependency scanning tools</li>
                       <li>Maintain a software bill of materials</li>
                    </ul>`
    }
};

// Attack categories for organization
const attackCategories = {
    "Injection Attacks": ["sql-injection", "command-injection", "xxe"],
    "Authentication Issues": ["brute-force", "session-hijacking", "csrf"],
    "Data Exposure": ["crypto-failure", "idor", "directory-traversal"],
    "Client-Side Attacks": ["xss", "clickjacking"],
    "Server-Side Attacks": ["ssrf", "insecure-deserialization"],
    "Network Attacks": ["mitm", "dos"],
    "Social Engineering": ["phishing"],
    "Configuration Issues": ["misconfiguration", "api-abuse"],
    "Emerging Threats": ["zero-day", "supply-chain"]
};

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    // Populate attack list by category
    const attackList = document.getElementById('attack-list');
    
    for (const [category, attackIds] of Object.entries(attackCategories)) {
        const categoryHeader = document.createElement('h3');
        categoryHeader.textContent = category;
        attackList.appendChild(categoryHeader);
        
        const categoryList = document.createElement('ul');
        categoryList.className = 'category-list';
        
        attackIds.forEach(attackId => {
            const attack = attacks[attackId];
            const li = document.createElement('li');
            li.textContent = attack.title;
            li.onclick = () => showAttack(attackId);
            categoryList.appendChild(li);
        });
        
        attackList.appendChild(categoryList);
    }

    // Search functionality
    document.getElementById('search').addEventListener('input', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        const categories = attackList.getElementsByClassName('category-list');
        
        Array.from(categories).forEach(category => {
            let hasVisibleItems = false;
            const items = category.getElementsByTagName('li');
            
            Array.from(items).forEach(item => {
                const text = item.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    item.style.display = 'block';
                    hasVisibleItems = true;
                } else {
                    item.style.display = 'none';
                }
            });
            
            // Hide entire category if no matches
            category.previousElementSibling.style.display = hasVisibleItems ? 'block' : 'none';
            category.style.display = hasVisibleItems ? 'block' : 'none';
        });
    });

    // Load attack from URL hash if present
    if (window.location.hash) {
        const attackId = window.location.hash.substring(1);
        if (attacks[attackId]) {
            showAttack(attackId);
        }
    }
});

// Show attack details
function showAttack(attackId) {
    const attack = attacks[attackId];
    
    // Update URL without page reload
    history.pushState(null, null, `#${attackId}`);
    
    // Set content
    document.getElementById('attack-title').textContent = attack.title;
    document.getElementById('attack-description').innerHTML = attack.description || '<p>No description available.</p>';
    document.getElementById('attack-code').textContent = attack.code || '// No code example available';
    document.getElementById('attack-prevention').innerHTML = attack.prevention || '<p>No prevention information available.</p>';
    
    // Handle visualization
    const visualContainer = document.getElementById('attack-visual');
    if (attack.visual) {
        visualContainer.innerHTML = `<div class="mermaid">${attack.visual}</div>`;
        // Initialize Mermaid if available
        if (typeof mermaid !== 'undefined') {
            mermaid.init();
        }
    } else {
        visualContainer.innerHTML = '<p>No visualization available.</p>';
    }
    
    // Show attack content and hide welcome message
    document.querySelector('.welcome-message').style.display = 'none';
    document.getElementById('attack-content').style.display = 'block';
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
    
    // Highlight selected attack in sidebar
    const allItems = document.querySelectorAll('#attack-list li');
    allItems.forEach(item => item.classList.remove('active'));
    
    const activeItems = document.querySelectorAll(`#attack-list li`);
    Array.from(activeItems).forEach(item => {
        if (item.textContent === attack.title) {
            item.classList.add('active');
        }
    });
}

// Handle browser back/forward buttons
window.addEventListener('popstate', function() {
    if (window.location.hash) {
        const attackId = window.location.hash.substring(1);
        if (attacks[attackId]) {
            showAttack(attackId);
        }
    } else {
        document.querySelector('.welcome-message').style.display = 'block';
        document.getElementById('attack-content').style.display = 'none';
    }
});
