

<h1>VulnScanner: Injection Vulnerability Detection Tool</h1>

<h2>Overview</h2>
<p>VulnScanner is a Python-based tool designed to automate the detection of injection vulnerabilities in web applications, emphasizing on Cross-Site Scripting (XSS) and SQL Injection (SQLi) vulnerabilities. Developed as part of a project at the University of Central Florida, this tool aims to enhance web application security by facilitating the early identification and remediation of potential vulnerabilities.</p>

<h2>Features</h2>
<ul>
    <li><strong>Automated Scanning:</strong> Quickly identifies injection vulnerabilities across web applications.</li>
    <li><strong>Support for XSS and SQLi:</strong> Focuses on the detection of Cross-Site Scripting and SQL Injection vulnerabilities.</li>
    <li><strong>User Authentication Support:</strong> Capable of scanning applications post-authentication using provided user credentials.</li>
    <li><strong>Flexible and Configurable:</strong> Easily adaptable to test various web applications with minor adjustments to the scanner's code.</li>
</ul>

<h2>Installation</h2>
<p>Ensure you have Python installed on your system (Windows or Linux). Minimum requirements: 8 GB Memory, 256 GB Storage.</p>

<h2>Dependencies</h2>
<p>Install the necessary Python libraries:</p>
<pre><code>pip install bs4
pip install requests</code></pre>

<h2>Setting Up Your Environment</h2>
<ul>
    <li>Install a Python IDE of your choice.</li>
    <li>Setup a virtual environment (optional but recommended).</li>
    <li>Clone this repository:</li>
</ul>
<pre><code>git clone https://github.com/Krishna-Vamsi-G/Advanced-Software-System-Security.git</code></pre>

<h2>Running VulnScanner</h2>
<p>Navigate to the cloned directory:</p>
<pre><code>cd VulnScanner</code></pre>
<p>Execute the script:</p>
<pre><code>python3 vulnerability_scanner.py</code></pre>
<p>Follow the on-screen instructions to select the target for vulnerability scanning. Options include predefined targets like MyUCF, VulnWeb, DVWA, or a custom URL.</p>

<h2>How It Works</h2>
<p>VulnScanner follows a three-step process:</p>
<ol>
    <li><strong>Crawling:</strong> Identifies all associated URLs of the target web application.</li>
    <li><strong>Form Extraction:</strong> Uses BeautifulSoup and Requests libraries to extract forms from webpages for testing.</li>
    <li><strong>Payload Injection:</strong> Tests for vulnerabilities by injecting payloads and analyzing the responses.</li>
</ol>

<h2>Contributions and Future Work</h2>
<p>We welcome contributions to VulnScanner! Future versions aim to improve SQLi detection accuracy and support for Multi-Factor Authentication scenarios. Feel free to fork this project and submit your pull requests.</p>

<h2>Acknowledgements</h2>
<p>Developed by Krishna Vamsi G and Khoushik Reddy C at the University of Central Florida.</p>

<h2>References</h2>
<p>For a detailed understanding of the methodologies and technologies used in this project, refer to the VulnScanner Project Report.</p>

</body>
</html>
