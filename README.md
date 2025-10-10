<div align="center">

# 🛡️ SafetyScan

### Automated Security Scanning Tool for Linux


**Comprehensive SAST & DAST security testing in one powerful command**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 📖 About

**SafetyScan** is a powerful, automated security scanning tool designed exclusively for **Linux environments**. It combines the best of both worlds by seamlessly integrating **Static Application Security Testing (SAST)** and **Dynamic Application Security Testing (DAST)** to provide comprehensive vulnerability detection for your applications.

> ⚠️ **Linux Only:** This tool is built specifically for Linux systems and requires a Linux environment to function properly.

### Why SafetyScan?

- 🔄 **Two-in-One Solution:** Combine SAST and DAST in a single tool
- 🐳 **Isolated Testing:** Docker-based containers ensure clean, reproducible scans
- 📊 **Actionable Reports:** Get detailed HTML and JSON reports you can actually use
- ⚡ **Developer-Friendly:** Simple CLI interface, complex security analysis
- 🆓 **Open Source:** Free, transparent, and community-driven

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Static Analysis (SAST)
- Powered by **Semgrep**
- Source code vulnerability detection
- Insecure coding pattern identification
- Multi-language support
- Zero false-positive ruleset

</td>
<td width="50%">

### 🚀 Dynamic Analysis (DAST)
- Powered by **OWASP ZAP**
- Runtime vulnerability testing
- Active security scanning
- API endpoint testing
- Configuration issue detection

</td>
</tr>
</table>

### 🎯 Core Capabilities

- ✅ **Automatic Detection:** Identifies project types and dependencies
- ✅ **Flexible Execution:** Run SAST, DAST, or both simultaneously
- ✅ **Docker Integration:** Containerized scans for security and consistency
- ✅ **Rich Reporting:** Multiple report formats (HTML, JSON, TXT)
- ✅ **Easy Setup:** Single installation script, global command access
- ✅ **Language Agnostic:** Supports Node.js, Python, Java, Go, Ruby, PHP, and more

---

## 💻 System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+, Fedora 30+, Arch Linux) |
| **Architecture** | x86_64 (64-bit) |
| **RAM** | 2 GB minimum, 4 GB recommended |
| **Disk Space** | 5 GB free space |
| **Docker** | Version 20.10+ |
| **Shell** | Bash 4.0+ |

### Tested Distributions

- ✅ Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS
- ✅ Debian 10 (Buster) / 11 (Bullseye) / 12 (Bookworm)
- ✅ CentOS 7 / 8 / Stream
- ✅ Fedora 35+
- ✅ Arch Linux
- ✅ Linux Mint 20+

---

## 📥 Installation

### Step 1: Install Docker

Docker is **required** for SafetyScan to function. Choose your distribution:

<details>
<summary><b>Ubuntu / Debian</b></summary>

```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Set up stable repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Verify installation
sudo docker --version
```

</details>

<details>
<summary><b>CentOS / RHEL / Fedora</b></summary>

```bash
# Remove old versions (if any)
sudo yum remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine

# Install required packages
sudo yum install -y yum-utils

# Add Docker repository
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker Engine
sudo yum install -y docker-ce docker-ce-cli containerd.io

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Verify installation
sudo docker --version
```

</details>

<details>
<summary><b>Arch Linux</b></summary>

```bash
# Install Docker
sudo pacman -S docker

# Start and enable Docker service
sudo systemctl start docker.service
sudo systemctl enable docker.service

# Verify installation
sudo docker --version
```

</details>

#### Post-Installation: Add User to Docker Group

Run Docker commands without `sudo`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply changes (log out and back in, or run)
newgrp docker

# Verify - this should work without sudo
docker run hello-world
```

### Step 2: Install SafetyScan

```bash
# Clone the repository
git clone https://github.com/IsMohit/SafetyScan-Automated-Security-Scanning-Tool-for-Linux-.git

# Navigate to directory
cd SafetyScan-Automated-Security-Scanning-Tool-for-Linux-

# Make install script executable
chmod +x install.sh

# Run installation (may require sudo)
./install.sh
```

### Step 3: Verify Installation

```bash
# Check if safetyscan is accessible
safetyscan --help

# Should display usage information
```

### Optional: Install jq for Enhanced JSON Parsing

```bash
# Ubuntu/Debian
sudo apt-get install jq

# CentOS/RHEL/Fedora
sudo yum install jq

# Arch Linux
sudo pacman -S jq
```

---

## 🚀 Usage

### Basic Syntax

```bash
safetyscan <project_path> --mode [sast|dast|both] [OPTIONS]
```

### Command-Line Options

| Option | Description | Required | Example |
|--------|-------------|----------|---------|
| `<project_path>` | Path to your project directory | ✅ Yes | `./myapp` |
| `--mode` | Scan type: `sast`, `dast`, or `both` | ✅ Yes | `--mode both` |
| `--start` | Command to start your application | ⚠️ DAST only | `--start "npm start"` |
| `--port` | Application port number | ⚠️ DAST only | `--port 3000` |
| `-h, --help` | Display help information | ❌ No | `-h` |

---

## 📚 Usage Examples

### Example 1: Static Analysis Only

Perfect for code review before runtime testing:

```bash
safetyscan ./my-web-app --mode sast
```

**What it does:**
- Analyzes source code for vulnerabilities
- Identifies insecure coding patterns
- Generates `semgrep.json` and `semgrep-summary.txt`

---

### Example 2: Dynamic Analysis - Node.js Application

Test a running Node.js application:

```bash
safetyscan ./my-node-app --mode dast --start "npm install && npm start" --port 3000
```

**What it does:**
- Installs dependencies and starts your app
- Runs OWASP ZAP against `http://localhost:3000`
- Generates HTML and JSON DAST reports

---

### Example 3: Dynamic Analysis - Python Flask Application

Test a Flask web application:

```bash
safetyscan ./my-flask-app --mode dast --start "pip install -r requirements.txt && python app.py" --port 5000
```

---

### Example 4: Dynamic Analysis - Java Spring Boot

Test a Spring Boot application:

```bash
safetyscan ./my-spring-app --mode dast --start "mvn spring-boot:run" --port 8080
```

---

### Example 5: Complete Security Audit (SAST + DAST)

Run both static and dynamic analysis:

```bash
safetyscan ./my-application --mode both --start "npm install && npm start" --port 3000
```

**What it does:**
1. ✅ Performs static code analysis (SAST)
2. ✅ Starts your application in a container
3. ✅ Runs dynamic security tests (DAST)
4. ✅ Generates comprehensive reports for both

---

### Example 6: React Application with Custom Port

```bash
safetyscan ./my-react-app --mode both --start "npm install && npm run start" --port 3001
```

---

### Example 7: Django Application

```bash
safetyscan ./my-django-app --mode both --start "pip install -r requirements.txt && python manage.py runserver 0.0.0.0:8000" --port 8000
```

---

## 📂 Report Structure

After scanning, all reports are saved in a timestamped directory:

```
<project_root>/
└── reports/
    └── <project_name>_YYYYMMDD_HHMMSS/
        ├── semgrep.json                 # Raw SAST output (machine-readable)
        ├── semgrep-summary.txt          # SAST findings summary (human-readable)
        ├── zap-report.html              # Full DAST report (browser-friendly)
        ├── zap-report.json              # Raw DAST output (machine-readable)
        ├── zap-warnings.html            # Critical DAST warnings (prioritized)
        └── scan-summary.txt             # Overall scan overview
```

### Report File Descriptions

| File | Format | Purpose | Best For |
|------|--------|---------|----------|
| `semgrep.json` | JSON | Complete SAST findings with metadata | CI/CD integration, automated processing |
| `semgrep-summary.txt` | Text | Human-readable vulnerability summary | Quick review, documentation |
| `zap-report.html` | HTML | Comprehensive DAST test results | Detailed analysis, stakeholder reports |
| `zap-report.json` | JSON | Structured DAST findings | Automation, tracking, dashboards |
| `zap-warnings.html` | HTML | High-priority vulnerabilities | Immediate action items |
| `scan-summary.txt` | Text | Combined SAST + DAST overview | Executive summary |

---

## 🔧 Technical Architecture

### SAST Engine: Semgrep

<table>
<tr>
<td width="30%"><b>Technology</b></td>
<td width="70%">Semgrep - Open-source static analysis</td>
</tr>
<tr>
<td><b>Analysis Method</b></td>
<td>Abstract Syntax Tree (AST) pattern matching</td>
</tr>
<tr>
<td><b>Language Support</b></td>
<td>30+ languages including JavaScript, TypeScript, Python, Java, Go, Ruby, PHP, C, C++, C#, Rust</td>
</tr>
<tr>
<td><b>Rulesets</b></td>
<td>OWASP Top 10, CWE, custom security rules</td>
</tr>
<tr>
<td><b>Output</b></td>
<td>Detailed vulnerability locations with severity ratings</td>
</tr>
</table>

### DAST Engine: OWASP ZAP

<table>
<tr>
<td width="30%"><b>Technology</b></td>
<td width="70%">OWASP Zed Attack Proxy (ZAP)</td>
</tr>
<tr>
<td><b>Analysis Method</b></td>
<td>Active web application penetration testing</td>
</tr>
<tr>
<td><b>Test Coverage</b></td>
<td>SQL Injection, XSS, CSRF, Security Headers, SSL/TLS, Authentication</td>
</tr>
<tr>
<td><b>Scanning Mode</b></td>
<td>Automated spider + active scanner</td>
</tr>
<tr>
<td><b>Standards</b></td>
<td>OWASP Top 10, PCI DSS compliance checks</td>
</tr>
</table>

---

## 🛠️ Troubleshooting

### Common Issues and Solutions

<details>
<summary><b>🔴 Docker daemon not running</b></summary>

**Error:** `Cannot connect to the Docker daemon`

**Solution:**
```bash
# Start Docker service
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Check Docker status
sudo systemctl status docker
```

</details>

<details>
<summary><b>🔴 Permission denied (Docker socket)</b></summary>

**Error:** `Got permission denied while trying to connect to the Docker daemon socket`

**Solution:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Apply changes
newgrp docker

# OR log out and back in

# Verify
docker run hello-world
```

</details>

<details>
<summary><b>🔴 Port already in use</b></summary>

**Error:** `Port 3000 is already in use`

**Solution:**
```bash
# Find process using the port
sudo lsof -i :3000

# OR
sudo netstat -tulpn | grep :3000

# Kill the process (replace PID)
kill -9 <PID>

# OR use a different port
safetyscan ./myapp --mode dast --start "npm start" --port 3001
```

</details>

<details>
<summary><b>🔴 Application fails to start in container</b></summary>

**Issue:** Application startup command doesn't work in Docker

**Solution:**
- Ensure all dependencies are installed in the start command
- Use `&&` to chain commands: `"npm install && npm start"`
- Check application logs in the container
- Verify the application binds to `0.0.0.0`, not just `localhost`

</details>

<details>
<summary><b>🔴 Command not found: safetyscan</b></summary>

**Solution:**
```bash
# Reinstall with proper permissions
cd SafetyScan-Automated-Security-Scanning-Tool-for-Linux-
sudo ./install.sh

# OR manually copy
sudo cp safetyscan.sh /usr/local/bin/safetyscan
sudo chmod +x /usr/local/bin/safetyscan
```

</details>

<details>
<summary><b>🔴 Disk space issues</b></summary>

**Solution:**
```bash
# Clean up Docker
docker system prune -a --volumes

# Check disk usage
df -h

# Remove old scan reports
rm -rf ./reports/*_old
```

</details>

---

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### How to Contribute

1. **🍴 Fork** the repository
2. **🌿 Create** a feature branch
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **💻 Commit** your changes
   ```bash
   git commit -m 'Add amazing feature'
   ```
4. **📤 Push** to your branch
   ```bash
   git push origin feature/amazing-feature
   ```
5. **🔀 Open** a Pull Request

### Contribution Guidelines

- ✅ Follow existing code style and conventions
- ✅ Write clear, descriptive commit messages
- ✅ Add comments for complex logic
- ✅ Test your changes thoroughly on multiple Linux distributions
- ✅ Update documentation for new features
- ✅ Ensure all scans pass before submitting PR

### Ideas for Contributions

- 🆕 Add support for additional scanners
- 🐛 Fix bugs and improve error handling
- 📖 Improve documentation and examples
- 🎨 Enhance report formatting
- ⚡ Performance optimizations
- 🌐 Add CI/CD integration examples

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for full details.

```
MIT License

Copyright (c) 2025 Mohit Khambekar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 🙏 Acknowledgments

SafetyScan is built on the shoulders of giants:

- **[Semgrep](https://semgrep.dev/)** - Fast, lightweight static analysis
- **[OWASP ZAP](https://www.zaproxy.org/)** - World's most popular DAST tool
- **[Docker](https://www.docker.com/)** - Containerization platform
- **[Linux Community](https://www.kernel.org/)** - For the amazing ecosystem

---

## 👨‍💻 Author

<div align="center">

**Mohit Khambekar**

[![GitHub](https://img.shields.io/badge/GitHub-IsMohit-black?logo=github)](https://github.com/IsMohit)

</div>

---

## 📞 Support & Contact

Need help? Have questions? Found a bug?

- 🐛 **Bug Reports:** [Open an Issue](https://github.com/IsMohit/SafetyScan-Automated-Security-Scanning-Tool-for-Linux-/issues/new?labels=bug)
- 💡 **Feature Requests:** [Suggest a Feature](https://github.com/IsMohit/SafetyScan-Automated-Security-Scanning-Tool-for-Linux-/issues/new?labels=enhancement)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/IsMohit/SafetyScan-Automated-Security-Scanning-Tool-for-Linux-/discussions)
- 📧 **Direct Contact:** Reach out via GitHub

---

## ⭐ Show Your Support

If SafetyScan helps secure your applications, please consider:

- ⭐ **Starring** this repository
- 🐛 **Reporting** bugs or issues
- 💡 **Suggesting** new features
- 📢 **Sharing** with your team and network
- 🤝 **Contributing** to the codebase

---

**Made with ❤️ for the Linux Community**

**Secure Code. Secure Future.**

[⬆ Back to Top](#️-safetyscan)

</div>
