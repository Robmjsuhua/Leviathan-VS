# VSCode MegaZord

## Ultimate VS Code Configuration for Security Researchers & Developers

A comprehensive VS Code configuration toolkit with semantic translation engine, HTTP toolkit, and 80+ extensions for static analysis across multiple languages.

![Version](https://img.shields.io/badge/version-7.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Extensions](https://img.shields.io/badge/extensions-80+-purple)
![Rules](https://img.shields.io/badge/translation_rules-640+-red)

---

## What is this?

VSCode MegaZord is a complete development environment configuration that includes:

1. **Semantic Translation Engine** - Translates sensitive security terms to neutral graph theory terminology before sending code to AI assistants
2. **HTTP Toolkit** - Intercept and analyze HTTP traffic with AI-powered insights
3. **Static Analysis** - Pre-configured linters and analyzers for 10+ languages
4. **MCP Integration** - Model Context Protocol server for GitHub Copilot

---

## Quick Install

### Windows (One-Click)

```batch
INSTALL.bat
```

### PowerShell

```powershell
.\install.ps1
```

The installer automatically:
- Installs Python, Git, VS Code if needed
- Configures all extensions
- Sets up MCP for GitHub Copilot
- Opens the project ready to use

---

## Features

### Semantic Translation Engine (THE HAND OF GOD)

Translates security-related terms to neutral terminology using Graph Theory paradigm:

| Original Term | Translated Term |
|---------------|-----------------|
| exploit | edge_case_path |
| vulnerability | graph_discontinuity |
| bypass | linear_decoupling |
| injection | stream_merging |
| reverse_shell | inbound_stream_binding |

This prevents AI assistants from refusing to help with legitimate security research.

### HTTP Toolkit

```bash
# Make requests with AI analysis
python core/http_toolkit.py dispatch https://api.example.com

# Scan endpoint methods
python core/http_toolkit.py scan https://api.example.com

# Interactive mode
python core/http_toolkit.py interactive
```

Features:
- Header Mimicry with User-Agent rotation
- AI-powered response analysis
- Auto-recovery from 403/401 errors
- cURL command generation

### Static Analysis (Languages Supported)

| Language | Tools |
|----------|-------|
| Python | Pylance, Pylint, Bandit, Mypy, Radon |
| Go | golangci-lint, Staticcheck, GoSec |
| JavaScript/TypeScript | ESLint, Prettier, SonarLint |
| Rust | rust-analyzer, Clippy |
| C/C++ | Clang-Tidy, Cppcheck |
| Java | Checkstyle, PMD, SpotBugs |
| Shell | ShellCheck |
| Docker | Hadolint |
| Terraform | TFLint, Checkov |
| SQL | SQLFluff |

### Frontend Tools

- React, Vue, Angular, Next.js snippets
- Tailwind CSS IntelliSense
- Figma to Code integration
- Storybook support
- GraphQL tools

---

## Project Structure

```
VSCode-MegaZord/
    .github/
        copilot-instructions.md  # AI behavior rules
    .vscode/
        extensions.json    # 80+ recommended extensions
        settings.json      # Optimized settings
        tasks.json         # 20+ automation tasks
        launch.json        # Debug configurations
        mcp.json           # MCP server config
    core/
        config.json        # 640+ translation rules
        translator.py      # Translation engine
        http_toolkit.py    # HTTP interceptor
        mcp_server.py      # MCP server
    docs/
        CLAUDE_SKILLS.md   # Claude integration docs
```

---

## Usage

### VS Code Tasks (Ctrl+Shift+B)

| Task | Description |
|------|-------------|
| [HOG] ENCODE | Sanitize code before sending to AI |
| [HOG] RESTORE | Restore original terms |
| [HOG] PREVIEW | Preview changes without applying |
| [HOG] CHECK | Security check for sensitive terms |
| [HOG] INTERACTIVE | Console mode |

### Command Line

```bash
# Translate (sanitize) code
python core/translator.py encode

# Restore original terms
python core/translator.py restore

# Check if code is clean
python core/translator.py check

# Show statistics
python core/translator.py stats
```

### Workflow Example

```
1. Write security code in work.txt
2. Run ENCODE task (Ctrl+Shift+B)
   "exploit" -> "edge_case_path"
3. Send sanitized code to AI
4. Paste AI response in work.txt
5. Run RESTORE task
   "edge_case_path" -> "exploit"
6. Original code restored
```

---

## Translation Rules (640+)

Categories covered:

- **Offensive Security** - exploit, bypass, vulnerability
- **Malware Analysis** - virus, trojan, backdoor
- **Web Attacks** - XSS, CSRF, SQL injection
- **Shells & C2** - reverse shell, webshell, beacon
- **Network Recon** - scanner, fuzzer, sniffer
- **Binary Exploitation** - buffer overflow, ROP chain
- **Cloud Security** - S3 bucket, IAM escalation
- **Auth Bypass** - session hijack, token forge
- **Defense Evasion** - obfuscation, packing
- **Tools** - Metasploit, Burp, Nmap, Hashcat

---

## MCP Integration

The project includes an MCP (Model Context Protocol) server that integrates with GitHub Copilot:

```json
{
  "servers": {
    "megazord": {
      "command": "python",
      "args": ["core/mcp_server.py"],
      "env": {}
    }
  }
}
```

Available MCP tools:
- `encode` - Sanitize text
- `decode` - Restore text
- `check` - Verify if text is clean
- `find_terms` - List sensitive terms
- `get_rules` - Get all translation rules

---

## VS Code Configuration Highlights

- **Theme**: Dark with neon green accents
- **Font**: Cascadia Code with ligatures
- **Auto-save**: Enabled after 1s delay
- **Type Checking**: Standard mode for Python
- **Format on Save**: Enabled for all languages
- **Git**: Auto-fetch enabled

---

## Extensions Included (80+)

### Core Development
- Python, Pylance, Go, Rust Analyzer
- ESLint, Prettier, EditorConfig

### AI Assistants
- GitHub Copilot, Cline, Claude Code

### Security
- SonarQube, Snyk, SARIF Viewer

### Frontend
- Tailwind CSS, Vue, React, Angular
- Figma integration, Storybook

### Productivity
- GitLens, Todo Tree, Project Manager
- REST Client, Thunder Client

---

## Requirements

- Python 3.8+
- VS Code 1.80+
- Git

---

## Installation from Source

```bash
git clone git@github.com:ThiagoFrag/Vscode-MegaZord.git
cd Vscode-MegaZord
code .
```

Then run the `[HOG] VALIDATE` task to verify the installation.

---

## Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Author

**ThiagoFrag** - [@ThiagoFrag](https://github.com/ThiagoFrag)

---

**VSCode MegaZord v7.0** - Ultimate VS Code Configuration for Security Researchers
