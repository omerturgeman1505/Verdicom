# Installation Guide - Required Python Packages

## Quick Installation

To install all required packages, run:

```bash
pip install -r requirements.txt
```

## Required Packages Breakdown

### Core Application Dependencies
- **flask** - Web framework for the dashboard
- **requests** - HTTP library for API calls
- **python-dotenv** - Environment variable management
- **certifi** - SSL certificates bundle

### Email Processing
- **extract-msg** - Extract attachments and content from .msg files
- **msg-parser** - Parse Outlook .msg files
- **beautifulsoup4** - HTML parsing for email body
- **feedparser** - RSS feed parsing

### File Analysis
- **pdfminer.six** - PDF text extraction
- **PyPDF2** / **pypdf2~=3.0.1** - PDF processing
- **python-docx** - Word document processing
- **filetype** - File type detection
- **openpyxl** - Excel file processing (used implicitly)

### Magic-Spoofing / DKIM Check Dependencies
- **pydig>=0.4.0** - DNS queries (required for DKIM/SPF/DMARC checks)
- **dnspython>=2.2.1** - DNS toolkit (required for DNS resolver)
- **ipaddress>=1.0.23** - IP address manipulation
- **dkimpy>=1.0.5** - DKIM signature support
- **python-whois>=0.7.3** - WHOIS queries
- **argparse>=1.4.0** - Command-line argument parsing
- **secure-smtplib>=0.1.1** - Secure SMTP
- **email-to>=0.1.0** - Email utilities

## Installation Steps

1. **Navigate to project directory:**
   ```bash
   cd threat-Mobileye-dashboard
   ```

2. **Install all packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify Magic-Spoofing dependencies:**
   After installation, start the application and check the console output:
   - You should see: `[App] ✓ Magic-Spoofing DKIM check available`
   - If you see: `[App] ⚠️ Magic-Spoofing DKIM check not available: [error]`
     - Check which package is missing
     - Verify that the `Magic-Spoofing` directory exists in the project root

## Important Notes

1. **Magic-Spoofing Directory:**
   - The `Magic-Spoofing` directory must be present in the project root
   - The DKIM check functionality requires this directory to be accessible

2. **DNS Resolution:**
   - The DKIM check requires DNS queries
   - Make sure your network allows DNS resolution
   - If you're behind a firewall, ensure DNS ports (53) are accessible

3. **Windows Users:**
   - Some packages may require Microsoft Visual C++ Build Tools
   - If you encounter compilation errors, install: [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

4. **Virtual Environment (Recommended):**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   
   pip install -r requirements.txt
   ```

## Troubleshooting

### DKIM Check Not Available

If DKIM check is not working:

1. Check console output for error messages
2. Verify all Magic-Spoofing dependencies are installed:
   ```bash
   pip list | grep -E "pydig|dnspython|dkimpy|ipaddress"
   ```
3. Check if Magic-Spoofing directory exists:
   ```bash
   ls Magic-Spoofing/  # Linux/Mac
   dir Magic-Spoofing  # Windows
   ```

### Missing Packages

If a package installation fails:

1. Update pip:
   ```bash
   python -m pip install --upgrade pip
   ```

2. Install problematic package separately:
   ```bash
   pip install [package-name]
   ```

3. For Windows users with compilation errors, consider using pre-compiled wheels or installing Visual C++ Build Tools.

