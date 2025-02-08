# PDF Security Testing Tool

A comprehensive security testing tool for PDF processing services and viewers. This tool generates PDF files containing various security test payloads to help identify potential vulnerabilities in PDF processing systems.

⚠️ **WARNING: This tool is for authorized security testing only. Never use against production systems without explicit permission.**

## Features

### Test Categories
- **Metadata Injection**
  - JNDI injection attempts
  - XXE in metadata
  - Template injection
  
- **JavaScript Execution**
  - Cloud metadata access
  - File system operations
  - Network callbacks
  
- **Embedded Content**
  - Malicious file attachments
  - Nested PDFs
  - Hidden JavaScript files
  
- **Structure Tests**
  - Malformed XRef tables
  - Invalid object streams
  - Buffer overflow attempts
  
- **Advanced Features**
  - XFA form injection
  - Digital signature manipulation
  - Font-based attacks
  - Annotation exploits

### Key Capabilities
- Configurable test categories
- Detailed execution logging
- Comprehensive reporting
- Cloud service testing (AWS, Azure, GCP)
- Multiple PDF viewer targeting

## Prerequisites

- Python 3.7+
- Required packages:
  ```bash
  pip install PyPDF2 reportlab
  ```

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pdf-security-tester.git
cd pdf-security-tester

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python pdf_security_tester.py --callback-host your.server.com --callback-port 8080
```

### With Configuration File

```bash
python pdf_security_tester.py --callback-host your.server.com --callback-port 8080 --config config.json
```

Example `config.json`:
```json
{
    "enabled_categories": [
        "metadata",
        "javascript",
        "xss",
        "embedded_files"
    ],
    "excluded_payloads": ["Command Injection"],
    "min_severity": "Medium",
    "callback_timeout": 30
}
```

### Command Line Options

```
--callback-host     Callback host for SSRF tests
--callback-port     Callback port
--output           Output PDF path (default: security_test.pdf)
--config           Path to configuration JSON file
--verbose          Enable verbose logging
```

## Test Categories

### 1. Metadata Tests
Tests PDF metadata handling including:
- XML external entity injection
- Template injection
- Command execution

### 2. JavaScript Tests
Tests PDF JavaScript execution:
- Cloud metadata access attempts
- File system operations
- Network callbacks

### 3. Embedded Content
Tests handling of embedded files:
- Executable attachments
- Nested PDFs
- Hidden JavaScript

### 4. Structure Tests
Tests PDF structure handling:
- Malformed XRef tables
- Invalid object streams
- Buffer overflow attempts

### 5. Advanced Tests
Additional test categories:
- XFA form injection
- Digital signature manipulation
- Font-based attacks
- Annotation exploits

## Configuration Options

### Category Enable/Disable
```json
{
    "enabled_categories": [
        "metadata",
        "javascript",
        "xss"
    ]
}
```

### Severity Filtering
```json
{
    "min_severity": "Medium",  // Low, Medium, High, Critical
    "excluded_payloads": ["Command Injection"]
}
```

### Custom Payloads
```json
{
    "custom_payloads": [
        {
            "name": "Custom Test",
            "content": "test content",
            "category": "xss",
            "severity": "High"
        }
    ]
}
```

## Output

### Generated Files
1. Test PDF (`security_test.pdf`)
2. Detailed report (`security_test.pdf.report.json`)
3. Execution log (`pdf_security_test_YYYYMMDD_HHMMSS.log`)

### Report Format
```json
{
    "timestamp": "2024-02-08T12:00:00",
    "pdf_path": "security_test.pdf",
    "test_id": "unique_test_id",
    "statistics": {
        "successful_payloads": 10,
        "failed_payloads": 2,
        "total_payloads": 12
    },
    "payloads": [
        {
            "name": "Test Name",
            "category": "Category",
            "severity": "High",
            "success": true
        }
    ]
}
```

## Security Considerations

### Testing Environment
- Use in isolated, controlled environments only
- Monitor all network traffic during testing
- Review logs for unexpected behavior
- Test with different PDF viewers

### Supported PDF Viewers
- Adobe Acrobat DC (JavaScript execution, metadata parsing)
- PDF.js (Limited JavaScript execution, content rendering)
- Chrome PDF Viewer (Basic rendering)
- Microsoft Edge PDF Viewer (Basic rendering)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Disclaimer

This tool is for authorized security testing only. Users are responsible for obtaining proper authorization before testing any systems.
