"""Unit tests for package scanner."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from src.scanner.scan_packages import PackageScanner, ScanResult, ScanStatus


@pytest.fixture
def temp_scans_dir(tmp_path):
    """Create temporary scans directory."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    return scans_dir


@pytest.fixture
def scanner(temp_scans_dir):
    """Create PackageScanner instance for testing."""
    with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
        return PackageScanner(
            scanner_type="trivy",
            timeout=60,
            scans_dir=str(temp_scans_dir),
            min_cvss_score=7.0,
            block_severities=["CRITICAL", "HIGH"],
        )


class TestPackageScanner:
    """Tests for PackageScanner class."""

    def test_parse_package_name(self, scanner):
        """Test package name parsing."""
        name, version = scanner._parse_package_name("curl_7.81.0-1ubuntu1.16_amd64.deb")
        assert name == "curl"
        assert version == "7.81.0-1ubuntu1.16"

    def test_parse_package_name_simple(self, scanner):
        """Test package name parsing with simple format."""
        name, version = scanner._parse_package_name("simple-package.deb")
        assert name == "simple-package.deb"
        assert version == "unknown"

    def test_analyze_results_no_vulnerabilities(self, scanner):
        """Test analysis with no vulnerabilities."""
        result = scanner._analyze_results("test-package", "1.0.0", [])

        assert result.package_name == "test-package"
        assert result.package_version == "1.0.0"
        assert result.status == ScanStatus.APPROVED
        assert result.cve_count == 0
        assert result.cvss_max == 0.0

    def test_analyze_results_with_high_severity(self, scanner):
        """Test analysis with high severity vulnerabilities."""
        vulnerabilities = [
            {
                "cve_id": "CVE-2023-1234",
                "severity": "HIGH",
                "cvss_score": 8.5,
                "package": "test-package",
            }
        ]

        result = scanner._analyze_results("test-package", "1.0.0", vulnerabilities)

        assert result.status == ScanStatus.BLOCKED
        assert result.cve_count == 1
        assert result.cvss_max == 8.5

    def test_analyze_results_below_threshold(self, scanner):
        """Test analysis with vulnerabilities below threshold."""
        vulnerabilities = [
            {
                "cve_id": "CVE-2023-5678",
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "package": "test-package",
            }
        ]

        result = scanner._analyze_results("test-package", "1.0.0", vulnerabilities)

        assert result.status == ScanStatus.APPROVED
        assert result.cve_count == 1
        assert result.cvss_max == 5.0

    def test_error_result(self, scanner):
        """Test error result creation."""
        result = scanner._error_result("test-package", "Scan failed", "1.0.0")

        assert result.package_name == "test-package"
        assert result.package_version == "1.0.0"
        assert result.status == ScanStatus.ERROR
        assert result.error_message == "Scan failed"

    def test_save_result(self, scanner, temp_scans_dir):
        """Test saving scan results."""
        result = ScanResult(
            package_name="test-package",
            package_version="1.0.0",
            status=ScanStatus.APPROVED,
            scan_date="2025-11-19T12:00:00",
            scanner_type="trivy",
            vulnerabilities=[],
        )

        scanner._save_result(result)

        # Check that a JSON file was created
        json_files = list(temp_scans_dir.glob("*.json"))
        assert len(json_files) == 1

        # Verify contents
        with json_files[0].open("r") as f:
            saved_data = json.load(f)
            assert saved_data["package_name"] == "test-package"
            assert saved_data["status"] == "approved"


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = ScanResult(
            package_name="test-package",
            package_version="1.0.0",
            status=ScanStatus.APPROVED,
            scan_date="2025-11-19T12:00:00",
            scanner_type="trivy",
            vulnerabilities=[],
        )

        result_dict = result.to_dict()

        assert result_dict["package_name"] == "test-package"
        assert result_dict["status"] == "approved"
        assert result_dict["vulnerabilities"] == []
