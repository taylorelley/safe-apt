"""Unit tests for approval list builder."""

import json
import pytest
from pathlib import Path
from datetime import datetime, timedelta
from src.publisher.build_approved_list import ApprovedListBuilder


@pytest.fixture
def temp_dirs(tmp_path):
    """Create temporary directories for testing."""
    scans_dir = tmp_path / "scans"
    approvals_dir = tmp_path / "approvals"
    scans_dir.mkdir()
    approvals_dir.mkdir()
    return scans_dir, approvals_dir


@pytest.fixture
def builder(temp_dirs):
    """Create ApprovedListBuilder instance for testing."""
    scans_dir, approvals_dir = temp_dirs
    return ApprovedListBuilder(
        scans_dir=str(scans_dir),
        approvals_dir=str(approvals_dir),
        max_scan_age_hours=48,
    )


@pytest.fixture
def sample_scan_approved(temp_dirs):
    """Create sample approved scan result."""
    scans_dir, _ = temp_dirs
    scan_data = {
        "package_name": "curl",
        "package_version": "7.81.0-1ubuntu1.16",
        "status": "approved",
        "scan_date": datetime.now().isoformat(),
        "scanner_type": "trivy",
        "vulnerabilities": [],
        "cve_count": 0,
        "cvss_max": 0.0,
    }

    scan_file = scans_dir / "curl_7.81.0-1ubuntu1.16_20251119_120000.json"
    with scan_file.open("w") as f:
        json.dump(scan_data, f)

    return scan_file


@pytest.fixture
def sample_scan_blocked(temp_dirs):
    """Create sample blocked scan result."""
    scans_dir, _ = temp_dirs
    scan_data = {
        "package_name": "vulnerable-pkg",
        "package_version": "1.0.0",
        "status": "blocked",
        "scan_date": datetime.now().isoformat(),
        "scanner_type": "trivy",
        "vulnerabilities": [
            {
                "cve_id": "CVE-2023-1234",
                "severity": "HIGH",
                "cvss_score": 8.5,
            }
        ],
        "cve_count": 1,
        "cvss_max": 8.5,
    }

    scan_file = scans_dir / "vulnerable-pkg_1.0.0_20251119_120000.json"
    with scan_file.open("w") as f:
        json.dump(scan_data, f)

    return scan_file


class TestApprovedListBuilder:
    """Tests for ApprovedListBuilder class."""

    def test_extract_package_name(self, builder):
        """Test package name extraction."""
        name = builder._extract_package_name("curl_7.81.0-1ubuntu1.16_amd64")
        assert name == "curl"

    def test_extract_package_name_simple(self, builder):
        """Test package name extraction without underscores."""
        name = builder._extract_package_name("simple-package")
        assert name == "simple-package"

    def test_is_scan_fresh(self, builder):
        """Test scan freshness check."""
        # Fresh scan
        fresh_scan = {
            "scan_date": datetime.now().isoformat()
        }
        assert builder._is_scan_fresh(fresh_scan) is True

        # Old scan
        old_date = datetime.now() - timedelta(hours=72)
        old_scan = {
            "scan_date": old_date.isoformat()
        }
        assert builder._is_scan_fresh(old_scan) is False

    def test_is_scan_fresh_invalid_date(self, builder):
        """Test scan freshness with invalid date."""
        invalid_scan = {
            "scan_date": "invalid-date"
        }
        assert builder._is_scan_fresh(invalid_scan) is False

    def test_load_scan_results(self, builder, sample_scan_approved, sample_scan_blocked):
        """Test loading scan results."""
        results = builder._load_scan_results()

        assert len(results) == 2
        package_names = [r["package_name"] for r in results]
        assert "curl" in package_names
        assert "vulnerable-pkg" in package_names

    def test_find_latest_scan(self, builder, sample_scan_approved):
        """Test finding latest scan for a package."""
        results = builder._load_scan_results()
        latest = builder._find_latest_scan("curl", results)

        assert latest is not None
        assert latest["package_name"] == "curl"

    def test_find_latest_scan_not_found(self, builder):
        """Test finding scan for non-existent package."""
        results = builder._load_scan_results()
        latest = builder._find_latest_scan("non-existent", results)

        assert latest is None

    def test_build_approved_list(self, builder, sample_scan_approved, sample_scan_blocked):
        """Test building approved list."""
        package_list = [
            "curl_7.81.0-1ubuntu1.16_amd64",
            "vulnerable-pkg_1.0.0_amd64",
        ]

        approved = builder.build_approved_list(package_list, output_file="test-approved.txt")

        assert len(approved) == 1
        assert "curl_7.81.0-1ubuntu1.16_amd64" in approved
        assert "vulnerable-pkg_1.0.0_amd64" not in approved

    def test_get_approval_stats(self, builder, sample_scan_approved, sample_scan_blocked):
        """Test getting approval statistics."""
        stats = builder.get_approval_stats()

        assert stats["total_scans"] == 2
        assert stats["approved"] == 1
        assert stats["blocked"] == 1
        assert stats["errors"] == 0
