"""Scanner module for safe-apt.

Handles package extraction and vulnerability scanning.
"""

from .scan_packages import PackageScanner, ScanResult, ScanStatus

__all__ = ["PackageScanner", "ScanResult", "ScanStatus"]
