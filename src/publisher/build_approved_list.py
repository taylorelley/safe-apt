"""Build approved package lists from scan results.

Reads scan results and generates an approved.txt file containing
only packages that passed security scans.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Set, Dict, Any, Optional

from ..common.logger import get_logger


class ApprovedListBuilder:
    """Builder for approved package lists."""

    def __init__(
        self,
        scans_dir: str = "/opt/apt-mirror-system/scans",
        approvals_dir: str = "/opt/apt-mirror-system/approvals",
        max_scan_age_hours: int = 48,
    ):
        """Initialize approved list builder.

        Args:
            scans_dir: Directory containing scan results
            approvals_dir: Directory to write approved lists
            max_scan_age_hours: Maximum age of scan results to consider
        """
        self.scans_dir = Path(scans_dir)
        self.approvals_dir = Path(approvals_dir)
        self.max_scan_age_hours = max_scan_age_hours
        self.logger = get_logger("publisher")

        # Ensure directories exist
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.approvals_dir.mkdir(parents=True, exist_ok=True)

    def build_approved_list(
        self, package_list: List[str], output_file: str = "approved.txt"
    ) -> Set[str]:
        """Build list of approved packages from scan results.

        Args:
            package_list: List of package keys to check (from aptly snapshot diff)
            output_file: Output filename for approved list

        Returns:
            Set of approved package keys
        """
        self.logger.info(f"Building approved list for {len(package_list)} packages")

        approved_packages: Set[str] = set()
        blocked_packages: List[str] = []
        missing_scans: List[str] = []

        # Load all scan results
        scan_results = self._load_scan_results()

        for package_key in package_list:
            # Parse package key: name_version_arch
            package_name = self._extract_package_name(package_key)

            # Find most recent scan for this package
            scan_result = self._find_latest_scan(package_name, scan_results)

            if scan_result is None:
                missing_scans.append(package_key)
                self.logger.warning(f"No scan found for package: {package_key}")
                continue

            # Check scan age
            if not self._is_scan_fresh(scan_result):
                missing_scans.append(package_key)
                self.logger.warning(f"Scan too old for package: {package_key}")
                continue

            # Check approval status
            status = scan_result.get("status", "error")
            if status == "approved":
                approved_packages.add(package_key)
            else:
                blocked_packages.append(package_key)
                self.logger.info(
                    f"Package blocked: {package_key} (status: {status}, "
                    f"CVEs: {scan_result.get('cve_count', 0)})"
                )

        # Write approved list
        output_path = self.approvals_dir / output_file
        self._write_approved_list(approved_packages, output_path)

        # Log summary
        self.logger.info(
            f"Approved: {len(approved_packages)}, "
            f"Blocked: {len(blocked_packages)}, "
            f"Missing scans: {len(missing_scans)}"
        )

        if blocked_packages:
            self.logger.info(f"Blocked packages: {', '.join(blocked_packages[:10])}")
            if len(blocked_packages) > 10:
                self.logger.info(f"... and {len(blocked_packages) - 10} more")

        return approved_packages

    def _load_scan_results(self) -> List[Dict[str, Any]]:
        """Load all scan result JSON files.

        Returns:
            List of scan result dictionaries
        """
        scan_results = []

        for scan_file in self.scans_dir.glob("*.json"):
            try:
                with scan_file.open("r") as f:
                    result = json.load(f)
                    result["_file"] = scan_file.name
                    scan_results.append(result)
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Failed to load scan result {scan_file}: {e}")

        self.logger.debug(f"Loaded {len(scan_results)} scan results")
        return scan_results

    def _find_latest_scan(
        self, package_name: str, scan_results: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Find the most recent scan for a package.

        Args:
            package_name: Package name to search for
            scan_results: List of all scan results

        Returns:
            Most recent scan result or None if not found
        """
        matching_scans = [
            scan
            for scan in scan_results
            if scan.get("package_name") == package_name
        ]

        if not matching_scans:
            return None

        # Sort by scan_date descending
        matching_scans.sort(key=lambda x: x.get("scan_date", ""), reverse=True)
        return matching_scans[0]

    def _is_scan_fresh(self, scan_result: Dict[str, Any]) -> bool:
        """Check if scan result is fresh enough to use.

        Args:
            scan_result: Scan result dictionary

        Returns:
            True if scan is fresh, False otherwise
        """
        scan_date_str = scan_result.get("scan_date")
        if not scan_date_str:
            return False

        try:
            scan_date = datetime.fromisoformat(scan_date_str)
            age = datetime.now() - scan_date
            return age < timedelta(hours=self.max_scan_age_hours)
        except (ValueError, TypeError):
            self.logger.warning(f"Invalid scan date format: {scan_date_str}")
            return False

    def _extract_package_name(self, package_key: str) -> str:
        """Extract package name from aptly package key.

        Args:
            package_key: Package key (e.g., 'curl_7.81.0-1ubuntu1.16_amd64')

        Returns:
            Package name (e.g., 'curl')
        """
        # Package key format: name_version_arch
        return package_key.split("_")[0] if "_" in package_key else package_key

    def _write_approved_list(self, approved_packages: Set[str], output_path: Path) -> None:
        """Write approved packages to file.

        Args:
            approved_packages: Set of approved package keys
            output_path: Path to output file
        """
        try:
            with output_path.open("w") as f:
                for package_key in sorted(approved_packages):
                    f.write(f"{package_key}\n")

            self.logger.info(f"Approved list written to {output_path}")
        except IOError:
            self.logger.exception("Failed to write approved list")
            raise

    def get_approval_stats(self) -> Dict[str, int]:
        """Get statistics about recent scans.

        Returns:
            Dictionary with approval statistics
        """
        scan_results = self._load_scan_results()

        stats = {
            "total_scans": len(scan_results),
            "approved": 0,
            "blocked": 0,
            "errors": 0,
            "fresh_scans": 0,
        }

        for scan in scan_results:
            status = scan.get("status", "error")
            if status == "approved":
                stats["approved"] += 1
            elif status == "blocked":
                stats["blocked"] += 1
            else:
                stats["errors"] += 1

            if self._is_scan_fresh(scan):
                stats["fresh_scans"] += 1

        return stats
