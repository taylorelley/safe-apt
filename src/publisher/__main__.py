"""CLI interface for approval list builder."""

import sys
import argparse
from pathlib import Path

from .build_approved_list import ApprovedListBuilder
from ..common.logger import setup_logger
from ..common.config import load_config


def main():
    """Main entry point for publisher CLI."""
    parser = argparse.ArgumentParser(description="Build approved package list")
    parser.add_argument(
        "--package-list",
        required=True,
        help="File containing list of packages to check",
    )
    parser.add_argument(
        "--output",
        default="/opt/apt-mirror-system/approvals/approved.txt",
        help="Output file for approved packages",
    )
    parser.add_argument(
        "--config",
        default="/opt/apt-mirror-system/config.yaml",
        help="Configuration file",
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        # Use defaults if config not found
        config = {
            "system": {
                "scans_dir": "/opt/apt-mirror-system/scans",
                "approvals_dir": "/opt/apt-mirror-system/approvals",
            }
        }

    # Setup logging
    logger = setup_logger(
        "publisher",
        log_dir=config.get("system", {}).get("logs_dir", "/opt/apt-mirror-system/logs"),
        level=config.get("logging", {}).get("level", "INFO"),
    )

    # Initialize builder
    builder = ApprovedListBuilder(
        scans_dir=config.get("system", {}).get("scans_dir", "/opt/apt-mirror-system/scans"),
        approvals_dir=config.get("system", {}).get(
            "approvals_dir", "/opt/apt-mirror-system/approvals"
        ),
    )

    # Load package list
    with open(args.package_list, "r") as f:
        packages = [line.strip() for line in f if line.strip()]

    logger.info(f"Processing {len(packages)} packages")

    # Build approved list
    approved = builder.build_approved_list(packages, output_file=Path(args.output).name)

    # Print statistics
    stats = builder.get_approval_stats()
    logger.info(f"Total scans: {stats['total_scans']}")
    logger.info(f"Approved: {stats['approved']}")
    logger.info(f"Blocked: {stats['blocked']}")
    logger.info(f"Errors: {stats['errors']}")
    logger.info(f"Approved packages written to: {args.output}")

    sys.exit(0)


if __name__ == "__main__":
    main()
