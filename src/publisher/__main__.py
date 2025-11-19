"""CLI interface for approval list builder."""

import sys
import argparse
from pathlib import Path

from src.publisher.build_approved_list import ApprovedListBuilder
from src.common.logger import setup_logger
from src.common.config import load_config


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

    # Parse output path
    output_path = Path(args.output)
    output_dir = output_path.parent
    output_filename = output_path.name

    # Initialize builder with output directory
    builder = ApprovedListBuilder(
        scans_dir=config.get("system", {}).get("scans_dir", "/opt/apt-mirror-system/scans"),
        approvals_dir=str(output_dir) if output_dir != Path('.') else config.get("system", {}).get(
            "approvals_dir", "/opt/apt-mirror-system/approvals"
        ),
    )

    # Load package list
    with open(args.package_list, "r") as f:
        packages = [line.strip() for line in f if line.strip()]

    logger.info(f"Processing {len(packages)} packages")

    # Build approved list
    approved = builder.build_approved_list(packages, output_file=output_filename)

    # Compute actual written path (file is written to builder's approvals_dir)
    actual_written_path = Path(builder.approvals_dir) / output_filename

    # Print statistics
    stats = builder.get_approval_stats()
    logger.info(f"Total scans: {stats['total_scans']}")
    logger.info(f"Approved: {stats['approved']}")
    logger.info(f"Blocked: {stats['blocked']}")
    logger.info(f"Errors: {stats['errors']}")
    logger.info(f"Approved {len(approved)} packages, written to: {actual_written_path.absolute()}")

    sys.exit(0)


if __name__ == "__main__":
    main()
