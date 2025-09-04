#!/usr/bin/env python3
"""
Branch-based benchmark comparison tool for BBOT performance tests.

This script takes two git branches, runs benchmarks on each, and generates
a comparison report showing performance differences between them.
"""

import json
import argparse
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Tuple


def run_command(cmd: List[str], cwd: Path = None, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=capture_output, text=True, check=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}")
        print(f"Exit code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        raise


def get_current_branch() -> str:
    """Get the current git branch name."""
    result = run_command(["git", "branch", "--show-current"])
    return result.stdout.strip()


def checkout_branch(branch: str, repo_path: Path = None):
    """Checkout a git branch."""
    print(f"Checking out branch: {branch}")
    run_command(["git", "checkout", branch], cwd=repo_path)


def run_benchmarks(output_file: Path, repo_path: Path = None) -> bool:
    """Run benchmarks and save results to JSON file."""
    print(f"Running benchmarks, saving to {output_file}")

    # Check if benchmarks directory exists
    benchmarks_dir = repo_path / "bbot/test/benchmarks" if repo_path else Path("bbot/test/benchmarks")
    if not benchmarks_dir.exists():
        print(f"Benchmarks directory not found: {benchmarks_dir}")
        print("This branch likely doesn't have benchmark tests yet.")
        return False

    try:
        cmd = [
            "poetry",
            "run",
            "python",
            "-m",
            "pytest",
            "bbot/test/benchmarks/",
            "--benchmark-only",
            f"--benchmark-json={output_file}",
            "-q",
        ]
        run_command(cmd, cwd=repo_path, capture_output=False)
        return True
    except subprocess.CalledProcessError:
        print("Benchmarks failed for current state")
        return False


def load_benchmark_data(filepath: Path) -> Dict[str, Any]:
    """Load benchmark data from JSON file."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Benchmark file not found: {filepath}")
        return {}
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON from {filepath}")
        return {}


def format_time(seconds: float) -> str:
    """Format time in human-readable format."""
    if seconds < 0.000001:  # Less than 1 microsecond
        return f"{seconds * 1000000000:.0f}ns"  # Show as nanoseconds with no decimal
    elif seconds < 0.001:  # Less than 1 millisecond
        return f"{seconds * 1000000:.2f}µs"  # Show as microseconds with 2 decimal places
    elif seconds < 1:  # Less than 1 second
        return f"{seconds * 1000:.2f}ms"  # Show as milliseconds with 2 decimal places
    else:
        return f"{seconds:.3f}s"  # Show as seconds with 3 decimal places


def format_ops(ops: float) -> str:
    """Format operations per second."""
    if ops > 1000:
        return f"{ops / 1000:.1f}K ops/sec"
    else:
        return f"{ops:.1f} ops/sec"


def calculate_change_percentage(old_value: float, new_value: float) -> Tuple[float, str]:
    """Calculate percentage change and return emoji indicator."""
    if old_value == 0:
        return 0, "🆕"

    change = ((new_value - old_value) / old_value) * 100

    if change > 10:
        return change, "⚠️"  # Regression (slower)
    elif change < -10:
        return change, "🚀"  # Improvement (faster)
    else:
        return change, "✅"  # No significant change


def generate_benchmark_table(benchmarks: List[Dict[str, Any]], title: str = "Results") -> str:
    """Generate markdown table for benchmark results."""
    if not benchmarks:
        return f"### {title}\nNo benchmark data available.\n"

    table = f"""### {title}

| Test Name | Mean Time | Ops/sec | Min | Max |
|-----------|-----------|---------|-----|-----|
"""

    for bench in benchmarks:
        stats = bench.get("stats", {})
        name = bench.get("name", "Unknown")
        # Generic test name cleanup - just remove 'test_' prefix and format nicely
        test_name = name.replace("test_", "").replace("_", " ").title()

        mean = format_time(stats.get("mean", 0))
        ops = format_ops(stats.get("ops", 0))
        min_time = format_time(stats.get("min", 0))
        max_time = format_time(stats.get("max", 0))

        table += f"| {test_name} | {mean} | {ops} | {min_time} | {max_time} |\n"

    return table + "\n"


def generate_comparison_table(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate comparison table between current and base benchmark results."""
    if not current_data or not base_data:
        return ""

    current_benchmarks = current_data.get("benchmarks", [])
    base_benchmarks = base_data.get("benchmarks", [])

    # Create lookup for base benchmarks
    base_lookup = {bench["name"]: bench for bench in base_benchmarks}

    if not current_benchmarks:
        return ""

    # Count changes for summary
    improvements = 0
    regressions = 0
    no_change = 0

    table = f"""## 📊 Performance Benchmark Report

> Comparing **`{base_branch}`** (baseline) vs **`{current_branch}`** (current)

<details>
<summary>📈 <strong>Detailed Results</strong> (All Benchmarks)</summary>

> 📋 **Complete results for all benchmarks** - includes both significant and insignificant changes

| 🧪 Test Name | 📏 Base | 📏 Current | 📈 Change | 🎯 Status |
|--------------|---------|------------|-----------|-----------|"""

    significant_changes = []
    performance_summary = []

    for current_bench in current_benchmarks:
        name = current_bench.get("name", "Unknown")
        # Generic test name cleanup - just remove 'test_' prefix and format nicely
        test_name = name.replace("test_", "").replace("_", " ").title()

        current_stats = current_bench.get("stats", {})
        current_mean = current_stats.get("mean", 0)
        # For multi-item benchmarks, calculate correct ops/sec
        if "excavate" in name:
            current_ops = 100 / current_mean  # 100 segments per test
        elif "event_validation" in name and "small" in name:
            current_ops = 100 / current_mean  # 100 targets per test
        elif "event_validation" in name and "large" in name:
            current_ops = 1000 / current_mean  # 1000 targets per test
        elif "make_event" in name and "small" in name:
            current_ops = 100 / current_mean  # 100 items per test
        elif "make_event" in name and "large" in name:
            current_ops = 1000 / current_mean  # 1000 items per test
        elif "ip" in name:
            current_ops = 1000 / current_mean  # 1000 IPs per test
        elif "bloom_filter" in name:
            if "dns_mutation" in name:
                current_ops = 2500 / current_mean  # 2500 operations per test
            else:
                current_ops = 13000 / current_mean  # 13000 operations per test
        else:
            current_ops = 1 / current_mean  # Default: single operation

        base_bench = base_lookup.get(name)
        if base_bench:
            base_stats = base_bench.get("stats", {})
            base_mean = base_stats.get("mean", 0)
            # For multi-item benchmarks, calculate correct ops/sec
            if "excavate" in name:
                base_ops = 100 / base_mean  # 100 segments per test
            elif "event_validation" in name and "small" in name:
                base_ops = 100 / base_mean  # 100 targets per test
            elif "event_validation" in name and "large" in name:
                base_ops = 1000 / base_mean  # 1000 targets per test
            elif "make_event" in name and "small" in name:
                base_ops = 100 / base_mean  # 100 items per test
            elif "make_event" in name and "large" in name:
                base_ops = 1000 / base_mean  # 1000 items per test
            elif "ip" in name:
                base_ops = 1000 / base_mean  # 1000 IPs per test
            elif "bloom_filter" in name:
                if "dns_mutation" in name:
                    base_ops = 2500 / base_mean  # 2500 operations per test
                else:
                    base_ops = 13000 / base_mean  # 13000 operations per test
            else:
                base_ops = 1 / base_mean  # Default: single operation

            change_percent, emoji = calculate_change_percentage(base_mean, current_mean)

            # Create visual change indicator
            if abs(change_percent) > 20:
                change_bar = "🔴🔴🔴" if change_percent > 0 else "🟢🟢🟢"
            elif abs(change_percent) > 10:
                change_bar = "🟡🟡" if change_percent > 0 else "🟢🟢"
            else:
                change_bar = "⚪"

            table += f"\n| **{test_name}** | `{format_time(base_mean)}` | `{format_time(current_mean)}` | **{change_percent:+.1f}%** {change_bar} | {emoji} |"

            # Track significant changes
            if abs(change_percent) > 10:
                direction = "🐌 slower" if change_percent > 0 else "🚀 faster"
                significant_changes.append(f"- **{test_name}**: {abs(change_percent):.1f}% {direction}")
                if change_percent > 0:
                    regressions += 1
                else:
                    improvements += 1
            else:
                no_change += 1

            # Add to performance summary
            ops_change = ((current_ops - base_ops) / base_ops) * 100 if base_ops > 0 else 0
            performance_summary.append(
                {
                    "name": test_name,
                    "time_change": change_percent,
                    "ops_change": ops_change,
                    "current_ops": current_ops,
                }
            )
        else:
            table += f"\n| **{test_name}** | `-` | `{format_time(current_mean)}` | **New** 🆕 | 🆕 |"
            significant_changes.append(
                f"- **{test_name}**: New test 🆕 ({format_time(current_mean)}, {format_ops(current_ops)})"
            )

    table += "\n\n</details>\n\n"

    # Add performance summary
    table += "## 🎯 Performance Summary\n\n"

    if improvements > 0 or regressions > 0:
        table += "```diff\n"
        if improvements > 0:
            table += f"+ {improvements} improvement{'s' if improvements != 1 else ''} 🚀\n"
        if regressions > 0:
            table += f"! {regressions} regression{'s' if regressions != 1 else ''} ⚠️\n"
        if no_change > 0:
            table += f"  {no_change} unchanged ✅\n"
        table += "```\n\n"
    else:
        table += "✅ **No significant performance changes detected** (all changes <10%)\n\n"

    # Add significant changes section
    if significant_changes:
        table += "### 🔍 Significant Changes (>10%)\n\n"
        for change in significant_changes:
            table += f"{change}\n"
        table += "\n"

    return table


def generate_report(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate complete benchmark comparison report."""

    if not current_data:
        report = """## 🚀 Performance Benchmark Report

> ⚠️ **No current benchmark data available**
> 
> This might be because:
> - Benchmarks failed to run
> - No benchmark tests found
> - Dependencies missing

"""
        return report

    if not base_data:
        report = f"""## 🚀 Performance Benchmark Report

> ℹ️ **No baseline benchmark data available**
> 
> Showing current results for **{current_branch}** only.

"""
        current_benchmarks = current_data.get("benchmarks", [])
        if current_benchmarks:
            report += f"""<details>
<summary>📊 Current Results ({current_branch}) - Click to expand</summary>

{generate_benchmark_table(current_benchmarks, "Results")}
</details>"""
    else:
        # Add comparison
        comparison = generate_comparison_table(current_data, base_data, current_branch, base_branch)
        if comparison:
            report = comparison
        else:
            # Fallback if no comparison data
            report = f"""## 🚀 Performance Benchmark Report

> ℹ️ **No baseline benchmark data available**
> 
> Showing current results for **{current_branch}** only.

"""

    # Get Python version info
    machine_info = current_data.get("machine_info", {})
    python_version = machine_info.get("python_version", "Unknown")

    report += f"\n\n---\n\n🐍 Python Version {python_version}"

    return report


def main():
    parser = argparse.ArgumentParser(description="Compare benchmark performance between git branches")
    parser.add_argument("--base", required=True, help="Base branch name (e.g., 'main', 'dev')")
    parser.add_argument("--current", required=True, help="Current branch name (e.g., 'feature-branch', 'HEAD')")
    parser.add_argument("--output", type=Path, help="Output markdown file (default: stdout)")
    parser.add_argument("--keep-results", action="store_true", help="Keep intermediate JSON files")

    args = parser.parse_args()

    # Get current working directory
    repo_path = Path.cwd()

    # Save original branch to restore later
    try:
        original_branch = get_current_branch()
        print(f"Current branch: {original_branch}")
    except subprocess.CalledProcessError:
        print("Warning: Could not determine current branch")
        original_branch = None

    # Create temporary files for benchmark results
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        base_results_file = temp_path / "base_results.json"
        current_results_file = temp_path / "current_results.json"

        base_data = {}
        current_data = {}

        base_data = {}
        current_data = {}

        try:
            # Run benchmarks on base branch
            print(f"\n=== Running benchmarks on base branch: {args.base} ===")
            checkout_branch(args.base, repo_path)
            if run_benchmarks(base_results_file, repo_path):
                base_data = load_benchmark_data(base_results_file)

            # Run benchmarks on current branch
            print(f"\n=== Running benchmarks on current branch: {args.current} ===")
            checkout_branch(args.current, repo_path)
            if run_benchmarks(current_results_file, repo_path):
                current_data = load_benchmark_data(current_results_file)

            # Generate report
            print("\n=== Generating comparison report ===")
            report = generate_report(current_data, base_data, args.current, args.base)

            # Output report
            if args.output:
                with open(args.output, "w") as f:
                    f.write(report)
                print(f"Report written to {args.output}")
            else:
                print("\n" + "=" * 80)
                print(report)

            # Keep results if requested
            if args.keep_results:
                if base_data:
                    with open("base_benchmark_results.json", "w") as f:
                        json.dump(base_data, f, indent=2)
                if current_data:
                    with open("current_benchmark_results.json", "w") as f:
                        json.dump(current_data, f, indent=2)
                print("Benchmark result files saved.")

        finally:
            # Restore original branch
            if original_branch:
                print(f"\nRestoring original branch: {original_branch}")
                try:
                    checkout_branch(original_branch, repo_path)
                except subprocess.CalledProcessError:
                    print(f"Warning: Could not restore original branch {original_branch}")


if __name__ == "__main__":
    main()
