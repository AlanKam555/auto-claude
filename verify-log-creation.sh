#!/bin/bash

# Verification script for PR review log file creation
# This script helps verify that log files are created during PR review execution

echo "=== PR Review Log File Verification ==="
echo ""

# Check if .auto-claude directory exists
if [ ! -d ".auto-claude" ]; then
    echo "✗ .auto-claude directory not found in current project"
    echo "  This directory is created when PR reviews are executed"
    exit 1
else
    echo "✓ .auto-claude directory exists"
fi

# Check for github/pr directory
if [ ! -d ".auto-claude/github" ]; then
    echo "✗ .auto-claude/github directory not found"
    echo "  This directory is created when first PR review runs"
    echo "  Status: No PR reviews have been executed yet"
else
    echo "✓ .auto-claude/github directory exists"

    if [ ! -d ".auto-claude/github/pr" ]; then
        echo "✗ .auto-claude/github/pr directory not found"
        echo "  Status: No PR reviews have been executed yet"
    else
        echo "✓ .auto-claude/github/pr directory exists"

        # List all log files
        echo ""
        echo "Searching for log files (logs_*.json)..."
        find .auto-claude/github/pr -name "logs_*.json" -type f 2>/dev/null | while read logfile; do
            echo "✓ Found: $logfile"
            ls -lh "$logfile"
        done

        # Count log files
        log_count=$(find .auto-claude/github/pr -name "logs_*.json" -type f 2>/dev/null | wc -l)
        if [ "$log_count" -eq 0 ]; then
            echo "✗ No log files found"
            echo "  Status: PR reviews may have run, but no logs were saved"
        else
            echo ""
            echo "Total log files found: $log_count"
        fi
    fi
fi

echo ""
echo "=== How to Verify During PR Review ==="
echo "1. Start a PR review from the frontend UI"
echo "2. While the review is running, check console output for:"
echo "   - 'PRLogCollector created' (shows log file path)"
echo "   - 'PRLogCollector.processLine()' (shows log processing)"
echo "   - 'PRLogCollector.save()' (shows save operations)"
echo "3. Run this script again to check if log file was created"
echo "4. Expected path: .auto-claude/github/pr/logs_PRNUMBER.json"
echo ""
