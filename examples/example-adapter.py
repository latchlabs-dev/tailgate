#!/usr/bin/env python3
"""A non-operational adapter showing the application phase interface."""
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('--plan', required=True)
parser.add_argument('--phase', required=True)
args = parser.parse_args()
plan = json.load(open(args.plan))
raise SystemExit(
    f"Example adapter cannot apply {args.phase} for {plan['application']['name']}; "
    "supply an installation-owned adapter")
