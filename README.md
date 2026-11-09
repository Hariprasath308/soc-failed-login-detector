# SOC Failed Login Detection System

## Overview
A Python-based SOC lab project that analyzes authentication
logs and detects repeated failed login attempts.

## Features
- Parses CSV authentication logs
- Counts failed logins by source IP
- Detects suspicious activity using a configurable threshold
- Generates security alerts
- Saves analysis reports to a text file

## Technologies
- Python 3
- Kali Linux
- CSV Log Analysis
- Basic Threat Detection

## How to Run
python3 detector.py

## Sample Detection
The tool identifies an IP with 5 or more failed login
attempts and generates a HIGH priority alert.

## Project Structure
- detector.py: Detection logic
- logs/auth.log: Sample authentication data
- reports/alerts.txt: Generated security report

## Disclaimer
Educational lab project using sample log data.
