# Security Event Dashboard

A Flask-based security monitoring dashboard that parses and classifies simulated security logs, generates alerts, and displays event activity through a SOC-style interface.

## Features
- Log ingestion via `.log` and `.txt`
- File validation and size limits
- Event classification and severity tagging
- Rule-based alert detection
- Brute-force detection
- Port scan detection
- Pagination for large event sets
- Responsive dark-themed dashboard

## Technologies Used
- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript

## Detection Rules
- FAILED_LOGIN >= 3 → Possible brute force attack
- PORT_SCAN >= 2 → Possible reconnaissance activity

## Future Improvements
- Charts and analytics
- Risk scoring
- Authentication
- Exportable reports
