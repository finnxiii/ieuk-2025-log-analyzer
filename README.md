# Traffic Log Analyzer

This project provides a Python script to analyze web server logs for suspicious (bot) traffic, API usage, and traffic spikes. It helps small teams quickly identify problematic traffic patterns and provides actionable recommendations to reduce server overload.

## Features

- Counts total, API, and per-endpoint requests
- Identifies suspicious user agents (bots, crawlers, scripts)
- Highlights top IPs and endpoints
- Shows hourly traffic breakdown
- Prints sample suspicious user agents
- Outputs recommendations for mitigation

## Requirements

- Python 3.8 or newer

## Usage

1. **Place your log file** (e.g., `sample-log.log`) in the project directory.
2. **Run the script:**
   ```sh
   python analyze_logs.py sample-log.log
   ```
   If no filename is given, it defaults to `sample-log.log`.

## Docker (Optional)

To run in a container:

1. Build the image:
   ```sh
   docker build -t log-analyzer .
   ```
2. Run the analyzer:
   ```sh
   docker run --rm log-analyzer
   ```
   To analyze a different log file, mount it:
   ```sh
   docker run --rm -v $(pwd)/your-log.log:/app/your-log.log log-analyzer python analyze_logs.py your-log.log
   ```

## Log Format

The script expects logs in this format:
```
IP - COUNTRY - [DATE:TIME] "METHOD PATH ..." STATUS ... "-" "USER_AGENT" LATENCY
```
Example:
```
123.45.67.89 - US - [17/07/2025:12:34:56] "GET /api/data ..." 200 ... "-" "Googlebot/2.1 ..." 123
```

## License

MIT License
