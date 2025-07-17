FROM python:3.10-slim

WORKDIR /app
COPY analyze_logs.py ./
COPY sample-log.log ./

CMD [ "python", "analyze_logs.py", "sample-log.log" ]