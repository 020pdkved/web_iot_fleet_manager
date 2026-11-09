FROM python:3.11-slim

WORKDIR /app

# Copy application files
COPY web_portal.py .
COPY fleet_registry.json .
COPY users.json .
COPY binaries/ ./binaries/
COPY static/ ./static/

ENV PORT=8080
EXPOSE 8080

CMD ["python3", "web_portal.py"]

