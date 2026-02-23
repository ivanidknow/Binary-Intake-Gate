# Speakeasy emulation for bin-gate (Linux; avoids Windows DLL issues)
FROM python:3.11-slim

RUN pip install --no-cache-dir "speakeasy-emulator>=1.5" "lief>=0.14"

WORKDIR /app
COPY run_emulation.py /app/

ENV INPUT_FILE=""
ENV OUTPUT_DIR="/output"

ENTRYPOINT ["python", "/app/run_emulation.py"]
