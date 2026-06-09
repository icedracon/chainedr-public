# ChainEDR — Smart Contract Security Scanner
# Multi-stage build: Python 3.12 + solc + analysis tools

FROM python:3.12-slim AS base

LABEL maintainer="chainedr@example.com" \
      description="ChainEDR: EIP-7702 + Solidity Security Analysis" \
      version="3.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gcc && \
    rm -rf /var/lib/apt/lists/*

# Install solc via solc-select
RUN pip install --no-cache-dir solc-select && \
    solc-select install 0.8.28 && \
    solc-select use 0.8.28

WORKDIR /app

COPY src/ ./src/
COPY benchmarks/ ./benchmarks/
COPY scripts/ ./scripts/
COPY conftest.py pytest.ini ./

RUN pip install --no-cache-dir ./src/ && \
    pip install --no-cache-dir slither-analyzer || true

RUN chainedr doctor || true

ENTRYPOINT ["chainedr"]
CMD ["--help"]
