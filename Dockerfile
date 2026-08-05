# syntax=docker/dockerfile:1

# --- Go build: only Go sources → config/script/requirements changes do not rebuild ---
FROM golang:1.24-bookworm AS build
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/camwatch ./cmd/camwatch \
 && CGO_ENABLED=1 GOOS=linux go build -o /out/live-spike ./cmd/live-spike

# --- Runtime ---
FROM python:3.11-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /out/camwatch /usr/local/bin/camwatch
COPY --from=build /out/live-spike /usr/local/bin/live-spike

# Pip layer: only invalidated when requirements change (not when .py edits).
COPY scripts/requirements-live.txt /app/scripts/requirements-live.txt
RUN python3 -m venv /opt/live-venv \
 && /opt/live-venv/bin/pip install --no-cache-dir -U pip \
 && /opt/live-venv/bin/pip install --no-cache-dir -r /app/scripts/requirements-live.txt \
 && mkdir -p /app/data/clips

COPY scripts/*.py /app/scripts/
RUN chmod +x /app/scripts/*.py

COPY configs/camwatch.example.yaml /app/configs/camwatch.example.yaml

ENV PATH="/opt/live-venv/bin:$PATH"
ENV CAMWATCH_CONFIG=/app/configs/camwatch.yaml
VOLUME ["/app/data", "/app/configs"]

# MTP uses outbound UDP to cloud ssAddrs; host networking recommended on Linux.
ENTRYPOINT ["/usr/local/bin/camwatch"]
CMD ["-config", "/app/configs/camwatch.yaml"]
