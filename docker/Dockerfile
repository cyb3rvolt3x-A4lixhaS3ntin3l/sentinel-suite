# Sentinel Suite — clean-room engine + UI image (Phase F)
# Host publishes only 127.0.0.1:8888 via compose; inside the container we bind
# 0.0.0.0 with --i-understand-lab so Docker port-mapping works (lab exception).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_HOME=/data/sentinel \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY packages/sentinel_core packages/sentinel_core
COPY packages/shadowseye packages/shadowseye
COPY packages/gungnir packages/gungnir
COPY packages/sentinel_cli packages/sentinel_cli
COPY packages/sentinel_suite packages/sentinel_suite
COPY ui ui
COPY pyproject.toml README.md LICENSE ./

RUN pip install --no-cache-dir \
      -e packages/sentinel_core \
      -e packages/shadowseye \
      -e packages/gungnir \
      -e packages/sentinel_cli \
      -e packages/sentinel_suite \
    && mkdir -p /data/sentinel

VOLUME ["/data/sentinel"]
EXPOSE 8888

CMD ["sentinel", "ui", "--bind", "0.0.0.0", "--port", "8888", "--i-understand-lab"]
