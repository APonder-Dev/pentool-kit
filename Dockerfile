# Minimal image for pentool. Runs as a non-root user; entrypoint is the CLI.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="pentool" \
      org.opencontainers.image.description="Authorized penetration-testing & self-audit toolkit" \
      org.opencontainers.image.source="https://github.com/APonder-Dev/pentool-kit" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY . /app

# Install with the optional dnspython extra for full DNS records.
RUN pip install --no-cache-dir ".[dns]"

# Drop privileges; the tool needs no root (TCP connect scanning only).
RUN useradd --create-home --uid 10001 pentool
USER pentool

# Lab default: skip the interactive auth prompt inside the container.
# Override at runtime if you want the prompt back.
ENV PENTOOL_AUTHORIZED=1

ENTRYPOINT ["pentool"]
CMD ["--help"]
