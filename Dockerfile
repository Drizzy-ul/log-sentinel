FROM python:3.12-alpine

# Install iptables for firewall operations
RUN apk add --no-cache iptables ip6tables bash

WORKDIR /app

# Copy application files
COPY . /app

# Run LogSentinel (in dry-run by default unless overridden)
ENTRYPOINT ["python3", "/app/main.py"]
CMD ["--log-file", "/var/log/nginx/access.log", "--backend", "dry-run"]
