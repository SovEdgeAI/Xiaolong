FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Pure stdlib — no dependencies to install.
COPY . .

# One action per container invocation; args come in via environment.
ENTRYPOINT ["python", "execute.py"]
