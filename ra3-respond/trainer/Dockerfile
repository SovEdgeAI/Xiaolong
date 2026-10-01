FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dry-run trainer: pure stdlib. A GPU trainer image would install
# torch + transformers + peft here and set train.TRAIN_BACKEND.
COPY . .

# One fine-tuning job per container; the spec comes in via $JOB_SPEC.
ENTRYPOINT ["python", "train.py"]
