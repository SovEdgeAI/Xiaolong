FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt requirements-jev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Local decision model (LLM_MODEL=anyjev): CPU-only torch + AnyJev. Weights are
# not baked in; mount the host Hugging Face cache at $HF_HOME instead.
ARG WITH_JEV=false
RUN if [ "$WITH_JEV" = "true" ]; then \
        pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch && \
        pip install --no-cache-dir -r requirements-jev.txt; \
    fi

# Copy application source
COPY . .

EXPOSE 8000

# Start the FastAPI app with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
