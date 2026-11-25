FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
RUN pip install --no-cache-dir ".[dev]"

# Runs are sandboxed: tools only touch an in-memory simulated world.
# The only network access is the model API call.
ENTRYPOINT ["injeval"]
CMD ["--help"]
