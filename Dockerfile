FROM python:3.11-slim

# Create a non-root user
RUN useradd -m -u 1001 sentinel

WORKDIR /app

# Copy requirements and install dependencies
COPY --chown=sentinel:sentinel requirements.txt .
RUN pip install --no-cache-dir --timeout=100 -r requirements.txt

# Copy gunicorn config
COPY --chown=sentinel:sentinel gunicorn.conf.py .

# Copy application code
COPY --chown=sentinel:sentinel ./src /app/src

# Switch to the non-root user
USER sentinel

EXPOSE 8000

CMD ["gunicorn", "--config", "/app/gunicorn.conf.py", "sentinel.main:app"]