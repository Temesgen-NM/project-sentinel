FROM python:3.11-slim

# Create a non-root user
RUN useradd -m -u 1001 sentinel

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=100 -r requirements.txt

# Copy gunicorn config
COPY gunicorn.conf.py .

# Set up virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy application code
COPY ./src /app/src

# Change ownership of the app directory
RUN chown -R sentinel:sentinel /app

# Switch to the non-root user
USER sentinel

EXPOSE 8000