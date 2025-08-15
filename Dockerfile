FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=100 -r requirements.txt

COPY ./src /app/src

EXPOSE 8000
