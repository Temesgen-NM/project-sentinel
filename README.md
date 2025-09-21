# Project-Sentinel

*A Rules-Based Threat Intelligence Platform for Proactive Security Defense.*

---

## 1. Overview

Project-Sentinel is a self-contained, automated platform that generates high-fidelity threat intelligence. It uses a live honeypot to capture real-world attack data, processes it through a Python-based analysis engine to enrich and score threats, and serves this intelligence via a REST API and a Kibana dashboard.

## 2. Core Features

*   **Live Threat Capture:** Utilizes a Cowrie SSH/Telnet honeypot to capture attacker interactions in real-time.
*   **Automated Processing Pipeline:** A continuous background process automatically fetches, cleans, and structures raw log data.
*   **Advanced Threat Scoring:** Each event is analyzed with a weighted scoring model that considers event type, suspicious commands, account privileges, geo-location, and time of day.
*   **REST API for Intelligence:** A secure, documented FastAPI provides endpoints to access the processed intelligence, including:
    *   Latest events.
    *   High-risk events.
    *   Advanced search by IP, date, and risk score.
*   **Structured Logging:** All application logs are in JSON format for easy integration with log management systems.
*   **Interactive C-SOC Dashboard:** A Kibana dashboard provides a geo-map of attacker origins, a sortable table of threats by risk score, and other key visualizations.
*   **Fully Containerized:** The entire stack is managed via Docker Compose for easy deployment and scalability.

## 3. How to Run

1.  Install Docker Desktop (includes Compose). Use `docker compose`, not `docker-compose`.
2.  Copy `.env.example` to `.env` and set values:
    - `ELASTICSEARCH_URL=http://elasticsearch:9200`
    - `ELASTIC_PASSWORD=<your-strong-password>`
    - `API_KEY=<your-secret-key>`
3.  Start the stack (first run builds Filebeat and app images):
    ```bash
    docker compose up -d --build
    ```
    The `bootstrap` service will automatically:
    - Create the `geoip` ingest pipeline
    - Create an index template for `sentinel-events` (date mapping, geo_point)
4.  Open Kibana: `http://localhost:5601`
5.  Open API docs: `http://localhost:8000/docs`

Create two Kibana data views (after events arrive):
- `filebeat-*` with time field `@timestamp` (raw Cowrie logs)
- `sentinel-events` with time field `timestamp` (processed, risk-scored)

## 4. API Endpoints

The API is available at `http://localhost:8000` and requires an `X-API-KEY` header for all intelligence endpoints.

*   `GET /api/v1/events/latest`: Get the most recent events.
*   `GET /api/v1/events/high-risk`: Get events with a risk score above the configured threshold.
*   `GET /api/v1/events/search`: Perform an advanced search with the following parameters:
    *   `source_ip` (string)
    *   `start_date` (datetime)
    *   `end_date` (datetime)
    *   `min_risk_score` (integer)

## 5. Technology Stack

*   **Application & API:** Python 3, FastAPI, Gunicorn
*   **Data Platform:** The Elastic Stack (Elasticsearch, Kibana, Filebeat)
*   **Sensor:** Cowrie Honeypot
*   **Logging:** python-json-logger
*   **Infrastructure:** Docker, Docker Compose

## 6. Security Notes

*  **Change Default Credentials:** It is critical to change the default `ELASTIC_PASSWORD` and `API_KEY` in the `.env` file before running the application.
*  **Local-only by default:** Kibana (`5601`), Elasticsearch (`9200`), and the API (`8000`) are bound to `127.0.0.1` to avoid public exposure. If deploying to a server, front these with a reverse proxy or carefully open ports with proper auth.
*  **API authentication:** Intelligence endpoints under `/api/v1/*` require `X-API-KEY`. Set `API_KEY` in `.env`.
*  **Optional secured Elasticsearch:** If you enable Elastic security, provide credentials and (optionally) TLS settings in `.env`:
   - `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`
   - `ELASTICSEARCH_URL` using `https://...`
   - `ELASTICSEARCH_VERIFY_CERTS=true` and (if needed) `ELASTICSEARCH_CA_CERTS=/app/certs/ca.crt`
  Filebeat and the app will use these automatically.

## Author

Temesgen Melaku

## 7. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.