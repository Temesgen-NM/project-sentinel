# Project-Sentinel

*An AI-Powered Threat Intelligence Platform for Proactive Security Defense.*

---

## 1. Overview

Project-Sentinel is a self-contained, automated platform that generates high-fidelity threat intelligence. It uses a live honeypot to capture real-world attack data, processes it through a Python-based analysis engine to enrich and score threats, and serves this intelligence via a REST API and a Kibana dashboard.

## 2. Core Features

*   **Live Threat Capture:** Utilizes a Cowrie SSH/Telnet honeypot to capture attacker interactions in real-time.
*   **Automated Processing Pipeline:** A continuous background process automatically fetches, cleans, and structures raw log data.
*   **Heuristic AI Risk Scoring:** Each event is analyzed and assigned a risk score based on its characteristics (e.g., successful logins, commands executed), allowing for instant threat prioritization.
*   **REST API for Intelligence:** A secure, documented FastAPI provides endpoints to access the processed intelligence, including a dedicated endpoint for high-risk events.
*   **Interactive C-SOC Dashboard:** A Kibana dashboard provides a geo-map of attacker origins, a sortable table of threats by risk score, and other key visualizations.
*   **Fully Containerized:** The entire stack is managed via Docker Compose for easy deployment and scalability.

## 3. How to Run

1.  Install Docker Desktop (includes Compose). Use `docker compose`, not `docker-compose`.
2.  Copy `.env.example` to `.env` and set values:
    - `ELASTICSEARCH_URL=http://elasticsearch:9200`
    - `API_KEY=<your-secret>`
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

## 4. Technology Stack

*   **Application & API:** Python 3, FastAPI
*   **Data Platform & AI:** The Elastic Stack (Elasticsearch, Kibana, Filebeat)
*   **Sensor:** Cowrie Honeypot
*   **Infrastructure:** Docker, Docker Compose

## 5. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.