# Project-Sentinel

*An AI-Powered Threat Intelligence Platform for Proactive Security Defense.*

A project by **Temesgen Melaku**.

---

## 1. Abstract

Project-Sentinel is a self-contained, automated platform engineered to generate high-fidelity threat intelligence. It addresses the limitations of generic security feeds by creating a proprietary data asset from real-world attack traffic. The platform leverages an integrated machine learning engine to analyze attacker behavior, automatically distinguishing between low-level automated noise and sophisticated, high-risk threats. Actionable intelligence is delivered through both an interactive analytics dashboard and a machine-readable API, enabling direct integration with security infrastructure for prioritized, proactive defense.

## 2. The Opportunity

Cybersecurity defense is often overwhelmed by the sheer volume of low-grade alerts, making it difficult to identify targeted and novel threats. This "alert fatigue" creates a critical visibility gap. Furthermore, reliance on generic external data prevents the development of a proprietary data asset that accurately reflects the specific threat landscape an organization faces. Project-Sentinel is designed to solve both problems: to filter the noise and to create a uniquely valuable, context-aware intelligence source.

## 3. The Sentinel Solution

Sentinel operates on a simple yet powerful principle: **Go to the threats, don't wait for them to arrive.**

The platform operates a network of sensors (honeypots) that act as decoys on the public internet, meticulously logging unsolicited malicious traffic. This raw data is ingested into a central analytics engine where it is enriched with contextual data.

Crucially, the platform then passes this data through an **AI analysis layer**. This layer uses behavioral modeling to learn what constitutes a "normal" automated attack. It then automatically prioritizes events that deviate from this baseline, assigning a risk score to every threat. The result is a continuously updated feed of pre-triaged intelligence, allowing security teams to focus their efforts where they matter most.

## 4. Core Capabilities

*   **Live Threat Capture:** Deploys and manages a network of sensors designed to attract and log malicious activity from the public internet in real-time.
*   **AI-Powered Threat Triage:** Utilizes a machine learning engine to analyze attacker behavior (e.g., session duration, command complexity) to distinguish between automated bots and potentially targeted threats, assigning a dynamic risk score to each event.
*   **Automated Contextual Enrichment:** Augments raw data with crucial context, such as GeoIP location, ISP information, and external threat reputation scores.
*   **Prioritized Analytics & Visualization:** Provides an interactive UI for visualizing attack patterns, with a specific focus on high-risk events flagged by the AI engine.
*   **Integratable Intelligence Feeds:** Delivers clean, machine-readable intelligence—including risk scores—via a REST API, enabling firewalls and SIEMs to take risk-based actions.

## 5. Primary Use Cases

1.  **Intelligent, Automated Defense:** The API feed allows firewalls to implement dynamic rules, such as blocking all IPs with a risk score above 90, providing a more resilient and intelligent defense than static blocklists.
2.  **High-Fidelity SIEM Enrichment:** By feeding prioritized alerts into a SIEM, Sentinel dramatically reduces alert fatigue for security analysts and allows them to immediately focus on the most significant threats.
3.  **Adversary Research & Tracking:** The platform enables analysts to study the TTPs (Tactics, Techniques, and Procedures) of the highest-risk actors, leading to a deeper understanding of the adversary landscape.

## 6. Proposed Technology Stack

The platform will be built using a robust, scalable, and modern open-source architecture.

*   **Core Application & API:** Python 3, FastAPI
*   **Data Platform & AI:** The Elastic Stack
    *   **Elasticsearch:** Storage, Search, and Machine Learning Anomaly Detection
    *   **Kibana:** Visualization and Alerting
    *   **Filebeat:** Data Ingestion
*   **Sensor Layer:** Cowrie (SSH/Telnet Honeypot), with a modular design to incorporate other sensors.
*   **Infrastructure:** Docker, Docker Compose

## 7. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.