
import httpx
import time
import logging

logging.basicConfig(level=logging.INFO)

KIBANA_URL = "http://kibana:5601"

def wait_for_kibana():
    """Wait for Kibana to be available."""
    logging.info("Waiting for Kibana...")
    while True:
        try:
            response = httpx.get(f"{KIBANA_URL}/api/status")
            if response.status_code == 200:
                logging.info("Kibana is up!")
                return
        except httpx.RequestError:
            pass
        time.sleep(5)

def create_data_view(name: str, time_field: str):
    """Create a Kibana data view."""
    logging.info(f"Creating data view: {name}")
    try:
        with httpx.Client() as client:
            response = client.post(
                f"{KIBANA_URL}/api/data_views/data_view",
                headers={
                    "kbn-xsrf": "true",
                    "Content-Type": "application/json"
                },
                json={
                    "data_view": {
                        "title": name,
                        "name": name,
                        "timeFieldName": time_field
                    }
                }
            )
            response.raise_for_status()
            logging.info(f"Data view '{name}' created successfully.")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409:
            logging.info(f"Data view '{name}' already exists.")
        else:
            logging.error(f"Error creating data view '{name}': {e}")
    except httpx.RequestError as e:
        logging.error(f"Error connecting to Kibana: {e}")

def main():
    wait_for_kibana()
    create_data_view("filebeat-*", "@timestamp")
    create_data_view("sentinel-events", "timestamp")

if __name__ == "__main__":
    main()
