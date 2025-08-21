# src/sentinel/main.py
import asyncio
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from sentinel.api import endpoints
from sentinel.core.services import process_new_events, wait_for_elasticsearch
from sentinel.config.settings import settings
from elasticsearch import AsyncElasticsearch

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application's startup and shutdown events.
    Initializes the Elasticsearch client and the background processor task.
    """
    logging.info("Application startup: Initializing Elasticsearch client and background tasks.")
    
    # Initialize the Elasticsearch client and attach it to the app state
    es_kwargs = {
        "hosts": [settings.ELASTICSEARCH_URL],
    }
    # Optional basic auth
    if settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
        es_kwargs["basic_auth"] = (
            settings.ELASTICSEARCH_USERNAME,
            settings.ELASTICSEARCH_PASSWORD,
        )
    # Optional TLS verification
    if settings.ELASTICSEARCH_CA_CERTS:
        es_kwargs["ca_certs"] = settings.ELASTICSEARCH_CA_CERTS
    es_kwargs["verify_certs"] = settings.ELASTICSEARCH_VERIFY_CERTS

    es_client = AsyncElasticsearch(**es_kwargs)
    app.state.es_client = es_client
    
    # Wait for Elasticsearch to be ready before starting the processor
    await wait_for_elasticsearch(es_client)
    
    # Create the background task for processing events
    processor_task = asyncio.create_task(process_new_events(es_client))
    
    # Yield control back to the server, allowing the app to run
    yield
    
    # --- Shutdown ---
    logging.info("Application shutdown: Cleaning up resources.")
    # Cancel the background task
    processor_task.cancel()
    try:
        await processor_task
    except asyncio.CancelledError:
        logging.info("Background task cancelled.")
    
    # Close the Elasticsearch client connection
    if hasattr(app.state, 'es_client') and app.state.es_client:
        await app.state.es_client.close()
        logging.info("Elasticsearch client closed.")

app = FastAPI(
    title='Project-Sentinel API',
    description='An API for generating and serving high-fidelity threat intelligence.',
    version='1.0.0',
    lifespan=lifespan
)

app.include_router(endpoints.router, prefix='/api/v1')

# Add a root endpoint for simple "hello world"
@app.get("/", tags=["Root"])
def read_root():
    return {"message": "Welcome to the Sentinel API. Visit /docs for API documentation."}
