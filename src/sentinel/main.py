# src/sentinel/main.py
import asyncio
from fastapi import FastAPI
from sentinel.api import endpoints
from sentinel.services.processor import process_new_events

app = FastAPI(
    title='Project-Sentinel API',
    description='An API for generating and serving high-fidelity threat intelligence.',
    version='1.0.0'
)

@app.on_event('startup')
async def startup_event():
    asyncio.create_task(process_new_events())

app.include_router(endpoints.router, prefix='/api/v1')
