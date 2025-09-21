from fastapi import APIRouter, Security, HTTPException, Depends, Request, Query
from datetime import datetime, timezone
from typing import Optional
import secrets
from fastapi.security import APIKeyHeader
from elasticsearch import AsyncElasticsearch
from sentinel.config.settings import settings

router = APIRouter()
api_key_header = APIKeyHeader(name='X-API-KEY')

def get_es_client(request: Request) -> AsyncElasticsearch:
    """
    Dependency to get the shared Elasticsearch client instance from the app state.
    This relies on the client being initialized in the lifespan of the FastAPI app.
    """
    return request.app.state.es_client

def get_api_key(api_key: str = Security(api_key_header)):
    # Use secrets.compare_digest to prevent timing attacks
    if secrets.compare_digest(api_key, settings.API_KEY):
        return api_key
    else:
        raise HTTPException(
            status_code=403,
            detail='Could not validate credentials',
        )

@router.get('/health', tags=['Monitoring'])
def health_check():
    return {'status': 'ok'}

@router.get('/events/latest', tags=['Intelligence'], dependencies=[Security(get_api_key)])
async def get_latest_events(
    limit: int = Query(10, gt=0, le=settings.API_EVENT_LIMIT),
    es_client: AsyncElasticsearch = Depends(get_es_client)
):
    query = {
        'query': {'match_all': {}},
        'sort': [{'timestamp': {'order': 'desc'}}],
        'size': limit
    }
    response = await es_client.search(
        index=settings.PROCESSED_INDEX,
        query=query['query'],
        sort=query['sort'],
        size=query['size']
    )
    return [hit['_source'] for hit in response['hits']['hits']]

@router.get('/events/high-risk', tags=['Intelligence'], dependencies=[Security(get_api_key)])
async def get_high_risk_events(
    limit: int = Query(25, gt=0, le=settings.API_EVENT_LIMIT),
    es_client: AsyncElasticsearch = Depends(get_es_client)
):
    query = {
        'query': {
            'range': {
                'risk_score': {
                    'gte': settings.HIGH_RISK_SCORE_THRESHOLD
                }
            }
        },
        'sort': [{'timestamp': {'order': 'desc'}}],
        'size': limit
    }
    response = await es_client.search(
        index=settings.PROCESSED_INDEX,
        query=query['query'],
        sort=query['sort'],
        size=query['size']
    )
    return [hit['_source'] for hit in response['hits']['hits']]

@router.get('/events/search', tags=['Intelligence'], dependencies=[Security(get_api_key)])
async def search_events(
    source_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    start_date: Optional[datetime] = Query(None, description="ISO 8601 format, e.g., 2024-01-01T00:00:00Z"),
    end_date: Optional[datetime] = Query(None, description="ISO 8601 format, e.g., 2024-01-02T00:00:00Z"),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score (0-100)"),
    limit: int = Query(100, gt=0, le=settings.API_EVENT_LIMIT),
    es_client: AsyncElasticsearch = Depends(get_es_client)
):
    """Advanced search for events with multiple filter criteria."""
    query_must = []
    if source_ip:
        query_must.append({'term': {'source_ip.keyword': source_ip}})

    time_range = {}
    if start_date:
        time_range['gte'] = start_date.isoformat()
    if end_date:
        time_range['lte'] = end_date.isoformat()
    if time_range:
        query_must.append({'range': {'timestamp': time_range}})

    if min_risk_score is not None:
        query_must.append({'range': {'risk_score': {'gte': min_risk_score}}})

    query = {'bool': {'must': query_must}} if query_must else {'match_all': {}}

    response = await es_client.search(
        index=settings.PROCESSED_INDEX,
        query=query,
        sort=[{'timestamp': {'order': 'desc'}}],
        size=limit
    )
    return [hit['_source'] for hit in response['hits']['hits']]