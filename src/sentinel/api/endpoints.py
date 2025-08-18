from fastapi import APIRouter, Security, HTTPException, Depends, Request
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
    if api_key == settings.API_KEY:
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
async def get_latest_events(limit: int = 10, es_client: AsyncElasticsearch = Depends(get_es_client)):
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
async def get_high_risk_events(limit: int = 25, es_client: AsyncElasticsearch = Depends(get_es_client)):
    query = {
        'query': {
            'range': {
                'risk_score': {
                    'gte': 70
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
