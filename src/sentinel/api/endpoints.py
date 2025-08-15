from fastapi import APIRouter, Security, HTTPException
from fastapi.security import APIKeyHeader
from elasticsearch import Elasticsearch
from sentinel.config.settings import settings

router = APIRouter()
es_client = Elasticsearch(hosts=[settings.ELASTICSEARCH_URL])
api_key_header = APIKeyHeader(name='X-API-KEY')

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
async def get_latest_events(limit: int = 10):
    query = {
        'query': {'match_all': {}},
        'sort': [{'timestamp': {'order': 'desc'}}],
        'size': limit
    }
    response = es_client.search(index=settings.PROCESSED_INDEX, body=query)
    return [hit['_source'] for hit in response['hits']['hits']]

@router.get('/events/high-risk', tags=['Intelligence'], dependencies=[Security(get_api_key)])
async def get_high_risk_events(limit: int = 25):
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
    response = es_client.search(index=settings.PROCESSED_INDEX, body=query)
    return [hit['_source'] for hit in response['hits']['hits']]
