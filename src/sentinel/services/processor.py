import asyncio
import logging
from elasticsearch import Elasticsearch, NotFoundError
from sentinel.config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

es_client = Elasticsearch(hosts=[settings.ELASTICSEARCH_URL], retry_on_timeout=True, max_retries=3)

def calculate_risk_score(event: dict) -> tuple[int, list[str]]:
    score = 10
    factors = ['Base Score']

    if event.get('eventid') == 'cowrie.login.success':
        score += 40
        factors.append('Successful Login')
    
    username = event.get('username', '').lower()
    password = event.get('password', '').lower()

    if username == 'root':
        score += 10
        factors.append('Root User Attempt')

    if password and password in ['root', 'admin', 'password', '123456']:
        score -= 5 # Common passwords are less sophisticated
        factors.append('Common Password')
    elif password:
        score += 10
        factors.append('Non-common Password')

    if event.get('eventid') == 'cowrie.command.input':
        score += 25
        factors.append('Command Executed')
        if 'wget' in event.get('message', '') or 'curl' in event.get('message', ''):
            score += 30
            factors.append('File Download Attempt')
    
    return min(max(score, 0), 100), factors

async def process_new_events():
    logger.info('Threat processor background task started. Waiting for events...')
    
    if not es_client.indices.exists(index=settings.PROCESSED_INDEX):
        try:
            es_client.indices.create(index=settings.PROCESSED_INDEX)
            logger.info(f'Created Elasticsearch index: {settings.PROCESSED_INDEX}')
        except Exception as e:
            logger.error(f'Failed to create index {settings.PROCESSED_INDEX}: {e}')
            return

    while True:
        try:
            query = {
                'query': {
                    'bool': {
                        'must_not': [{'exists': {'field': 'sentinel_processed'}}]
                    }
                }
            }
            
            response = es_client.search(
                index=settings.SOURCE_INDEX,
                body=query,
                size=100
            )

            hits = response['hits']['hits']
            if not hits:
                await asyncio.sleep(10)
                continue

            logger.info(f'Found {len(hits)} new events to process.')

            for hit in hits:
                source_doc = hit['_source']
                risk_score, risk_factors = calculate_risk_score(source_doc)
                
                processed_event = {
                    'timestamp': source_doc.get('@timestamp'),
                    'source_ip': source_doc.get('src_ip'),
                    'source_port': source_doc.get('src_port'),
                    'username': source_doc.get('username'),
                    'password': source_doc.get('password'),
                    'event_type': source_doc.get('eventid'),
                    'session_id': source_doc.get('session'),
                    'message': source_doc.get('message'),
                    'risk_score': risk_score,
                    'risk_factors': risk_factors
                }
                
                es_client.index(
                    index=settings.PROCESSED_INDEX,
                    document=processed_event
                )
                
                es_client.update(
                    index=hit['_index'],
                    id=hit['_id'],
                    body={'doc': {'sentinel_processed': True}}
                )

        except Exception as e:
            logger.error(f'Error in threat processor loop: {e}')
            await asyncio.sleep(30)
