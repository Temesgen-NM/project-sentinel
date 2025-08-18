import asyncio
import logging
from elasticsearch import AsyncElasticsearch
from sentinel.config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def wait_for_elasticsearch(es_client: AsyncElasticsearch):
    """
    Waits for Elasticsearch to become available before proceeding.
    """
    logger.info("Checking Elasticsearch connection (waiting for cluster health >= yellow)...")
    # Small initial delay to let the container start
    await asyncio.sleep(2)
    while True:
        try:
            health = await es_client.cluster.health(wait_for_status="yellow", timeout="10s")
            status = health.get("status", "unknown")
            logger.info(f"Elasticsearch cluster health: {status}")
            if status in ("yellow", "green"):
                logger.info("Elasticsearch connection successful.")
                break
            logger.warning("Elasticsearch not ready (health not yellow/green). Retrying in 10 seconds...")
        except Exception as e:
            logger.error(f"Elasticsearch connection check failed: {e}. Retrying in 10 seconds...")
        await asyncio.sleep(10)

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

async def process_new_events(es_client: AsyncElasticsearch): # Accept client as argument
    logger.info('Threat processor background task started. Waiting for events...')
    # Assumes wait_for_elasticsearch was called during app startup lifecycle
    
    # Ensure processed index exists (retry if transient failure)
    try:
        exists = await es_client.indices.exists(index=settings.PROCESSED_INDEX)
    except Exception as e:
        logger.error(f'Failed to check index existence {settings.PROCESSED_INDEX}: {e}')
        exists = False
    if not exists:
        for attempt in range(5):
            try:
                await es_client.indices.create(index=settings.PROCESSED_INDEX)
                logger.info(f'Created Elasticsearch index: {settings.PROCESSED_INDEX}')
                break
            except Exception as e:
                logger.error(f'Failed to create index {settings.PROCESSED_INDEX} (attempt {attempt+1}/5): {e}')
                await asyncio.sleep(5)

    while True:
        try:
            query = {
                'query': {
                    'bool': {
                        'must_not': [{'exists': {'field': 'sentinel_processed'}}]
                    }
                }
            }
            
            response = await es_client.search(
                index=settings.SOURCE_INDEX,
                query=query['query'],
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
                    'geoip': source_doc.get('geoip'),
                    'username': source_doc.get('username'),
                    'password': source_doc.get('password'),
                    'event_type': source_doc.get('eventid'),
                    'session_id': source_doc.get('session'),
                    'message': source_doc.get('message'),
                    'risk_score': risk_score,
                    'risk_factors': risk_factors
                }
                
                await es_client.index(
                    index=settings.PROCESSED_INDEX,
                    document=processed_event
                )
                
                await es_client.update(
                    index=hit['_index'],
                    id=hit['_id'],
                    doc={'sentinel_processed': True}
                )

        except Exception as e:
            logger.error(f'Error in threat processor loop: {e}')
            await asyncio.sleep(30)
