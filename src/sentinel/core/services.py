"""Core services: background processing and integrations."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from elasticsearch import AsyncElasticsearch, NotFoundError

from sentinel.config.settings import settings
from sentinel.core.models import ProcessedEvent

# Configure module-level logger
logger = logging.getLogger(__name__)


async def wait_for_elasticsearch(es_client: Any, timeout_seconds: int = 60, interval_seconds: float = 2.0) -> None:
    """Wait until Elasticsearch responds to ping or timeout.

    Args:
        es_client: An AsyncElasticsearch-like client with an async ping() method.
        timeout_seconds: Max time to wait before raising TimeoutError.
        interval_seconds: Seconds between retries.
    """
    logger.info("Waiting for Elasticsearch to become ready...")
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    last_error: Exception | None = None

    while asyncio.get_event_loop().time() < deadline:
        try:
            if await es_client.ping():
                logger.info("Elasticsearch is ready.")
                return
        except Exception as exc:  # noqa: BLE001 - log and retry, typical for boot waiters
            last_error = exc
        await asyncio.sleep(interval_seconds)

    msg = "Timed out waiting for Elasticsearch to become ready."
    logger.error(msg)
    if last_error:
        logger.debug("Last ping error: %r", last_error)
    raise TimeoutError(msg)


async def get_last_processed_timestamp(es: AsyncElasticsearch) -> datetime:
    """
    Query Elasticsearch for the most recent timestamp from the processed index.
    Returns a datetime object or None if the index is empty.
    """
    logger.info("Querying for last processed event timestamp...")
    try:
        resp = await es.search(
            index=settings.PROCESSED_INDEX,
            query={"match_all": {}},
            sort=[{"timestamp": {"order": "desc"}}],
            size=1,
            _source=["timestamp"],
        )
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            logger.info("No previously processed events found. Starting from 5 minutes ago.")
            return datetime.now(timezone.utc) - timedelta(minutes=5)

        last_ts_str = hits[0]["_source"]["timestamp"]
        last_ts = datetime.fromisoformat(last_ts_str)
        logger.info("Resuming from last processed timestamp: %s", last_ts.isoformat())
        return last_ts
    except NotFoundError:
        logger.info("Processed index not found. Starting from 5 minutes ago.")
        return datetime.now(timezone.utc) - timedelta(minutes=5)
    except Exception:
        logger.exception("Error fetching last timestamp. Defaulting to 5 minutes ago.")
        return datetime.now(timezone.utc) - timedelta(minutes=5)


async def process_new_events(es_client: AsyncElasticsearch, poll_interval_seconds: float = 10.0) -> None:
    """Continuously fetch recent raw events, score, and index into processed index."""
    logger.info("Event processor started.")

    last_seen_ts = await get_last_processed_timestamp(es_client)

    try:
        while True:
            try:
                new_docs = await _fetch_recent_raw(es_client, since=last_seen_ts)
                if new_docs:
                    logger.info("Fetched %d new raw events since %s", len(new_docs), last_seen_ts.isoformat())
                    processed_events = []
                    source_hits = []
                    for hit in new_docs:
                        transformed = _transform_and_score(hit)
                        if transformed:
                            processed_events.append(transformed)
                            source_hits.append(hit)

                    if processed_events:
                        await _bulk_index_processed(es_client, processed_events, source_hits=source_hits)

                    # Advance watermark to max @timestamp observed
                    max_ts = max(_extract_timestamp(h) for h in new_docs if _extract_timestamp(h))
                    if max_ts and max_ts > last_seen_ts:
                        last_seen_ts = max_ts
                else:
                    logger.debug("No new events since %s", last_seen_ts.isoformat())
            except Exception as exc:  # noqa: BLE001 - keep loop alive, log error
                logger.exception("Processor iteration error: %s", exc)

            await asyncio.sleep(poll_interval_seconds)
    except asyncio.CancelledError:
        logger.info("Event processor cancellation received.")
        raise
    finally:
        logger.info("Event processor stopped.")


def _extract_timestamp(hit: Dict[str, Any]) -> Optional[datetime]:
    """Extracts @timestamp from a Filebeat hit into aware datetime (UTC)."""
    src = hit.get("_source", {})
    ts_str = src.get("@timestamp") or src.get("timestamp")
    if not ts_str or not isinstance(ts_str, str):
        logger.warning("Skipping event with missing or invalid timestamp: %s", hit.get("_id", "N/A"))
        return None

    # Rely on fromisoformat for RFC3339; strip Z if present
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        logger.warning("Skipping event with malformed timestamp: %s", ts_str, exc_info=True)
        return None


async def _fetch_recent_raw(es: AsyncElasticsearch, since: datetime) -> List[Dict[str, Any]]:
    """
    Query Filebeat indices for events newer than `since` using a Point in Time (PIT)
    and `search_after` to enable deep pagination and avoid data loss.
    """
    all_hits = []
    pit = None
    try:
        pit = await es.open_point_in_time(index=settings.SOURCE_INDEX, keep_alive="1m")
        pit_id = pit["id"]

        query = {"range": {"@timestamp": {"gt": since.isoformat()}}}
        sort = [{"@timestamp": {"order": "asc"}}]
        
        search_after_val = None
        while True:
            resp = await es.search(
                body={
                    "query": query,
                    "size": 500,
                    "sort": sort,
                    "pit": {"id": pit_id, "keep_alive": "1m"},
                    **({"search_after": search_after_val} if search_after_val else {}),
                }
            )
            hits = resp.get("hits", {}).get("hits", [])
            if not hits:
                break
            
            all_hits.extend(hits)
            search_after_val = hits[-1]["sort"]

    except Exception:
        logger.exception("Error fetching recent raw events.")
        # In case of error, return what we have so far
        return all_hits
    finally:
        if pit:
            try:
                await es.close_point_in_time(id=pit["id"])
            except Exception:
                logger.exception("Error closing PIT.")
    
    return all_hits


def _transform_and_score(hit: Dict[str, Any]) -> Optional[ProcessedEvent]:
    """Map raw Cowrie/Filebeat event to ProcessedEvent with heuristic scoring."""
    src = hit.get("_source", {})
    ts_dt = _extract_timestamp(hit)
    if not ts_dt:
        return None  # Skip events we can't parse a timestamp for

    event_type = src.get("eventid") or src.get("event_type") or "unknown"
    username = src.get("username")
    password = src.get("password")
    session_id = src.get("session") or src.get("session_id") or ""
    message = src.get("message")
    source_ip = src.get("src_ip") or src.get("source_ip") or ""
    source_port = src.get("src_port") or src.get("source_port")
    geoip = src.get("geoip")

    score, factors = _score_event(event_type=event_type, src=src)

    model = ProcessedEvent(
        timestamp=ts_dt,
        source_ip=source_ip,
        source_port=source_port,
        geoip=geoip,
        username=username,
        password=password,
        event_type=event_type,
        session_id=session_id,
        message=message,
        risk_score=score,
        risk_factors=factors,
    )
    return model


def _score_event(event_type: str, src: Dict[str, Any]) -> tuple[int, List[str]]:
    """Simple heuristic risk scoring based on Cowrie event types and context."""
    score = 0
    factors: List[str] = []

    # Event type based weights
    if "cowrie.login.success" in event_type:
        score += 90
        factors.append("successful_login")
    if "cowrie.command.input" in event_type:
        score += 15
        factors.append("command_input")
    if "cowrie.session.file_download" in event_type or "cowrie.session.file_upload" in event_type:
        score += 25
        factors.append("file_transfer")
    if "cowrie.login.failed" in event_type:
        score += 10
        factors.append("failed_login")

    # Username/password patterns
    if src.get("username") in {"root", "admin"}:
        score += 10
        factors.append("privileged_account")

    # GeoIP risk: example if country is in a simple watchlist (placeholder)
    country = (src.get("geoip") or {}).get("country_name")
    if country and country in settings.GEOIP_RISK_COUNTRIES:
        score += 5
        factors.append("geo_risk")

    # Clamp 0..100
    score = max(0, min(100, score))
    return score, factors


async def _bulk_index_processed(
    es: AsyncElasticsearch,
    events: List[ProcessedEvent],
    source_hits: List[Dict[str, Any]],
) -> None:
    """Bulk index processed events using deterministic IDs based on source _id."""
    if not events:
        return

    # Build bulk body
    body: List[Dict[str, Any]] = []
    for evt, hit in zip(events, source_hits):
        src_id = hit.get("_id")
        action = {"index": {"_index": settings.PROCESSED_INDEX, "_id": src_id}}
        body.append(action)
        body.append(evt.model_dump(mode="json"))

    resp = await es.bulk(operations=body, refresh=False)
    if resp.get("errors"):
        # Log first few errors for visibility
        items = resp.get("items", [])
        errs = [it for it in items if it.get("index", {}).get("error")]
        logger.warning("Bulk index completed with %d errors (showing up to 3): %s",
                       len(errs), errs[:3])
