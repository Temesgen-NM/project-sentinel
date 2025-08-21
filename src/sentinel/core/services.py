"""Core services: background processing and integrations.

This module provides minimal async stubs to allow the app to start.
Production logic can be added incrementally without breaking imports.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from elasticsearch import AsyncElasticsearch

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


async def process_new_events(es_client: AsyncElasticsearch, poll_interval_seconds: float = 5.0) -> None:
    """Continuously fetch recent raw events, score, and index into processed index.

    Strategy
    - Maintain a moving watermark `last_seen_ts` on the Filebeat `@timestamp` field.
    - On each iteration, query events with `@timestamp > last_seen_ts`.
    - Transform and bulk index into `settings.PROCESSED_INDEX`.
    Notes
    - This in-memory watermark resets on restart; acceptable for MVP. Duplicates are
      mitigated by using deterministic IDs based on source doc `_id`.
    """
    logger.info("Event processor started.")

    last_seen_ts: datetime = datetime.now(timezone.utc) - timedelta(minutes=5)

    try:
        while True:
            try:
                new_docs = await _fetch_recent_raw(es_client, since=last_seen_ts)
                if new_docs:
                    logger.info("Fetched %d new raw events since %s", len(new_docs), last_seen_ts.isoformat())
                    processed = [_transform_and_score(hit) for hit in new_docs]
                    await _bulk_index_processed(es_client, processed, source_hits=new_docs)

                    # Advance watermark to max @timestamp observed
                    max_ts = max(_extract_timestamp(h) for h in new_docs)
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


def _extract_timestamp(hit: Dict[str, Any]) -> datetime:
    """Extracts @timestamp from a Filebeat hit into aware datetime (UTC)."""
    src = hit.get("_source", {})
    ts = src.get("@timestamp") or src.get("timestamp")
    if not ts:
        return datetime.now(timezone.utc)
    # Rely on fromisoformat for RFC3339; strip Z if present
    if isinstance(ts, str):
        ts = ts.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


async def _fetch_recent_raw(es: AsyncElasticsearch, since: datetime, size: int = 500) -> List[Dict[str, Any]]:
    """Query Filebeat indices for events newer than `since` using @timestamp."""
    query = {
        "range": {
            "@timestamp": {"gt": since.isoformat()}
        }
    }
    resp = await es.search(
        index=settings.SOURCE_INDEX,
        query=query,
        size=size,
        sort=[{"@timestamp": {"order": "asc"}}],
    )
    return resp.get("hits", {}).get("hits", [])


def _transform_and_score(hit: Dict[str, Any]) -> ProcessedEvent:
    """Map raw Cowrie/Filebeat event to ProcessedEvent with heuristic scoring."""
    src = hit.get("_source", {})

    # Basic field extraction with fallbacks
    ts = src.get("timestamp") or src.get("@timestamp")
    if isinstance(ts, str):
        ts = ts.replace("Z", "+00:00")
        try:
            ts_dt = datetime.fromisoformat(ts)
        except ValueError:
            ts_dt = datetime.now(timezone.utc)
    else:
        ts_dt = datetime.now(timezone.utc)

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
    if country in {"Russian Federation", "China", "Iran"}:
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
        body.append(evt.model_dump())

    resp = await es.bulk(operations=body, refresh=False)
    if resp.get("errors"):
        # Log first few errors for visibility
        items = resp.get("items", [])
        errs = [it for it in items if it.get("index", {}).get("error")]
        logger.warning("Bulk index completed with %d errors (showing up to 3): %s",
                       len(errs), errs[:3])