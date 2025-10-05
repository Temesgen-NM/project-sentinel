"""Core services: background processing and integrations."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx
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
    consecutive_errors = 0
    MAX_CONSECUTIVE_ERRORS = 5

    try:
        while True:
            try:
                new_docs = await _fetch_recent_raw(es_client, since=last_seen_ts)
                if new_docs:
                    logger.info("Fetched %d new raw events since %s", len(new_docs), last_seen_ts.isoformat())
                    processed_events = []
                    source_hits = []
                    
                    # Create a list of tasks to run in parallel
                    tasks = [_transform_and_score(hit) for hit in new_docs]
                    results = await asyncio.gather(*tasks)
                    
                    for i, transformed in enumerate(results):
                        if transformed:
                            processed_events.append(transformed)
                            source_hits.append(new_docs[i])

                    if processed_events:
                        await _bulk_index_processed(es_client, processed_events, source_hits=source_hits)

                    # Advance watermark to max @timestamp observed
                    max_ts = max(_extract_timestamp(h) for h in new_docs if _extract_timestamp(h))
                    if max_ts and max_ts > last_seen_ts:
                        last_seen_ts = max_ts
                else:
                    logger.debug("No new events since %s", last_seen_ts.isoformat())
                
                consecutive_errors = 0 # Reset on success

            except Exception as exc:  # noqa: BLE001 - keep loop alive, log error
                logger.exception("Processor iteration error: %s", exc)
                consecutive_errors += 1
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    logger.error("Exceeded max consecutive errors. Shutting down processor.")
                    raise RuntimeError("Event processor failed due to repeated errors.")
                await asyncio.sleep(5) # Wait before retrying

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


async def _transform_and_score(hit: Dict[str, Any]) -> Optional[ProcessedEvent]:
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

    score, factors = await _score_event(event_type=event_type, src=src, timestamp=ts_dt)

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


async def _score_event(event_type: str, src: Dict[str, Any], timestamp: datetime) -> tuple[int, List[str]]:
    """
    Advanced heuristic risk scoring for Cowrie events.
    Uses a weighted system and considers event context.
    """
    score = 0
    factors: List[str] = []

    # --- Define weights for different indicators ---
    WEIGHTS = {
        "login_success": 80,
        "login_failed": 10,
        "privileged_account": 15,
        "command_input": 5,
        "suspicious_command": 30,
        "file_transfer": 40,
        "geo_risk": 10,
        "night_activity": 5,  # Activity during non-business hours
        "ip_reputation_risk": 50, # Placeholder for external service
    }

    # --- Event Type Scoring ---
    if "cowrie.login.success" in event_type:
        score += WEIGHTS["login_success"]
        factors.append("successful_login")
    elif "cowrie.login.failed" in event_type:
        score += WEIGHTS["login_failed"]
        factors.append("failed_login")
    elif "cowrie.command.input" in event_type:
        score += WEIGHTS["command_input"]
        factors.append("command_input")
        # Check for suspicious commands
        command = src.get("input", "")
        if any(cmd in command for cmd in settings.SUSPICIOUS_COMMANDS):
            score += WEIGHTS["suspicious_command"]
            factors.append("suspicious_command")
    elif "cowrie.session.file_download" in event_type or "cowrie.session.file_upload" in event_type:
        score += WEIGHTS["file_transfer"]
        factors.append("file_transfer")

    # --- Contextual Scoring ---
    if src.get("username") in {"root", "admin"}:
        score += WEIGHTS["privileged_account"]
        factors.append("privileged_account")

    country = (src.get("geoip") or {}).get("country_name")
    if country and country in settings.GEOIP_RISK_COUNTRIES:
        score += WEIGHTS["geo_risk"]
        factors.append("geo_risk")

    # Check if the event occurred at night (e.g., 10 PM to 5 AM UTC)
    if timestamp.hour >= 22 or timestamp.hour <= 5:
        score += WEIGHTS["night_activity"]
        factors.append("night_activity")
        
    # --- IP Reputation (Placeholder) ---
    # In a real system, you would call an external service here.
    # This function is a placeholder to show where to integrate it.
    if await _check_ip_reputation(src.get("src_ip")):
        score += WEIGHTS["ip_reputation_risk"]
        factors.append("ip_reputation_risk")

    # Clamp score to a 0-100 range
    score = max(0, min(100, score))
    return score, sorted(list(set(factors))) # Return unique, sorted factors


async def _check_ip_reputation(ip_address: Optional[str]) -> bool:
    """
    Check an IP address against the AbuseIPDB API.
    
    Args:
        ip_address: The IP address to check.
        
    Returns:
        True if the IP is considered high-risk, False otherwise.
    """
    if not ip_address or not settings.ABUSEIPDB_API_KEY:
        return False

    try:
        async with httpx.AsyncClient() as client:
            headers = {
                'Accept': 'application/json',
                'Key': settings.ABUSEIPDB_API_KEY
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }
            response = await client.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("data", {}).get("abuseConfidenceScore", 0) > settings.ABUSEIPDB_CONFIDENCE_THRESHOLD:
                logger.info(f"High-risk IP detected: {ip_address} (Score: {data['data']['abuseConfidenceScore']})")
                return True
                
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error while checking IP reputation for {ip_address}: {e}")
    except Exception as e:
        logger.error(f"Failed to check IP reputation for {ip_address}: {e}")
        
    return False


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
