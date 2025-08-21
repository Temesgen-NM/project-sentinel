"""Core services: background processing and integrations.

This module provides minimal async stubs to allow the app to start.
Production logic can be added incrementally without breaking imports.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

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


async def process_new_events(es_client: Any, poll_interval_seconds: float = 5.0) -> None:
    """Background loop placeholder to process and index events.

    This stub keeps the task alive to validate lifecycle handling. Replace the
    loop body with real fetch/transform/index logic.
    """
    logger.info("Event processor started (stub).")
    try:
        while True:
            # TODO: fetch new raw events from source index, transform to ProcessedEvent,
            # and index into settings.PROCESSED_INDEX
            await asyncio.sleep(poll_interval_seconds)
    except asyncio.CancelledError:
        logger.info("Event processor cancellation received.")
        raise
    finally:
        logger.info("Event processor stopped.")