import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock

from sentinel.main import app
from sentinel.api.endpoints import get_es_client
from sentinel.config.settings import settings

# Override API Key for testing purposes
settings.API_KEY = "test-key"

@pytest.fixture
def api_key():
    """Provides the test API key."""
    return {"X-API-KEY": settings.API_KEY}

@pytest.fixture
def mock_es_client():
    """Mocks the Elasticsearch client to avoid real connections during tests."""
    # Use AsyncMock for async methods
    mock = MagicMock()
    mock.search = AsyncMock()
    
    app.dependency_overrides[get_es_client] = lambda: mock
    yield mock
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_health_check():
    """
    Tests the health check endpoint to ensure the API is responsive.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

@pytest.mark.asyncio
async def test_get_latest_events(mock_es_client, api_key):
    """
    Tests the /events/latest endpoint.
    """
    # Mock the Elasticsearch response
    mock_es_client.search.return_value = {
        "hits": {
            "hits": [
                {"_source": {"message": "event 1"}},
                {"_source": {"message": "event 2"}},
            ]
        }
    }
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/events/latest", headers=api_key)
        
        assert response.status_code == 200
        assert response.json() == [{"message": "event 1"}, {"message": "event 2"}]
        # Verify that the es_client.search was called correctly
        mock_es_client.search.assert_called_once()

@pytest.mark.asyncio
async def test_get_high_risk_events(mock_es_client, api_key):
    """
    Tests the /events/high-risk endpoint.
    """
    mock_es_client.search.return_value = {
        "hits": {
            "hits": [
                {"_source": {"risk_score": 80}},
            ]
        }
    }
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/events/high-risk", headers=api_key)
        
        assert response.status_code == 200
        assert response.json() == [{"risk_score": 80}]
        
        # Check that the query sent to Elasticsearch was correct
        _, kwargs = mock_es_client.search.call_args
        assert kwargs["query"]["range"]["risk_score"]["gte"] == 70

@pytest.mark.asyncio
async def test_api_key_missing(mock_es_client):
    """
    Tests that a protected endpoint returns 403 Forbidden without an API key.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/events/latest")
        assert response.status_code == 403
        assert response.json() == {"detail": "Not authenticated"}

@pytest.mark.asyncio
async def test_invalid_api_key(mock_es_client):
    """
    Tests that a protected endpoint returns 403 Forbidden with an invalid API key.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/events/latest", headers={"X-API-KEY": "invalid-key"})
        assert response.status_code == 403
        assert response.json() == {"detail": "Could not validate credentials"}
