import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import MagicMock

from sentinel.main import app
from sentinel.api.endpoints import get_es_client

@pytest.fixture
def mock_es_client():
    """Mocks the Elasticsearch client to avoid real connections during tests."""
    mock = MagicMock()
    # The dependency now expects a Request object, but we can bypass that in tests
    # by providing a simple lambda that returns our mock.
    app.dependency_overrides[get_es_client] = lambda: mock
    yield mock
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_health_check(mock_es_client):
    """
    Tests the health check endpoint to ensure the API is responsive.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
