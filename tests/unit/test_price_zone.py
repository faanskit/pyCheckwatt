"""Regression coverage for price zones obtained from site statuses."""

from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import ClientResponseError

from pycheckwatt import CheckwattManager


@pytest.fixture
def manager():
    manager = CheckwattManager("test_user", "test_pass")
    manager.customer_details = {"Meter": [{"RpiSerial": "abc123"}]}
    manager.jwt_token = "test-token"
    manager.session = Mock()
    return manager


def mock_response(manager, payload):
    response = Mock(status=200)
    response.json = AsyncMock(return_value=payload)
    context = manager.session.get.return_value
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=False)
    return response


@pytest.mark.asyncio
async def test_site_status_zone_is_used_for_spot_prices(manager):
    response = mock_response(manager, None)
    prices = {"Prices": [{"Price": 0.42}]}
    response.json.side_effect = [[{"Mba": "SE3"}], prices]

    assert await manager.get_spot_price() is True
    assert manager.price_zone == "SE3"
    assert manager.spot_prices == prices
    requests = manager.session.get.call_args_list
    assert len(requests) == 2
    assert requests[0].args[0] == (
        "https://api.checkwatt.se/site/Statuses?serial=ABC123"
    )
    assert requests[0].kwargs["headers"]["authorization"] == "Bearer test-token"
    assert (
        requests[1]
        .args[0]
        .startswith("https://api.checkwatt.se/ems/spotprice?zone=SE3&")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        [],
        [None],
        [{}],
        [{"Mba": None}],
        [{"Mba": ""}],
        [{"Mba": "  "}],
        [{"Mba": 3}],
    ],
)
async def test_invalid_zone_stops_spot_price_request(manager, payload):
    mock_response(manager, payload)

    assert await manager.get_spot_price() is False
    assert manager.price_zone is None
    manager.session.get.assert_called_once()


@pytest.mark.asyncio
async def test_missing_serial_does_not_send_request(manager):
    manager.customer_details = {"Meter": []}

    assert await manager.get_price_zone() is False
    manager.session.get.assert_not_called()


@pytest.mark.asyncio
async def test_http_failure_stops_spot_price_request(manager):
    response = mock_response(manager, None)
    response.raise_for_status.side_effect = ClientResponseError(
        request_info=Mock(real_url="https://api.checkwatt.se/site/Statuses"),
        history=(),
        status=404,
    )

    assert await manager.get_spot_price() is False
    assert manager.price_zone is None
    manager.session.get.assert_called_once()
    response.json.assert_not_awaited()
