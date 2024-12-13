import json
import pytest
import stripe
from unittest import mock
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from pretix.base.settings import GlobalSettingsObject

from eventyay_stripe.views import webhook 


@pytest.fixture
def factory():
    return RequestFactory()


@pytest.fixture
def mock_global_settings():
    with mock.patch('pretix.base.settings.GlobalSettingsObject') as MockGlobalSettings:
        instance = MockGlobalSettings.return_value
        instance.settings.payment_stripe_connect_secret_key = 'sk_test_123'
        instance.settings.payment_stripe_connect_test_secret_key = 'sk_test_123'
        instance.settings.payment_stripe_webhook_secret = 'whsec_123'
        yield instance


@pytest.fixture
def valid_payload():
    return json.dumps({
        "id": "evt_1",
        "object": "event",
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "object": "charge",
                "id": "pi_1",
                "amount": 2000,
                "currency": "usd",
                "status": "succeeded",
                "livemode": True,
                "pending_webhooks": 1,
                "request": "req_977XOWC8zk51Z9",
                "type": "charge.succeeded"
            }
        }
    })


@pytest.mark.django_db
def test_webhook_invalid_payload(factory, mock_global_settings):
    invalid_payload = "invalid_payload"
    request = factory.post('/webhook', data=invalid_payload, content_type='application/json')
    with mock.patch('stripe.Webhook.construct_event', side_effect=ValueError("Invalid JSON")):
        response = webhook(request)
        assert response.status_code == 400
        assert response.content == b"Invalid JSON payload"


@pytest.mark.django_db
def test_webhook_invalid_signature(factory, valid_payload, mock_global_settings):
    request = factory.post('/webhook', data=valid_payload, content_type='application/json')
    request.META['HTTP_STRIPE_SIGNATURE'] = 'invalid_signature'

    with mock.patch('stripe.Webhook.construct_event', side_effect=stripe.error.SignatureVerificationError("Invalid signature", 'sig_123')):
        response = webhook(request)
        assert response.status_code == 400
        assert response.content == b"Invalid Stripe signature"


@pytest.mark.django_db
def test_webhook_success(factory, valid_payload, mock_global_settings):
    request = factory.post('/webhook', data=valid_payload, content_type='application/json')
    request.META['HTTP_STRIPE_SIGNATURE'] = 'valid_signature'

    with mock.patch('stripe.Webhook.construct_event', return_value={"type": "payment_intent.succeeded"}):
        response = webhook(request)
        assert response.status_code == 200
