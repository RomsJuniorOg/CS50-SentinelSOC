"""
test_app.py - Integration tests for Flask endpoints, user authentication, and incident lifecycle.
CS50 Final Project.
"""

import pytest
from app import app as flask_app
from database import query_db


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False

    with flask_app.test_client() as client:
        yield client


def test_index_redirects_unauthenticated(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_successful(client):
    response = client.post("/login", data={
        "username": "admin",
        "password": "Sentinel123!"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Security Operations Center" in response.data


def test_login_invalid_credentials(client):
    response = client.post("/login", data={
        "username": "admin",
        "password": "WrongPassword!"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_register_validation(client):
    # Short password
    response = client.post("/register", data={
        "full_name": "Test Analyst",
        "username": "testuser",
        "password": "123",
        "confirmation": "123"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"at least 8 characters" in response.data


def test_api_stats_endpoint(client):
    # Log in first
    client.post("/login", data={"username": "admin", "password": "Sentinel123!"})
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "severity" in data
    assert "category" in data
    assert "status" in data


def test_create_and_view_incident(client):
    client.post("/login", data={"username": "admin", "password": "Sentinel123!"})

    # Create new incident
    create_resp = client.post("/incidents/new", data={
        "title": "Integration Test Probe Incident",
        "description": "Automated incident created during test suite run.",
        "severity": "High",
        "category": "Web Attack",
        "affected_asset": "test-srv.corp.internal",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "initial_ioc": "194.26.29.112"
    }, follow_redirects=True)

    assert create_resp.status_code == 200
    assert b"Integration Test Probe Incident" in create_resp.data
    assert b"194.26.29.112" in create_resp.data


def test_threat_lookup_endpoint(client):
    client.post("/login", data={"username": "admin", "password": "Sentinel123!"})

    response = client.post("/threat_lookup", data={
        "ioc": "45.142.214.18"
    })
    assert response.status_code == 200
    assert b"Cobalt Strike TeamServer" in response.data
    assert b"Malicious" in response.data
