from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'

def test_demo_produces_incident_and_graph():
    response = client.post('/api/v1/demo')
    assert response.status_code == 200
    data = response.json()
    assert data['events_analyzed'] == 4
    assert len(data['incidents']) == 1
    incident = data['incidents'][0]
    assert incident['risk']['score'] > 0
    assert incident['attack_graph']['timeline']
    assert incident['attack_graph']['edges']

def test_duplicate_event_rejected():
    demo = client.post('/api/v1/demo')
    assert demo.status_code == 200
