def test_health_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
