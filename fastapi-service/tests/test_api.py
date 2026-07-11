from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "fastapi-service"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_and_get_item():
    response = client.post("/items", json={"name": "widget", "description": "a widget"})
    assert response.status_code == 201
    item = response.json()
    assert item["name"] == "widget"

    response = client.get(f"/items/{item['id']}")
    assert response.status_code == 200
    assert response.json() == item


def test_list_items():
    client.post("/items", json={"name": "gadget"})
    response = client.get("/items")
    assert response.status_code == 200
    assert len(response.json()) >= 1


def test_get_missing_item_returns_404():
    response = client.get("/items/999999")
    assert response.status_code == 404


def test_delete_item():
    item_id = client.post("/items", json={"name": "temp"}).json()["id"]
    response = client.delete(f"/items/{item_id}")
    assert response.status_code == 204
    assert client.get(f"/items/{item_id}").status_code == 404
