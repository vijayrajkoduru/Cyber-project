# FastAPI Service

A Python FastAPI service scaffold with a clean project layout, example router, tests, and Docker support.

## Project Structure

```
fastapi-service/
├── app/
│   ├── __init__.py
│   ├── main.py          # App factory and root/health endpoints
│   ├── config.py        # Settings via environment variables
│   └── routers/
│       ├── __init__.py
│       └── items.py     # Example CRUD router
├── tests/
│   └── test_api.py      # API tests using TestClient
├── requirements.txt     # Runtime dependencies
├── requirements-dev.txt # Dev/test dependencies
├── Dockerfile
└── .gitignore
```

## Getting Started

### Local Development

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run the development server (auto-reload)
uvicorn app.main:app --reload
```

The API is served at http://localhost:8000.
Interactive docs: http://localhost:8000/docs

### Running Tests

```bash
pytest
```

### Docker

```bash
docker build -t fastapi-service .
docker run -p 8000:8000 fastapi-service
```

## Configuration

Settings are read from environment variables (see `app/config.py`):

| Variable      | Default           | Description              |
|---------------|-------------------|--------------------------|
| `APP_NAME`    | `fastapi-service` | Application name         |
| `DEBUG`       | `false`           | Enable debug mode        |

## Endpoints

| Method | Path          | Description            |
|--------|---------------|------------------------|
| GET    | `/`           | Service info           |
| GET    | `/health`     | Health check           |
| GET    | `/items`      | List items             |
| POST   | `/items`      | Create an item         |
| GET    | `/items/{id}` | Get an item by id      |
| DELETE | `/items/{id}` | Delete an item by id   |
