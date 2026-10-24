# Orders API

Order capture, pricing and refunds for the retail checkout. FastAPI + SQLite.

```bash
pip install -r requirements.txt -r requirements-dev.txt
uvicorn orders_api.main:app --reload
pytest
```

Infrastructure lives in `infra/` (Terraform, eu-west-1).
