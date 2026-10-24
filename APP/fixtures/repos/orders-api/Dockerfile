FROM python:latest
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY orders_api ./orders_api
CMD ["uvicorn", "orders_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
