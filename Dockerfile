# This demonstration starts by pulling a tag for simplicity. We will replace this with a digest later.
FROM python:3.13-slim@sha256:baf66684c5fcafbda38a54b227ee30ec41e40af1e4073edee3a7110a417756ba

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080

CMD ["python", "app.py"]