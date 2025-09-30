FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup -S app && adduser -S app -G app
RUN apk add --no-cache tzdata ca-certificates && update-ca-certificates

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

COPY signer /opt/signer
USER app
WORKDIR /opt/signer
ENTRYPOINT ["python", "/opt/signer/signer.py"]
