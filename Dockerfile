FROM python:3.14.5-slim


WORKDIR /app

COPY pyproject.toml ./

RUN pip install --no-cache-dir .

COPY genius_analysis.py .

EXPOSE 8443

ENV PYTHONUNBUFFERED=1

CMD ["tetragon-edr"]
