# va-triage-agent as a CI step: docker run --rm -v "$PWD:/work" va-triage-agent lab --out /work/out
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/va
COPY pyproject.toml ./
COPY vatriage/ vatriage/
COPY data/ data/
COPY lab/ lab/
RUN pip install --no-cache-dir ".[dev]" && useradd --system --uid 10001 va
USER 10001
WORKDIR /work
ENTRYPOINT ["vatriage"]
CMD ["--help"]
