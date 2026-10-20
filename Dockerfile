FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin map
USER 10001:10001

EXPOSE 8765
ENTRYPOINT ["map-server"]
CMD ["--transport", "http"]
