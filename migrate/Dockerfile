FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY alembic.ini seed.py seed.sql ./
COPY alembic ./alembic
RUN useradd --system --uid 10002 migrator
USER migrator
CMD ["sh", "-c", "alembic upgrade head && python seed.py"]
