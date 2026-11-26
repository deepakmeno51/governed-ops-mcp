# Build from the repo root: the UI reuses the governed/ package (database roles, audit chain, approvals).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY approval_ui/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp_server/governed ./governed
COPY approval_ui/app.py approval_ui/templates.py ./
RUN useradd --system --uid 10004 ui
USER ui
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
