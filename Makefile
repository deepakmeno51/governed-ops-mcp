include .env
export

up:
	docker compose up -d --build
	docker compose ps

down:
	docker compose down

reset:            ## wipe the volume and re-run db/init/*.sql
	docker compose down -v
	docker compose up -d --build

psql:
	docker compose exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

psql-ro:
	docker compose exec -e PGPASSWORD=$(AGENT_RO_PASSWORD) postgres psql -U agent_ro -d $(POSTGRES_DB)

logs:
	docker compose logs -f

counts:
	docker compose exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c "\
	SELECT 'users' t, count(*) FROM users UNION ALL SELECT 'orders', count(*) FROM orders \
	UNION ALL SELECT 'app_logs', count(*) FROM app_logs UNION ALL SELECT 'tickets', count(*) FROM tickets \
	UNION ALL SELECT 'stuck_orders', count(*) FROM orders WHERE status='processing';"

smoke:
	docker compose exec mcp-server python -m scripts.smoke_client

test:                ## all tests, against a throwaway Postgres (never touches the real database)
	docker compose --profile test run --rm --build tests
	docker compose --profile test rm -sfv postgres-test migrate-test

test-unit:           ## fast tests that need no database, inside the running server container
	docker compose exec mcp-server python -m pytest -q -p no:cacheprovider

verify-audit:
	docker compose exec mcp-server python -m scripts.verify_audit

demo:
	docker compose exec mcp-server python -m scripts.demo_outage

demo-auto:           ## the incident demo with no human: approves through the real UI as carol
	docker compose exec mcp-server python -m scripts.demo_outage --auto-approve

demo-reset:          ## fresh database (250 stuck orders again), then rebuild
	docker compose down -v
	docker compose up -d --build

evals:               ## 24 adversarial scenarios against the running stack
	docker compose exec mcp-server python -m evals.run
