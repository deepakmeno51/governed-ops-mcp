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
