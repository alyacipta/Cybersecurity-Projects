# ©AngelaMos | 2026
# Makefile

.DEFAULT_GOAL := help
SHELL := /bin/bash

COMPOSE_PROD := docker compose -f compose.yml
COMPOSE_DEV  := docker compose -f dev.compose.yml
COMPOSE_TUN  := docker compose -f compose.yml -f cloudflared.compose.yml

.PHONY: help up up-dev up-tunnel down down-dev logs logs-dev ps ps-dev migrate migrate-dev psql redis-cli backend-shell frontend-shell tidy fmt test build-prod stop clean

help:
	@echo 'Monitor the Situation — Make targets:'
	@echo ''
	@echo '  Production:'
	@echo '    up               start production stack (no tunnel)'
	@echo '    up-tunnel        start production stack + cloudflared'
	@echo '    down             stop production stack'
	@echo '    logs             tail production logs'
	@echo '    ps               status of production services'
	@echo ''
	@echo '  Development:'
	@echo '    up-dev           start dev stack (vite + air)'
	@echo '    down-dev         stop dev stack'
	@echo '    logs-dev         tail dev logs'
	@echo '    ps-dev           status of dev services'
	@echo ''
	@echo '  Database:'
	@echo '    migrate          run goose migrations against prod db'
	@echo '    migrate-dev      run goose migrations against dev db'
	@echo '    psql             psql shell into dev db'
	@echo '    redis-cli        redis-cli shell into dev redis'
	@echo ''
	@echo '  Backend:'
	@echo '    backend-shell    shell into the dev backend container'
	@echo '    test             run all backend tests with -race'
	@echo '    fmt              format Go code'
	@echo '    tidy             go mod tidy'
	@echo ''
	@echo '  Frontend:'
	@echo '    frontend-shell   shell into the dev frontend container'
	@echo ''

up:
	$(COMPOSE_PROD) up -d --build

up-tunnel:
	$(COMPOSE_TUN) up -d --build

up-dev:
	$(COMPOSE_DEV) up -d --build

down:
	$(COMPOSE_PROD) down

down-dev:
	$(COMPOSE_DEV) down

logs:
	$(COMPOSE_PROD) logs -f --tail=200

logs-dev:
	$(COMPOSE_DEV) logs -f --tail=200

ps:
	$(COMPOSE_PROD) ps

ps-dev:
	$(COMPOSE_DEV) ps

migrate:
	$(COMPOSE_PROD) exec backend sh -c 'goose -dir /migrations postgres "$$DATABASE_URL" up'

migrate-dev:
	$(COMPOSE_DEV) exec backend sh -c 'cd /app && goose -dir migrations postgres "$$DATABASE_URL" up'

psql:
	$(COMPOSE_DEV) exec postgres psql -U $${POSTGRES_USER:-monitor} -d $${POSTGRES_DB:-monitor}

redis-cli:
	$(COMPOSE_DEV) exec redis redis-cli

backend-shell:
	$(COMPOSE_DEV) exec backend sh

frontend-shell:
	$(COMPOSE_DEV) exec frontend sh

test:
	cd backend && go test -race -count=1 ./...

fmt:
	cd backend && gofumpt -w . && goimports -w .

tidy:
	cd backend && go mod tidy

build-prod:
	$(COMPOSE_PROD) build

stop:
	$(COMPOSE_DEV) stop ; $(COMPOSE_PROD) stop

clean: stop
	$(COMPOSE_DEV) down -v
	$(COMPOSE_PROD) down -v
