PYTHON ?= python
COMPOSE = docker compose --env-file .env -f docker/docker-compose.yml
.PHONY: install ml init db-up db-down schema demo test integration lint format security run analytics predict index quality benchmark golden audit
install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install --no-deps --no-build-isolation -e .
ml:
	$(PYTHON) -m pip install -r requirements-ml.txt --extra-index-url https://download.pytorch.org/whl/cpu
init:
	$(PYTHON) -m scripts.init_env
db-up:
	$(COMPOSE) up -d
	$(PYTHON) -m scripts.wait_neo4j
schema:
	$(PYTHON) -m src.cli schema
db-down:
	$(COMPOSE) down
# Demo is synthetic and local. It never downloads feeds.
demo: init db-up schema
	$(PYTHON) -m src.cli load
	$(PYTHON) -m src.cli quality
	$(PYTHON) -m src.cli analytics
run:
	$(PYTHON) -m app.app
test:
	$(PYTHON) -m pytest -q -m 'not integration'
integration:
	CTIG_INTEGRATION=1 $(PYTHON) -m pytest -q
lint:
	$(PYTHON) -m ruff check src tests scripts app
	$(PYTHON) -m ruff format --check src tests scripts app
format:
	$(PYTHON) -m ruff format src tests scripts app
security:
	$(PYTHON) -m bandit -q -r src app scripts
audit:
	$(PYTHON) -m pip_audit -r requirements.txt
	$(PYTHON) -m scripts.audit_dependencies
analytics:
	$(PYTHON) -m src.cli analytics
predict:
	$(PYTHON) -m src.cli predict --sentence
index:
	$(PYTHON) -m src.cli index --mode sentence
quality:
	$(PYTHON) -m src.cli quality
benchmark:
	$(PYTHON) -m src.cli benchmark
golden:
	$(PYTHON) -m src.cli golden --questions data/eval/fixture_golden.json
