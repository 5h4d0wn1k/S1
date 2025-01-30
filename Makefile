.PHONY: install dev test lint clean build deploy

# Development Setup
install:
	cd frontend && npm install
	cd backend && pip install -r requirements.txt

# Development
dev:
	docker-compose up -d
	cd frontend && npm run dev & cd backend && uvicorn src.main:app --reload --port 8000

# Testing
test:
	cd frontend && npm run test
	cd backend && pytest

# Linting
lint:
	cd frontend && npm run lint
	cd backend && black . && isort . && flake8

# Cleaning
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "node_modules" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Building
build:
	cd frontend && npm run build
	cd backend && python -m build

# Deployment
deploy:
	kubectl apply -f infrastructure/kubernetes/

# Infrastructure
infra-init:
	cd infrastructure/terraform && terraform init

infra-plan:
	cd infrastructure/terraform && terraform plan

infra-apply:
	cd infrastructure/terraform && terraform apply

# Database
db-migrate:
	cd backend && alembic upgrade head

db-rollback:
	cd backend && alembic downgrade -1

# Docker
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# Development Tools
format:
	cd frontend && npm run format
	cd backend && black . && isort .

type-check:
	cd frontend && npm run type-check
	cd backend && mypy .

security-check:
	cd frontend && npm audit
	cd backend && safety check

# Documentation
docs-serve:
	cd docs && mkdocs serve

docs-build:
	cd docs && mkdocs build

# Help
help:
	@echo "Available commands:"
	@echo "  make install         - Install all dependencies"
	@echo "  make dev            - Start development servers"
	@echo "  make test           - Run all tests"
	@echo "  make lint           - Run linters"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make build          - Build for production"
	@echo "  make deploy         - Deploy to Kubernetes"
	@echo "  make docker-up      - Start Docker containers"
	@echo "  make docker-down    - Stop Docker containers"
	@echo "  make format         - Format code"
	@echo "  make type-check     - Run type checking"
	@echo "  make security-check - Run security audits"
	@echo "  make docs-serve     - Serve documentation locally" 