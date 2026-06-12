.PHONY: install test dev demo observe mcp-server agent probe report extension help

install:  ## Install all dependencies (main + dev + demo extras)
	.venv/bin/pip install -e ".[test,demo]"

test:  ## Run test suite
	.venv/bin/python -m pytest tests/ -q

dev:  ## Start core services (Redis + Postgres + API)
	docker compose up -d redis postgres api

demo:  ## Start full demo stack including demo MCP servers
	docker compose --profile demo up -d

observe:  ## Start with Jaeger tracing (set SENTINEL_OTEL_ENDPOINT=http://jaeger:4317)
	SENTINEL_OTEL_ENDPOINT=http://jaeger:4317 docker compose --profile observability up -d

mcp-server:  ## Run SentinelMCP as an MCP server (port 8889)
	.venv/bin/python demo/sentinel_mcp_server.py

agent:  ## Run the LangGraph security research agent
	.venv/bin/python demo/sentinel_agent.py

probe:  ## Run security probe against SERVER= (e.g. make probe SERVER=http://localhost:8001)
	@curl -s -X POST http://localhost:8888/probe \
	  -H "X-Sentinel-Key: $${SENTINEL_API_KEY:-dev-key-123}" \
	  -H "Content-Type: application/json" \
	  -d '{"server_url":"$(SERVER)","attacks":["all"]}' | python3 -m json.tool

report:  ## Show compliance report (PCI DSS + SOC2)
	@curl -s http://localhost:8888/gateway/compliance/report \
	  -H "X-Sentinel-Key: $${SENTINEL_API_KEY:-dev-key-123}" | python3 -m json.tool

threats:  ## Show recent threats
	@curl -s "http://localhost:8888/gateway/threats?limit=20" \
	  -H "X-Sentinel-Key: $${SENTINEL_API_KEY:-dev-key-123}" | python3 -m json.tool

stats:  ## Show threat statistics
	@curl -s http://localhost:8888/gateway/threats/stats \
	  -H "X-Sentinel-Key: $${SENTINEL_API_KEY:-dev-key-123}" | python3 -m json.tool

extension:  ## Build VS Code extension
	cd extension && npm install && npm run compile

health:  ## Check gateway health
	@curl -s http://localhost:8888/health | python3 -m json.tool

register-rest:  ## Register a REST adapter (BASE_URL= OPENAPI_URL= NAME=)
	@curl -s -X POST http://localhost:8888/adapters/rest/register \
	  -H "X-Sentinel-Key: $${SENTINEL_API_KEY:-dev-key-123}" \
	  -H "Content-Type: application/json" \
	  -d '{"name":"$(NAME)","base_url":"$(BASE_URL)","openapi_url":"$(OPENAPI_URL)"}' \
	  | python3 -m json.tool

attacks:  ## List available probe attack types
	@curl -s http://localhost:8888/probe/attacks | python3 -m json.tool

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'
