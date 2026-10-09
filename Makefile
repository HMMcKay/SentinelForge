.PHONY: up down logs demo test validate clean

up:
	docker compose up --build -d
	docker compose ps

down:
	docker compose down

logs:
	docker compose logs -f backend frontend

demo:
	docker compose --profile tools run --rm sentinelctl demo seed --seed 1337

test:
	docker compose -f compose.test.yaml build
	docker compose -f compose.test.yaml run --rm backend-tests
	docker compose -f compose.test.yaml run --rm frontend-tests
	docker compose -f compose.test.yaml run --rm cli-tests
	dotnet test agent/SentinelForge.Agent.sln --configuration Release
	pwsh -NoProfile -File simulations/tests/Run-SafetyTests.ps1

validate:
	pwsh -NoProfile -File scripts/validate.ps1

clean:
	docker compose down --remove-orphans
