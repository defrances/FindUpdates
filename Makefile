.PHONY: lint format-check typecheck test compile check

lint:
	ruff check .

format-check:
	ruff format --check .

typecheck:
	mypy src

test:
	python -m unittest discover -s tests/unit -p 'test_*.py' -v

compile:
	python -m compileall -q src

check: lint format-check typecheck test compile
