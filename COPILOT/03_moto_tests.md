# Task 03 — AWS Inventory Tests (moto) & Untagged Defaults
**Prompt:**
Update `integrations/aws/aws_inventory.py` to set defaults for untagged assets. Write moto tests for pagination, throttling resilience, tag mapping, and defaults. Add `.github/workflows/tests.yml` to run pytest.

**Commands:**
```bash
pip install -r integrations/aws/requirements-dev.txt
pytest -q
```

**Acceptance:**
- Tests green locally and in CI. WORKLOG updated.
