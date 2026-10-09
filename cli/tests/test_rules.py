from sentinelctl.main import validate_rule_document


def test_cli_validator_accepts_supported_subset() -> None:
    errors = validate_rule_document(
        {
            "title": "Test",
            "id": "SF-CLI-TEST",
            "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"process.command_line|contains": "-enc"},
                "condition": "selection",
            },
            "level": "high",
        },
        "test.yml",
    )
    assert errors == []


def test_cli_validator_rejects_unsupported_sigma_features() -> None:
    errors = validate_rule_document(
        {
            "title": "Test",
            "id": "SF-CLI-TEST",
            "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"process.command_line|re": ".*"},
                "timeframe": "5m",
                "condition": "selection",
            },
            "level": "high",
        },
        "test.yml",
    )
    assert any("timeframe" in error for error in errors)
    assert any("unsupported modifiers" in error for error in errors)
