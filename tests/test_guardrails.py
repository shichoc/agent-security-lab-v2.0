import pytest

from gateway.app.guardrails.credential_detector import CredentialDetector
from gateway.app.guardrails.pipeline import GuardrailPipeline


@pytest.mark.parametrize(
    "content,signal",
    [
        ("password=Secret123!", "credential.password"),
        ("My password is Secret123!", "credential.password"),
        ("api_key=abc123456", "credential.api_key"),
        ("Authorization: Bearer abc.def.123", "credential.bearer_token"),
        ("Use key sk-test12345678", "credential.openai_key"),
    ],
)
@pytest.mark.asyncio
async def test_blocks_credentials(content, signal):
    result = await GuardrailPipeline([CredentialDetector()]).evaluate(content)
    assert result.decision == "deny"
    assert signal in result.signals
    assert "Secret123" not in result.redacted_content


@pytest.mark.parametrize(
    "content",
    [
        "What is a strong password policy?",
        "Explain what the word password means.",
        "How should an API key be stored?",
    ],
)
@pytest.mark.asyncio
async def test_allows_safe_discussion(content):
    result = await GuardrailPipeline([CredentialDetector()]).evaluate(content)
    assert result.decision == "allow"
    assert result.content == content
