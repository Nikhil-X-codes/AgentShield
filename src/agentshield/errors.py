"""Actionable errors raised by AgentShield boundaries."""


class AgentShieldError(Exception):
    """Base class for expected, user-actionable failures."""


class ConfigurationError(AgentShieldError):
    """The project configuration is invalid or incomplete."""


class ScopeViolation(AgentShieldError):
    """An operation falls outside the explicitly configured test scope."""


class ProviderError(AgentShieldError):
    """An optional model provider failed or returned invalid data."""
