"""
BBOT's MCP layer: a registry of named capabilities, each mapping one
functionality to one BBOT configuration, for consumption by AI agents.

Nothing here is imported at BBOT startup. Importing this package is cheap;
loading the registry (`bbot.mcp.registry.REGISTRY`) is not, because deriving a
capability's facts requires baking its preset.
"""
