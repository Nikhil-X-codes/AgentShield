"""Run the local AgentShield web API bound only to loopback."""

from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run("agentshield.web.api:app", host="127.0.0.1", port=8000, reload=False, access_log=False)


if __name__ == "__main__":
    main()
