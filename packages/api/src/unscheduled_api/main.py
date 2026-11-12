"""The ASGI app uvicorn serves in the Vercel container (Dockerfile.vercel, port 80).

The services are built from the environment when this module is imported: the database variables
the Neon integration wrote, UNSCHED_CORS_ORIGINS, and config/budgets.yaml. Nothing connects until
the lifespan runs the migrations or the first request arrives.
"""

from __future__ import annotations

from unscheduled_api.app import create_app

app = create_app()
