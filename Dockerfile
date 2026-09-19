# The MCP server as registries and clients run it: no dependencies, stdio in and out.
FROM python:3.14-slim

WORKDIR /app
COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python3", "mcp_server.py"]
