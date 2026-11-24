"""
client.py — Minimal MCP stdio client with tool-call trace logging.

Works with OpenAI (gpt-4o-mini by default) or a local Ollama server
(set OLLAMA_MODEL and it points base_url at http://localhost:11434/v1).

Usage:
    python client.py                  # connects to server.py
    python client.py poisoned_server.py
    python client.py partner_server.py   # Phase 2 swap

This is the UNHARDENED client. It sends tool output back to the model with no
data/instruction separation, so it is vulnerable to indirect prompt injection.
Use hardened_client.py for the Blue Team (Defense 4).
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

# OpenAI by default; Ollama if OLLAMA_MODEL is set.
if os.getenv("OLLAMA_MODEL"):
    llm = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    MODEL = os.environ["OLLAMA_MODEL"]
else:
    llm = OpenAI()  # uses OPENAI_API_KEY
    MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

SERVER_SCRIPT = sys.argv[1] if len(sys.argv) > 1 else "server.py"


async def main():
    server_params = StdioServerParameters(command=sys.executable, args=[SERVER_SCRIPT])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_resp = await session.list_tools()

            print(f"[Client] Connected to {SERVER_SCRIPT}. Tools discovered:")
            for t in tools_resp.tools:
                print(f"  - {t.name}: {t.description!r}")

            openai_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.inputSchema,
                    },
                }
                for t in tools_resp.tools
            ]

            messages = [{"role": "user", "content": input("\nPrompt: ")}]
            while True:
                resp = llm.chat.completions.create(
                    model=MODEL, messages=messages, tools=openai_tools
                )
                msg = resp.choices[0].message
                messages.append(msg)
                if not msg.tool_calls:
                    print("\nAssistant:", msg.content)
                    break
                for tc in msg.tool_calls:
                    print(f"[Client] Calling tool: {tc.function.name}({tc.function.arguments})")
                    result = await session.call_tool(
                        tc.function.name, json.loads(tc.function.arguments)
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": str(result.content),
                        }
                    )


if __name__ == "__main__":
    asyncio.run(main())
