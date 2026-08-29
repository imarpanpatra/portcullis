// Portcullis MCP server.
//
// TrueForge connects to MCP servers over HTTP, so this listens on a port and speaks
// the MCP streamable-HTTP transport at POST /mcp. Register it in TrueForge under
// Settings -> Connectors -> Add MCP Server, with no auth: every upstream this
// server talks to is a public, keyless API, so there is no credential to leak.

import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools } from "./tools.mjs";

const PORT = Number(process.env.PORTCULLIS_MCP_PORT || 8941);

function buildServer() {
  const server = new McpServer(
    { name: "portcullis", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );
  return registerTools(server);
}

const app = express();
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", server: "portcullis", transport: "streamable-http", path: "/mcp" });
});

app.post("/mcp", async (req, res) => {
  // Stateless: a fresh server and transport per request, so there is no session to
  // track. Every tool here is a plain request/response lookup, which is exactly the
  // case this mode is meant for.
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("[portcullis-mcp] request failed:", err?.message || err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

app.listen(PORT, () => {
  console.log(`[portcullis-mcp] listening on http://localhost:${PORT}/mcp`);
});
