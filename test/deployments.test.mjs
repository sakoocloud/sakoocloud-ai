import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createServer } from "../dist/server.js";

const appId = "019b0000-0000-7000-8000-000000000001";
const deployId = "019b0000-0000-7000-8000-000000000002";
const app = { app_id: appId };
const deployment = { ...app, deploy_id: deployId };

async function connect(t, api, confirm) {
  const server = createServer(api);
  const client = new Client({ name: "tool-test", version: "1.0.0" }, {
    capabilities: confirm ? { elicitation: { form: {} } } : {},
  });
  if (confirm) client.setRequestHandler(ElicitRequestSchema, confirm);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => {
    await client.close();
    await server.close();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
}

async function call(client, tool, args) {
  return client.callTool({ name: `sakoocloud_${tool}`, arguments: args });
}

async function read(client, tool, args) {
  const result = await call(client, tool, args);
  assert.equal(result.isError, undefined, result.content[0].text);
  return JSON.parse(result.content[0].text);
}

const accept = async () => ({ action: "accept", content: { confirm: true } });

test("deployment detail is discoverable and reads status for the specified app and deployment", async (t) => {
  const client = await connect(t, {
    async getDeployment(...args) {
      assert.deepEqual(args, [appId, deployId]);
      return { id: deployId, status: "running", buildLogUrl: "signed-url" };
    },
  });
  const catalog = await client.listTools();
  const tool = catalog.tools.find(({ name }) => name === "sakoocloud_get_deployment");
  assert.deepEqual(tool.annotations, { readOnlyHint: true, destructiveHint: false });
  assert.deepEqual(await read(client, "get_deployment", deployment), {
    id: deployId, status: "running", buildLogUrl: "[REDACTED]",
  });
});

test("build tail and cursor pages preserve next cursor and completion; runtime tail scrubs credentials", async (t) => {
  const buildLines = ["one", "two", "TOKEN=build-secret", "four"];
  const client = await connect(t, {
    async getBuildLogs(app, dep, cursor) {
      assert.deepEqual([app, dep], [appId, deployId]);
      return { lines: buildLines.slice(cursor), cursor: buildLines.length, done: true };
    },
    async getRuntimeLogs(app, limit) {
      assert.deepEqual([app, limit], [appId, 2]);
      return ["old", "GET /health", "Authorization: Bearer runtime-secret"];
    },
  }, accept);

  const page = await read(client, "get_build_logs", { ...deployment, lines: 2, cursor: 0 });
  assert.deepEqual(page, { lines: ["one", "two"], cursor: 2, done: false });
  const latest = { lines: ["[REDACTED]", "four"], cursor: 4, done: true };
  assert.deepEqual(await read(client, "get_build_logs", { ...deployment, lines: 2, cursor: page.cursor }), latest);
  assert.deepEqual(await read(client, "get_build_logs", { ...deployment, lines: 2 }), latest);
  assert.deepEqual(await read(client, "get_runtime_logs", { ...app, lines: 2 }), {
    lines: ["GET /health", "Authorization: [REDACTED]"],
  });
  for (const args of [{ lines: 1001 }, { cursor: -1 }, { app_id: "../different-app" }]) {
    assert.equal((await call(client, "get_build_logs", { ...deployment, ...args })).isError, true);
  }
});

test("app env lists names by default and reveals only explicitly public values after confirmation", async (t) => {
  let reads = 0;
  let confirmation = "decline";
  const client = await connect(t, {
    async getEnv(id) {
      assert.equal(id, appId);
      reads++;
      return [
        { key: "MODE", value: "production", is_secret: false },
        { key: "PASSWORD", value: "unexpected-cleartext", is_secret: true },
        { key: "UNKNOWN", value: "unclassified" },
        { key: "SERVICE_API_KEY", value: "misclassified", is_secret: false },
      ];
    },
  }, async () => ({ action: confirmation, content: { confirm: true } }));

  assert.deepEqual(await read(client, "get_env", app), {
    vars: [{ key: "MODE" }, { key: "PASSWORD" }, { key: "UNKNOWN" }, { key: "SERVICE_API_KEY" }],
  });
  assert.equal((await call(client, "get_env", { ...app, include_values: true })).isError, true);
  assert.equal(reads, 1);
  confirmation = "accept";
  assert.deepEqual(await read(client, "get_env", { ...app, include_values: true }), {
    vars: [
      { key: "MODE", value: "production" },
      { key: "PASSWORD", value: "[REDACTED]" },
      { key: "UNKNOWN", value: "[REDACTED]" },
      { key: "SERVICE_API_KEY", value: "[REDACTED]" },
    ],
  });
});

test("deployment, env, and domain mutations require approval, with destructive rollback annotated", async (t) => {
  const calls = [];
  const client = await connect(t, {
    async rollbackDeployment(...args) {
      calls.push(args);
      return { status: "pending", credentials: { password: "secret" } };
    },
  }, accept);
  const { tools } = await client.listTools();
  const mutations = ["deploy_app", "redeploy_app", "rollback_deployment", "set_env", "delete_env_var", "add_domain"];
  for (const name of mutations) {
    const tool = tools.find((tool) => tool.name === `sakoocloud_${name}`);
    assert.equal(tool.annotations.readOnlyHint, false);
    assert.equal(tool.annotations.destructiveHint, name !== "add_domain");
  }
  assert.deepEqual(await read(client, "rollback_deployment", deployment), {
    status: "pending", credentials: "[REDACTED]",
  });
  assert.deepEqual(calls, [[appId, deployId]]);

  const unapproved = await connect(t, {
    async rollbackDeployment(...args) { calls.push(args); },
  });
  assert.equal((await call(unapproved, "rollback_deployment", deployment)).isError, true);
  assert.equal(calls.length, 1);
});

test("env write errors keep submitted values private", async (t) => {
  const client = await connect(t, {
    async setEnv() {
      throw new Error("Invalid parameter: hidden-value");
    },
  }, accept);
  const failed = await call(client, "set_env", { ...app, vars: [{ key: "SECRET", value: "hidden-value" }] });
  assert.equal(failed.isError, true);
  assert.doesNotMatch(failed.content[0].text, /hidden-value/);
});

test("project database list preserves pagination and redacts connection strings without elicitation", async (t) => {
  const database = { id: deployId, name: "demo", status: "running", connectionUser: "private-user", publicUri: "postgres://private" };
  const client = await connect(t, {
    async getDatabases(...args) {
      assert.deepEqual(args, [appId, 2, 5]);
      return { data: [database], total: 1, page: 2, limit: 5 };
    },
  });

  const metadata = { ...database, connectionUser: "[REDACTED]", publicUri: "[REDACTED]" };
  assert.deepEqual(await read(client, "list_databases", { project_id: appId, page: 2, limit: 5 }), {
    data: [metadata], total: 1, page: 2, limit: 5,
  });
});

test("domain creation validates hostnames before requesting confirmation", async (t) => {
  let confirmations = 0;
  const client = await connect(t, {
    async addDomain(id, domain) {
      assert.equal(id, appId);
      assert.equal(domain, "app.example.com");
      return { domain };
    },
  }, async () => {
    confirmations++;
    return accept();
  });

  for (const domain of ["https://example.com", "example.com/path", "example.com:443", "127.0.0.1", "localhost", "bad-.example.com"]) {
    assert.equal((await call(client, "add_domain", { ...app, domain })).isError, true);
  }
  assert.equal(confirmations, 0);
  assert.deepEqual(await read(client, "add_domain", { ...app, domain: "app.example.com" }), { domain: "app.example.com" });
  assert.equal(confirmations, 1);
});
