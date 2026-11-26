export interface ToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
}

interface ToolDetails {
  name: string;
  description: string;
}

interface ConfirmationRequest {
  mode: "form";
  message: string;
  requestedSchema: {
    type: "object";
    properties: {
      confirm: {
        type: "boolean";
        title: string;
      };
    };
    required: string[];
  };
}

interface ConfirmationResponse {
  action: "accept" | "decline" | "cancel";
  content?: Record<string, unknown>;
}

export interface ConfirmationRequester {
  getClientCapabilities(): { elicitation?: { form?: unknown } } | undefined;
  elicitInput(params: ConfirmationRequest): Promise<ConfirmationResponse>;
}

const DESTRUCTIVE_TOOL_NAME = /(delete|remove|revoke|rotate|restore|rollback|disable|stop|unlink|unassign|detach|cancel|disconnect|_deploy_app$|_redeploy_app$|_set_env$)/;
const CONFIRMATION_REQUIRED_READS = new Set([
  "sakoocloud_get_build_logs",
  "sakoocloud_get_runtime_logs",
  "sakoocloud_list_domains",
]);
const LOW_RISK_READ_ONLY_TOOLS = new Set([
  "sakoocloud_whoami",
  "sakoocloud_list_regions",
  "sakoocloud_list_projects",
  "sakoocloud_get_project",
  "sakoocloud_list_members",
  "sakoocloud_list_invites",
  "sakoocloud_list_apps",
  "sakoocloud_get_app",
  "sakoocloud_list_environments",
  "sakoocloud_list_deployments",
  "sakoocloud_get_deployment",
  "sakoocloud_get_env",
  "sakoocloud_list_databases",
  "sakoocloud_get_database",
  "sakoocloud_get_database_versions",
  "sakoocloud_list_backups",
  "sakoocloud_list_dns_zones",
  "sakoocloud_list_dns_records",
  "sakoocloud_list_templates",
  "sakoocloud_get_template",
  "sakoocloud_get_template_deployment",
  "sakoocloud_get_app_metrics",
  "sakoocloud_get_database_metrics",
  "sakoocloud_get_tiers",
  "sakoocloud_get_usage",
  "sakoocloud_get_plans",
  "sakoocloud_list_alert_rules",
  "sakoocloud_list_tasks",
  "sakoocloud_list_all_buckets",
  "sakoocloud_list_buckets",
  "sakoocloud_get_bucket",
  "sakoocloud_get_bucket_cors",
  "sakoocloud_get_bucket_versioning",
  "sakoocloud_get_bucket_lifecycle",
  "sakoocloud_list_all_registries",
  "sakoocloud_list_registries",
  "sakoocloud_get_registry",
  "sakoocloud_list_functions",
  "sakoocloud_get_function",
  "sakoocloud_get_function_metrics",
  "sakoocloud_list_function_triggers",
  "sakoocloud_list_crons",
  "sakoocloud_get_cron",
  "sakoocloud_get_cron_runs",
  "sakoocloud_list_disks",
  "sakoocloud_get_disk",
  "sakoocloud_list_disk_backups",
]);
const SENSITIVE_FIELD_NAMES = new Set([
  "password",
  "passphrase",
  "secret",
  "secretkey",
  "secretaccesskey",
  "accesskey",
  "accesskeyid",
  "refreshtoken",
  "accesstoken",
  "idtoken",
  "authorization",
  "apikey",
  "privatekey",
  "connectionstring",
  "databaseurl",
  "credentials",
  "connectionuri",
  "uri",
  "publicuri",
  "connectionuser",
  "buildlogurl",
  "releaseconfig",
]);

function isReadOnlyTool(name: string): boolean {
  return LOW_RISK_READ_ONLY_TOOLS.has(name);
}

export function requiresUserConfirmation(name: string, args?: Record<string, unknown>): boolean {
  return !isReadOnlyTool(name) || (name === "sakoocloud_get_env" && args?.include_values === true);
}

export function getToolAnnotations(name: string): ToolAnnotations {
  if (isReadOnlyTool(name) || CONFIRMATION_REQUIRED_READS.has(name)) {
    return { readOnlyHint: true, destructiveHint: false };
  }

  return {
    readOnlyHint: false,
    destructiveHint: DESTRUCTIVE_TOOL_NAME.test(name),
  };
}

export async function executeWithUserConfirmation<T>(
  requester: ConfirmationRequester,
  tool: ToolDetails,
  handler: () => Promise<T>,
): Promise<T> {
  const capabilities = requester.getClientCapabilities();
  if (!capabilities?.elicitation?.form) {
    throw new Error("This client does not support user confirmations; refusing to execute this tool.");
  }

  const response = await requester.elicitInput({
    mode: "form",
    message: `Confirm execution of ${tool.name}: ${tool.description}`,
    requestedSchema: {
      type: "object",
      properties: {
        confirm: { type: "boolean", title: "Confirm" },
      },
      required: ["confirm"],
    },
  });

  if (response.action !== "accept" || response.content?.confirm !== true) {
    throw new Error("The user declined or cancelled this tool execution.");
  }

  return handler();
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeFieldName(name: string): string {
  return name.replace(/[-_]/g, "").toLowerCase();
}

export function redactEnvValue(key: string, value: string | null | undefined, isSecret?: boolean): string | null {
  if (isSecret !== false || /(?:password|passphrase|secret|token|apikey|accesskey|privatekey|databaseurl|connectionstring)$/.test(normalizeFieldName(key))) {
    return "[REDACTED]";
  }
  return value ?? null;
}

export function redactLogLine(line: string): string {
  // Logs are free-form. Strip common credential forms before limiting line length.
  return line
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\b(?:bearer|basic)\s+[^\s,;"']+/gi, "[REDACTED]")
    .replace(/\b(authorization|cookie|set-cookie)["']?\s*[:=].*/gi, "$1: [REDACTED]")
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s/"']*@/gi, "[REDACTED]@")
    .replace(/\bsakoo_sk_[A-Za-z0-9_-]+/g, "[REDACTED]")
    .replace(/\b[A-Za-z0-9_-]{0,255}(?:password|passphrase|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|database[-_]?url|connection[-_]?string|x-amz-signature)[A-Za-z0-9_-]{0,255}["']?\s*[:=].*/gi, "[REDACTED]")
    .slice(0, 2048);
}

export function redactSensitiveResult(result: unknown): unknown {
  const seen = new WeakSet<object>();

  const redact = (value: unknown): unknown => {
    if (value === null || typeof value !== "object") return value;
    if (!Array.isArray(value) && !isPlainObject(value)) return value;
    if (seen.has(value)) return "[Circular]";
    seen.add(value);

    if (Array.isArray(value)) return value.map(redact);

    const copy: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      if (key === "__proto__") continue;
      const field = normalizeFieldName(key);
      if (SENSITIVE_FIELD_NAMES.has(field)) {
        copy[key] = "[REDACTED]";
        continue;
      }

      try {
        const entry = value[key];
        copy[key] = field === "errormessage" && typeof entry === "string" ? redactLogLine(entry) : redact(entry);
      } catch {
        copy[key] = "[Unserializable]";
      }
    }
    return copy;
  };

  return redact(result);
}
