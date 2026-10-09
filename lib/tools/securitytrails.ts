/**
 * SecurityTrails — historical DNS + subdomain enumeration.
 *
 * Requires SECURITYTRAILS_API_KEY (free tier: 50 queries/month — one
 * API call per hunt by design).
 * Auth: `APIKEY: {key}` header.
 * Endpoint: GET https://api.securitytrails.com/v1/history/{domain}/dns/a
 */

import { ToolFunction, type FetchResult, type Finding } from "./base";
import { getSettings } from "../config";

export class SecurityTrailsTool extends ToolFunction {
  readonly name = "securitytrails";
  readonly accepts = new Set(["domain", "person", "org"]);
  readonly emits = new Set(["domain", "ipv4"]);
  readonly key_required: boolean = true;
  readonly docs_url = "https://docs.securitytrails.com/";
  readonly description = "SecurityTrails — historical DNS + subdomain enumeration.";
  readonly per_request_timeout_ms = 15_000;

  protected async _fetch(query: { target: string }): Promise<FetchResult> {
    const key = getSettings().securitytrails_api_key;
    const target = (query.target || "").trim().toLowerCase();
    const url = `https://api.securitytrails.com/v1/history/${encodeURIComponent(target)}/dns/a`;
    const r = await fetch(url, {
      headers: { APIKEY: key || "" },
      signal: AbortSignal.timeout(this.per_request_timeout_ms),
    });
    return {
      bytes: Buffer.from(await r.arrayBuffer()),
      contentType: r.headers.get("content-type") || "application/json",
    };
  }

  protected _parse(raw: Buffer, query: { target: string }): Finding[] {
    let data: any;
    try {
      data = JSON.parse(raw.toString("utf-8"));
    } catch {
      return [];
    }
    if (!data.records) return [];
    const target = (query.target || "").trim().toLowerCase();
    const findings: Finding[] = [];
    for (const rec of data.records || []) {
      for (const v of rec.values || []) {
        if (!v.ip) continue;
        findings.push({
          source_tool: this.name,
          entity_kind: "ipv4",
          entity_value: v.ip,
          attributes: {
            finding: "historical_a",
            domain: target,
            first_seen: (v.first_seen || "").slice(0, 10),
            last_seen: (v.last_seen || "").slice(0, 10),
            ip_count: v.ip_count,
          },
        });
        if (findings.length > 25) break;
      }
      if (findings.length > 25) break;
    }
    return findings;
  }
}

// Backwards-compatible export (registry previously referenced the stub).
export { SecurityTrailsTool as SecurityTrailsStub };
