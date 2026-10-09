/**
 * VirusTotal — file/URL/domain/IP reputation (v3 API).
 *
 * Requires VIRUSTOTAL_API_KEY (free tier: 500 requests/day, 4/min).
 * Endpoints: /api/v3/domains/{domain}, /api/v3/ip_addresses/{ip}
 * Auth: x-apikey header.
 */

import { ToolFunction, type FetchResult, type Finding } from "./base";
import { getSettings } from "../config";

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export class VirusTotalTool extends ToolFunction {
  readonly name = "virustotal";
  readonly accepts = new Set(["domain", "ipv4", "url", "hash", "person", "org"]);
  readonly emits = new Set(["domain", "hash", "url"]);
  readonly key_required: boolean = true;
  readonly docs_url = "https://docs.virustotal.com/";
  readonly description = "VirusTotal — file/URL/domain reputation.";
  readonly per_request_timeout_ms = 15_000;

  protected async _fetch(query: { target: string }): Promise<FetchResult> {
    const key = getSettings().virustotal_api_key;
    const target = (query.target || "").trim().toLowerCase();
    const endpoint = IPV4_RE.test(target)
      ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(target)}`
      : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(target)}`;
    const r = await fetch(endpoint, {
      headers: { "x-apikey": key || "" },
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
    if (data.error) return [];
    const attrs = (data.data && data.data.attributes) || {};
    const stats = attrs.last_analysis_stats || {};
    const findings: Finding[] = [];
    const target = (query.target || "").trim().toLowerCase();

    // Reputation verdict.
    findings.push({
      source_tool: this.name,
      entity_kind: IPV4_RE.test(target) ? "ipv4" : "domain",
      entity_value: target,
      attributes: {
        finding: "reputation",
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        harmless: stats.harmless ?? 0,
        undetected: stats.undetected ?? 0,
        reputation: attrs.reputation,
        total_votes_harmless: attrs.total_votes?.harmless,
        total_votes_malicious: attrs.total_votes?.malicious,
      },
    });
    // Categories assigned by vendors.
    const cats = attrs.categories || {};
    for (const [vendor, cat] of Object.entries(cats)) {
      findings.push({
        source_tool: this.name,
        entity_kind: "domain",
        entity_value: target,
        attributes: { finding: "category", vendor, category: String(cat) },
      });
      if (findings.length > 12) break;
    }
    // Registrar / network context.
    if (attrs.registrar)
      findings.push({
        source_tool: this.name, entity_kind: "domain", entity_value: target,
        attributes: { finding: "registrar", registrar: attrs.registrar },
      });
    if (attrs.as_owner)
      findings.push({
        source_tool: this.name, entity_kind: "ipv4", entity_value: target,
        attributes: { finding: "as_owner", as_owner: attrs.as_owner, asn: attrs.asn, country: attrs.country },
      });
    return findings;
  }
}

// Backwards-compatible export (registry previously referenced the stub).
export { VirusTotalTool as VirusTotalStub };
