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
    const isIp = IPV4_RE.test(target);
    const baseUrl = isIp
      ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(target)}`
      : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(target)}`;
    const headers = { "x-apikey": key || "" };
    const get = async (url: string): Promise<any | null> => {
      try {
        const r = await fetch(url, {
          headers,
          signal: AbortSignal.timeout(this.per_request_timeout_ms),
        });
        if (!r.ok) return null;
        return await r.json();
      } catch {
        return null;
      }
    };
    const envelope: Record<string, any> = { base: await get(baseUrl) };
    // Domain-only enrichment: historical resolutions + subdomains.
    // These are the closest free substitute for a SecurityTrails feed:
    // resolutions reveal pre-CDN origin IPs, subdomains expand the surface.
    if (!isIp) {
      envelope.resolutions = await get(
        `${baseUrl}/relationships/resolutions?limit=40`
      );
      envelope.subdomains = await get(
        `${baseUrl}/relationships/subdomains?limit=40`
      );
    }
    return {
      bytes: Buffer.from(JSON.stringify(envelope)),
      contentType: "application/json",
    };
  }

  protected _parse(raw: Buffer, query: { target: string }): Finding[] {
    let data: any;
    try {
      data = JSON.parse(raw.toString("utf-8"));
    } catch {
      return [];
    }
    // Unwrap the enrichment envelope; tolerate the legacy bare-object shape.
    const base = data && data.base !== undefined ? data.base : data;
    if (!base || base.error) return [];
    const attrs = (base.data && base.data.attributes) || {};
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
    // Historical DNS resolutions: (ip, last-seen) pairs. A pre-CDN IP here
    // is the closest free substitute for SecurityTrails history.
    const resolutions = (data.resolutions && data.resolutions.data) || [];
    for (const rel of resolutions) {
      const ip = rel?.attributes?.ip_address;
      const date = rel?.attributes?.date;
      if (!ip) continue;
      findings.push({
        source_tool: this.name, entity_kind: "ipv4", entity_value: String(ip),
        attributes: { finding: "historical_ip", domain: target, last_seen: date ?? null },
      });
      if (findings.length > 60) break;
    }
    // Known subdomains expand the attack surface.
    const subdomains = (data.subdomains && data.subdomains.data) || [];
    for (const sd of subdomains) {
      const name = sd?.id || sd?.attributes?.id;
      if (!name) continue;
      findings.push({
        source_tool: this.name, entity_kind: "domain", entity_value: String(name),
        attributes: { finding: "subdomain", parent: target },
      });
      if (findings.length > 100) break;
    }
    return findings;
  }
}

// Backwards-compatible export (registry previously referenced the stub).
export { VirusTotalTool as VirusTotalStub };
