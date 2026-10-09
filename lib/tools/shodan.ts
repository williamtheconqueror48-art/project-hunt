/**
 * Shodan — internet-wide host scanning & banners.
 *
 * Requires SHODAN_API_KEY (free tier: 100 query credits/month).
 * Host lookup: GET https://api.shodan.io/shodan/host/{ip}?key={key}
 */

import { ToolFunction, type FetchResult, type Finding } from "./base";
import { getSettings } from "../config";

export class ShodanTool extends ToolFunction {
  readonly name = "shodan";
  readonly accepts = new Set(["domain", "ipv4", "ipv6", "person", "org"]);
  readonly emits = new Set(["ipv4", "asn", "org", "url"]);
  readonly key_required: boolean = true;
  readonly docs_url = "https://developer.shodan.io/api";
  readonly description = "Shodan — internet-wide host scanning & banners.";
  readonly per_request_timeout_ms = 15_000;

  protected async _fetch(query: { target: string }): Promise<FetchResult> {
    const key = getSettings().shodan_api_key;
    let target = (query.target || "").trim();
    // Resolve domains to IP first via DNS-over-HTTPS (Shodan host API needs an IP).
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(target) && !target.includes(":")) {
      try {
        const dr = await fetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(target)}&type=A`,
          { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(8000) }
        );
        const dj: any = await dr.json();
        const a = (dj.Answer || []).find((x: any) => x.type === 1);
        if (a) target = a.data;
      } catch {
        // fall through with the original target
      }
    }
    const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(target)}?key=${encodeURIComponent(key || "")}`;
    const r = await fetch(url, { signal: AbortSignal.timeout(this.per_request_timeout_ms) });
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
    const findings: Finding[] = [];
    const ip = data.ip_str || query.target;

    // Open ports + banners.
    for (const svc of data.data || []) {
      const attrs: Record<string, unknown> = { ip, port: svc.port, transport: svc.transport };
      if (svc.product) attrs.product = svc.product;
      if (svc.version) attrs.version = svc.version;
      if (svc.http?.title) attrs.http_title = String(svc.http.title).slice(0, 120);
      if (svc.ssl?.cert?.subject?.CN) attrs.cert_cn = svc.ssl.cert.subject.CN;
      findings.push({
        source_tool: this.name,
        entity_kind: "ipv4",
        entity_value: ip,
        attributes: { ...attrs, finding: "open_port" },
      });
    }
    // Hostnames seen on the IP.
    for (const h of data.hostnames || []) {
      findings.push({
        source_tool: this.name,
        entity_kind: "url",
        entity_value: String(h),
        attributes: { ip, finding: "hostname" },
      });
    }
    // Org / ASN / OS summary.
    const summary: Record<string, unknown> = { finding: "host_summary", ip };
    if (data.org) summary.org = data.org;
    if (data.asn) summary.asn = data.asn;
    if (data.os) summary.os = data.os;
    if (data.country_name) summary.country = data.country_name;
    if (data.city) summary.city = data.city;
    if (Array.isArray(data.ports)) summary.port_count = data.ports.length;
    findings.push({
      source_tool: this.name,
      entity_kind: "ipv4",
      entity_value: ip,
      attributes: summary,
    });
    return findings;
  }
}

// Backwards-compatible export (registry previously referenced the stub).
export { ShodanTool as ShodanStub };
