import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  AlertTriangle,
  RefreshCw,
  Globe,
  Server,
  MapPin,
} from 'lucide-react';
import {
  getDomainIntelligence,
  getIPIntelligence,
  lookupThreatIndicator,
  DomainIntelResponse,
  IPIntelResponse,
  AggregatedThreatIntelResponse,
} from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';

type QueryType = 'domain' | 'ip';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'safe';

const EXAMPLES: { type: QueryType; value: string }[] = [
  { type: 'domain', value: 'login-secure-update.example' },
  { type: 'domain', value: 'accounts-verification.example' },
  { type: 'ip', value: '185.220.101.5' },
  { type: 'ip', value: '8.8.8.8' },
];

const riskSeverity = (level?: string | null): Severity => {
  switch (level) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'low';
  }
};

const verdictSeverity = (verdict?: string | null): Severity => {
  switch (verdict) {
    case 'MALICIOUS':
      return 'critical';
    case 'SUSPICIOUS':
      return 'medium';
    case 'BENIGN':
      return 'safe';
    default:
      return 'low';
  }
};

const fmtDate = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '—');

const Field: React.FC<{ label: string; children: React.ReactNode; mono?: boolean }> = ({ label, children, mono }) => (
  <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border">
    <div className="text-[11px] text-text-muted font-medium">{label}</div>
    <div className={`mt-0.5 text-sm font-semibold text-text-primary break-words ${mono ? 'font-mono text-xs' : ''}`}>
      {children}
    </div>
  </div>
);

const TagList: React.FC<{ label: string; items: string[]; mono?: boolean }> = ({ label, items, mono }) => {
  if (!items || items.length === 0) return null;
  return (
    <div>
      <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item, i) => (
          <span
            key={i}
            className={`px-2 py-1 rounded-md bg-workspace border border-workspace-border text-text-secondary text-xs ${mono ? 'font-mono' : ''}`}
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
};

const ConsensusPanel: React.FC<{ data: AggregatedThreatIntelResponse }> = ({ data }) => (
  <div className="rounded-xl bg-workspace-card border border-workspace-border p-5 space-y-4">
    <div className="flex items-center justify-between flex-wrap gap-2">
      <h3 className="text-sm font-bold text-text-primary">Multi-Provider Consensus</h3>
      <StatusBadge type="severity" value={verdictSeverity(data.consensus_verdict)} label={data.consensus_verdict} size="sm" />
    </div>
    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
      <Field label="Threat Score">{data.consensus_threat_score}</Field>
      <Field label="Confidence">{Math.round(data.consensus_confidence * 100)}%</Field>
      <Field label="Providers Queried">{data.provider_count}</Field>
    </div>
    <TagList label="Aggregated Tags" items={data.aggregated_tags} />
    {data.provider_reports.length > 0 && (
      <div>
        <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">Provider Reports</div>
        <div className="overflow-x-auto rounded-lg border border-workspace-border">
          <table className="w-full text-left text-xs">
            <thead className="bg-workspace-header text-text-muted uppercase text-[10px]">
              <tr>
                <th className="px-3 py-2 font-semibold">Provider</th>
                <th className="px-3 py-2 font-semibold">Verdict</th>
                <th className="px-3 py-2 font-semibold">Score</th>
                <th className="px-3 py-2 font-semibold">Votes (M/S/H)</th>
                <th className="px-3 py-2 font-semibold">Queried</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-workspace-border">
              {data.provider_reports.map((r, i) => (
                <tr key={i}>
                  <td className="px-3 py-2 font-medium text-text-primary">
                    {r.provider}
                    {r.is_fallback && <span className="ml-1.5 text-[10px] text-text-muted">(fallback)</span>}
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge type="severity" value={verdictSeverity(r.verdict)} label={r.verdict} size="sm" />
                  </td>
                  <td className="px-3 py-2 font-mono text-text-secondary">{r.threat_score}</td>
                  <td className="px-3 py-2 font-mono text-text-secondary">
                    {r.malicious_votes}/{r.suspicious_votes}/{r.harmless_votes}
                  </td>
                  <td className="px-3 py-2 text-text-muted whitespace-nowrap">{fmtDate(r.queried_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )}
  </div>
);

export const ThreatIntelView: React.FC = () => {
  const [queryType, setQueryType] = useState<QueryType>('domain');
  const [queryInput, setQueryInput] = useState<string>('');
  const [domainResult, setDomainResult] = useState<DomainIntelResponse | null>(null);
  const [ipResult, setIpResult] = useState<IPIntelResponse | null>(null);
  const [consensus, setConsensus] = useState<AggregatedThreatIntelResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [searched, setSearched] = useState<boolean>(false);

  const executeQuery = async (type: QueryType, target: string) => {
    const value = target.trim();
    if (!value) return;
    setLoading(true);
    setError(null);
    setSearched(true);
    setConsensus(null);
    try {
      if (type === 'domain') {
        const res = await getDomainIntelligence(value);
        setDomainResult(res);
        setIpResult(null);
      } else {
        const res = await getIPIntelligence(value);
        setIpResult(res);
        setDomainResult(null);
      }
      // Best-effort: multi-provider consensus is a separate lookup and
      // shouldn't block showing the domain/IP intelligence we already have.
      try {
        const agg = await lookupThreatIndicator(type === 'domain' ? 'DOMAIN' : 'IP', value);
        setConsensus(agg);
      } catch {
        setConsensus(null);
      }
    } catch (err: any) {
      setDomainResult(null);
      setIpResult(null);
      setError(err.response?.data?.detail || err.message || 'Threat indicator query failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuery = (e: React.FormEvent) => {
    e.preventDefault();
    executeQuery(queryType, queryInput);
  };

  const handleExample = (ex: typeof EXAMPLES[0]) => {
    setQueryType(ex.type);
    setQueryInput(ex.value);
    executeQuery(ex.type, ex.value);
  };

  const hasResult = Boolean(domainResult || ipResult);

  return (
    <div className="space-y-6">
      {/* Page Title + Description */}
      <div className="flex items-center gap-3.5">
        <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-text-primary tracking-tight">Threat Intel</h1>
          <p className="text-sm text-text-muted mt-0.5">
            Look up a domain or IP address to see its WHOIS/DNS signals, infrastructure classification, and
            multi-provider reputation.
          </p>
        </div>
      </div>

      {/* Query Form */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-4">
        <form onSubmit={handleQuery} className="flex flex-col sm:flex-row gap-3">
          <div className="flex items-center gap-1 bg-workspace border border-workspace-border rounded-lg p-1 shrink-0">
            <button
              type="button"
              onClick={() => setQueryType('domain')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                queryType === 'domain' ? 'bg-brand text-white' : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              Domain
            </button>
            <button
              type="button"
              onClick={() => setQueryType('ip')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                queryType === 'ip' ? 'bg-brand text-white' : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              IP Address
            </button>
          </div>

          <div className="relative flex-1">
            <Search className="w-4 h-4 text-text-muted absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              placeholder={queryType === 'domain' ? 'e.g. login-secure-update.example' : 'e.g. 185.220.101.5'}
              className="w-full pl-10 pr-4 py-2 text-sm bg-workspace border border-workspace-border rounded-lg text-text-primary font-mono focus:outline-none focus:border-brand transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !queryInput.trim()}
            className="px-5 py-2 rounded-lg bg-brand text-white text-sm font-semibold hover:bg-brand-hover disabled:opacity-50 transition-colors shrink-0 flex items-center justify-center gap-2"
          >
            {loading && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            Query Indicator
          </button>
        </form>

        <div className="pt-3 border-t border-workspace-border flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-text-muted">Example queries:</span>
          {EXAMPLES.map((ex, i) => (
            <button
              key={i}
              type="button"
              onClick={() => handleExample(ex)}
              className="px-2.5 py-1 rounded-md bg-workspace hover:bg-workspace-secondary text-text-secondary hover:text-text-primary text-xs font-mono border border-workspace-border transition-colors"
            >
              {ex.value}
            </button>
          ))}
        </div>

        {error && (
          <div className="p-3.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-severity-high text-sm flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Before-search explanation, per Design.md §38 (search-driven tool, not a list) */}
      {!searched && (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-10 text-center">
          <div className="w-12 h-12 rounded-xl bg-brand-soft text-brand flex items-center justify-center mx-auto mb-4">
            <Search className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-text-primary">Search a domain or IP to get started</p>
          <p className="text-sm text-text-muted mt-1 max-w-md mx-auto">
            MailinteL will resolve DNS/WHOIS signals for a domain, or ASN/geolocation and infrastructure
            classification for an IP, then cross-check it against multiple threat intelligence providers.
          </p>
        </div>
      )}

      {searched && !loading && !hasResult && !error && (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-10 text-center text-sm text-text-muted">
          No intelligence record found for this indicator.
        </div>
      )}

      {/* Domain Result */}
      {domainResult && (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-workspace-border pb-4 gap-2">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] font-semibold uppercase text-text-muted">Domain</div>
                <h2 className="text-base font-mono font-bold text-text-primary mt-0.5">{domainResult.domain}</h2>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-text-muted">Resolved {fmtDate(domainResult.resolved_at)}</span>
              <StatusBadge type="severity" value={riskSeverity(domainResult.risk_level)} label={`${domainResult.risk_level} RISK`} />
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Field label="Root Domain" mono>{domainResult.root_domain}</Field>
            <Field label="Newly Registered (NRD)">
              <span className={domainResult.is_nrd ? 'text-severity-high' : 'text-severity-safe'}>
                {domainResult.is_nrd ? 'Yes' : 'No'}
              </span>
            </Field>
            <Field label="Dynamic DNS / Disposable">{domainResult.is_dynamic_dns ? 'Yes' : 'No'}</Field>
            <Field label="Punycode / Homograph">{domainResult.is_punycode ? 'Yes' : 'No'}</Field>
          </div>

          <TagList label="Risk Tags" items={domainResult.risk_tags} />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <TagList label="MX Hosts" items={domainResult.mx_hosts} mono />
            <TagList label="A Records" items={domainResult.a_records} mono />
            <TagList label="NS Records" items={domainResult.ns_records} mono />
            <TagList label="TXT Records" items={domainResult.txt_records} mono />
          </div>

          {domainResult.dns_records.length > 0 && (
            <div>
              <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">DNS Records</div>
              <div className="overflow-x-auto rounded-lg border border-workspace-border">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-workspace-header text-text-muted uppercase text-[10px] font-sans">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Type</th>
                      <th className="px-3 py-2 font-semibold">Value</th>
                      <th className="px-3 py-2 font-semibold">Priority</th>
                      <th className="px-3 py-2 font-semibold">TTL</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-workspace-border">
                    {domainResult.dns_records.map((r, i) => (
                      <tr key={i}>
                        <td className="px-3 py-2 text-text-primary">{r.record_type}</td>
                        <td className="px-3 py-2 text-text-secondary break-all">{r.record_value}</td>
                        <td className="px-3 py-2 text-text-muted">{r.priority ?? '—'}</td>
                        <td className="px-3 py-2 text-text-muted">{r.ttl ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {domainResult.registration_intel ? (
            <div>
              <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">Registration Intelligence</div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Field label="Source">{domainResult.registration_intel.source}</Field>
                <Field label="Registrar">{domainResult.registration_intel.registrar || '—'}</Field>
                <Field label="Registered">{fmtDate(domainResult.registration_intel.registered_at)}</Field>
                <Field label="Expires">{fmtDate(domainResult.registration_intel.expires_at)}</Field>
                <Field label="Last Updated">{fmtDate(domainResult.registration_intel.updated_at)}</Field>
                <Field label="Domain Age">
                  {domainResult.registration_intel.domain_age_days != null
                    ? `${domainResult.registration_intel.domain_age_days} days`
                    : '—'}
                </Field>
              </div>
              <div className="mt-3">
                <TagList label="Nameservers" items={domainResult.registration_intel.nameservers} mono />
              </div>
            </div>
          ) : (
            <p className="text-xs text-text-muted">No registration/WHOIS intelligence available for this domain.</p>
          )}
        </div>
      )}

      {/* IP Result */}
      {ipResult && (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-workspace-border pb-4 gap-2">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] font-semibold uppercase text-text-muted">
                  IP Address {ipResult.is_private && '· Private/Internal'}
                </div>
                <h2 className="text-base font-mono font-bold text-text-primary mt-0.5">{ipResult.ip_address}</h2>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-text-muted">Resolved {fmtDate(ipResult.resolved_at)}</span>
              <StatusBadge type="severity" value={riskSeverity(ipResult.risk_level)} label={`${ipResult.risk_level} RISK`} />
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Field label="IP Type">{ipResult.ip_type}</Field>
            <Field label="ASN">{ipResult.asn || '—'}</Field>
            <Field label="ASN Organization">{ipResult.asn_org || '—'}</Field>
            <Field label="ISP">{ipResult.isp || '—'}</Field>
            <Field label="Network Owner">{ipResult.network_owner || '—'}</Field>
            <Field label="Hosting Provider">{ipResult.hosting_provider || '—'}</Field>
            <Field label="Reverse DNS (PTR)" mono>{ipResult.reverse_dns || '—'}</Field>
            <Field label="Geolocation">
              <span className="inline-flex items-center gap-1">
                <MapPin className="w-3 h-3 text-text-muted shrink-0" />
                {[ipResult.city_name, ipResult.region_name, ipResult.country_name].filter(Boolean).join(', ') || '—'}
                {ipResult.country_code ? ` (${ipResult.country_code})` : ''}
              </span>
            </Field>
          </div>

          {(ipResult.latitude != null || ipResult.longitude != null) && (
            <Field label="Coordinates" mono>
              {ipResult.latitude ?? '—'}, {ipResult.longitude ?? '—'}
            </Field>
          )}

          <TagList label="Risk Tags" items={ipResult.risk_tags} />

          {ipResult.classifications.length > 0 && (
            <div>
              <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">
                Infrastructure Classifications
              </div>
              <div className="space-y-2">
                {ipResult.classifications.map((c, i) => (
                  <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-workspace border border-workspace-border text-sm">
                    <div>
                      <span className="font-semibold text-text-primary">{c.classification_type}</span>
                      <span className="text-text-muted ml-2 text-xs">via {c.source}</span>
                    </div>
                    <span className="text-xs font-mono text-text-secondary">{Math.round(c.confidence * 100)}% confidence</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {consensus && <ConsensusPanel data={consensus} />}
    </div>
  );
};
export default ThreatIntelView;
