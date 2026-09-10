import axios from 'axios';
import { apiEvents } from './apiEvents';
import { getAuthToken, clearAuthToken } from './authStorage';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 45000,
});

// Attach the bearer token (if any) to every outgoing request.
apiClient.interceptors.request.use((config) => {
  const token = getAuthToken();
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Centralized handling for global session expiry and true network loss.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error)) {
      if (!error.response) {
        // Only trigger full-app offline screen on genuine network disconnection,
        // not on individual query timeouts (ECONNABORTED) or cancelled requests.
        const isTrueNetworkLoss =
          error.code === 'ERR_NETWORK' ||
          (typeof window !== 'undefined' && !window.navigator.onLine);

        if (isTrueNetworkLoss) {
          apiEvents.emit('network-error');
        }
      } else if (error.response.status === 401) {
        // Session is gone — stop sending a now-invalid token and let
        // AuthContext clear its state so AuthGate switches to LoginScreen.
        clearAuthToken();
        apiEvents.emit('unauthorized');
      }
    }
    return Promise.reject(error);
  }
);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface AuthUser {
  id: string;
  email: string;
  full_name: string | null;
  organization_id: string | null;
  organization_name: string | null;
  role: string;
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user: AuthUser;
}

export interface RegisterPayload {
  email: string;
  password: string;
  full_name?: string;
  organization_name?: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export const registerAccount = async (payload: RegisterPayload): Promise<AuthTokenResponse> => {
  const response = await apiClient.post<AuthTokenResponse>('/auth/register', payload);
  return response.data;
};

export const loginAccount = async (payload: LoginPayload): Promise<AuthTokenResponse> => {
  const response = await apiClient.post<AuthTokenResponse>('/auth/login', payload);
  return response.data;
};

export const getCurrentUser = async (): Promise<AuthUser> => {
  const response = await apiClient.get<AuthUser>('/auth/me');
  return response.data;
};

export interface HealthResponse {
  status: string;
  app_name: string;
  environment: string;
  timestamp: string;
  version: string;
  services?: {
    database?: {
      status: string;
      latency_ms: number;
    };
    storage?: {
      status: string;
      latency_ms: number;
    };
    redis?: {
      status: string;
      latency_ms: number;
    };
  };
}

export interface DbHealthResponse {
  status: string;
  database: string;
  host: string;
  port: number;
  latency_ms: number;
  error: string | null;
  pgvector?: {
    available: boolean;
    version: string | null;
    error: string | null;
  };
  timestamp: string;
}

export interface StorageHealthResponse {
  status: string;
  endpoint: string;
  latency_ms: number;
  available_buckets: string[];
  required_buckets: string[];
  error: string | null;
  timestamp: string;
}

export interface RedisHealthResponse {
  status: string;
  host: string;
  port: number;
  db: number;
  latency_ms: number;
  error: string | null;
  timestamp: string;
}

export interface DetailedHealthResponse {
  status: string;
  app_name: string;
  environment: string;
  debug: boolean;
  timestamp: string;
  runtime: {
    python_version: string;
    platform: string;
  };
  demo_context: {
    mode: string;
    user_id: string;
    user_name: string;
    user_email: string;
    organization_id: string;
    organization_name: string;
    role: string;
  };
  services: {
    postgres: {
      status: string;
      configured_host: string;
      configured_port: number;
      configured_db: string;
      latency_ms?: number;
      error?: string | null;
      pgvector?: {
        available: boolean;
        version: string | null;
        error: string | null;
      };
    };
    minio: {
      status: string;
      configured_endpoint: string;
      latency_ms?: number;
      available_buckets: string[];
      required_buckets: string[];
      error?: string | null;
    };
    redis: {
      configured_host: string;
      configured_port: number;
    };
  };
}

export interface ReadinessResponse {
  ready: boolean;
  status: string;
  app_name: string;
  environment: string;
  timestamp: string;
  services: {
    postgres: {
      status: string;
      latency_ms: number;
      pgvector: boolean;
    };
    minio: {
      status: string;
      latency_ms: number;
    };
    redis: {
      status: string;
      latency_ms: number;
    };
  };
}

export type JobStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type JobStage =
  | 'QUEUED'
  | 'ACQUIRING_EVIDENCE'
  | 'PARSING_EMAIL'
  | 'EXTRACTING_IOCS'
  | 'ANALYZING_THREATS'
  | 'GENERATING_DNA'
  | 'GEO_LOCATING'
  | 'CORRELATING_CAMPAIGN'
  | 'GENERATING_REPORT'
  | 'COMPLETED'
  | 'FAILED';

export interface JobRecord {
  job_id: string;
  job_type: string;
  status: JobStatus;
  stage: JobStage;
  progress: number;
  email_id?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
  result?: Record<string, unknown> | null;
  metadata?: Record<string, unknown>;
}

export interface UploadEmailResponse {
  email_id: string;
  evidence_id: string;
  job_id: string;
  filename: string;
  sha256_hash: string;
  size_bytes: number;
  analysis_status: string;
  qualification_status: string;
  created_at: string;
  message: string;
}

export interface EmailDetailResponse {
  id: string;
  source_type: string;
  original_filename?: string | null;
  subject?: string | null;
  sender_address?: string | null;
  sender_display_name?: string | null;
  sent_at?: string | null;
  received_at?: string | null;
  email_size_bytes?: number | null;
  analysis_status: string;
  qualification_status: string;
  created_at: string;
  updated_at: string;
  sha256_hash?: string | null;
  evidence_id?: string | null;
  organization_id?: string | null;
  organization_name?: string | null;
}

export interface EmailListResponse {
  total: number;
  items: EmailDetailResponse[];
}

export interface CustodyEventResponse {
  id: string;
  evidence_id: string;
  event_type: string;
  actor_user_id?: string | null;
  case_id?: string | null;
  event_at: string;
  event_metadata?: Record<string, unknown> | null;
  previous_event_hash?: string | null;
  event_hash?: string | null;
  created_at: string;
}

export interface EvidenceObjectResponse {
  id: string;
  email_id?: string | null;
  case_id?: string | null;
  parent_evidence_id?: string | null;
  evidence_type: string;
  original_filename: string;
  content_type: string;
  size_bytes: number;
  sha256_hash: string;
  bucket_name: string;
  object_key: string;
  immutable: boolean;
  retention_status: string;
  acquired_at: string;
  stored_at: string;
  created_at: string;
}

export interface EvidenceDownloadResponse {
  evidence_id: string;
  filename: string;
  sha256_hash: string;
  download_url: string;
  expires_in_seconds: number;
  message: string;
}

export interface EvidenceVerificationResponse {
  evidence_id: string;
  original_filename: string;
  stored_sha256: string;
  computed_sha256?: string | null;
  is_valid: boolean;
  status: 'VERIFIED' | 'TAMPERED' | 'OBJECT_NOT_FOUND';
  verified_at: string;
  details: Record<string, unknown>;
}

export interface RecipientItem {
  recipient_type: 'TO' | 'CC' | 'BCC' | string;
  address: string;
  display_name?: string | null;
}

export interface HeaderItem {
  header_name: string;
  header_value: string;
  normalized_value?: string | null;
  header_order: number;
}

export interface MimePartItem {
  part_index: number;
  content_type: string;
  content_disposition?: string | null;
  filename?: string | null;
  charset?: string | null;
  transfer_encoding?: string | null;
  size_bytes: number;
  is_attachment: boolean;
  content_id?: string | null;
  sub_parts: MimePartItem[];
}

export interface EmailStructureResponse {
  email_id: string;
  subject?: string | null;
  sender_address?: string | null;
  sender_display_name?: string | null;
  sent_at?: string | null;
  raw_date_str?: string | null;
  message_id?: string | null;
  return_path?: string | null;
  reply_to?: string | null;
  reply_to_display_name?: string | null;
  recipients: RecipientItem[];
  plain_text_body?: string | null;
  html_body?: string | null;
  has_attachments: boolean;
  attachment_count: number;
  total_mime_parts: number;
  is_multipart: boolean;
  root_content_type: string;
  mime_parts: MimePartItem[];
}

export interface EmailHeadersResponse {
  email_id: string;
  total_headers: number;
  headers: HeaderItem[];
}

export interface RelayHopItem {
  sequence_number: number;
  source_host?: string | null;
  source_ip?: string | null;
  destination_host?: string | null;
  observed_at?: string | null;
  reliability: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNVERIFIED' | string;
  protocol?: string | null;
  queue_id?: string | null;
  envelope_to?: string | null;
  tls_info?: string | null;
  transit_delay_seconds?: number | null;
  raw_header?: string | null;
}

export interface RelayHopsResponse {
  email_id: string;
  total_hops: number;
  originating_ip?: string | null;
  originating_host?: string | null;
  hops: RelayHopItem[];
}

export interface DkimSignatureItem {
  domain?: string | null;
  selector?: string | null;
  algorithm?: string | null;
  body_hash?: string | null;
  signature_preview?: string | null;
}

export interface EmailAuthResponse {
  email_id: string;
  spf_result?: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR' | string | null;
  dkim_result?: 'PASS' | 'FAIL' | 'NONE' | 'TEMPERROR' | 'PERMERROR' | 'UNVERIFIED' | string | null;
  dmarc_result?: 'PASS' | 'FAIL' | 'NONE' | 'TEMPERROR' | 'PERMERROR' | string | null;
  from_alignment_result?: 'PASS' | 'FAIL' | 'NONE' | string | null;
  return_path?: string | null;
  reply_to?: string | null;
  auth_serv_id?: string | null;
  dkim_signatures: DkimSignatureItem[];
  evidence: Record<string, unknown>;
}

export interface ExtractedURLItem {
  url: string;
  normalized_url: string;
  url_hash: string;
  domain?: string | null;
  root_domain?: string | null;
  context: string;
  anchor_text?: string | null;
  is_defanged: boolean;
  defanged_url: string;
}

export interface ExtractedDomainItem {
  domain: string;
  root_domain: string;
  source_contexts: string[];
  is_suspicious_tld: boolean;
  is_punycode: boolean;
}

export interface ExtractedIPItem {
  ip_address: string;
  ip_version: number;
  category: string;
  source_contexts: string[];
}

export interface ExtractedAttachmentItem {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256_hash: string;
  md5_hash: string;
  extension: string;
  is_dangerous: boolean;
  is_archive: boolean;
  has_double_extension: boolean;
}

export interface EmailArtifactsResponse {
  email_id: string;
  total_urls: number;
  total_domains: number;
  total_ips: number;
  total_attachments: number;
  has_dangerous_attachments: boolean;
  urls: ExtractedURLItem[];
  domains: ExtractedDomainItem[];
  ip_addresses: ExtractedIPItem[];
  attachments: ExtractedAttachmentItem[];
}

export interface DNSRecordItem {
  record_type: string;
  record_value: string;
  priority?: number | null;
  ttl?: number | null;
}

export interface RegistrationIntelItem {
  source: string;
  registrar?: string | null;
  registered_at?: string | null;
  expires_at?: string | null;
  updated_at?: string | null;
  domain_age_days?: number | null;
  nameservers: string[];
  raw_summary: Record<string, unknown>;
}

export interface DomainIntelResponse {
  domain: string;
  root_domain: string;
  is_nrd: boolean;
  is_dynamic_dns: boolean;
  is_punycode: boolean;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  risk_tags: string[];
  mx_hosts: string[];
  a_records: string[];
  txt_records: string[];
  ns_records: string[];
  dns_records: DNSRecordItem[];
  registration_intel?: RegistrationIntelItem | null;
  resolved_at: string;
}

export interface EmailDomainIntelResponse {
  email_id: string;
  total_domains_analyzed: number;
  domains: DomainIntelResponse[];
}

export interface InfrastructureClassificationItem {
  classification_type: string;
  confidence: number;
  source: string;
  evidence: Record<string, unknown>;
}

export interface IPIntelResponse {
  ip_address: string;
  ip_type: string;
  is_private: boolean;
  reverse_dns?: string | null;
  asn?: string | null;
  asn_org?: string | null;
  isp?: string | null;
  network_owner?: string | null;
  hosting_provider?: string | null;
  country_code?: string | null;
  country_name?: string | null;
  region_name?: string | null;
  city_name?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  classifications: InfrastructureClassificationItem[];
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  risk_tags: string[];
  resolved_at: string;
}

export interface EmailInfrastructureResponse {
  email_id: string;
  total_ips_analyzed: number;
  has_tor_relay: boolean;
  has_vpn_relay: boolean;
  has_cloud_hosted_relay: boolean;
  ips: IPIntelResponse[];
}

export interface ThreatIntelReportItem {
  indicator_type: string;
  indicator_value: string;
  provider: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  threat_score: number;
  confidence: number;
  tags: string[];
  malicious_votes: number;
  suspicious_votes: number;
  harmless_votes: number;
  total_votes: number;
  raw_data: Record<string, unknown>;
  queried_at: string;
  is_fallback: boolean;
  details?: string | null;
}

export interface AggregatedThreatIntelResponse {
  indicator_type: string;
  indicator_value: string;
  consensus_verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  consensus_threat_score: number;
  consensus_confidence: number;
  aggregated_tags: string[];
  provider_reports: ThreatIntelReportItem[];
  provider_count: number;
  queried_at: string;
}

export interface EmailThreatIntelSummaryResponse {
  email_id: string;
  total_iocs_analyzed: number;
  malicious_ioc_count: number;
  suspicious_ioc_count: number;
  overall_threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  indicators: AggregatedThreatIntelResponse[];
}

export interface AnalysisFindingItem {
  finding_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
}

export interface EmailAnalysisResponse {
  analysis_run_id: string;
  email_id: string;
  threat_classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'PHISHING' | 'SPOOFING' | string;
  threat_risk_score: number;
  evidence_confidence_score: number;
  summary: string;
  compromised_account_likelihood: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNLIKELY' | string;
  spoofed_domain_likelihood: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNLIKELY' | string;
  anonymized_infrastructure_likelihood: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNLIKELY' | string;
  malicious_environment_likelihood: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNLIKELY' | string;
  findings: AnalysisFindingItem[];
  created_at: string;
}

export interface FindingsListResponse {
  email_id: string;
  total_findings: number;
  findings: AnalysisFindingItem[];
}

export interface EmailDNAProfileResponse {
  email_id: string;
  dna_version: string;
  overall_dna_hash: string;
  content_fingerprint: Record<string, unknown>;
  technical_fingerprint: Record<string, unknown>;
  infrastructure_fingerprint: Record<string, unknown>;
  behavioral_fingerprint: Record<string, unknown>;
  temporal_fingerprint: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface EmbeddingItemResponse {
  id: string;
  email_id: string;
  embedding_type: string;
  model_name: string;
  dimension: number;
  metadata: Record<string, unknown>;
  created_at?: string | null;
}

export interface SimilarityLinkResponse {
  id: string;
  source_email_id: string;
  related_email_id: string;
  similarity_type: string;
  similarity_score: number;
  evidence: Record<string, unknown>;
  created_at?: string | null;
}

export interface SimilaritySearchParams {
  min_similarity_threshold?: number;
  top_k?: number;
}

export interface CorrelationSignalItem {
  signal_type: string;
  confidence: number;
  weight: number;
  description: string;
  evidence: Record<string, unknown>;
}

export interface CorrelatedEmailItem {
  source_email_id: string;
  target_email_id: string;
  target_subject?: string | null;
  target_sender?: string | null;
  composite_correlation_score: number;
  primary_link_reason: string;
  evidence_count: number;
  is_actionable_correlation: boolean;
  signals: CorrelationSignalItem[];
}

export interface EmailCorrelationsResponse {
  email_id: string;
  total_correlated_emails: number;
  correlations: CorrelatedEmailItem[];
}

export interface CampaignMembershipItem {
  id: string;
  email_id: string;
  email_subject?: string | null;
  email_sender?: string | null;
  membership_confidence: number;
  membership_status: string;
  evidence_summary: Record<string, unknown>;
  created_at?: string | null;
}

export interface CampaignEvidenceItem {
  id: string;
  evidence_type: string;
  confidence: number;
  explanation: string;
  created_at?: string | null;
}

export interface CampaignEventItem {
  id: string;
  event_type: string;
  occurred_at?: string | null;
  description: string;
  metadata: Record<string, unknown>;
}

export interface CampaignDetailResponse {
  id: string;
  campaign_name?: string | null;
  campaign_status: string;
  campaign_confidence: number;
  threat_summary?: string | null;
  first_detected_at?: string | null;
  last_activity_at?: string | null;
  total_members: number;
  total_evidence_links: number;
  memberships: CampaignMembershipItem[];
  evidence: CampaignEvidenceItem[];
  events: CampaignEventItem[];
}

export interface CampaignListItemResponse {
  id: string;
  campaign_name?: string | null;
  campaign_status: string;
  campaign_confidence: number;
  threat_summary?: string | null;
  first_detected_at?: string | null;
  last_activity_at?: string | null;
  member_count: number;
}

export interface EmailCampaignMembershipItem {
  membership_id: string;
  campaign_id: string;
  campaign_name?: string | null;
  campaign_status: string;
  membership_confidence: number;
  membership_status: string;
  evidence_summary: Record<string, unknown>;
}

export interface EmailMembershipsResponse {
  email_id: string;
  is_bridge_entity: boolean;
  total_campaigns: number;
  investigation_note: string;
  memberships: EmailCampaignMembershipItem[];
}

export interface CreateCampaignPayload {
  campaign_name: string;
  threat_summary?: string;
  campaign_status?: string;
  campaign_confidence?: number;
  initial_email_ids?: string[];
}

export interface AutoClusterResponse {
  total_clusters_created: number;
  clusters: { campaign_id: string; campaign_name?: string | null; members_count: number }[];
}

export interface GraphNodeItem {
  id: string;
  label: string;
  node_type: string;
  display_name: string;
  risk_level: string;
  metadata: Record<string, unknown>;
}

export interface GraphEdgeItem {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  label: string;
  confidence: number;
  evidence: Record<string, unknown>;
}

export interface InvestigationGraphResponse {
  focal_node_id?: string | null;
  total_nodes: number;
  total_edges: number;
  statistics: Record<string, number>;
  nodes: GraphNodeItem[];
  edges: GraphEdgeItem[];
}




export const checkHealth = async (): Promise<HealthResponse> => {
  const response = await apiClient.get<HealthResponse>('/health');
  return response.data;
};


export const checkDbHealth = async (): Promise<DbHealthResponse> => {
  const response = await apiClient.get<DbHealthResponse>('/health/db');
  return response.data;
};

export const checkStorageHealth = async (): Promise<StorageHealthResponse> => {
  const response = await apiClient.get<StorageHealthResponse>('/health/storage');
  return response.data;
};

export const checkRedisHealth = async (): Promise<RedisHealthResponse> => {
  const response = await apiClient.get<RedisHealthResponse>('/health/redis');
  return response.data;
};

export const checkReadiness = async (): Promise<ReadinessResponse> => {
  const response = await apiClient.get<ReadinessResponse>('/health/ready');
  return response.data;
};

export const checkDetailedHealth = async (): Promise<DetailedHealthResponse> => {
  const response = await apiClient.get<DetailedHealthResponse>('/health/detailed');
  return response.data;
};

export const getJobStatus = async (jobId: string): Promise<JobRecord> => {
  const response = await apiClient.get<JobRecord>(`/jobs/${jobId}`);
  return response.data;
};

export const listJobs = async (limit = 50, status?: JobStatus): Promise<JobRecord[]> => {
  const params: Record<string, unknown> = { limit };
  if (status) params.status = status;
  const response = await apiClient.get<JobRecord[]>('/jobs', { params });
  return response.data;
};

export const cancelJob = async (jobId: string): Promise<{ message: string; status: string }> => {
  const response = await apiClient.post<{ message: string; status: string }>(`/jobs/${jobId}/cancel`);
  return response.data;
};

export const uploadEmlFile = async (file: File): Promise<UploadEmailResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await apiClient.post<UploadEmailResponse>('/emails/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const getEmailDetails = async (emailId: string): Promise<EmailDetailResponse> => {
  const response = await apiClient.get<EmailDetailResponse>(`/emails/${emailId}`);
  return response.data;
};

export const listEmails = async (
  skip = 0,
  limit = 50,
  analysisStatus?: string,
  qualificationStatus?: string,
  organizationId?: string
): Promise<EmailListResponse> => {
  const params: Record<string, unknown> = { skip, limit };
  if (analysisStatus) params.analysis_status = analysisStatus;
  if (qualificationStatus) params.qualification_status = qualificationStatus;
  if (organizationId) params.organization_id = organizationId;
  const response = await apiClient.get<EmailListResponse>('/emails', { params });
  return response.data;
};

export const getEvidenceMetadata = async (evidenceId: string): Promise<EvidenceObjectResponse> => {
  const response = await apiClient.get<EvidenceObjectResponse>(`/evidence/${evidenceId}`);
  return response.data;
};

export const getEvidenceDownloadUrl = async (evidenceId: string): Promise<EvidenceDownloadResponse> => {
  const response = await apiClient.get<EvidenceDownloadResponse>(`/evidence/${evidenceId}/download`);
  return response.data;
};

export const getEvidenceCustody = async (evidenceId: string): Promise<CustodyEventResponse[]> => {
  const response = await apiClient.get<CustodyEventResponse[]>(`/evidence/${evidenceId}/custody`);
  return response.data;
};

export const verifyEvidenceIntegrity = async (
  evidenceId: string
): Promise<EvidenceVerificationResponse> => {
  const response = await apiClient.post<EvidenceVerificationResponse>(`/evidence/${evidenceId}/verify`);
  return response.data;
};

export const getEmailStructure = async (emailId: string): Promise<EmailStructureResponse> => {
  const response = await apiClient.get<EmailStructureResponse>(`/emails/${emailId}/structure`);
  return response.data;
};

export const getEmailHeaders = async (emailId: string): Promise<EmailHeadersResponse> => {
  const response = await apiClient.get<EmailHeadersResponse>(`/emails/${emailId}/headers`);
  return response.data;
};

export const triggerEmailParse = async (emailId: string): Promise<EmailStructureResponse> => {
  const response = await apiClient.post<EmailStructureResponse>(`/emails/${emailId}/parse`);
  return response.data;
};

export const getEmailRelayHops = async (emailId: string): Promise<RelayHopsResponse> => {
  const response = await apiClient.get<RelayHopsResponse>(`/emails/${emailId}/hops`);
  return response.data;
};

export const getEmailAuthResults = async (emailId: string): Promise<EmailAuthResponse> => {
  const response = await apiClient.get<EmailAuthResponse>(`/emails/${emailId}/auth`);
  return response.data;
};

export const analyzeEmailHeaders = async (emailId: string): Promise<RelayHopsResponse> => {
  const response = await apiClient.post<RelayHopsResponse>(`/emails/${emailId}/analyze-headers`);
  return response.data;
};

export const getEmailArtifacts = async (emailId: string): Promise<EmailArtifactsResponse> => {
  const response = await apiClient.get<EmailArtifactsResponse>(`/emails/${emailId}/artifacts`);
  return response.data;
};

export const extractEmailArtifacts = async (emailId: string): Promise<EmailArtifactsResponse> => {
  const response = await apiClient.post<EmailArtifactsResponse>(`/emails/${emailId}/extract-artifacts`);
  return response.data;
};

export const getDomainIntelligence = async (domainName: string): Promise<DomainIntelResponse> => {
  const response = await apiClient.get<DomainIntelResponse>(`/intelligence/domains/${encodeURIComponent(domainName)}`);
  return response.data;
};

export const getEmailDomainIntelligence = async (emailId: string): Promise<EmailDomainIntelResponse> => {
  const response = await apiClient.get<EmailDomainIntelResponse>(`/intelligence/emails/${emailId}/domains`);
  return response.data;
};

export const getIPIntelligence = async (ipAddress: string): Promise<IPIntelResponse> => {
  const response = await apiClient.get<IPIntelResponse>(`/intelligence/ips/${encodeURIComponent(ipAddress)}`);
  return response.data;
};

export const getEmailInfrastructureIntelligence = async (
  emailId: string
): Promise<EmailInfrastructureResponse> => {
  const response = await apiClient.get<EmailInfrastructureResponse>(
    `/intelligence/emails/${emailId}/infrastructure`
  );
  return response.data;
};

export const lookupThreatIndicator = async (
  indicatorType: string,
  indicatorValue: string
): Promise<AggregatedThreatIntelResponse> => {
  const response = await apiClient.get<AggregatedThreatIntelResponse>(
    `/intelligence/threat/lookup?indicator_type=${encodeURIComponent(
      indicatorType
    )}&indicator_value=${encodeURIComponent(indicatorValue)}`
  );
  return response.data;
};

export const getEmailThreatIntelligence = async (
  emailId: string
): Promise<EmailThreatIntelSummaryResponse> => {
  const response = await apiClient.get<EmailThreatIntelSummaryResponse>(
    `/intelligence/emails/${emailId}/threat-intel`
  );
  return response.data;
};

export const enrichEmailThreatIntelligence = async (
  emailId: string
): Promise<EmailThreatIntelSummaryResponse> => {
  const response = await apiClient.post<EmailThreatIntelSummaryResponse>(
    `/intelligence/emails/${emailId}/enrich`
  );
  return response.data;
};

export const getEmailAnalysis = async (emailId: string): Promise<EmailAnalysisResponse> => {
  const response = await apiClient.get<EmailAnalysisResponse>(`/emails/${emailId}/analysis`);
  return response.data;
};

export const triggerEmailAnalysis = async (emailId: string): Promise<EmailAnalysisResponse> => {
  const response = await apiClient.post<EmailAnalysisResponse>(`/emails/${emailId}/analyze`);
  return response.data;
};

export const getEmailFindings = async (
  emailId: string,
  severity?: string
): Promise<FindingsListResponse> => {
  const url = severity
    ? `/emails/${emailId}/findings?severity=${encodeURIComponent(severity)}`
    : `/emails/${emailId}/findings`;
  const response = await apiClient.get<FindingsListResponse>(url);
  return response.data;
};

export const getEmailDNA = async (emailId: string): Promise<EmailDNAProfileResponse> => {
  const response = await apiClient.get<EmailDNAProfileResponse>(`/emails/${emailId}/dna`);
  return response.data;
};

export const generateEmailDNA = async (emailId: string): Promise<EmailDNAProfileResponse> => {
  const response = await apiClient.post<EmailDNAProfileResponse>(`/emails/${emailId}/dna`);
  return response.data;
};

export const getEmailEmbeddings = async (emailId: string): Promise<EmbeddingItemResponse[]> => {
  const response = await apiClient.get<EmbeddingItemResponse[]>(`/emails/${emailId}/embeddings`);
  return response.data;
};

export const generateEmailEmbeddings = async (emailId: string): Promise<EmbeddingItemResponse[]> => {
  const response = await apiClient.post<EmbeddingItemResponse[]>(`/emails/${emailId}/embeddings`);
  return response.data;
};

export const getSimilarEmails = async (emailId: string): Promise<SimilarityLinkResponse[]> => {
  const response = await apiClient.get<SimilarityLinkResponse[]>(`/emails/${emailId}/similar`);
  return response.data;
};

export const computeSimilarEmails = async (
  emailId: string,
  params?: SimilaritySearchParams
): Promise<SimilarityLinkResponse[]> => {
  const response = await apiClient.post<SimilarityLinkResponse[]>(
    `/emails/${emailId}/similar`,
    params || {}
  );
  return response.data;
};

export const computeEmailCorrelations = async (
  emailId: string,
  minScore = 40.0
): Promise<EmailCorrelationsResponse> => {
  const response = await apiClient.post<EmailCorrelationsResponse>(
    `/campaigns/correlate/${emailId}?min_score=${minScore}`
  );
  return response.data;
};

export const getEmailCorrelations = async (
  emailId: string,
  minScore = 40.0
): Promise<EmailCorrelationsResponse> => {
  const response = await apiClient.get<EmailCorrelationsResponse>(
    `/campaigns/correlations/${emailId}?min_score=${minScore}`
  );
  return response.data;
};

export const createCampaign = async (payload: CreateCampaignPayload): Promise<CampaignDetailResponse> => {
  const response = await apiClient.post<CampaignDetailResponse>('/campaigns', payload);
  return response.data;
};

export const listCampaigns = async (
  status?: string,
  skip = 0,
  limit = 50
): Promise<CampaignListItemResponse[]> => {
  const params: Record<string, unknown> = { skip, limit };
  if (status) params.status = status;
  const response = await apiClient.get<CampaignListItemResponse[]>('/campaigns', { params });
  return response.data;
};

export const getCampaign = async (campaignId: string): Promise<CampaignDetailResponse> => {
  const response = await apiClient.get<CampaignDetailResponse>(`/campaigns/${campaignId}`);
  return response.data;
};

export const addEmailToCampaign = async (
  campaignId: string,
  emailId: string,
  payload?: { membership_confidence?: number; membership_status?: string; evidence_summary?: Record<string, unknown> }
): Promise<CampaignMembershipItem> => {
  const response = await apiClient.post<CampaignMembershipItem>(
    `/campaigns/${campaignId}/emails/${emailId}`,
    payload || {}
  );
  return response.data;
};

export const removeEmailFromCampaign = async (
  campaignId: string,
  emailId: string
): Promise<{ message: string }> => {
  const response = await apiClient.delete<{ message: string }>(
    `/campaigns/${campaignId}/emails/${emailId}`
  );
  return response.data;
};

export const getEmailCampaignMemberships = async (emailId: string): Promise<EmailMembershipsResponse> => {
  const response = await apiClient.get<EmailMembershipsResponse>(
    `/campaigns/emails/${emailId}/memberships`
  );
  return response.data;
};

export const autoClusterCampaigns = async (minScore = 60.0): Promise<AutoClusterResponse> => {
  const response = await apiClient.post<AutoClusterResponse>(
    `/campaigns/auto-cluster?min_score=${minScore}`
  );
  return response.data;
};

export const getInvestigationGraphForEmail = async (emailId: string): Promise<InvestigationGraphResponse> => {
  const response = await apiClient.get<InvestigationGraphResponse>(`/graph/email/${emailId}`);
  return response.data;
};

export const getInvestigationGraphForCampaign = async (
  campaignId: string
): Promise<InvestigationGraphResponse> => {
  const response = await apiClient.get<InvestigationGraphResponse>(`/graph/campaign/${campaignId}`);
  return response.data;
};

export const getGlobalInvestigationGraph = async (limit = 30): Promise<InvestigationGraphResponse> => {
  const response = await apiClient.get<InvestigationGraphResponse>(`/graph/global?limit=${limit}`);
  return response.data;
};

export interface GeoIPLookupResponse {
  ip_address: string;
  is_private: boolean;
  country_code: string;
  country_name: string;
  region_name?: string | null;
  city_name?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy_radius_km?: number | null;
  source: string;
  confidence: number;
  attribution_statement: string;
  connection_type?: 'TOR' | 'VPN' | 'CLOUD' | 'PERSONAL_MAIL' | 'RESIDENTIAL' | 'INTERNAL' | 'RELAY' | string;
  provider?: string | null;
  is_tor?: boolean;
  is_vpn?: boolean;
  is_datacenter?: boolean;
  is_cloud?: boolean;
  is_personal_mail?: boolean;
  asn?: string | null;
  asn_org?: string | null;
  reverse_dns?: string | null;
  classification_badges?: string[];
}

export interface GeoMarkerItem {
  id: string;
  entity_type?: string;
  sequence_number?: number | null;
  ip_address: string;
  host?: string | null;
  latitude: number;
  longitude: number;
  country_code: string;
  country_name: string;
  region_name?: string | null;
  city_name?: string | null;
  accuracy_radius_km?: number | null;
  confidence: number;
  role?: string | null;
  associated_email_count?: number | null;
  associated_email_ids?: string[] | null;
  connection_type?: 'TOR' | 'VPN' | 'CLOUD' | 'PERSONAL_MAIL' | 'RESIDENTIAL' | 'INTERNAL' | 'RELAY' | string;
  provider?: string | null;
  is_tor?: boolean;
  is_vpn?: boolean;
  is_datacenter?: boolean;
  is_cloud?: boolean;
  is_personal_mail?: boolean;
  asn?: string | null;
  asn_org?: string | null;
  reverse_dns?: string | null;
  classification_badges?: string[];
}

export interface GeoPathSegment {
  from_hop: number;
  to_hop: number;
  from_ip: string;
  to_ip: string;
  from_coords: [number, number];
  to_coords: [number, number];
  label: string;
}

export interface HopGeoNode {
  sequence_number: number;
  source_host?: string | null;
  source_ip: string;
  destination_host?: string | null;
  reliability: string;
  geolocation: GeoIPLookupResponse;
  connection_type?: 'TOR' | 'VPN' | 'CLOUD' | 'PERSONAL_MAIL' | 'RESIDENTIAL' | 'INTERNAL' | 'RELAY' | string;
  provider?: string | null;
  is_tor?: boolean;
  is_vpn?: boolean;
  is_datacenter?: boolean;
  is_cloud?: boolean;
  is_personal_mail?: boolean;
  asn?: string | null;
  asn_org?: string | null;
  reverse_dns?: string | null;
  classification_badges?: string[];
}

export interface EmailGeoInfrastructureResponse {
  email_id: string;
  subject?: string | null;
  total_hops: number;
  total_markers: number;
  tor_node_count?: number;
  vpn_node_count?: number;
  cloud_node_count?: number;
  personal_mail_node_count?: number;
  hops: HopGeoNode[];
  markers: GeoMarkerItem[];
  paths: GeoPathSegment[];
  country_distribution: Record<string, number>;
  attribution_disclaimer: string;
}

export interface CampaignGeoInfrastructureResponse {
  campaign_id: string;
  campaign_name: string;
  campaign_status?: string | null;
  total_emails: number;
  total_unique_ips: number;
  total_markers: number;
  tor_node_count?: number;
  vpn_node_count?: number;
  cloud_node_count?: number;
  personal_mail_node_count?: number;
  markers: GeoMarkerItem[];
  country_distribution: Record<string, number>;
  attribution_disclaimer: string;
}

export interface GlobalGeoInfrastructureResponse {
  total_emails_scanned: number;
  total_unique_ips: number;
  total_markers: number;
  tor_node_count?: number;
  vpn_node_count?: number;
  cloud_node_count?: number;
  personal_mail_node_count?: number;
  markers: Record<string, unknown>[];
  country_distribution: Record<string, number>;
  attribution_disclaimer: string;
}

export const getIPGeolocation = async (ipAddress: string): Promise<GeoIPLookupResponse> => {
  const response = await apiClient.get<GeoIPLookupResponse>(`/geo/ip/${ipAddress}`);
  return response.data;
};

export const getEmailGeoInfrastructure = async (emailId: string): Promise<EmailGeoInfrastructureResponse> => {
  const response = await apiClient.get<EmailGeoInfrastructureResponse>(`/geo/email/${emailId}`);
  return response.data;
};

export const getCampaignGeoInfrastructure = async (
  campaignId: string
): Promise<CampaignGeoInfrastructureResponse> => {
  const response = await apiClient.get<CampaignGeoInfrastructureResponse>(`/geo/campaign/${campaignId}`);
  return response.data;
};

export const getGlobalGeoInfrastructure = async (
  limit = 50
): Promise<GlobalGeoInfrastructureResponse> => {
  const response = await apiClient.get<GlobalGeoInfrastructureResponse>(`/geo/global?limit=${limit}`);
  return response.data;
};

export interface ReportItem {
  id: string;
  report_type: string;
  email_id?: string | null;
  campaign_id?: string | null;
  evidence_object_id?: string | null;
  report_version: string;
  generated_at: string;
  summary: Record<string, any>;
}

export interface ReportListResponse {
  total_reports: number;
  reports: ReportItem[];
}

export interface GenerateReportResponse {
  report_id: string;
  report_type: string;
  format: string;
  email_id?: string | null;
  campaign_id?: string | null;
  generated_at: string;
  summary: Record<string, any>;
  report_data: Record<string, any>;
}

export const generateEmailReport = async (
  emailId: string,
  format: 'html' | 'markdown' | 'json' = 'html'
): Promise<GenerateReportResponse> => {
  const response = await apiClient.post<GenerateReportResponse>(`/reports/email/${emailId}?format=${format}`);
  return response.data;
};

export const getEmailReportData = async (emailId: string): Promise<Record<string, any>> => {
  const response = await apiClient.get<Record<string, any>>(`/reports/email/${emailId}`);
  return response.data;
};

export const exportEmailReport = async (
  emailId: string,
  format: 'html' | 'markdown' | 'json' = 'html'
): Promise<string> => {
  const response = await apiClient.get<string>(`/reports/email/${emailId}/export?format=${format}`, {
    responseType: 'text',
  });
  return response.data;
};

export const generateCampaignReport = async (
  campaignId: string,
  format: 'html' | 'markdown' | 'json' = 'html'
): Promise<GenerateReportResponse> => {
  const response = await apiClient.post<GenerateReportResponse>(`/reports/campaign/${campaignId}?format=${format}`);
  return response.data;
};

export const getCampaignReportData = async (campaignId: string): Promise<Record<string, any>> => {
  const response = await apiClient.get<Record<string, any>>(`/reports/campaign/${campaignId}`);
  return response.data;
};

export const listReports = async (
  emailId?: string,
  campaignId?: string,
  limit = 50
): Promise<ReportListResponse> => {
  const params: Record<string, unknown> = { limit };
  if (emailId) params.email_id = emailId;
  if (campaignId) params.campaign_id = campaignId;
  const response = await apiClient.get<ReportListResponse>('/reports', { params });
  return response.data;
};

export const getReportById = async (reportId: string): Promise<ReportItem> => {
  const response = await apiClient.get<ReportItem>(`/reports/${reportId}`);
  return response.data;
};

// ---------------------------------------------------------------------------
// Users & Access Management (org roster, invite, role changes, deactivation)
// ---------------------------------------------------------------------------
// Listing requires ANALYST_ROLES; invite/role-change/deactivate require
// ADMIN_ROLES (INSTITUTION_ADMIN or SYSTEM_ADMIN) — see backend
// app/api/v1/endpoints/users.py. Callers should be prepared for a 403 from
// the mutating endpoints if the signed-in user isn't an org admin.

export const ASSIGNABLE_ROLES = ['SECURITY_ANALYST', 'USER'] as const;
export type AssignableRole = typeof ASSIGNABLE_ROLES[number];

export interface OrgMember {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  account_status: string;
  membership_status: string;
  created_at: string;
  last_login_at: string | null;
}

export interface InviteUserPayload {
  email: string;
  full_name?: string;
  role_code: AssignableRole;
}

export interface InviteUserResponse {
  user: OrgMember;
  // Shown once — there is no outbound email delivery in this build. The
  // admin is responsible for relaying this to the invited teammate.
  temporary_password: string;
}

export const listOrgMembers = async (): Promise<OrgMember[]> => {
  const response = await apiClient.get<OrgMember[]>('/users');
  return response.data;
};

export const inviteOrgMember = async (payload: InviteUserPayload): Promise<InviteUserResponse> => {
  const response = await apiClient.post<InviteUserResponse>('/users/invite', payload);
  return response.data;
};

export const updateOrgMemberRole = async (userId: string, roleCode: AssignableRole): Promise<OrgMember> => {
  const response = await apiClient.patch<OrgMember>(`/users/${userId}/role`, { role_code: roleCode });
  return response.data;
};

export const deactivateOrgMember = async (userId: string): Promise<void> => {
  await apiClient.delete(`/users/${userId}`);
};

export interface PlatformMember extends OrgMember {
  organization_id: string;
  organization_name: string;
}
export interface OrganizationItem {
  id: string;
  name: string;
  organization_type: string;
  status: string;
  created_at: string;
}
export const listPlatformOrganizations = async (): Promise<OrganizationItem[]> =>
  (await apiClient.get<OrganizationItem[]>('/platform/organizations')).data;
export const listPlatformUsers = async (organizationId?: string): Promise<PlatformMember[]> =>
  (await apiClient.get<PlatformMember[]>('/platform/users', { params: organizationId ? { organization_id: organizationId } : undefined })).data;
// Deliberately NOT `InviteUserPayload & {...}` -- InviteUserPayload's
// role_code is narrowed to AssignableRole (the org-scoped roles), which
// would make CYBER_CELL_INVESTIGATOR/SYSTEM_ADMIN a type error here even
// though the backend's PLATFORM_ROLES (and ALL_ASSIGNABLE_ROLES) allow them.
export interface PlatformInvitePayload {
  email: string;
  full_name?: string;
  organization_id: string;
  role_code: string;
}
export const invitePlatformUser = async (payload: PlatformInvitePayload): Promise<InviteUserResponse> =>
  (await apiClient.post<InviteUserResponse>('/platform/users/invite', payload)).data;
export const updatePlatformUserRole = async (userId: string, roleCode: string): Promise<PlatformMember> =>
  (await apiClient.patch<PlatformMember>(`/platform/users/${userId}/role`, { role_code: roleCode })).data;
export const deactivatePlatformUser = async (userId: string): Promise<void> => {
  await apiClient.delete(`/platform/users/${userId}`);
};

export interface CreateOrganizationPayload {
  name: string;
  organization_type?: string;
}
export const createPlatformOrganization = async (payload: CreateOrganizationPayload): Promise<OrganizationItem> =>
  (await apiClient.post<OrganizationItem>('/platform/organizations', payload)).data;

// ---------------------------------------------------------------------------
// Platform audit log (SYSTEM_ADMIN only) — see
// app.api.v1.endpoints.platform_admin.list_audit_log for the matching
// query params (actor_user_id, organization_id, action, date_from, date_to,
// limit). There is no offset/cursor param server-side, so "pagination" here
// is a growing `limit` ("load more") rather than page numbers.
export interface AuditLogEntry {
  id: string;
  actor_user_id: string | null;
  organization_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  occurred_at: string;
  metadata_json: Record<string, unknown> | null;
}
export interface AuditLogFilters {
  actor_user_id?: string;
  organization_id?: string;
  action?: string;
  date_from?: string;
  date_to?: string;
  limit?: number;
}
export const listPlatformAuditLog = async (filters: AuditLogFilters = {}): Promise<AuditLogEntry[]> =>
  (await apiClient.get<AuditLogEntry[]>('/platform/audit-log', { params: filters })).data;

// ---------------------------------------------------------------------------
// AI & RAG Intelligence (Groq-Powered Forensic Reasoning & Case Assistant)
// ---------------------------------------------------------------------------

export interface AIReasoningItem {
  finding: string;
  evidence: string;
  confidence: number;
}

export interface AIThreatReasoningResponse {
  classification: 'legitimate' | 'suspicious' | 'phishing' | 'impersonation' | 'fraud' | 'BEC' | string;
  reasoning: AIReasoningItem[];
  social_engineering_indicators: string[];
  attack_intent: string[];
  recommended_actions: string[];
  confidence: number;
}

export interface AIInvestigateResponse {
  email_id: string;
  question: string;
  answer: string;
  grounded_sources: {
    findings_count?: number;
    similar_emails_count?: number;
    campaigns_count?: number;
    urls_count?: number;
  };
}

export interface AICaseSummaryResponse {
  email_id: string;
  summary: string;
  classification: string;
  threat_score: number;
  top_findings: string[];
  recommended_actions: string[];
}

export interface AIStatusResponse {
  provider: string;
  groq_configured: boolean;
  model: string;
  fallback_model: string;
  temperature: number;
  rag_pgvector_active: boolean;
}

export const getAIThreatReasoning = async (emailId: string): Promise<AIThreatReasoningResponse> =>
  (await apiClient.post<AIThreatReasoningResponse>(`/ai/${emailId}/explain`)).data;

export const investigateCaseWithAI = async (
  emailId: string,
  question: string,
  history: { role: string; content: string }[] = []
): Promise<AIInvestigateResponse> =>
  (await apiClient.post<AIInvestigateResponse>(`/ai/${emailId}/investigate`, { question, history })).data;

export const getAICaseSummary = async (emailId: string): Promise<AICaseSummaryResponse> =>
  (await apiClient.post<AICaseSummaryResponse>(`/ai/${emailId}/summarize`)).data;

export const getAIStatus = async (): Promise<AIStatusResponse> =>
  (await apiClient.get<AIStatusResponse>('/ai/status')).data;

// --- Human Layer, Triage Tiers & Active Learning Precedents ---
export type TriageTier = 'TIER_1_AUTO' | 'TIER_2_HUMAN_GATED' | 'TIER_3_AUTO_CLEARED' | 'HUMAN_RESOLVED';

export interface AnalystPrecedentItem {
  precedent_email_id: string;
  similarity_score: number;
  analyst_verdict: string;
  analyst_notes?: string | null;
  reviewer_name: string;
  reviewed_at?: string | null;
  shared_indicators: string[];
}

export interface EmailDispositionResponse {
  email_id: string;
  is_resolved: boolean;
  triage_tier: TriageTier;
  tier_label: string;
  verdict?: string | null;
  confidence: number;
  analyst_notes?: string | null;
  flagged_iocs: Record<string, any>[];
  remediation_actions: string[];
  reviewed_by_name?: string | null;
  reviewed_at?: string | null;
  conflict_reasons: string[];
  recommendation?: string;
  precedents: AnalystPrecedentItem[];
}

export interface SubmitDispositionRequest {
  verdict: string;
  notes: string;
  actions?: string[];
  flagged_iocs?: Record<string, any>[];
}

export const getEmailDisposition = async (emailId: string): Promise<EmailDispositionResponse> =>
  (await apiClient.get<EmailDispositionResponse>(`/disposition/${emailId}`)).data;

export const submitEmailDisposition = async (
  emailId: string,
  payload: SubmitDispositionRequest
): Promise<EmailDispositionResponse> =>
  (await apiClient.post<EmailDispositionResponse>(`/disposition/${emailId}`, payload)).data;

export const getEmailPrecedents = async (emailId: string): Promise<AnalystPrecedentItem[]> =>
  (await apiClient.get<AnalystPrecedentItem[]>(`/disposition/${emailId}/precedents`)).data;
