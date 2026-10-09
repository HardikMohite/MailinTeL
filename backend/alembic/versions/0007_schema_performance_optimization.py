"""comprehensive schema performance optimization and index coverage

Revision ID: 0007_perf_opt
Revises: 0006_user_username
Create Date: 2026-10-08 23:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0007_perf_opt"
down_revision: Union[str, None] = "0006_user_username"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEXES_TO_CREATE = [
    # 1. Extensions
    ("CREATE EXTENSION IF NOT EXISTS pg_trgm;", "DROP EXTENSION IF EXISTS pg_trgm;"),
    ("CREATE EXTENSION IF NOT EXISTS btree_gin;", "DROP EXTENSION IF EXISTS btree_gin;"),

    # 2. Emails - High frequency list, filter, and fuzzy search
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_org_created_desc ON emails (organization_id, created_at DESC);",
        "DROP INDEX IF EXISTS ix_emails_org_created_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_created_desc ON emails (created_at DESC);",
        "DROP INDEX IF EXISTS ix_emails_created_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_source_id ON emails (source_id);",
        "DROP INDEX IF EXISTS ix_emails_source_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_org_analysis_status ON emails (organization_id, analysis_status, created_at DESC);",
        "DROP INDEX IF EXISTS ix_emails_org_analysis_status;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_org_qual_status ON emails (organization_id, qualification_status, created_at DESC);",
        "DROP INDEX IF EXISTS ix_emails_org_qual_status;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_subject_trgm ON emails USING gin (subject gin_trgm_ops);",
        "DROP INDEX IF EXISTS ix_emails_subject_trgm;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_emails_sender_trgm ON emails USING gin (sender_address gin_trgm_ops);",
        "DROP INDEX IF EXISTS ix_emails_sender_trgm;",
    ),

    # 3. Email Sources
    (
        "CREATE INDEX IF NOT EXISTS ix_email_sources_org_created_desc ON email_sources (organization_id, created_at DESC);",
        "DROP INDEX IF EXISTS ix_email_sources_org_created_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_email_sources_user_id ON email_sources (user_id);",
        "DROP INDEX IF EXISTS ix_email_sources_user_id;",
    ),

    # 4. Evidence Objects
    (
        "CREATE INDEX IF NOT EXISTS ix_evidence_objects_email_type ON evidence_objects (email_id, evidence_type);",
        "DROP INDEX IF EXISTS ix_evidence_objects_email_type;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_evidence_objects_parent_evidence_id ON evidence_objects (parent_evidence_id);",
        "DROP INDEX IF EXISTS ix_evidence_objects_parent_evidence_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_evidence_objects_created_by ON evidence_objects (created_by);",
        "DROP INDEX IF EXISTS ix_evidence_objects_created_by;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_evidence_objects_case_id ON evidence_objects (case_id);",
        "DROP INDEX IF EXISTS ix_evidence_objects_case_id;",
    ),

    # 5. Email Headers
    (
        "CREATE INDEX IF NOT EXISTS ix_email_headers_email_order ON email_headers (email_id, header_order ASC);",
        "DROP INDEX IF EXISTS ix_email_headers_email_order;",
    ),

    # 6. Campaigns & Memberships
    (
        "CREATE INDEX IF NOT EXISTS ix_campaigns_org_activity_desc ON campaigns (organization_id, last_activity_at DESC);",
        "DROP INDEX IF EXISTS ix_campaigns_org_activity_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_campaigns_status_activity ON campaigns (campaign_status, last_activity_at DESC);",
        "DROP INDEX IF EXISTS ix_campaigns_status_activity;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_campaigns_name_trgm ON campaigns USING gin (campaign_name gin_trgm_ops);",
        "DROP INDEX IF EXISTS ix_campaigns_name_trgm;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_campaign_memberships_camp_email ON campaign_memberships (campaign_id, email_id);",
        "DROP INDEX IF EXISTS ix_campaign_memberships_camp_email;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_campaign_memberships_email_id ON campaign_memberships (email_id);",
        "DROP INDEX IF EXISTS ix_campaign_memberships_email_id;",
    ),

    # 7. Cases & Case Links
    (
        "CREATE INDEX IF NOT EXISTS ix_cases_org_created_desc ON cases (organization_id, created_at DESC);",
        "DROP INDEX IF EXISTS ix_cases_org_created_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_cases_status_created ON cases (status, created_at DESC);",
        "DROP INDEX IF EXISTS ix_cases_status_created;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_cases_created_by ON cases (created_by);",
        "DROP INDEX IF EXISTS ix_cases_created_by;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_case_emails_case_email ON case_emails (case_id, email_id);",
        "DROP INDEX IF EXISTS ix_case_emails_case_email;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_case_emails_email_id ON case_emails (email_id);",
        "DROP INDEX IF EXISTS ix_case_emails_email_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_case_campaigns_campaign_id ON case_campaigns (campaign_id);",
        "DROP INDEX IF EXISTS ix_case_campaigns_campaign_id;",
    ),

    # 8. Threat Indicators & Sightings
    (
        "CREATE INDEX IF NOT EXISTS ix_threat_indicators_type_val ON threat_indicators (indicator_type, normalized_value);",
        "DROP INDEX IF EXISTS ix_threat_indicators_type_val;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_threat_indicators_val_trgm ON threat_indicators USING gin (normalized_value gin_trgm_ops);",
        "DROP INDEX IF EXISTS ix_threat_indicators_val_trgm;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_threat_indicators_status_rep ON threat_indicators (status, reputation);",
        "DROP INDEX IF EXISTS ix_threat_indicators_status_rep;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_indicator_sightings_email_id ON indicator_sightings (email_id);",
        "DROP INDEX IF EXISTS ix_indicator_sightings_email_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_indicator_sightings_campaign_id ON indicator_sightings (campaign_id);",
        "DROP INDEX IF EXISTS ix_indicator_sightings_campaign_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_indicator_sightings_evidence_id ON indicator_sightings (evidence_id);",
        "DROP INDEX IF EXISTS ix_indicator_sightings_evidence_id;",
    ),

    # 9. Email Analysis & Findings
    (
        "CREATE INDEX IF NOT EXISTS ix_email_analysis_run_id ON email_analysis (analysis_run_id);",
        "DROP INDEX IF EXISTS ix_email_analysis_run_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_email_analysis_threat_risk ON email_analysis (threat_classification, threat_risk_score DESC);",
        "DROP INDEX IF EXISTS ix_email_analysis_threat_risk;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_analysis_findings_run_id ON analysis_findings (analysis_run_id);",
        "DROP INDEX IF EXISTS ix_analysis_findings_run_id;",
    ),

    # 10. Audit Logs
    (
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_org_occurred_desc ON audit_logs (organization_id, occurred_at DESC);",
        "DROP INDEX IF EXISTS ix_audit_logs_org_occurred_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_occurred_desc ON audit_logs (actor_user_id, occurred_at DESC);",
        "DROP INDEX IF EXISTS ix_audit_logs_actor_occurred_desc;",
    ),

    # 11. Reports
    (
        "CREATE INDEX IF NOT EXISTS ix_reports_generated_at_desc ON reports (generated_at DESC);",
        "DROP INDEX IF EXISTS ix_reports_generated_at_desc;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_reports_email_id ON reports (email_id);",
        "DROP INDEX IF EXISTS ix_reports_email_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_reports_case_id ON reports (case_id);",
        "DROP INDEX IF EXISTS ix_reports_case_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_reports_campaign_id ON reports (campaign_id);",
        "DROP INDEX IF EXISTS ix_reports_campaign_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_reports_evidence_id ON reports (evidence_object_id);",
        "DROP INDEX IF EXISTS ix_reports_evidence_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_reports_generated_by ON reports (generated_by);",
        "DROP INDEX IF EXISTS ix_reports_generated_by;",
    ),

    # 12. URLs, Entities, Classifications & Remaining FKs
    (
        "CREATE INDEX IF NOT EXISTS ix_urls_domain_id ON urls (domain_id);",
        "DROP INDEX IF EXISTS ix_urls_domain_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_email_urls_url_id ON email_urls (url_id);",
        "DROP INDEX IF EXISTS ix_email_urls_url_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_infra_class_ip_id ON infrastructure_classifications (ip_id);",
        "DROP INDEX IF EXISTS ix_infra_class_ip_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_infra_class_domain_id ON infrastructure_classifications (domain_id);",
        "DROP INDEX IF EXISTS ix_infra_class_domain_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_entity_geolocations_geo_id ON entity_geolocations (geolocation_id);",
        "DROP INDEX IF EXISTS ix_entity_geolocations_geo_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_email_similarity_related_id ON email_similarity_links (related_email_id);",
        "DROP INDEX IF EXISTS ix_email_similarity_related_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_custody_events_actor_user_id ON custody_events (actor_user_id);",
        "DROP INDEX IF EXISTS ix_custody_events_actor_user_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_investigation_actions_actor_user_id ON investigation_actions (actor_user_id);",
        "DROP INDEX IF EXISTS ix_investigation_actions_actor_user_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_retention_assignments_policy_id ON retention_assignments (policy_id);",
        "DROP INDEX IF EXISTS ix_retention_assignments_policy_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_retention_assignments_email_id ON retention_assignments (email_id);",
        "DROP INDEX IF EXISTS ix_retention_assignments_email_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_retention_assignments_evidence_id ON retention_assignments (evidence_id);",
        "DROP INDEX IF EXISTS ix_retention_assignments_evidence_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_retention_policies_org_id ON retention_policies (organization_id);",
        "DROP INDEX IF EXISTS ix_retention_policies_org_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_masking_rules_org_id ON masking_rules (organization_id);",
        "DROP INDEX IF EXISTS ix_masking_rules_org_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_masking_rules_role_id ON masking_rules (role_id);",
        "DROP INDEX IF EXISTS ix_masking_rules_role_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_organization_members_role_id ON organization_members (role_id);",
        "DROP INDEX IF EXISTS ix_organization_members_role_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_role_permissions_permission_id ON role_permissions (permission_id);",
        "DROP INDEX IF EXISTS ix_role_permissions_permission_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_extension_events_user_id ON extension_events (user_id);",
        "DROP INDEX IF EXISTS ix_extension_events_user_id;",
    ),
    (
        "CREATE INDEX IF NOT EXISTS ix_extension_events_email_id ON extension_events (email_id);",
        "DROP INDEX IF EXISTS ix_extension_events_email_id;",
    ),
]


def upgrade() -> None:
    for sql_up, _ in INDEXES_TO_CREATE:
        op.execute(sql_up)
    # Recalculate statistics for query planner
    op.execute("ANALYZE emails;")
    op.execute("ANALYZE evidence_objects;")
    op.execute("ANALYZE email_headers;")
    op.execute("ANALYZE campaigns;")
    op.execute("ANALYZE threat_indicators;")
    op.execute("ANALYZE cases;")


def downgrade() -> None:
    for _, sql_down in reversed(INDEXES_TO_CREATE):
        op.execute(sql_down)
