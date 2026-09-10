"""initial_mailintel_schema

Revision ID: 0001_initial
Revises: 
Create Date: 2026-09-06 13:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from pgvector.sqlalchemy import Vector

# revision identifiers, used by Alembic.
revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Enable required PostgreSQL extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # 2. Identity & Organization Tables
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('password_hash', sa.Text(), nullable=True),
        sa.Column('auth_provider', sa.String(length=50), nullable=False, server_default='LOCAL'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('organization_type', sa.String(length=100), nullable=False, server_default='ENTERPRISE'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('code', sa.String(length=50), nullable=False, unique=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
    )
    op.create_index('ix_roles_code', 'roles', ['code'])

    op.create_table(
        'permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('code', sa.String(length=100), nullable=False, unique=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
    )
    op.create_index('ix_permissions_code', 'permissions', ['code'])

    op.create_table(
        'role_permissions',
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
    )

    op.create_table(
        'organization_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_organization_members_org_id', 'organization_members', ['organization_id'])
    op.create_index('ix_organization_members_user_id', 'organization_members', ['user_id'])

    # 3. Email Ingestion & Forensics Tables
    op.create_table(
        'email_sources',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('source_type', sa.String(length=50), nullable=False, server_default='FILE_UPLOAD'),
        sa.Column('source_provider', sa.String(length=50), nullable=True),
        sa.Column('source_reference', sa.String(length=255), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'emails',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('source_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('email_sources.id', ondelete='CASCADE'), nullable=False),
        sa.Column('external_message_id', sa.String(length=255), nullable=True),
        sa.Column('message_id_header', sa.String(length=500), nullable=True),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('sender_address', sa.String(length=255), nullable=True),
        sa.Column('sender_display_name', sa.String(length=255), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('email_size_bytes', sa.BigInteger(), nullable=True),
        sa.Column('analysis_status', sa.String(length=50), nullable=False, server_default='PENDING'),
        sa.Column('qualification_status', sa.String(length=50), nullable=False, server_default='NORMAL'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_emails_message_id_header', 'emails', ['message_id_header'])
    op.create_index('ix_emails_external_message_id', 'emails', ['external_message_id'])
    op.create_index('ix_emails_sender_address', 'emails', ['sender_address'])
    op.create_index('ix_emails_analysis_status', 'emails', ['analysis_status'])
    op.create_index('ix_emails_qualification_status', 'emails', ['qualification_status'])

    op.create_table(
        'email_headers',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('header_name', sa.String(length=255), nullable=False),
        sa.Column('header_value', sa.Text(), nullable=False),
        sa.Column('normalized_value', sa.Text(), nullable=True),
        sa.Column('header_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_email_headers_email_id', 'email_headers', ['email_id'])

    op.create_table(
        'email_recipients',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('recipient_type', sa.String(length=10), nullable=False),
        sa.Column('address', sa.String(length=255), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_email_recipients_email_id', 'email_recipients', ['email_id'])
    op.create_index('ix_email_recipients_address', 'email_recipients', ['address'])

    op.create_table(
        'email_authentication_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('spf_result', sa.String(length=50), nullable=True),
        sa.Column('dkim_result', sa.String(length=50), nullable=True),
        sa.Column('dmarc_result', sa.String(length=50), nullable=True),
        sa.Column('from_alignment_result', sa.String(length=50), nullable=True),
        sa.Column('return_path', sa.String(length=255), nullable=True),
        sa.Column('reply_to', sa.String(length=255), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'relay_hops',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('sequence_number', sa.Integer(), nullable=False),
        sa.Column('source_host', sa.String(length=255), nullable=True),
        sa.Column('source_ip', sa.String(length=50), nullable=True),
        sa.Column('destination_host', sa.String(length=255), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reliability', sa.String(length=50), nullable=False, server_default='UNVERIFIED'),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_relay_hops_email_id', 'relay_hops', ['email_id'])

    # 4. Evidence Object & Custody Tables
    op.create_table(
        'evidence_objects',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='SET NULL'), nullable=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('parent_evidence_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('evidence_objects.id', ondelete='SET NULL'), nullable=True),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('content_type', sa.String(length=100), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('bucket_name', sa.String(length=100), nullable=False),
        sa.Column('object_key', sa.Text(), nullable=False),
        sa.Column('object_version_id', sa.String(length=100), nullable=True),
        sa.Column('source_type', sa.String(length=50), nullable=False, server_default='UPLOAD'),
        sa.Column('acquired_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('stored_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('immutable', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('retention_status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_evidence_objects_sha256_hash', 'evidence_objects', ['sha256_hash'])
    op.create_index('ix_evidence_objects_email_id', 'evidence_objects', ['email_id'])

    op.create_table(
        'custody_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('evidence_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('evidence_objects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('actor_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('event_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('event_metadata', sa.JSON(), nullable=True),
        sa.Column('previous_event_hash', sa.String(length=64), nullable=True),
        sa.Column('event_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_custody_events_evidence_id', 'custody_events', ['evidence_id'])
    op.create_index('ix_custody_events_event_at', 'custody_events', ['event_at'])

    # 5. Domain, URL, IP & Infrastructure Tables
    op.create_table(
        'domains',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('normalized_domain', sa.String(length=255), nullable=False, unique=True),
        sa.Column('root_domain', sa.String(length=255), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_domains_normalized_domain', 'domains', ['normalized_domain'])

    op.create_table(
        'domain_dns_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('domain_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('record_type', sa.String(length=20), nullable=False),
        sa.Column('record_value', sa.Text(), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False, server_default='DNS_QUERY'),
    )
    op.create_index('ix_domain_dns_records_domain_id', 'domain_dns_records', ['domain_id'])

    op.create_table(
        'domain_registration_intel',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('domain_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False, server_default='RDAP'),
        sa.Column('registrar', sa.String(length=255), nullable=True),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('nameservers', sa.JSON(), nullable=True),
        sa.Column('raw_summary', sa.JSON(), nullable=True),
        sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_domain_registration_intel_domain_id', 'domain_registration_intel', ['domain_id'])

    op.create_table(
        'urls',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('normalized_url', sa.Text(), nullable=False, unique=True),
        sa.Column('url_hash', sa.String(length=64), nullable=False),
        sa.Column('domain_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='SET NULL'), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_urls_url_hash', 'urls', ['url_hash'])

    op.create_table(
        'email_urls',
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('url_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('urls.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('context', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'ip_addresses',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('ip_address', sa.String(length=50), nullable=False, unique=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_ip_addresses_ip_address', 'ip_addresses', ['ip_address'])

    op.create_table(
        'ip_intelligence',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('ip_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('ip_addresses.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asn', sa.String(length=50), nullable=True),
        sa.Column('isp', sa.String(length=255), nullable=True),
        sa.Column('network_owner', sa.String(length=255), nullable=True),
        sa.Column('hosting_provider', sa.String(length=255), nullable=True),
        sa.Column('reverse_dns', sa.String(length=255), nullable=True),
        sa.Column('intelligence_source', sa.String(length=50), nullable=False, server_default='MAXMIND'),
        sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_ip_intelligence_ip_id', 'ip_intelligence', ['ip_id'])
    op.create_index('ix_ip_intelligence_asn', 'ip_intelligence', ['asn'])

    op.create_table(
        'infrastructure_classifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('ip_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('ip_addresses.id', ondelete='CASCADE'), nullable=True),
        sa.Column('domain_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=True),
        sa.Column('classification_type', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False, server_default='INTERNAL'),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_infrastructure_classifications_type', 'infrastructure_classifications', ['classification_type'])

    # 6. Geolocation Tables
    op.create_table(
        'geolocations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('country_code', sa.String(length=10), nullable=False),
        sa.Column('country_name', sa.String(length=100), nullable=False),
        sa.Column('region_name', sa.String(length=100), nullable=True),
        sa.Column('city_name', sa.String(length=100), nullable=True),
        sa.Column('latitude', sa.Numeric(precision=10, scale=7), nullable=True),
        sa.Column('longitude', sa.Numeric(precision=10, scale=7), nullable=True),
        sa.Column('accuracy_radius_km', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(length=50), nullable=False, server_default='MAXMIND_GEOIP'),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_geolocations_country_code', 'geolocations', ['country_code'])

    op.create_table(
        'entity_geolocations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('entity_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('geolocation_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('geolocations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_entity_geolocations_entity_id', 'entity_geolocations', ['entity_id'])

    # 7. Threat Analysis & Explainable Findings Tables
    op.create_table(
        'analysis_runs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('analysis_type', sa.String(length=50), nullable=False, server_default='FULL_PIPELINE'),
        sa.Column('analysis_version', sa.String(length=50), nullable=False, server_default='1.0'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='RUNNING'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('worker_reference', sa.String(length=100), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_analysis_runs_email_id', 'analysis_runs', ['email_id'])

    op.create_table(
        'email_analysis',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('analysis_run_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('analysis_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('threat_classification', sa.String(length=50), nullable=False),
        sa.Column('threat_risk_score', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('evidence_confidence_score', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('compromised_account_likelihood', sa.String(length=50), nullable=True),
        sa.Column('spoofed_domain_likelihood', sa.String(length=50), nullable=True),
        sa.Column('anonymized_infrastructure_likelihood', sa.String(length=50), nullable=True),
        sa.Column('malicious_environment_likelihood', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_email_analysis_email_id', 'email_analysis', ['email_id'])

    op.create_table(
        'analysis_findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('analysis_run_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('analysis_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_analysis_findings_email_id', 'analysis_findings', ['email_id'])

    # 8. Email DNA, Similarity & Vector Embeddings
    op.create_table(
        'email_dna_profiles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('content_fingerprint', sa.JSON(), nullable=True),
        sa.Column('technical_fingerprint', sa.JSON(), nullable=True),
        sa.Column('infrastructure_fingerprint', sa.JSON(), nullable=True),
        sa.Column('behavioral_fingerprint', sa.JSON(), nullable=True),
        sa.Column('temporal_fingerprint', sa.JSON(), nullable=True),
        sa.Column('dna_version', sa.String(length=50), nullable=False, server_default='1.0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'email_similarity_links',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('source_email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('related_email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('similarity_type', sa.String(length=50), nullable=False),
        sa.Column('similarity_score', sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_email_similarity_links_source_email_id', 'email_similarity_links', ['source_email_id'])

    op.create_table(
        'email_embeddings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('embedding_type', sa.String(length=50), nullable=False, server_default='EMAIL_CONTENT'),
        sa.Column('model_name', sa.String(length=100), nullable=False, server_default='all-MiniLM-L6-v2'),
        sa.Column('dimension', sa.Integer(), nullable=False, server_default='384'),
        sa.Column('embedding', Vector(384), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_email_embeddings_email_id', 'email_embeddings', ['email_id'])

    # 9. Campaign Intelligence Tables
    op.create_table(
        'campaigns',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('campaign_name', sa.String(length=255), nullable=True),
        sa.Column('campaign_status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('campaign_confidence', sa.Numeric(precision=5, scale=2), nullable=False, server_default='0.0'),
        sa.Column('threat_summary', sa.Text(), nullable=True),
        sa.Column('first_detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'campaign_memberships',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('campaigns.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('membership_confidence', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('membership_status', sa.String(length=50), nullable=False, server_default='CONFIRMED'),
        sa.Column('evidence_summary', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_campaign_memberships_campaign_id', 'campaign_memberships', ['campaign_id'])
    op.create_index('ix_campaign_memberships_email_id', 'campaign_memberships', ['email_id'])

    op.create_table(
        'campaign_evidence',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('campaigns.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('source_entity_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('target_entity_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_campaign_evidence_campaign_id', 'campaign_evidence', ['campaign_id'])

    op.create_table(
        'campaign_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('campaigns.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_campaign_events_campaign_id', 'campaign_events', ['campaign_id'])

    # 10. Unified Investigation Graph Tables
    op.create_table(
        'intel_entities',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('normalized_value', sa.Text(), nullable=False),
        sa.Column('display_value', sa.Text(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_intel_entities_entity_type', 'intel_entities', ['entity_type'])

    op.create_table(
        'intel_relationships',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('source_entity_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('intel_entities.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_entity_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('intel_entities.id', ondelete='CASCADE'), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_intel_relationships_source', 'intel_relationships', ['source_entity_id'])
    op.create_index('ix_intel_relationships_target', 'intel_relationships', ['target_entity_id'])

    # 11. Cases & Investigation Records
    op.create_table(
        'cases',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('case_number', sa.String(length=100), nullable=False, unique=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='OPEN'),
        sa.Column('priority', sa.String(length=50), nullable=False, server_default='MEDIUM'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('opened_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_cases_case_number', 'cases', ['case_number'])

    op.create_table(
        'case_emails',
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'case_campaigns',
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('campaigns.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'investigation_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('actor_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_type', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('action_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_investigation_actions_case_id', 'investigation_actions', ['case_id'])

    # 12. Reports
    op.create_table(
        'reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('report_type', sa.String(length=50), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='SET NULL'), nullable=True),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('campaigns.id', ondelete='SET NULL'), nullable=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='SET NULL'), nullable=True),
        sa.Column('evidence_object_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('evidence_objects.id', ondelete='SET NULL'), nullable=True),
        sa.Column('report_version', sa.String(length=50), nullable=False, server_default='1.0'),
        sa.Column('generated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('summary', sa.JSON(), nullable=True),
    )

    # 13. Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('actor_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_audit_logs_resource', 'audit_logs', ['resource_type', 'resource_id'])
    op.create_index('ix_audit_logs_occurred_at', 'audit_logs', ['occurred_at'])

    # 14. Retention & Privacy Tables
    op.create_table(
        'retention_policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('data_category', sa.String(length=50), nullable=False),
        sa.Column('retention_days', sa.Integer(), nullable=True),
        sa.Column('deletion_action', sa.String(length=50), nullable=False, server_default='DELETE'),
        sa.Column('active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'retention_assignments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('evidence_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('evidence_objects.id', ondelete='CASCADE'), nullable=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('retention_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('retain_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('hold_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'data_classifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('resource_type', sa.String(length=100), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('classification', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )

    op.create_table(
        'masking_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('data_type', sa.String(length=50), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE'), nullable=True),
        sa.Column('masking_strategy', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # 15. Threat Indicators & Sightings
    op.create_table(
        'threat_indicators',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('indicator_type', sa.String(length=50), nullable=False),
        sa.Column('normalized_value', sa.Text(), nullable=False),
        sa.Column('reputation', sa.String(length=50), nullable=True),
        sa.Column('confidence', sa.Numeric(precision=5, scale=2), nullable=False, server_default='0.0'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_threat_indicators_type', 'threat_indicators', ['indicator_type'])

    op.create_table(
        'indicator_sightings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('indicator_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('threat_indicators.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=True),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('campaigns.id', ondelete='CASCADE'), nullable=True),
        sa.Column('evidence_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('evidence_objects.id', ondelete='CASCADE'), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('context', sa.JSON(), nullable=True),
    )
    op.create_index('ix_indicator_sightings_indicator_id', 'indicator_sightings', ['indicator_id'])

    # 16. Integrations (OAuth & Extension)
    op.create_table(
        'oauth_connections',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('provider_account_id', sa.String(length=255), nullable=False),
        sa.Column('granted_scopes', sa.JSON(), nullable=True),
        sa.Column('token_reference', sa.Text(), nullable=False),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('connected_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_oauth_connections_user_id', 'oauth_connections', ['user_id'])

    op.create_table(
        'extension_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='SET NULL'), nullable=True),
        sa.Column('provider', sa.String(length=50), nullable=True),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('analysis_mode', sa.String(length=50), nullable=False, server_default='VISIBLE_DATA_ONLY'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    # Drop all created tables in reverse dependency order
    op.drop_table('extension_events')
    op.drop_table('oauth_connections')
    op.drop_table('indicator_sightings')
    op.drop_table('threat_indicators')
    op.drop_table('masking_rules')
    op.drop_table('data_classifications')
    op.drop_table('retention_assignments')
    op.drop_table('retention_policies')
    op.drop_table('audit_logs')
    op.drop_table('reports')
    op.drop_table('investigation_actions')
    op.drop_table('case_campaigns')
    op.drop_table('case_emails')
    op.drop_table('cases')
    op.drop_table('intel_relationships')
    op.drop_table('intel_entities')
    op.drop_table('campaign_events')
    op.drop_table('campaign_evidence')
    op.drop_table('campaign_memberships')
    op.drop_table('campaigns')
    op.drop_table('email_embeddings')
    op.drop_table('email_similarity_links')
    op.drop_table('email_dna_profiles')
    op.drop_table('analysis_findings')
    op.drop_table('email_analysis')
    op.drop_table('analysis_runs')
    op.drop_table('entity_geolocations')
    op.drop_table('geolocations')
    op.drop_table('infrastructure_classifications')
    op.drop_table('ip_intelligence')
    op.drop_table('ip_addresses')
    op.drop_table('email_urls')
    op.drop_table('urls')
    op.drop_table('domain_registration_intel')
    op.drop_table('domain_dns_records')
    op.drop_table('domains')
    op.drop_table('custody_events')
    op.drop_table('evidence_objects')
    op.drop_table('relay_hops')
    op.drop_table('email_authentication_results')
    op.drop_table('email_recipients')
    op.drop_table('email_headers')
    op.drop_table('emails')
    op.drop_table('email_sources')
    op.drop_table('organization_members')
    op.drop_table('role_permissions')
    op.drop_table('permissions')
    op.drop_table('roles')
    op.drop_table('organizations')
    op.drop_table('users')
