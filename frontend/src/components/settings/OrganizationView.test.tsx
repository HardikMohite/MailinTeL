import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OrganizationView } from './OrganizationView';
import { useAuth } from '../../context/AuthContext';
import * as api from '../../services/api';

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../../services/api', async () => {
  const actual = await vi.importActual<typeof import('../../services/api')>('../../services/api');
  return {
    ...actual,
    listPlatformOrganizations: vi.fn(),
    getPlatformOrganization: vi.fn(),
    createPlatformOrganization: vi.fn(),
    deletePlatformOrganization: vi.fn(),
    updatePlatformOrganizationStatus: vi.fn(),
    assignOrganizationMember: vi.fn(),
    assignCompanyAdmin: vi.fn(),
    removeOrganizationMember: vi.fn(),
    listEligibleUsers: vi.fn(),
  };
});

const mockedUseAuth = vi.mocked(useAuth);

const mockOrganizations: api.OrganizationItem[] = [
  {
    id: 'org-111',
    name: 'MailIntel Security Operations',
    organization_type: 'ENTERPRISE',
    status: 'ACTIVE',
    created_at: '2026-01-15T00:00:00Z',
    company_admin: {
      id: 'admin-1',
      full_name: 'Lead SecOps Admin',
      email: 'secops.admin@mailintel.test',
    },
    member_count: 5,
  },
  {
    id: 'org-222',
    name: 'PhishVerse',
    organization_type: 'ENTERPRISE',
    status: 'ACTIVE',
    created_at: '2026-02-10T00:00:00Z',
    company_admin: null,
    member_count: 2,
  },
  {
    id: 'org-999',
    name: 'Personal Workspace',
    organization_type: 'PERSONAL',
    status: 'ACTIVE',
    created_at: '2026-03-01T00:00:00Z',
    company_admin: null,
    member_count: 1,
  },
];

const mockOrgDetail: api.OrganizationDetail = {
  id: 'org-111',
  name: 'MailIntel Security Operations',
  organization_type: 'ENTERPRISE',
  status: 'ACTIVE',
  created_at: '2026-01-15T00:00:00Z',
  updated_at: '2026-01-15T12:00:00Z',
  company_admin: {
    id: 'admin-1',
    full_name: 'Lead SecOps Admin',
    email: 'secops.admin@mailintel.test',
  },
  member_count: 2,
  members: [
    {
      id: 'admin-1',
      email: 'secops.admin@mailintel.test',
      full_name: 'Lead SecOps Admin',
      role: 'INSTITUTION_ADMIN',
      account_status: 'ACTIVE',
      membership_status: 'ACTIVE',
      created_at: '2026-01-15T00:00:00Z',
      last_login_at: null,
    },
    {
      id: 'analyst-2',
      email: 'analyst.two@mailintel.test',
      full_name: 'Jane Analyst',
      role: 'SECURITY_ANALYST',
      account_status: 'ACTIVE',
      membership_status: 'ACTIVE',
      created_at: '2026-02-01T00:00:00Z',
      last_login_at: null,
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
  mockedUseAuth.mockReturnValue({
    user: {
      id: 'platform-admin-id',
      email: 'platform.admin@mailintel.test',
      full_name: 'System Platform Admin',
      organization_id: null,
      organization_name: null,
      role: 'SYSTEM_ADMIN',
    },
    isCrossOrg: () => true,
    isAdmin: () => true,
    accessToken: 'test-token',
    isAuthenticated: true,
    isLoading: false,
    sessionMessage: null,
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    clearSessionMessage: vi.fn(),
    canInvite: vi.fn(),
    canManageRole: vi.fn(),
  } as any);

  vi.mocked(api.listPlatformOrganizations).mockResolvedValue(mockOrganizations);
  vi.mocked(api.getPlatformOrganization).mockResolvedValue(mockOrgDetail);
  vi.mocked(api.listEligibleUsers).mockResolvedValue([
    {
      id: 'user-3',
      email: 'eligible.user@mailintel.test',
      full_name: 'Eligible User',
      status: 'ACTIVE',
      created_at: '2026-02-15T00:00:00Z',
    },
  ]);
});

describe('OrganizationView — Platform Admin Organization Management', () => {
  it('renders dynamic organizations from database with Company Admin and member count', async () => {
    render(<OrganizationView />);

    expect(await screen.findByText('MailIntel Security Operations')).toBeInTheDocument();
    expect(screen.getByText('PhishVerse')).toBeInTheDocument();
    expect(screen.getByText('Lead SecOps Admin')).toBeInTheDocument();
    expect(screen.getByText('secops.admin@mailintel.test')).toBeInTheDocument();
    expect(screen.getByText('Unassigned')).toBeInTheDocument();
    expect(screen.queryByText('Personal Workspace')).not.toBeInTheDocument();
    expect(screen.getByText('Showing 2 of 2 organizations')).toBeInTheDocument();
  });

  it('drills down into organization details and shows members when an organization is clicked', async () => {
    const user = userEvent.setup();
    render(<OrganizationView />);

    const orgRow = await screen.findByText('MailIntel Security Operations');
    await user.click(orgRow);

    expect(await screen.findByText('Back to Organizations')).toBeInTheDocument();
    expect(screen.getByText('Organization Members')).toBeInTheDocument();
    expect(screen.getByText('Jane Analyst')).toBeInTheDocument();
    expect(screen.getAllByText('Company Admin').length).toBeGreaterThanOrEqual(1);
  });


  it('renders workspace profile when non-platform user views Organization', async () => {
    mockedUseAuth.mockReturnValue({
      user: {
        id: 'member-1',
        email: 'analyst@org.test',
        full_name: 'Regular Analyst',
        organization_id: 'org-111',
        organization_name: 'Target Org',
        role: 'SECURITY_ANALYST',
      },
      isCrossOrg: () => false,
      isAdmin: () => false,
      accessToken: 'token',
      isAuthenticated: true,
      isLoading: false,
      sessionMessage: null,
      login: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      clearSessionMessage: vi.fn(),
      canInvite: vi.fn(),
      canManageRole: vi.fn(),
    } as any);

    render(<OrganizationView />);

    expect(screen.getByText('Workspace profile, organizational governance, and identity parameters.')).toBeInTheDocument();
    expect(screen.queryByText('New organization')).not.toBeInTheDocument();
  });
});
