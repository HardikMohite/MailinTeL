import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PlatformAdminView } from './PlatformAdminView';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';

vi.mock('../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../services/api', async () => {
  const actual = await vi.importActual<typeof import('../services/api')>('../services/api');
  return {
    ...actual,
    listPlatformOrganizations: vi.fn(),
    listPlatformUsers: vi.fn(),
    listPlatformAuditLog: vi.fn(),
    createPlatformOrganization: vi.fn(),
    invitePlatformUser: vi.fn(),
    updatePlatformUserRole: vi.fn(),
    deactivatePlatformUser: vi.fn(),
    listEmails: vi.fn(),
    getEvidenceDownloadUrl: vi.fn(),
  };
});

const mockedUseAuth = vi.mocked(useAuth);

function mockAuthFor(role: string) {
  mockedUseAuth.mockReturnValue({
    user: { id: 'u1', email: 'admin@test.com', full_name: null, organization_id: null, organization_name: null, role },
    isCrossOrg: () => role === 'CYBER_CELL_INVESTIGATOR' || role === 'SYSTEM_ADMIN',
    isAdmin: () => role === 'INSTITUTION_ADMIN' || role === 'SYSTEM_ADMIN',
    accessToken: null,
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
}

beforeEach(() => {
  vi.mocked(api.listPlatformOrganizations).mockResolvedValue([
    { id: 'org-1', name: 'Org One', organization_type: 'ENTERPRISE', status: 'ACTIVE', created_at: new Date().toISOString() },
  ]);
  vi.mocked(api.listPlatformUsers).mockResolvedValue([]);
  vi.mocked(api.listPlatformAuditLog).mockResolvedValue([]);
  vi.mocked(api.listEmails).mockResolvedValue({ total: 0, items: [] });
});

describe('PlatformAdminView — access gating', () => {
  it('renders the full admin UI for SYSTEM_ADMIN', async () => {
    mockAuthFor('SYSTEM_ADMIN');
    render(<PlatformAdminView />);
    expect(await screen.findByText('Platform Administration')).toBeInTheDocument();
    expect(screen.getByText('Users & Access')).toBeInTheDocument();
    expect(screen.getByText('Organizations (1)')).toBeInTheDocument();
    expect(screen.queryByText('Audit log')).not.toBeInTheDocument();
  });

  it('does not render the admin UI for CYBER_CELL_INVESTIGATOR', () => {
    mockAuthFor('CYBER_CELL_INVESTIGATOR');
    render(<PlatformAdminView />);
    expect(screen.queryByText('Users across organizations')).not.toBeInTheDocument();
    expect(screen.getByText(/only available to System Administrators/i)).toBeInTheDocument();
  });

  it('does not render the admin UI for INSTITUTION_ADMIN', () => {
    mockAuthFor('INSTITUTION_ADMIN');
    render(<PlatformAdminView />);
    expect(screen.queryByText('Users across organizations')).not.toBeInTheDocument();
    expect(screen.getByText(/only available to System Administrators/i)).toBeInTheDocument();
  });
});

describe('PlatformAdminView — invite role dropdown', () => {
  it('offers CYBER_CELL_INVESTIGATOR and SYSTEM_ADMIN alongside the org-scoped roles', async () => {
    mockAuthFor('SYSTEM_ADMIN');
    const user = userEvent.setup();
    render(<PlatformAdminView />);

    const usersTab = await screen.findByRole('button', { name: /users & access/i });
    await user.click(usersTab);
    await user.click(screen.getByRole('button', { name: /invite user/i }));

    // TeamView/PlatformAdminView don't associate <label> with <select> via
    // htmlFor, so fall back to DOM adjacency rather than getByLabelText.
    const roleSelect = screen.getByText('Role').nextElementSibling as HTMLSelectElement;
    const optionValues = Array.from(roleSelect.options).map((o) => o.value);

    expect(optionValues).toContain('CYBER_CELL_INVESTIGATOR');
    expect(optionValues).toContain('SYSTEM_ADMIN');
    expect(optionValues).toContain('INSTITUTION_ADMIN');
    expect(optionValues).toContain('SECURITY_ANALYST');
    expect(optionValues).toContain('USER');
  });
});

describe('PlatformAdminView — phishing-only triage queue', () => {
  it('requests threat_only=true and strictly filters out safe/normal emails from the triage table', async () => {
    mockAuthFor('SYSTEM_ADMIN');
    const user = userEvent.setup();
    vi.mocked(api.listEmails).mockResolvedValue({
      total: 2,
      items: [
        {
          id: 'email-1',
          source_type: 'FILE_UPLOAD',
          subject: 'Critical Phishing Wire Fraud',
          sender_address: 'attacker@evil.com',
          sender_display_name: 'Evil Boss',
          analysis_status: 'COMPLETED',
          qualification_status: 'CRITICAL',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        } as any,
        {
          id: 'email-2',
          source_type: 'FILE_UPLOAD',
          subject: 'Safe Monthly Newsletter',
          sender_address: 'news@legit.com',
          sender_display_name: 'Legit Team',
          analysis_status: 'COMPLETED',
          qualification_status: 'NORMAL',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        } as any,
      ],
    });

    render(<PlatformAdminView />);

    const triageTab = await screen.findByRole('button', { name: /phishing triage/i });
    await user.click(triageTab);

    // Verify listEmails called with threatOnly = true (6th argument)
    expect(api.listEmails).toHaveBeenCalledWith(0, 100, undefined, undefined, undefined, true);

    // Threat email should be displayed
    expect(await screen.findByText('Critical Phishing Wire Fraud')).toBeInTheDocument();

    // Normal / safe email must NOT be displayed
    expect(screen.queryByText('Safe Monthly Newsletter')).not.toBeInTheDocument();

    // KPI cards must show threat-focused metrics and not "Normal / Benign"
    expect(screen.getByText('Total Phishing Threats')).toBeInTheDocument();
    expect(screen.getByText('Active Investigations')).toBeInTheDocument();
    expect(screen.queryByText('Normal / Benign')).not.toBeInTheDocument();
    expect(screen.queryByText('Clean verified emails')).not.toBeInTheDocument();

    // Threat verdict filter select should not have "Normal / Safe"
    const threatSelect = screen.getByDisplayValue('All Threat Verdicts') as HTMLSelectElement;
    const optionValues = Array.from(threatSelect.options).map((o) => o.value);
    expect(optionValues).not.toContain('NORMAL');
    expect(optionValues).toContain('CRITICAL');
    expect(optionValues).toContain('HIGH');
    expect(optionValues).toContain('SUSPICIOUS');
  });
});
