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
});

describe('PlatformAdminView — access gating', () => {
  it('renders the full admin UI for SYSTEM_ADMIN', async () => {
    mockAuthFor('SYSTEM_ADMIN');
    render(<PlatformAdminView />);
    expect(await screen.findByText('Platform Administration')).toBeInTheDocument();
    expect(screen.getByText('Users across organizations')).toBeInTheDocument();
    expect(screen.getByText('Audit log')).toBeInTheDocument();
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

    const usersTab = await screen.findByRole('button', { name: /users across organizations/i });
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
