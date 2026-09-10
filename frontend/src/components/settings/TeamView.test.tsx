import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TeamView } from './TeamView';
import { useAuth } from '../../context/AuthContext';
import * as api from '../../services/api';

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../../services/api', async () => {
  const actual = await vi.importActual<typeof import('../../services/api')>('../../services/api');
  return {
    ...actual,
    listOrgMembers: vi.fn(),
    inviteOrgMember: vi.fn(),
    updateOrgMemberRole: vi.fn(),
    deactivateOrgMember: vi.fn(),
  };
});

const mockedUseAuth = vi.mocked(useAuth);

beforeEach(() => {
  mockedUseAuth.mockReturnValue({
    user: { id: 'admin-1', email: 'admin@org.test', full_name: null, organization_id: 'org-1', organization_name: 'Org', role: 'INSTITUTION_ADMIN' },
    isCrossOrg: () => false,
    isAdmin: () => true,
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
  vi.mocked(api.listOrgMembers).mockResolvedValue([]);
});

describe('TeamView — org-scoped invite dropdown', () => {
  it('does NOT offer CYBER_CELL_INVESTIGATOR or SYSTEM_ADMIN', async () => {
    const user = userEvent.setup();
    render(<TeamView />);

    await user.click(await screen.findByRole('button', { name: /invite/i }));

    // <label> isn't associated with <select> via htmlFor here, so fall back
    // to DOM adjacency rather than getByLabelText.
    const roleSelect = screen.getByText('Role').nextElementSibling as HTMLSelectElement;
    const optionValues = Array.from(roleSelect.options).map((o) => o.value);

    expect(optionValues).not.toContain('CYBER_CELL_INVESTIGATOR');
    expect(optionValues).not.toContain('SYSTEM_ADMIN');
    expect(optionValues).not.toContain('INSTITUTION_ADMIN');
    // Sanity: only SECURITY_ANALYST and USER are assignable by org admin
    expect(optionValues).toContain('SECURITY_ANALYST');
    expect(optionValues).toContain('USER');
  });
});
