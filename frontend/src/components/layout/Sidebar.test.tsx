import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Sidebar } from './Sidebar';
import { useAuth } from '../../context/AuthContext';

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

const mockedUseAuth = vi.mocked(useAuth);

function mockAuthFor(role: string) {
  mockedUseAuth.mockReturnValue({
    user: { id: 'u1', email: 'x@test.com', full_name: null, organization_id: null, organization_name: null, role },
    isAdmin: () => role === 'INSTITUTION_ADMIN' || role === 'SYSTEM_ADMIN',
    isCrossOrg: () => role === 'CYBER_CELL_INVESTIGATOR' || role === 'SYSTEM_ADMIN',
    // Unused by Sidebar, but present on the real context shape.
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

describe('Sidebar — Platform Admin nav item', () => {
  it('is visible for SYSTEM_ADMIN', () => {
    mockAuthFor('SYSTEM_ADMIN');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);
    expect(screen.getByText('Platform Admin')).toBeInTheDocument();
  });

  it('is hidden for CYBER_CELL_INVESTIGATOR (cross-org, but not a platform admin)', () => {
    mockAuthFor('CYBER_CELL_INVESTIGATOR');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);
    expect(screen.queryByText('Platform Admin')).not.toBeInTheDocument();
  });

  it('is hidden for INSTITUTION_ADMIN', () => {
    mockAuthFor('INSTITUTION_ADMIN');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);
    expect(screen.queryByText('Platform Admin')).not.toBeInTheDocument();
  });

  it('is hidden for SECURITY_ANALYST', () => {
    mockAuthFor('SECURITY_ANALYST');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);
    expect(screen.queryByText('Platform Admin')).not.toBeInTheDocument();
  });

  it('is hidden for USER', () => {
    mockAuthFor('USER');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);
    expect(screen.queryByText('Platform Admin')).not.toBeInTheDocument();
  });
});
