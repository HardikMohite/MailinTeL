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

describe('Sidebar — Admin Panel Information Architecture', () => {
  it('removes Email Investigation and displays Campaign in Investigation Operations for SYSTEM_ADMIN', () => {
    mockAuthFor('SYSTEM_ADMIN');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);

    // CHANGE 1: Email Investigation is removed from Admin Panel
    expect(screen.queryByText('Email Investigation')).not.toBeInTheDocument();

    // CHANGE 2 & 3: Campaign Clusters is renamed to exactly 'Campaign' and moved into Investigation Operations
    expect(screen.getByText('Campaign')).toBeInTheDocument();
    expect(screen.queryByText('Campaign Clusters')).not.toBeInTheDocument();

    // Verify other Investigation Operations items are present
    expect(screen.getByText('Analysis History')).toBeInTheDocument();
    expect(screen.getByText('Evidence Vault')).toBeInTheDocument();
    expect(screen.getByText('Forensic Reports')).toBeInTheDocument();

    // Verify Threat Intelligence items are present
    expect(screen.getByText('IOC Threat Intel')).toBeInTheDocument();
    expect(screen.getByText('Investigation Graph')).toBeInTheDocument();
    expect(screen.getByText('Geo Transmission Map')).toBeInTheDocument();
  });

  it('preserves Email Investigation and Campaign Clusters in analyst panel', () => {
    mockAuthFor('SECURITY_ANALYST');
    render(<Sidebar activeTab="dashboard" onTabChange={() => {}} />);

    // Preserved for analyst-facing workflow
    expect(screen.getByText('Email Investigation')).toBeInTheDocument();
    expect(screen.getByText('Campaign Clusters')).toBeInTheDocument();
  });
});

