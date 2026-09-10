import React, { useEffect, useState } from 'react';
import { listPlatformOrganizations, OrganizationItem } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

const STORAGE_KEY = 'mailintel.organization_filter';

export const OrganizationSwitcher: React.FC = () => {
  const { isCrossOrg } = useAuth();
  const [organizations, setOrganizations] = useState<OrganizationItem[]>([]);
  const [value, setValue] = useState(() => localStorage.getItem(STORAGE_KEY) || '');

  useEffect(() => {
    if (!isCrossOrg()) return;
    listPlatformOrganizations().then(setOrganizations).catch(() => setOrganizations([]));
  }, [isCrossOrg]);

  if (!isCrossOrg()) return null;
  const update = (next: string) => {
    setValue(next);
    if (next) localStorage.setItem(STORAGE_KEY, next);
    else localStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new CustomEvent('mailintel:organization-filter', { detail: next || null }));
  };

  return (
    <label className="hidden xl:flex items-center gap-2 text-[12px] text-text-muted">
      <span>Organization</span>
      <select value={value} onChange={(event) => update(event.target.value)} className="max-w-44 px-2 py-1.5 bg-workspace border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/25">
        <option value="">All organizations</option>
        {organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
      </select>
    </label>
  );
};

export default OrganizationSwitcher;
