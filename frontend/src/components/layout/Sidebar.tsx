import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  History,
  ShieldAlert,
  Flag,
  Network,
  Globe,
  FolderLock,
  FileText,
  Settings,
  Users,
  UserCheck,
  Building2,
  ShieldCheck,
  ExternalLink,
} from 'lucide-react';
import { BrandLogo } from '../common/BrandLogo';
import { useAuth } from '../../context/AuthContext';

// Roles that keep organization-wide visibility on the backend (see
// app.api.deps.ANALYST_ROLES): SECURITY_ANALYST, CYBER_CELL_INVESTIGATOR,
// INSTITUTION_ADMIN, SYSTEM_ADMIN. A plain "USER" account is scoped down to
// its own uploads/campaigns and gets a 403 from the correlation graph and
// the team roster — those nav items are hidden for that role so the UI
// doesn't dangle links that always error out.
const ANALYST_AND_UP_ROLES = ['SECURITY_ANALYST', 'CYBER_CELL_INVESTIGATOR', 'INSTITUTION_ADMIN', 'SYSTEM_ADMIN'];

export type NavTab =
  | 'dashboard'
  | 'analyze'
  | 'history'
  | 'intelligence'
  | 'campaigns'
  | 'graph'
  | 'geo'
  | 'evidence'
  | 'reports'
  | 'team'
  | 'users'
  | 'organization'
  | 'settings'
  | 'platform-admin';

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
}

interface NavSection {
  title: string;
  items: {
    id: NavTab;
    label: string;
    icon: React.ElementType;
    badge?: string;
  }[];
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onTabChange }) => {
  const { user, isAdmin, isCrossOrg } = useAuth();
  const isAnalystAndUp = !!user?.role && ANALYST_AND_UP_ROLES.includes(user.role);
  const canManageTeam = isAdmin() && !isCrossOrg() || user?.role === 'SYSTEM_ADMIN';
  // Cross-org /platform/* administration (org creation, cross-org
  // invite/role-change/deactivate, audit log) is SYSTEM_ADMIN only — a
  // narrower gate than isCrossOrg() alone, which also covers
  // CYBER_CELL_INVESTIGATOR. Reuses the existing AuthContext helper rather
  // than re-deriving cross-org membership here.
  const canAccessPlatformAdmin = isCrossOrg() && user?.role === 'SYSTEM_ADMIN';

  const sections: NavSection[] = canAccessPlatformAdmin
    ? [
        {
          title: 'Admin Command',
          items: [
            { id: 'dashboard', label: 'Admin Dashboard', icon: LayoutDashboard },
            { id: 'platform-admin' as const, label: 'Platform Admin', icon: ShieldCheck, badge: 'Lead' },
          ],
        },
        {
          title: 'Investigation Operations',
          items: [
            { id: 'history', label: 'Analysis History', icon: History },
            { id: 'campaigns', label: 'Campaign', icon: Flag },
            { id: 'evidence', label: 'Evidence Vault', icon: FolderLock },
            { id: 'reports', label: 'Forensic Reports', icon: FileText },
          ],
        },
        {
          title: 'Threat Intelligence',
          items: [
            { id: 'intelligence', label: 'IOC Threat Intel', icon: ShieldAlert },
            { id: 'graph' as const, label: 'Investigation Graph', icon: Network },
            { id: 'geo', label: 'Geo Transmission Map', icon: Globe },
          ],
        },
        {
          title: 'Governance & Access',
          items: [
            ...(canManageTeam ? [{ id: 'users' as const, label: 'User Panel', icon: Users }] : []),
            { id: 'organization' as const, label: 'Organization', icon: Building2 },
            ...(canManageTeam ? [{ id: 'team' as const, label: 'Team & Access', icon: UserCheck }] : []),
            { id: 'settings', label: 'Settings', icon: Settings, badge: 'Planned' },
          ],
        },
      ]
    : [
        {
          title: 'Investigation Operations',
          items: [
            { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
            { id: 'analyze', label: 'Email Investigation', icon: UploadCloud },
            { id: 'history', label: 'Analysis History', icon: History },
          ],
        },
        {
          title: 'Threat Intelligence',
          items: [
            { id: 'intelligence', label: 'IOC Threat Intel', icon: ShieldAlert },
            { id: 'campaigns', label: 'Campaign Clusters', icon: Flag },
            ...(isAnalystAndUp ? [{ id: 'graph' as const, label: 'Investigation Graph', icon: Network }] : []),
            { id: 'geo', label: 'Geo Transmission Map', icon: Globe },
          ],
        },
        {
          title: 'Forensic Management',
          items: [
            { id: 'evidence', label: 'Evidence Vault', icon: FolderLock },
            { id: 'reports', label: 'Forensic Reports', icon: FileText },
            ...(canManageTeam ? [{ id: 'users' as const, label: 'User Panel', icon: Users }] : []),
            ...(canManageTeam ? [{ id: 'organization' as const, label: 'Organization', icon: Building2 }] : []),
            ...(canManageTeam ? [{ id: 'team' as const, label: 'Team & Access', icon: UserCheck }] : []),
            { id: 'settings', label: 'Settings', icon: Settings, badge: 'Planned' },
          ],
        },
      ];

  return (
    <aside className="w-[232px] bg-navy-sidebar text-text-dark flex flex-col h-screen sticky top-0 border-r border-navy-border select-none z-20 shrink-0">
      {/* Brand */}
      <div className="h-16 flex items-center px-4 border-b border-navy-border shrink-0">
        <BrandLogo variant="sidebar" onClick={() => onTabChange('dashboard')} />
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto scrollbar-dark px-3 py-4 space-y-5">
        {sections.map((section) => (
          <div key={section.title}>
            <div className="px-2.5 mb-1.5 text-[10.5px] font-semibold uppercase tracking-wider text-slate-500">
              {section.title}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onTabChange(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-colors ${
                      isActive
                        ? 'bg-brand text-white'
                        : 'text-slate-300 hover:bg-navy-elevated hover:text-white'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span className="truncate flex-1 text-left">{item.label}</span>
                    {item.badge && (
                      <span className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-navy-elevated text-slate-400 border border-navy-border">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-navy-border shrink-0">
        <div className="rounded-lg bg-navy-deep border border-navy-border px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            MVP — Phase 9
          </div>
          <p className="text-[10.5px] text-slate-500 leading-snug mt-1">
            Authentication and role-based access control are live.
          </p>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="mt-2 flex items-center gap-1 text-[10.5px] font-medium text-sky-400 hover:text-sky-300"
          >
            API Docs <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
    </aside>
  );
};
export default Sidebar;
