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
  UserCheck,
  Building2,
  ExternalLink,
} from 'lucide-react';
import { BrandLogo } from '../common/BrandLogo';
import { useAuth } from '../../context/AuthContext';

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
  const canManageTeam = (isAdmin() && !isCrossOrg()) || user?.role === 'SYSTEM_ADMIN';
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
          ],
        },
        {
          title: 'Investigation Operations',
          items: [
            { id: 'history', label: 'Analysis History', icon: History },
            { id: 'graph' as const, label: 'Investigation Graph', icon: Network },
            { id: 'evidence', label: 'Evidence Vault', icon: FolderLock },
            { id: 'reports', label: 'Forensic Reports', icon: FileText },
          ],
        },
        {
          title: 'Threat Intelligence Services',
          items: [
            { id: 'intelligence', label: 'IOC Threat Intel', icon: ShieldAlert },
            { id: 'campaigns', label: 'Campaign Clusters', icon: Flag },
            { id: 'geo', label: 'Geo Transmission Map', icon: Globe },
          ],
        },
        {
          title: 'Governance & Access',
          items: [
            ...(canManageTeam ? [{ id: 'team' as const, label: 'Team & Access', icon: UserCheck }] : []),
            { id: 'organization' as const, label: 'Organization', icon: Building2 },
            { id: 'settings', label: 'Settings', icon: Settings },
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
            { id: 'graph' as const, label: 'Investigation Graph', icon: Network },
            { id: 'evidence', label: 'Evidence Vault', icon: FolderLock },
            { id: 'reports', label: 'Forensic Reports', icon: FileText },
          ],
        },
        {
          title: 'Threat Intelligence Services',
          items: [
            { id: 'intelligence', label: 'IOC Threat Intel', icon: ShieldAlert },
            { id: 'campaigns', label: 'Campaign Clusters', icon: Flag },
            { id: 'geo', label: 'Geo Transmission Map', icon: Globe },
          ],
        },
        {
          title: 'Settings & Administration',
          items: [
            ...(canManageTeam ? [{ id: 'team' as const, label: 'Team & Access', icon: UserCheck }] : []),
            ...(canManageTeam ? [{ id: 'organization' as const, label: 'Organization', icon: Building2 }] : []),
            { id: 'settings', label: 'Settings', icon: Settings },
          ],
        },
      ];

  return (
    <aside className="w-[240px] bg-white text-slate-800 flex flex-col h-screen sticky top-0 border-r border-slate-200/90 select-none z-20 shrink-0 shadow-[1px_0_4px_rgba(0,0,0,0.02)]">
      {/* Brand */}
      <div className="h-16 flex items-center px-4 border-b border-slate-100 shrink-0 bg-white">
        <BrandLogo variant="sidebar" surface="light" onClick={() => onTabChange('dashboard')} />
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
        {sections.map((section) => (
          <div key={section.title}>
            <div className="px-2.5 mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
              {section.title}
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onTabChange(item.id)}
                    className={`relative w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-[13px] transition-all group ${
                      isActive
                        ? 'bg-blue-600 text-white font-semibold shadow-md shadow-blue-500/25'
                        : 'text-slate-600 hover:bg-blue-50/70 hover:text-blue-700 font-medium'
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 transition-transform ${isActive ? 'scale-105 text-white' : 'text-slate-400 group-hover:text-blue-600 group-hover:scale-105'}`} />
                    <span className="truncate flex-1 text-left">{item.label}</span>
                    {item.badge && (
                      <span className={`text-[9.5px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-md ${
                        isActive 
                          ? 'bg-blue-700/60 text-blue-100 border border-blue-400/30'
                          : 'bg-slate-100 text-slate-500 border border-slate-200'
                      }`}>
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
      <div className="p-3 border-t border-slate-100 shrink-0 bg-white">
        <div className="rounded-xl bg-gradient-to-br from-blue-50/90 to-indigo-50/50 border border-blue-100 px-3 py-2.5">
          <div className="flex items-center gap-2 text-[11px] font-bold text-blue-950">
            <span className="relative flex h-2 w-2">
              <span className="beacon-pulse absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            <span>Security Engine Live</span>
          </div>
          <p className="text-[10.5px] text-slate-500 leading-snug mt-1">
            Forensic intelligence & RBAC active.
          </p>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="mt-2 inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:text-blue-700 transition-colors"
          >
            API Documentation <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
    </aside>
  );
};
export default Sidebar;
