import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { DashboardView } from './components/dashboard/DashboardView';
import { GeoIntelligenceMap } from './components/geo/GeoIntelligenceMap';
import { AnalysisWorkspace } from './components/workspace/AnalysisWorkspace';
import { CampaignView } from './components/campaigns/CampaignView';
import { InvestigationGraphView } from './components/graph/InvestigationGraphView';
import { AnalysisHistoryView } from './components/history/AnalysisHistoryView';
import { ThreatIntelView } from './components/intelligence/ThreatIntelView';
import { EvidenceVaultView } from './components/evidence/EvidenceVaultView';
import { ForensicReportView } from './components/reports/ForensicReportView';
import { SettingsView } from './components/settings/SettingsView';
import { TeamView } from './components/settings/TeamView';
import { OrganizationView } from './components/settings/OrganizationView';
import { PlatformAdminView } from './pages/PlatformAdminView';
import { useAuth } from './context/AuthContext';
import { checkHealth, checkDetailedHealth, HealthResponse, DetailedHealthResponse } from './services/api';
import { apiEvents } from './services/apiEvents';
import {
  ErrorBoundary,
  OfflineScreen,
  NotFoundScreen,
} from './components/errors';

export const App: React.FC = () => {
  const { user, isCrossOrg } = useAuth();
  const isPlatformAdmin = isCrossOrg() && user?.role === 'SYSTEM_ADMIN';
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [visitedTabs, setVisitedTabs] = useState<Set<NavTab>>(() => new Set<NavTab>(['dashboard']));

  useEffect(() => {
    setVisitedTabs((prev) => {
      if (prev.has(activeTab)) return prev;
      const next = new Set(prev);
      next.add(activeTab);
      return next;
    });
  }, [activeTab]);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [detailedHealth, setDetailedHealth] = useState<DetailedHealthResponse | null>(null);
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true);
  const [focalEmailId, setFocalEmailId] = useState<string>('');
  // Set by the axios interceptor on any request that gets no response at all
  // (backend unreachable, CORS rejection, timeout) — see services/api.ts.
  const [isOffline, setIsOffline] = useState<boolean>(false);
  // Session expiry (401 from any call, anywhere in the app) is handled by
  // AuthGate/AuthContext one level up — once a session goes invalid, AuthGate
  // unmounts <App/> entirely and shows LoginScreen with a "session expired"
  // message, so App itself doesn't need to track or react to it.

  const fetchHealthStatus = async () => {
    setLoadingHealth(true);
    try {
      // 1. Fetch basic liveness immediately so header status indicator turns green fast
      const basic = await checkHealth();
      setHealth(basic);
      setLoadingHealth(false);

      // 2. Fetch detailed diagnostics asynchronously in the background
      checkDetailedHealth().then((detailed) => {
        setDetailedHealth(detailed);
      }).catch((e) => {
        console.warn('Detailed health check notice:', e?.message);
      });
    } catch (err) {
      console.error('Failed to fetch backend health status:', err);
      setHealth(null);
      setDetailedHealth(null);
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    fetchHealthStatus();

    // Keepalive heartbeat: ping backend health periodically when tab is active
    // to prevent Render free-tier cloud instances from spinning down during active sessions.
    const keepAliveInterval = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
        checkHealth().catch(() => {});
      }
    }, 4 * 60 * 1000); // every 4 minutes

    return () => clearInterval(keepAliveInterval);
  }, []);

  // Global network-failure handling: triggered when browser connectivity is genuinely lost.
  // OfflineScreen polls checkHealth and calls handleBackOnline the moment connection is restored.
  useEffect(() => {
    return apiEvents.on('network-error', () => setIsOffline(true));
  }, []);

  const handleBackOnline = useCallback(() => {
    setIsOffline(false);
    fetchHealthStatus();
  }, []);


  const handleInspectEmailInWorkspace = (emailId: string) => {
    setFocalEmailId(emailId);
    setActiveTab('history');
  };

  const handleOpenReportForEmail = (emailId: string) => {
    setFocalEmailId(emailId);
    setActiveTab('reports');
  };

  const TAB_META: Record<NavTab, { title: string; breadcrumb: string[] }> = {
    dashboard: { title: 'Dashboard', breadcrumb: ['MailinteL'] },
    analyze: { title: 'Analyze Email', breadcrumb: ['MailinteL', 'Main'] },
    history: { title: 'Analysis History', breadcrumb: ['MailinteL', 'Main'] },
    intelligence: { title: 'Threat Intel', breadcrumb: ['MailinteL', 'Email Intelligence'] },
    campaigns: { title: 'Campaigns', breadcrumb: ['MailinteL', 'Email Intelligence'] },
    graph: { title: 'Investigation Graph', breadcrumb: ['MailinteL', 'Email Intelligence'] },
    geo: { title: 'Geo Intelligence', breadcrumb: ['MailinteL', 'Email Intelligence'] },
    evidence: { title: 'Evidence Vault', breadcrumb: ['MailinteL', 'Forensic Management'] },
    reports: { title: 'Reports', breadcrumb: ['MailinteL', 'Forensic Management'] },
    team: { title: 'Team & Access', breadcrumb: ['MailinteL', 'Forensic Management'] },
    organization: { title: 'Organization', breadcrumb: ['MailinteL', 'Governance & Access'] },
    settings: { title: 'Settings', breadcrumb: ['MailinteL', 'Forensic Management'] },
    'platform-admin': { title: 'Platform Administration', breadcrumb: ['MailinteL', 'Platform Administration'] },
  };

  // Maps each breadcrumb segment label to the tab it should navigate to when clicked.
  const BREADCRUMB_NAV: Record<string, NavTab> = {
    'MailinteL': 'dashboard',
    'Main': 'dashboard',
    'Email Intelligence': 'intelligence',
    'Forensic Management': 'evidence',
    'Platform Administration': 'platform-admin',
  };

  const handleBreadcrumbClick = (crumb: string) => {
    const target = BREADCRUMB_NAV[crumb];
    if (target) setActiveTab(target);
  };

  const KNOWN_TABS = Object.keys(TAB_META);
  // Defensive: activeTab is typed as NavTab today, but this guards against a
  // future tab being added to the sidebar/state without a matching branch
  // below (or any other way an unrecognized value ends up here).
  const isKnownTab = KNOWN_TABS.includes(activeTab as string);

  return (
    <div className="flex min-h-screen bg-workspace">
      {/* Sidebar Navigation */}
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header
          health={health}
          loading={loadingHealth}
          onRefreshHealth={fetchHealthStatus}
          title={isKnownTab ? TAB_META[activeTab].title : 'Not Found'}
          breadcrumb={isKnownTab ? TAB_META[activeTab].breadcrumb : ['MailinteL']}
          onBreadcrumbClick={handleBreadcrumbClick}
          onNavigateToSettings={() => setActiveTab('settings')}
        />

        <main className="flex-1 p-8 overflow-y-auto space-y-6">
        <ErrorBoundary>
          {isOffline ? (
            <OfflineScreen onBackOnline={handleBackOnline} />
          ) : !isKnownTab ? (
            <NotFoundScreen onGoBack={() => setActiveTab('dashboard')} />
          ) : (
          <>
          {/* Tab Content Views with instant keep-alive preservation */}
          {visitedTabs.has('dashboard') && (
            <div className={activeTab === 'dashboard' ? 'block' : 'hidden'}>
              {isPlatformAdmin ? (
                <PlatformAdminView
                  onSelectEmail={handleInspectEmailInWorkspace}
                  onOpenReport={handleOpenReportForEmail}
                  onAnalyze={() => setActiveTab('analyze')}
                  onExploreGraph={() => setActiveTab('graph')}
                />
              ) : (
                <DashboardView
                  onAnalyze={() => setActiveTab('analyze')}
                  onExploreGraph={() => setActiveTab('graph')}
                  onSelectEmail={handleInspectEmailInWorkspace}
                />
              )}
            </div>
          )}

          {/* Analyze Email Tab / Email Investigation Workspace (Dedicated Uploadation Page) */}
          {visitedTabs.has('analyze') && (
            <div className={activeTab === 'analyze' ? 'block' : 'hidden'}>
              <AnalysisWorkspace
                onOpenReport={handleOpenReportForEmail}
                onExploreGeo={(emailId) => {
                  setFocalEmailId(emailId);
                  setActiveTab('geo');
                }}
                onExploreGraph={(emailId) => {
                  setFocalEmailId(emailId);
                  setActiveTab('graph');
                }}
                onExploreEvidence={(emailId: string) => {
                  setFocalEmailId(emailId);
                  setActiveTab('evidence');
                }}
              />
            </div>
          )}

          {/* Analysis History Tab (Stored Forensic Dossiers & Stack View) */}
          {visitedTabs.has('history') && (
            <div className={activeTab === 'history' ? 'block' : 'hidden'}>
              <AnalysisHistoryView
                initialEmailId={focalEmailId}
                onOpenReport={handleOpenReportForEmail}
                onExploreGeo={(emailId) => {
                  setFocalEmailId(emailId);
                  setActiveTab('geo');
                }}
                onExploreGraph={(emailId) => {
                  setFocalEmailId(emailId);
                  setActiveTab('graph');
                }}
                onNavigateToAnalyze={() => setActiveTab('analyze')}
              />
            </div>
          )}

          {/* Threat Intelligence Tab */}
          {visitedTabs.has('intelligence') && (
            <div className={activeTab === 'intelligence' ? 'block' : 'hidden'}>
              <ThreatIntelView />
            </div>
          )}

          {/* Campaigns Tab */}
          {visitedTabs.has('campaigns') && (
            <div className={activeTab === 'campaigns' ? 'block' : 'hidden'}>
              <CampaignView onSelectEmail={handleInspectEmailInWorkspace} />
            </div>
          )}

          {/* Investigation Graph Tab */}
          {visitedTabs.has('graph') && (
            <div className={activeTab === 'graph' ? 'block' : 'hidden'}>
              <InvestigationGraphView
                initialEmailId={focalEmailId}
                onSelectEmail={handleInspectEmailInWorkspace}
              />
            </div>
          )}

          {/* Geo Intelligence Tab */}
          {visitedTabs.has('geo') && (
            <div className={activeTab === 'geo' ? 'block' : 'hidden'}>
              <GeoIntelligenceMap initialEmailId={focalEmailId} />
            </div>
          )}

          {/* Evidence Vault Tab */}
          {visitedTabs.has('evidence') && (
            <div className={activeTab === 'evidence' ? 'block' : 'hidden'}>
              <EvidenceVaultView onSelectEmail={handleInspectEmailInWorkspace} />
            </div>
          )}

          {/* Forensic Reports Tab */}
          {visitedTabs.has('reports') && (
            <div className={activeTab === 'reports' ? 'block' : 'hidden'}>
              <ForensicReportView initialEmailId={focalEmailId} />
            </div>
          )}

          {/* Team & Access Tab */}
          {visitedTabs.has('team') && (
            <div className={activeTab === 'team' ? 'block' : 'hidden'}>
              <TeamView />
            </div>
          )}

          {/* Organization Tab */}
          {visitedTabs.has('organization') && (
            <div className={activeTab === 'organization' ? 'block' : 'hidden'}>
              <OrganizationView />
            </div>
          )}

          {/* Platform Administration Tab */}
          {visitedTabs.has('platform-admin') && (
            <div className={activeTab === 'platform-admin' ? 'block' : 'hidden'}>
              <PlatformAdminView
                onSelectEmail={handleInspectEmailInWorkspace}
                onOpenReport={handleOpenReportForEmail}
              />
            </div>
          )}

          {/* Settings Tab */}
          {visitedTabs.has('settings') && (
            <div className={activeTab === 'settings' ? 'block' : 'hidden'}>
              <SettingsView
                health={health}
                detailedHealth={detailedHealth}
                loading={loadingHealth}
                onRefreshHealth={fetchHealthStatus}
              />
            </div>
          )}
          </>
          )}
        </ErrorBoundary>
        </main>
      </div>
    </div>
  );
};
export default App;
