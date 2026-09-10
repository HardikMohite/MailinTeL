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
import { checkHealth, checkDetailedHealth, HealthResponse, DetailedHealthResponse } from './services/api';
import { apiEvents } from './services/apiEvents';
import {
  ErrorBoundary,
  OfflineScreen,
  NotFoundScreen,
} from './components/errors';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
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
  }, []);

  // Global network-failure handling: any apiClient call that gets no
  // response at all flips the app into OfflineScreen. OfflineScreen itself
  // polls checkHealth and calls this back the moment the backend answers.
  useEffect(() => {
    return apiEvents.on('network-error', () => setIsOffline(true));
  }, []);

  const handleBackOnline = useCallback(() => {
    setIsOffline(false);
    fetchHealthStatus();
  }, []);

  const handleInspectEmailInWorkspace = (emailId: string) => {
    setFocalEmailId(emailId);
    setActiveTab('analyze');
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
        />

        <main className="flex-1 p-8 overflow-y-auto space-y-6">
        <ErrorBoundary>
          {isOffline ? (
            <OfflineScreen onBackOnline={handleBackOnline} />
          ) : !isKnownTab ? (
            <NotFoundScreen onGoBack={() => setActiveTab('dashboard')} />
          ) : (
          <>
          {/* Tab Content Views */}
          {activeTab === 'dashboard' && (
            <DashboardView
              onAnalyze={() => setActiveTab('analyze')}
              onExploreGraph={() => setActiveTab('graph')}
              onSelectEmail={handleInspectEmailInWorkspace}
            />
          )}
          {/* Analyze Email Tab / Investigation Workspace */}
          {activeTab === 'analyze' && (
            <AnalysisWorkspace
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
              onExploreEvidence={(emailId) => {
                setFocalEmailId(emailId);
                setActiveTab('evidence');
              }}
            />
          )}

          {/* Analysis History Tab */}
          {activeTab === 'history' && (
            <AnalysisHistoryView
              onSelectEmail={handleInspectEmailInWorkspace}
              onOpenReport={handleOpenReportForEmail}
            />
          )}

          {/* Threat Intelligence Tab */}
          {activeTab === 'intelligence' && <ThreatIntelView />}

          {/* Campaigns Tab */}
          {activeTab === 'campaigns' && (
            <CampaignView onSelectEmail={handleInspectEmailInWorkspace} />
          )}

          {/* Investigation Graph Tab */}
          {activeTab === 'graph' && (
            <InvestigationGraphView
              initialEmailId={focalEmailId}
              onSelectEmail={handleInspectEmailInWorkspace}
            />
          )}

          {/* Geo Intelligence Tab */}
          {activeTab === 'geo' && <GeoIntelligenceMap initialEmailId={focalEmailId} />}

          {/* Evidence Vault Tab */}
          {activeTab === 'evidence' && (
            <EvidenceVaultView onSelectEmail={handleInspectEmailInWorkspace} />
          )}

          {/* Forensic Reports Tab */}
          {activeTab === 'reports' && <ForensicReportView initialEmailId={focalEmailId} />}

          {/* Team & Access Tab */}
          {activeTab === 'team' && <TeamView />}

          {/* Organization Tab */}
          {activeTab === 'organization' && <OrganizationView />}

          {/* Platform Administration Tab */}
          {activeTab === 'platform-admin' && (
            <PlatformAdminView
              onSelectEmail={handleInspectEmailInWorkspace}
              onOpenReport={handleOpenReportForEmail}
            />
          )}

          {/* Settings Tab */}
          {activeTab === 'settings' && (
            <SettingsView
              health={health}
              detailedHealth={detailedHealth}
              loading={loadingHealth}
              onRefreshHealth={fetchHealthStatus}
            />
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
