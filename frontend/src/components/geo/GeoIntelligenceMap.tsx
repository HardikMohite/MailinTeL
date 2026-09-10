import React, { useState, useEffect, useMemo, useRef } from 'react';
import L from 'leaflet';
import {
  Globe,
  MapPin,
  Search,
  RefreshCw,
  Flag,
  Mail,
  ZoomIn,
  ZoomOut,
  Navigation,
  Crosshair,
  Shield,
  Key,
  Cloud,
  CheckCircle2,
  XCircle,
  Activity,
  Layers,
  Sparkles,
  UserCheck,
} from 'lucide-react';
import {
  getIPGeolocation,
  getEmailGeoInfrastructure,
  getCampaignGeoInfrastructure,
  getGlobalGeoInfrastructure,
  listEmails,
  listCampaigns,
  GeoMarkerItem,
  GeoPathSegment,
  EmailGeoInfrastructureResponse,
  CampaignGeoInfrastructureResponse,
  GlobalGeoInfrastructureResponse,
  EmailDetailResponse,
  CampaignListItemResponse,
} from '../../services/api';

type ViewMode = 'email' | 'campaign' | 'global' | 'lookup';
type TileLayerType = 'dark' | 'voyager' | 'osm';
type CategoryFilterType = 'ALL' | 'TOR' | 'VPN' | 'CLOUD' | 'PERSONAL_MAIL';

interface GeoIntelligenceMapProps {
  initialEmailId?: string;
  initialCampaignId?: string;
  embedded?: boolean; // When rendered inside AnalysisWorkspace
}

const TILE_SERVERS: Record<
  TileLayerType,
  {
    url: string;
    options: L.TileLayerOptions;
    name: string;
  }
> = {
  dark: {
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    options: {
      attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; OpenStreetMap',
      subdomains: 'abcd',
      maxZoom: 19,
    },
    name: 'Tactical Dark',
  },
  voyager: {
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',
    options: {
      attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ, TomTom, Intermap, USGS, METI',
      maxZoom: 19,
    },
    name: 'City Streets (Detailed)',
  },
  osm: {
    url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    options: {
      attribution: '&copy; OpenStreetMap contributors',
      maxZoom: 19,
    },
    name: 'Standard OSM',
  },
};

export const GeoIntelligenceMap: React.FC<GeoIntelligenceMapProps> = ({
  initialEmailId,
  initialCampaignId,
  embedded = false,
}) => {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const markersLayerGroupRef = useRef<L.LayerGroup | null>(null);
  const pathsLayerGroupRef = useRef<L.LayerGroup | null>(null);

  const [viewMode, setViewMode] = useState<ViewMode>(
    initialEmailId ? 'email' : initialCampaignId ? 'campaign' : 'email'
  );
  const [activeTileType, setActiveTileType] = useState<TileLayerType>('dark');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilterType>('ALL');

  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignListItemResponse[]>([]);
  const [selectedEmailId, setSelectedEmailId] = useState<string>(initialEmailId || '');
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>(initialCampaignId || '');

  // Data state
  const [emailGeo, setEmailGeo] = useState<EmailGeoInfrastructureResponse | null>(null);
  const [campaignGeo, setCampaignGeo] = useState<CampaignGeoInfrastructureResponse | null>(null);
  const [globalGeo, setGlobalGeo] = useState<GlobalGeoInfrastructureResponse | null>(null);

  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedMarker, setSelectedMarker] = useState<GeoMarkerItem | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [ipQuery, setIpQuery] = useState<string>('');
  const [searchingIp, setSearchingIp] = useState<boolean>(false);

  // Initialize Base Map
  useEffect(() => {
    if (!mapContainerRef.current) return;
    if (mapInstanceRef.current) return;

    const map = L.map(mapContainerRef.current, {
      center: [25, 10],
      zoom: 2,
      minZoom: 2,
      maxZoom: 18,
      zoomControl: false,
      attributionControl: false,
    });

    const activeConfig = TILE_SERVERS[activeTileType];
    const tileLayer = L.tileLayer(activeConfig.url, activeConfig.options).addTo(map);

    tileLayerRef.current = tileLayer;
    markersLayerGroupRef.current = L.layerGroup().addTo(map);
    pathsLayerGroupRef.current = L.layerGroup().addTo(map);
    mapInstanceRef.current = map;

    // Load available email context
    loadContext();

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Switch Tile Layer
  const handleTileChange = (type: TileLayerType) => {
    if (!mapInstanceRef.current || activeTileType === type) return;
    setActiveTileType(type);
    if (tileLayerRef.current) {
      mapInstanceRef.current.removeLayer(tileLayerRef.current);
    }
    const targetConfig = TILE_SERVERS[type];
    const newTile = L.tileLayer(targetConfig.url, targetConfig.options).addTo(mapInstanceRef.current);
    tileLayerRef.current = newTile;
  };

  const loadContext = async () => {
    try {
      const [emailRes, campRes] = await Promise.allSettled([
        listEmails(0, 50),
        listCampaigns(undefined, 0, 50),
      ]);
      const emailList = emailRes.status === 'fulfilled' ? emailRes.value?.items || [] : [];
      const campList = campRes.status === 'fulfilled' ? campRes.value || [] : [];
      setEmails(emailList);
      setCampaigns(campList);

      if (initialCampaignId) {
        setSelectedCampaignId(initialCampaignId);
        setViewMode('campaign');
        fetchCampaignGeo(initialCampaignId);
      } else if (initialEmailId) {
        setSelectedEmailId(initialEmailId);
        setViewMode('email');
        fetchEmailGeo(initialEmailId);
      } else if (emailList.length > 0) {
        setSelectedEmailId(emailList[0].id);
        setViewMode('email');
        fetchEmailGeo(emailList[0].id);
      } else if (campList.length > 0) {
        setSelectedCampaignId(campList[0].id);
        setViewMode('campaign');
        fetchCampaignGeo(campList[0].id);
      } else {
        setViewMode('global');
        fetchGlobalGeo();
      }
    } catch (err) {
      console.error('Failed to load geo context:', err);
      setViewMode('global');
      fetchGlobalGeo();
    }
  };

  useEffect(() => {
    if (initialEmailId && initialEmailId !== selectedEmailId) {
      setSelectedEmailId(initialEmailId);
      setViewMode('email');
      fetchEmailGeo(initialEmailId);
    }
  }, [initialEmailId]);

  useEffect(() => {
    if (initialCampaignId && initialCampaignId !== selectedCampaignId) {
      setSelectedCampaignId(initialCampaignId);
      setViewMode('campaign');
      fetchCampaignGeo(initialCampaignId);
    }
  }, [initialCampaignId]);

  const fetchEmailGeo = async (emailId: string) => {
    if (!emailId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getEmailGeoInfrastructure(emailId);
      setEmailGeo(data);
      const humanNode = data.markers?.find((m) => m.role === 'DEDUCED_HUMAN_ORIGIN' || m.id === 'marker-deduced-human-origin');
      if (humanNode) {
        setSelectedMarker(humanNode);
      } else if (data.markers && data.markers.length > 0) {
        setSelectedMarker(data.markers[0]);
      } else {
        setSelectedMarker(null);
      }
    } catch (err: any) {
      setError(err.message || 'Could not load geographic infrastructure for this email.');
      setSelectedMarker(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchCampaignGeo = async (campaignId: string) => {
    if (!campaignId) return;
    setLoading(true);
    setError(null);
    setSelectedMarker(null);
    try {
      const data = await getCampaignGeoInfrastructure(campaignId);
      setCampaignGeo(data);
    } catch (err: any) {
      setError(err.message || 'Could not load campaign geographic infrastructure.');
    } finally {
      setLoading(false);
    }
  };

  const fetchGlobalGeo = async () => {
    setLoading(true);
    setError(null);
    setSelectedMarker(null);
    try {
      const data = await getGlobalGeoInfrastructure(100);
      setGlobalGeo(data);
    } catch (err: any) {
      setError(err.message || 'Could not load global infrastructure markers.');
    } finally {
      setLoading(false);
    }
  };

  const handleIpLookup = async () => {
    const clean = ipQuery.trim();
    if (!clean) return;
    setSearchingIp(true);
    setError(null);
    try {
      const data = await getIPGeolocation(clean);
      if (data.latitude && data.longitude) {
        const marker: GeoMarkerItem = {
          id: `lookup-${clean}`,
          entity_type: 'LOOKUP_TARGET',
          ip_address: clean,
          host: clean,
          latitude: data.latitude,
          longitude: data.longitude,
          country_code: data.country_code,
          country_name: data.country_name,
          region_name: data.region_name,
          city_name: data.city_name,
          accuracy_radius_km: data.accuracy_radius_km,
          confidence: data.confidence,
          role: 'LOOKUP_TARGET',
          connection_type: data.connection_type,
          provider: data.provider,
          is_tor: data.is_tor,
          is_vpn: data.is_vpn,
          is_datacenter: data.is_datacenter,
          is_cloud: data.is_cloud,
          is_personal_mail: data.is_personal_mail,
          asn: data.asn,
          asn_org: data.asn_org,
          reverse_dns: data.reverse_dns,
          classification_badges: data.classification_badges,
        };
        setEmailGeo({
          email_id: `lookup-${clean}`,
          total_hops: 1,
          total_markers: 1,
          tor_node_count: data.is_tor ? 1 : 0,
          vpn_node_count: data.is_vpn ? 1 : 0,
          cloud_node_count: data.is_cloud ? 1 : 0,
          personal_mail_node_count: data.is_personal_mail ? 1 : 0,
          hops: [],
          markers: [marker],
          paths: [],
          country_distribution: { [data.country_code]: 1 },
          attribution_disclaimer: data.attribution_statement,
        });
        setSelectedMarker(marker);
        if (mapInstanceRef.current) {
          mapInstanceRef.current.flyTo([data.latitude, data.longitude], 10, { duration: 1.5 });
        }
      } else {
        setError(`No geographic coordinates resolved for IP ${clean}`);
      }
    } catch (err: any) {
      setError(`Failed to geolocate IP: ${err.message}`);
    } finally {
      setSearchingIp(false);
    }
  };

  // Extract all current markers and paths
  const allCurrentMarkers = useMemo((): GeoMarkerItem[] => {
    return emailGeo?.markers || campaignGeo?.markers || ((globalGeo?.markers as unknown) as GeoMarkerItem[]) || [];
  }, [emailGeo, campaignGeo, globalGeo]);

  const currentPaths = useMemo((): GeoPathSegment[] => {
    return emailGeo?.paths || [];
  }, [emailGeo]);

  // Compute live breakdown counts across the 4 key categories
  const { torCount, vpnCount, cloudCount, personalCount } = useMemo(() => {
    let tor = 0;
    let vpn = 0;
    let cloud = 0;
    let personal = 0;

    allCurrentMarkers.forEach((m) => {
      const type = (m.connection_type || '').toUpperCase();
      if (m.is_tor || type === 'TOR') tor++;
      if (m.is_vpn || type === 'VPN') vpn++;
      if (m.is_cloud || m.is_datacenter || type === 'CLOUD' || type === 'CLOUD_HOSTED') cloud++;
      if (m.is_personal_mail || type === 'PERSONAL_MAIL' || type === 'RESIDENTIAL' || type === 'RESIDENTIAL_ISP') personal++;
    });

    return { torCount: tor, vpnCount: vpn, cloudCount: cloud, personalCount: personal };
  }, [allCurrentMarkers]);

  // Filtered markers based on active category and text search
  const displayedMarkers = useMemo((): GeoMarkerItem[] => {
    return allCurrentMarkers.filter((m) => {
      const type = (m.connection_type || '').toUpperCase();
      const isTor = m.is_tor || type === 'TOR';
      const isVpn = m.is_vpn || type === 'VPN';
      const isCloud = m.is_cloud || m.is_datacenter || type === 'CLOUD' || type === 'CLOUD_HOSTED';
      const isPersonal = m.is_personal_mail || type === 'PERSONAL_MAIL' || type === 'RESIDENTIAL' || type === 'RESIDENTIAL_ISP';

      if (categoryFilter === 'TOR' && !isTor) return false;
      if (categoryFilter === 'VPN' && !isVpn) return false;
      if (categoryFilter === 'CLOUD' && !isCloud) return false;
      if (categoryFilter === 'PERSONAL_MAIL' && !isPersonal) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        (m.ip_address && m.ip_address.toLowerCase().includes(q)) ||
        (m.city_name && m.city_name.toLowerCase().includes(q)) ||
        (m.country_name && m.country_name.toLowerCase().includes(q)) ||
        (m.host && m.host.toLowerCase().includes(q)) ||
        (m.provider && m.provider.toLowerCase().includes(q)) ||
        (m.asn && m.asn.toLowerCase().includes(q))
      );
    });
  }, [allCurrentMarkers, categoryFilter, searchQuery]);

  // Render Real Markers and Flight Lines on Leaflet
  const renderMapData = (markers: GeoMarkerItem[], paths: GeoPathSegment[]) => {
    const map = mapInstanceRef.current;
    if (!map || !markersLayerGroupRef.current || !pathsLayerGroupRef.current) return;

    markersLayerGroupRef.current.clearLayers();
    pathsLayerGroupRef.current.clearLayers();

    const boundsLatLngs: L.LatLng[] = [];

    // 1. Draw Flight Lines between Sender -> Relays -> Destination
    paths.forEach((p) => {
      if (!p.from_coords || !p.to_coords) return;
      const latlngs: [number, number][] = [
        [p.from_coords[0], p.from_coords[1]],
        [p.to_coords[0], p.to_coords[1]],
      ];

      const isInferred = p.is_inferred || (p.label && p.label.toLowerCase().includes('deduced'));

      const polyline = L.polyline(latlngs, {
        color: isInferred ? '#10B981' : '#0284C7', // Emerald dash for deduced human-to-cloud arc, sky-blue for relay
        weight: isInferred ? 3.5 : 3,
        opacity: 0.9,
        dashArray: isInferred ? '6, 6' : '8, 8',
      });

      polyline.bindTooltip(
        `<div class="text-xs font-semibold font-mono p-1 text-slate-100">${isInferred ? '⚡ Passive Forensic Arc: ' : 'Route Segment: '}${p.label || `${p.from_ip} → ${p.to_ip}`}</div>`,
        { sticky: true }
      );

      pathsLayerGroupRef.current?.addLayer(polyline);
    });

    // 2. Draw Interactive Classified Markers
    markers.forEach((m, idx) => {
      if (m.latitude == null || m.longitude == null) return;
      const latlng = L.latLng(m.latitude, m.longitude);
      boundsLatLngs.push(latlng);

      const isDeducedOrigin = m.role === 'DEDUCED_HUMAN_ORIGIN' || m.id === 'marker-deduced-human-origin';
      const type = (m.connection_type || '').toUpperCase();
      const isTor = m.is_tor || type === 'TOR';
      const isVpn = m.is_vpn || type === 'VPN';
      const isCloud = m.is_cloud || m.is_datacenter || type === 'CLOUD' || type === 'CLOUD_HOSTED';
      const isPersonal = m.is_personal_mail || type === 'PERSONAL_MAIL' || type === 'RESIDENTIAL' || type === 'RESIDENTIAL_ISP';

      let markerColor = '#0EA5E9'; // default blue
      let badgeLabel = 'RELAY';
      let iconSymbol = '⚡';
      let categoryBadge = '🔵 Transit Relay';

      if (isDeducedOrigin) {
        markerColor = '#10B981'; // Emerald
        badgeLabel = 'HUMAN';
        iconSymbol = '👤';
        categoryBadge = '🟢 Physical Human Origin (Deduced)';
      } else if (isTor) {
        markerColor = '#A855F7'; // Purple
        badgeLabel = 'TOR';
        iconSymbol = '🧅';
        categoryBadge = '🟣 Tor Exit Relay';
      } else if (isVpn) {
        markerColor = '#F59E0B'; // Amber
        badgeLabel = 'VPN';
        iconSymbol = '🛡️';
        categoryBadge = '🟠 VPN Tunnel';
      } else if (isPersonal) {
        markerColor = '#10B981'; // Emerald
        badgeLabel = 'MAIL';
        iconSymbol = '✉️';
        categoryBadge = '🟢 Personal / Webmail';
      } else if (isCloud) {
        markerColor = '#0284C7'; // Sky Blue
        badgeLabel = 'CLOUD';
        iconSymbol = '☁️';
        categoryBadge = '🔵 Cloud Datacenter';
      }

      const isOrigin = isDeducedOrigin || m.role === 'ORIGIN_HOP' || (m.sequence_number === 1);
      const isDestination = m.role === 'DESTINATION_NODE';

      // Custom pulsing HTML marker with distinct category badge & icon
      const customIcon = L.divIcon({
        className: 'custom-geo-marker',
        html: `
          <div style="position: relative; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; cursor: pointer;">
            ${isDeducedOrigin ? `
              <div style="position: absolute; width: 44px; height: 44px; border-radius: 9999px; border: 2px solid #10B981; animation: pulse-ring 1.8s cubic-bezier(0.4, 0, 0.6, 1) infinite;"></div>
              <div style="position: absolute; width: 38px; height: 38px; border-radius: 9999px; border: 2px dashed #34D399; animation: spin-slow 10s linear infinite;"></div>
            ` : isOrigin ? `<div style="position: absolute; width: 36px; height: 36px; border-radius: 9999px; border: 2px dashed #EF4444; animation: spin-slow 8s linear infinite;"></div>` : ''}
            <div style="position: absolute; width: 30px; height: 30px; border-radius: 9999px; background-color: ${markerColor}; opacity: 0.35; animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;"></div>
            <div style="position: relative; width: 24px; height: 24px; border-radius: 9999px; background-color: ${markerColor}; border: 2px solid #FFFFFF; box-shadow: 0 0 12px ${markerColor}; display: flex; align-items: center; justify-content: center; color: #FFFFFF; font-size: ${isDeducedOrigin ? '12px' : '10px'}; font-weight: 800; font-family: monospace;">
              ${isDeducedOrigin ? '👤' : (m.sequence_number != null ? m.sequence_number : idx + 1)}
            </div>
            <div style="position: absolute; bottom: -8px; background: #0F172A; border: 1px solid ${markerColor}; border-radius: 4px; padding: 1px 4px; font-size: 8px; font-weight: 800; color: ${markerColor}; text-transform: uppercase; white-space: nowrap; box-shadow: 0 2px 4px rgba(0,0,0,0.6);">
              ${badgeLabel}
            </div>
          </div>
        `,
        iconSize: [36, 36],
        iconAnchor: [18, 18],
      });

      const isCloudProvider = isCloud || Boolean(
        (m.provider && (m.provider.toLowerCase().includes('microsoft') || m.provider.toLowerCase().includes('google') || m.provider.toLowerCase().includes('amazon'))) ||
        (m.asn_org && (m.asn_org.toLowerCase().includes('microsoft') || m.asn_org.toLowerCase().includes('google') || m.asn_org.toLowerCase().includes('amazon')))
      );

      // Interactive Tactical Popup
      const popupContent = `
        <div style="min-width: 250px; padding: 6px; font-family: inherit; color: #F8FAFC;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 6px;">
            <span style="font-size: 10px; font-weight: 800; text-transform: uppercase; background: ${markerColor}22; color: ${markerColor}; border: 1px solid ${markerColor}66; border-radius: 4px; padding: 2px 6px;">
              ${iconSymbol} ${categoryBadge}
            </span>
            ${isDeducedOrigin ? `<span style="font-size: 9px; font-weight: 800; background: #10B98133; color: #34D399; border: 1px solid #10B98166; border-radius: 4px; padding: 1px 4px;">DEDUCED SENDER</span>` : isOrigin ? (isCloudProvider ? `<span style="font-size: 9px; font-weight: 800; background: #F59E0B33; color: #FBBF24; border: 1px solid #F59E0B66; border-radius: 4px; padding: 1px 4px;">CLOUD RELAY</span>` : `<span style="font-size: 9px; font-weight: 800; background: #10B98133; color: #34D399; border: 1px solid #10B98166; border-radius: 4px; padding: 1px 4px;">CLIENT ORIGIN</span>`) : isDestination ? `<span style="font-size: 9px; font-weight: 800; background: #38BDF833; color: #38BDF8; border: 1px solid #38BDF866; border-radius: 4px; padding: 1px 4px;">GATEWAY</span>` : ''}
          </div>
          ${isDeducedOrigin && m.forensic_explanation ? `
            <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; padding: 6px 8px; margin-bottom: 6px; font-size: 11px; color: #A7F3D0; line-height: 1.4;">
              <strong style="color: #34D399; display: block; margin-bottom: 2px;">⚡ Passive .EML Forensic Evidence:</strong>
              ${m.forensic_explanation}
            </div>
          ` : ''}
          <div style="font-weight: 700; font-size: 13px; color: #F8FAFC; margin-bottom: 4px;">
            ${m.city_name ? `${m.city_name}, ` : ''}${m.region_name ? `${m.region_name}, ` : ''}${m.country_name || 'Unknown Location'}
          </div>
          <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(51, 65, 85, 0.6); border-radius: 8px; padding: 8px; font-size: 11px; space-y: 4px; margin-bottom: 6px;">
            <div>IP / Node: <strong style="color: #38BDF8; font-family: monospace;">${m.ip_address}</strong></div>
            ${m.provider ? `<div>Provider: <strong style="color: #F1F5F9;">${m.provider}</strong></div>` : ''}
            ${m.asn ? `<div>ASN: <span style="color: #94A3B8; font-family: monospace;">${m.asn}</span></div>` : ''}
            ${m.host ? `<div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">Host: <span style="color: #CBD5E1;">${m.host}</span></div>` : ''}
            <div>Coordinates: <span style="color: #94A3B8; font-family: monospace;">${m.latitude.toFixed(4)}, ${m.longitude.toFixed(4)}</span></div>
            ${m.confidence != null ? `<div>Accuracy / Confidence: <strong style="color: #34D399;">${Math.round(m.confidence * 100)}%</strong></div>` : ''}
          </div>
          <div style="font-size: 10px; color: #94A3B8; text-align: center;">Click to inspect detailed hop telemetry</div>
        </div>
      `;

      const marker = L.marker(latlng, { icon: customIcon });
      marker.bindPopup(popupContent);

      marker.on('click', () => {
        setSelectedMarker(m);
      });

      markersLayerGroupRef.current?.addLayer(marker);
    });

    // Automatically fit view bounds to encompass the visible markers
    if (boundsLatLngs.length > 0) {
      if (boundsLatLngs.length === 1) {
        map.setView(boundsLatLngs[0], 9);
      } else {
        const bounds = L.latLngBounds(boundsLatLngs);
        map.fitBounds(bounds, { padding: [50, 50], maxZoom: 12 });
      }
    }
  };

  // Re-render map markers when displayedMarkers or currentPaths change
  useEffect(() => {
    renderMapData(displayedMarkers, currentPaths);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [displayedMarkers, currentPaths]);

  const handleZoomIn = () => {
    mapInstanceRef.current?.zoomIn();
  };

  const handleZoomOut = () => {
    mapInstanceRef.current?.zoomOut();
  };

  const handleFitRoute = () => {
    const valid = displayedMarkers.filter((m) => m.latitude != null && m.longitude != null);
    if (valid.length > 0 && mapInstanceRef.current) {
      const bounds = L.latLngBounds(valid.map((m) => [m.latitude, m.longitude] as [number, number]));
      mapInstanceRef.current.fitBounds(bounds, { padding: [60, 60], maxZoom: 12 });
    }
  };

  const handleResetWorld = () => {
    mapInstanceRef.current?.setView([25, 10], 2);
  };

  // Helper to determine node theme colors & description
  const getNodeClassificationInfo = (m: GeoMarkerItem) => {
    if (m.role === 'DEDUCED_HUMAN_ORIGIN' || m.id === 'marker-deduced-human-origin') {
      return {
        label: 'Deduced Human Actor Origin (Passive .EML Triangulation)',
        badge: 'HUMAN SENDER',
        color: 'text-emerald-400',
        bg: 'bg-emerald-500/20 border-emerald-500/40',
        cardBorder: 'border-emerald-500/50',
        icon: UserCheck,
        description: 'Physical sender location triangulated purely from passive evidence within the .eml file (Timezone offset, regional postal PIN codes, telephone prefixes, and client-ip auth traces) without social engineering or tracking pixels.',
      };
    }
    const type = (m.connection_type || '').toUpperCase();
    if (m.is_tor || type === 'TOR') {
      return {
        label: 'Tor Exit Node',
        badge: 'TOR',
        color: 'text-purple-400',
        bg: 'bg-purple-500/15 border-purple-500/30',
        cardBorder: 'border-purple-500/40',
        icon: Shield,
        description: 'Anonymization Tor Exit Relay — Conceals the human actor’s physical device location and routing origin.',
      };
    }
    if (m.is_vpn || type === 'VPN') {
      return {
        label: 'Commercial VPN Tunnel',
        badge: 'VPN',
        color: 'text-amber-400',
        bg: 'bg-amber-500/15 border-amber-500/30',
        cardBorder: 'border-amber-500/40',
        icon: Key,
        description: 'Encrypted VPN Proxy Tunnel — Masks physical broadband egress through a commercial or private gateway.',
      };
    }
    if (m.is_personal_mail || type === 'PERSONAL_MAIL' || type === 'RESIDENTIAL' || type === 'RESIDENTIAL_ISP') {
      return {
        label: 'Personal Webmail / Residential',
        badge: 'PERSONAL',
        color: 'text-emerald-400',
        bg: 'bg-emerald-500/15 border-emerald-500/30',
        cardBorder: 'border-emerald-500/40',
        icon: Mail,
        description: 'Consumer Personal Mail / Residential ISP — End-user webmail interface (Gmail, Outlook, Yahoo) or consumer broadband submission.',
      };
    }
    if (m.is_cloud || m.is_datacenter || type === 'CLOUD' || type === 'CLOUD_HOSTED') {
      return {
        label: 'Cloud Server / Datacenter',
        badge: 'CLOUD',
        color: 'text-sky-400',
        bg: 'bg-sky-500/15 border-sky-500/30',
        cardBorder: 'border-sky-500/40',
        icon: Cloud,
        description: 'Public Cloud Datacenter Infrastructure — Hosted Virtual Private Server (VPS) or cloud MTA service (AWS, GCP, Azure).',
      };
    }
    return {
      label: 'Standard MTA Relay',
      badge: 'RELAY',
      color: 'text-blue-400',
      bg: 'bg-blue-500/15 border-blue-500/30',
      cardBorder: 'border-blue-500/40',
      icon: Activity,
      description: 'Intermediate Mail Transfer Agent (MTA) Relay transit server.',
    };
  };

  return (
    <div className={`space-y-4 ${embedded ? '' : 'p-6 rounded-2xl bg-workspace-card border border-workspace-border'}`}>
      {/* Dynamic Keyframes for Map Markers */}
      <style>{`
        @keyframes pulse-ring {
          0% { transform: scale(0.95); opacity: 0.6; }
          50% { transform: scale(1.4); opacity: 0.1; }
          100% { transform: scale(0.95); opacity: 0.6; }
        }
        @keyframes spin-slow {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>

      {/* Top Header & View Controls */}
      {!embedded && (
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <Globe className="w-5 h-5 text-brand" />
              <h1 className="text-xl font-bold text-text-primary">Geographic Infrastructure Intelligence</h1>
            </div>
            <p className="text-xs text-text-muted mt-0.5">
              Multi-vector forensic geolocation tracking Tor exit relays, VPN proxy tunnels, Cloud datacenters, and Personal webmail origins.
            </p>
          </div>

          {/* Mode Selector */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex rounded-lg bg-workspace p-1 border border-workspace-border">
              <button
                onClick={() => {
                  setViewMode('email');
                  if (selectedEmailId) fetchEmailGeo(selectedEmailId);
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                  viewMode === 'email' ? 'bg-brand text-white shadow-sm' : 'text-text-muted hover:text-text-primary'
                }`}
              >
                <Mail className="w-3.5 h-3.5" />
                Email Route
              </button>
              <button
                onClick={() => {
                  setViewMode('campaign');
                  if (selectedCampaignId) fetchCampaignGeo(selectedCampaignId);
                  else if (campaigns.length > 0) {
                    setSelectedCampaignId(campaigns[0].id);
                    fetchCampaignGeo(campaigns[0].id);
                  }
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                  viewMode === 'campaign' ? 'bg-brand text-white shadow-sm' : 'text-text-muted hover:text-text-primary'
                }`}
              >
                <Flag className="w-3.5 h-3.5" />
                Campaign Infra
              </button>
              <button
                onClick={() => {
                  setViewMode('global');
                  fetchGlobalGeo();
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                  viewMode === 'global' ? 'bg-brand text-white shadow-sm' : 'text-text-muted hover:text-text-primary'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                Global Grid
              </button>
              <button
                onClick={() => setViewMode('lookup')}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                  viewMode === 'lookup' ? 'bg-brand text-white shadow-sm' : 'text-text-muted hover:text-text-primary'
                }`}
              >
                <Search className="w-3.5 h-3.5" />
                IP Lookup
              </button>
            </div>

            {/* Email / Campaign Dropdown Selectors */}
            {viewMode === 'email' && emails.length > 0 && (
              <select
                value={selectedEmailId}
                onChange={(e) => {
                  setSelectedEmailId(e.target.value);
                  fetchEmailGeo(e.target.value);
                }}
                className="px-3 py-1.5 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary font-medium focus:outline-none focus:border-brand max-w-xs"
              >
                {emails.map((em) => (
                  <option key={em.id} value={em.id}>
                    {em.subject ? em.subject.substring(0, 36) : em.original_filename || em.id}
                  </option>
                ))}
              </select>
            )}

            {viewMode === 'campaign' && campaigns.length > 0 && (
              <select
                value={selectedCampaignId}
                onChange={(e) => {
                  setSelectedCampaignId(e.target.value);
                  fetchCampaignGeo(e.target.value);
                }}
                className="px-3 py-1.5 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary font-medium focus:outline-none focus:border-brand max-w-xs"
              >
                {campaigns.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.campaign_name || 'Unnamed Campaign'}
                  </option>
                ))}
              </select>
            )}

            <button
              onClick={() => {
                if (viewMode === 'email' && selectedEmailId) fetchEmailGeo(selectedEmailId);
                else if (viewMode === 'campaign' && selectedCampaignId) fetchCampaignGeo(selectedCampaignId);
                else if (viewMode === 'global') fetchGlobalGeo();
              }}
              className="p-1.5 rounded-lg bg-workspace border border-workspace-border text-text-muted hover:text-brand transition-colors"
              title="Refresh Map Data"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      )}

      {/* Standalone IP Lookup Bar */}
      {viewMode === 'lookup' && (
        <div className="flex items-center gap-2 p-3 bg-workspace rounded-xl border border-workspace-border max-w-md">
          <Crosshair className="w-4 h-4 text-brand shrink-0" />
          <input
            type="text"
            placeholder="Enter IPv4 or IPv6 (e.g. 185.220.101.5, 54.210.1.2)..."
            value={ipQuery}
            onChange={(e) => setIpQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleIpLookup()}
            className="flex-1 bg-transparent text-xs text-text-primary placeholder:text-text-muted focus:outline-none font-mono"
          />
          <button
            onClick={handleIpLookup}
            disabled={searchingIp || !ipQuery.trim()}
            className="px-3 py-1 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors disabled:opacity-50"
          >
            {searchingIp ? 'Resolving…' : 'Locate'}
          </button>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg bg-severity-high-soft border border-severity-high/20 text-xs text-severity-high">
          {error}
        </div>
      )}

      {/* TACTICAL CATEGORY FILTER BAR: Tor, VPN, Cloud Server, Personal Mail */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-xl bg-workspace border border-workspace-border">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1.5 mr-1">
            <Layers className="w-3.5 h-3.5 text-brand" />
            Infrastructure Filter:
          </span>

          <button
            onClick={() => setCategoryFilter('ALL')}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 ${
              categoryFilter === 'ALL'
                ? 'bg-slate-700 text-white shadow-sm border border-slate-600'
                : 'bg-workspace-card text-text-muted hover:text-text-primary border border-workspace-border'
            }`}
          >
            All Nodes
            <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 font-mono">
              {allCurrentMarkers.length}
            </span>
          </button>

          {/* 🟣 Tor Exit Relays Filter */}
          <button
            onClick={() => setCategoryFilter('TOR')}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              categoryFilter === 'TOR'
                ? 'bg-purple-600 text-white shadow-sm ring-2 ring-purple-500/40 border border-purple-400'
                : 'bg-purple-500/10 text-purple-300 hover:bg-purple-500/20 border border-purple-500/30'
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-purple-400" />
            Tor Nodes
            <span className={`ml-1 text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
              categoryFilter === 'TOR' ? 'bg-purple-800 text-white' : 'bg-purple-950 text-purple-300'
            }`}>
              {torCount}
            </span>
          </button>

          {/* 🟠 VPN Tunnels Filter */}
          <button
            onClick={() => setCategoryFilter('VPN')}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              categoryFilter === 'VPN'
                ? 'bg-amber-600 text-white shadow-sm ring-2 ring-amber-500/40 border border-amber-400'
                : 'bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 border border-amber-500/30'
            }`}
          >
            <Key className="w-3.5 h-3.5 text-amber-400" />
            VPN Tunnels
            <span className={`ml-1 text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
              categoryFilter === 'VPN' ? 'bg-amber-800 text-white' : 'bg-amber-950 text-amber-300'
            }`}>
              {vpnCount}
            </span>
          </button>

          {/* 🔵 Cloud Servers Filter */}
          <button
            onClick={() => setCategoryFilter('CLOUD')}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              categoryFilter === 'CLOUD'
                ? 'bg-sky-600 text-white shadow-sm ring-2 ring-sky-500/40 border border-sky-400'
                : 'bg-sky-500/10 text-sky-300 hover:bg-sky-500/20 border border-sky-500/30'
            }`}
          >
            <Cloud className="w-3.5 h-3.5 text-sky-400" />
            Cloud Servers
            <span className={`ml-1 text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
              categoryFilter === 'CLOUD' ? 'bg-sky-800 text-white' : 'bg-sky-950 text-sky-300'
            }`}>
              {cloudCount}
            </span>
          </button>

          {/* 🟢 Personal Mail / Residential Filter */}
          <button
            onClick={() => setCategoryFilter('PERSONAL_MAIL')}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              categoryFilter === 'PERSONAL_MAIL'
                ? 'bg-emerald-600 text-white shadow-sm ring-2 ring-emerald-500/40 border border-emerald-400'
                : 'bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 border border-emerald-500/30'
            }`}
          >
            <Mail className="w-3.5 h-3.5 text-emerald-400" />
            Personal Mail / Webmail
            <span className={`ml-1 text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
              categoryFilter === 'PERSONAL_MAIL' ? 'bg-emerald-800 text-white' : 'bg-emerald-950 text-emerald-300'
            }`}>
              {personalCount}
            </span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] text-text-muted font-mono">
            Showing <strong className="text-text-primary">{displayedMarkers.length}</strong> of {allCurrentMarkers.length} hops
          </span>
        </div>
      </div>

      {/* Forensic Passive Origin Triangulation Alert Banner */}
      {viewMode === 'email' && emailGeo?.deduced_human_origin?.deduced_city && (
        <div className="p-3.5 rounded-xl bg-gradient-to-r from-emerald-950/70 via-slate-900 to-slate-900 border border-emerald-500/40 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 shrink-0 mt-0.5">
              <UserCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                  Forensic Human Sender Triangulation (Passive .EML Evidence)
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                  {Math.round((emailGeo.deduced_human_origin.confidence_score || 0.85) * 100)}% Confidence
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-medium">
                  Zero Social Engineering / Canary Free
                </span>
              </div>
              <div className="text-sm font-semibold text-white mt-1">
                Triangulated Human Physical Location:{' '}
                <span className="text-emerald-300 font-bold">
                  {emailGeo.deduced_human_origin.deduced_city}
                  {emailGeo.deduced_human_origin.deduced_region ? `, ${emailGeo.deduced_human_origin.deduced_region}` : ''}
                  {emailGeo.deduced_human_origin.deduced_country ? `, ${emailGeo.deduced_human_origin.deduced_country}` : ''}
                </span>
                {emailGeo.deduced_human_origin.is_redacted_by_provider && (
                  <span className="text-xs font-normal text-slate-400 ml-2">
                    (Cloud Provider {emailGeo.deduced_human_origin.provider_name || 'Datacenter'} Redacted Raw IP; Derived from Multi-Artifact Correlation)
                  </span>
                )}
              </div>
              {emailGeo.deduced_human_origin.forensic_explanation && (
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                  {emailGeo.deduced_human_origin.forensic_explanation}
                </p>
              )}
            </div>
          </div>
          {emailGeo.deduced_human_origin.latitude && emailGeo.deduced_human_origin.longitude && (
            <button
              onClick={() => {
                if (mapInstanceRef.current && emailGeo.deduced_human_origin?.latitude && emailGeo.deduced_human_origin?.longitude) {
                  mapInstanceRef.current.setView(
                    [emailGeo.deduced_human_origin.latitude, emailGeo.deduced_human_origin.longitude],
                    10
                  );
                }
              }}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shrink-0 transition-colors flex items-center gap-1.5 shadow-md self-start md:self-center"
            >
              <Navigation className="w-3.5 h-3.5" />
              Focus Human Origin
            </button>
          )}
        </div>
      )}

      {/* Main Interactive Map Canvas & Telemetry Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Map Viewport Container */}
        <div className="lg:col-span-3 rounded-xl border border-workspace-border bg-navy-deep relative overflow-hidden shadow-inner flex flex-col h-[540px]">
          {/* Leaflet Map Div */}
          <div ref={mapContainerRef} className="w-full h-full z-0" />

          {/* Tactical Floating Color Legend */}
          <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-3 bg-slate-900/90 backdrop-blur-md px-3.5 py-2 rounded-lg border border-slate-700/60 shadow-xl text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 border border-white shadow-sm shadow-emerald-400/50"></span>
              <span className="text-emerald-300 font-bold">👤 Human Origin (Deduced)</span>
            </div>
            <span className="text-slate-600">·</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500 shadow-sm shadow-purple-500/50"></span>
              <span className="text-purple-300 font-semibold">Tor Node</span>
            </div>
            <span className="text-slate-600">·</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-sm shadow-amber-500/50"></span>
              <span className="text-amber-300 font-semibold">VPN Tunnel</span>
            </div>
            <span className="text-slate-600">·</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-500 shadow-sm shadow-sky-500/50"></span>
              <span className="text-sky-300 font-semibold">Cloud VPS</span>
            </div>
            <span className="text-slate-600">·</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/50"></span>
              <span className="text-emerald-300 font-semibold">Personal Mail</span>
            </div>
            <span className="text-slate-600">·</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full border-2 border-red-500 animate-pulse"></span>
              <span className="text-red-400 font-medium">Origin Beacon</span>
            </div>
          </div>

          {/* Tactical Zoom & Layer Controls */}
          <div className="absolute top-3 right-3 z-10 flex flex-col gap-1.5">
            <div className="bg-slate-900/90 backdrop-blur-md rounded-lg border border-slate-700/60 p-1 flex flex-col shadow-lg">
              <button
                onClick={handleZoomIn}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors"
                title="Zoom In (City Level)"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                onClick={handleZoomOut}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors border-t border-slate-700/40"
                title="Zoom Out (World Level)"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                onClick={handleFitRoute}
                className="p-1.5 text-slate-300 hover:text-brand hover:bg-slate-800 rounded transition-colors border-t border-slate-700/40"
                title="Fit Route Bounds"
              >
                <Crosshair className="w-4 h-4" />
              </button>
              <button
                onClick={handleResetWorld}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors border-t border-slate-700/40"
                title="Reset World View"
              >
                <Navigation className="w-4 h-4" />
              </button>
            </div>

            {/* Tile Layer Selector */}
            <div className="bg-slate-900/90 backdrop-blur-md rounded-lg border border-slate-700/60 p-1 flex flex-col shadow-lg">
              <button
                onClick={() => handleTileChange('dark')}
                className={`px-2 py-1 text-[10px] font-semibold rounded text-left transition-colors ${
                  activeTileType === 'dark' ? 'bg-brand text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Dark
              </button>
              <button
                onClick={() => handleTileChange('voyager')}
                className={`px-2 py-1 text-[10px] font-semibold rounded text-left transition-colors ${
                  activeTileType === 'voyager' ? 'bg-brand text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Streets
              </button>
              <button
                onClick={() => handleTileChange('osm')}
                className={`px-2 py-1 text-[10px] font-semibold rounded text-left transition-colors ${
                  activeTileType === 'osm' ? 'bg-brand text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                OSM
              </button>
            </div>
          </div>

          {/* Bottom attribution disclaimer */}
          <div className="absolute bottom-2 left-3 z-10 text-[10px] text-slate-400 bg-slate-950/85 px-3 py-1 rounded-md border border-slate-800 backdrop-blur-sm">
            Observable infrastructure coordinates indicate relay/MTA egress routing locations, not guaranteed physical user presence.
          </div>
        </div>

        {/* Right Telemetry & Node Inspector Panel */}
        <div className="rounded-xl border border-workspace-border bg-workspace-card p-4 flex flex-col justify-between space-y-4 h-[540px] overflow-y-auto">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-workspace-border pb-2">
              <h3 className="text-xs font-bold text-text-primary uppercase tracking-wide flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-brand" />
                Infrastructure Telemetry
              </h3>
              <span className="text-[10px] text-text-muted font-mono">
                {displayedMarkers.length} node(s)
              </span>
            </div>

            {/* Quick Node Search */}
            <div className="relative">
              <Search className="w-3 h-3 absolute left-2.5 top-2.5 text-text-muted" />
              <input
                type="text"
                placeholder="Search by IP, provider, ASN, city..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-7 pr-2 py-1.5 text-[11px] bg-workspace border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand"
              />
            </div>

            {/* Selected Node Details with Rich Classification Card */}
            {selectedMarker ? (
              (() => {
                const nodeInfo = getNodeClassificationInfo(selectedMarker);
                const IconComponent = nodeInfo.icon;
                return (
                  <div className="space-y-3">
                    <div className={`p-3 rounded-lg bg-workspace border ${nodeInfo.cardBorder} space-y-2.5 shadow-sm`}>
                      {/* Connection Category Banner */}
                      <div className={`p-2 rounded-md border flex items-start gap-2 ${nodeInfo.bg}`}>
                        <IconComponent className={`w-4 h-4 shrink-0 mt-0.5 ${nodeInfo.color}`} />
                        <div>
                          <div className={`text-xs font-bold ${nodeInfo.color}`}>
                            {nodeInfo.label}
                          </div>
                          <div className="text-[10px] text-text-muted leading-tight mt-0.5">
                            {nodeInfo.description}
                          </div>
                        </div>
                      </div>

                      {/* Header Info */}
                      {(() => {
                        const isDeduced = selectedMarker.role === 'DEDUCED_HUMAN_ORIGIN' || selectedMarker.id === 'marker-deduced-human-origin';
                        const isOrigin = isDeduced || selectedMarker.role === 'ORIGIN_HOP' || selectedMarker.sequence_number === 1;
                        const isCloudRelay = !isDeduced && Boolean(
                          selectedMarker.is_cloud || selectedMarker.is_datacenter ||
                          (selectedMarker.provider && (selectedMarker.provider.toLowerCase().includes('microsoft') || selectedMarker.provider.toLowerCase().includes('google') || selectedMarker.provider.toLowerCase().includes('amazon'))) ||
                          (selectedMarker.asn_org && (selectedMarker.asn_org.toLowerCase().includes('microsoft') || selectedMarker.asn_org.toLowerCase().includes('google') || selectedMarker.asn_org.toLowerCase().includes('amazon')))
                        );

                        return (
                          <>
                            <div className="flex items-center justify-between gap-1">
                              <span className={`font-bold text-sm font-mono truncate ${isDeduced ? 'text-emerald-400' : 'text-text-primary'}`}>
                                {selectedMarker.ip_address}
                              </span>
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 ${
                                isDeduced
                                  ? 'bg-emerald-500/25 text-emerald-300 border border-emerald-500/40'
                                  : isOrigin
                                  ? isCloudRelay
                                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                  : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                              }`}>
                                {isDeduced
                                  ? '🎯 Deduced Human Sender'
                                  : isOrigin
                                  ? isCloudRelay
                                    ? 'First Cloud Relay (MTA)'
                                    : 'Sender Client Device'
                                  : `Hop #${selectedMarker.sequence_number || '1'}`}
                              </span>
                            </div>

                            {/* Location & Provider */}
                            <div className="text-xs text-text-secondary space-y-0.5">
                              <div>
                                <strong className="text-text-primary">
                                  {selectedMarker.city_name ? `${selectedMarker.city_name}, ` : ''}
                                </strong>
                                {selectedMarker.region_name ? `${selectedMarker.region_name}, ` : ''}
                                {selectedMarker.country_name || 'Unknown Country'}
                              </div>
                              {selectedMarker.provider && (
                                <div className="text-[11px] text-text-secondary font-medium">
                                  Provider / Network: <span className="text-text-primary">{selectedMarker.provider}</span>
                                </div>
                              )}
                              {selectedMarker.asn && (
                                <div className="text-[11px] text-text-muted font-mono">
                                  ASN: <span className="text-slate-300">{selectedMarker.asn}</span> {selectedMarker.asn_org ? `(${selectedMarker.asn_org})` : ''}
                                </div>
                              )}
                              {selectedMarker.host && (
                                <div className="text-[11px] text-text-muted truncate font-mono">
                                  Host: {selectedMarker.host}
                                </div>
                              )}
                            </div>

                            {/* Deduced Forensic Evidence Signals Breakdown */}
                            {selectedMarker.forensic_explanation && (
                              <div className="p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-[11px] text-emerald-200/90 leading-relaxed space-y-1.5">
                                <div className="flex items-center gap-1.5 font-bold text-emerald-300">
                                  <Sparkles className="w-3.5 h-3.5" />
                                  <span>Passive .EML Forensic Triangulation:</span>
                                </div>
                                <div className="text-slate-300 text-[11px]">
                                  {selectedMarker.forensic_explanation}
                                </div>
                              </div>
                            )}

                            {selectedMarker.evidence_signals && selectedMarker.evidence_signals.length > 0 && (
                              <div className="space-y-1.5 pt-1.5 border-t border-workspace-border">
                                <div className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider flex items-center justify-between">
                                  <span>Forensic Evidence Signals</span>
                                  <span className="text-[9px] text-slate-400 font-normal">Passive .eml parsing</span>
                                </div>
                                <div className="space-y-1">
                                  {selectedMarker.evidence_signals.map((sig, sIdx) => (
                                    <div key={sIdx} className="p-1.5 rounded bg-slate-900/80 border border-emerald-500/20 text-[10px]">
                                      <div className="flex items-center justify-between text-emerald-300 font-semibold">
                                        <span>{sig.category.toUpperCase()}: {sig.signal}</span>
                                        <span className="text-emerald-400/90 font-mono">+{Math.round(sig.confidence_weight * 100)}%</span>
                                      </div>
                                      <div className="text-white font-mono text-[11px] mt-0.5">{sig.value}</div>
                                      <div className="text-text-muted mt-0.5">{sig.detail}</div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {isOrigin && isCloudRelay && (
                              <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-[11px] text-amber-200/90 leading-relaxed">
                                <strong className="text-amber-300 block mb-0.5">ℹ️ Provider Privacy Shield:</strong>
                                Webmail providers (Microsoft Outlook, Google Gmail) redact the user's home IP to protect privacy. This observable hop represents the provider's mail server ({selectedMarker.provider || selectedMarker.asn_org || 'Cloud Datacenter'}), not the personal device. Check the Deduced Human Origin node (#0) on the map for the physical sender location triangulated from internal .eml evidence.
                              </div>
                            )}
                          </>
                        );
                      })()}

                      {/* 4-Pill Privacy Classification Matrix */}
                      <div className="pt-2 border-t border-workspace-border grid grid-cols-2 gap-1.5 text-[10px]">
                        <div className={`px-2 py-1 rounded flex items-center justify-between border ${
                          selectedMarker.is_tor || selectedMarker.connection_type === 'TOR'
                            ? 'bg-purple-500/20 text-purple-300 border-purple-500/40 font-bold'
                            : 'bg-workspace text-text-muted border-workspace-border'
                        }`}>
                          <span>Tor Exit:</span>
                          {selectedMarker.is_tor || selectedMarker.connection_type === 'TOR' ? (
                            <CheckCircle2 className="w-3 h-3 text-purple-400" />
                          ) : (
                            <XCircle className="w-3 h-3 opacity-40" />
                          )}
                        </div>

                        <div className={`px-2 py-1 rounded flex items-center justify-between border ${
                          selectedMarker.is_vpn || selectedMarker.connection_type === 'VPN'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold'
                            : 'bg-workspace text-text-muted border-workspace-border'
                        }`}>
                          <span>VPN Tunnel:</span>
                          {selectedMarker.is_vpn || selectedMarker.connection_type === 'VPN' ? (
                            <CheckCircle2 className="w-3 h-3 text-amber-400" />
                          ) : (
                            <XCircle className="w-3 h-3 opacity-40" />
                          )}
                        </div>

                        <div className={`px-2 py-1 rounded flex items-center justify-between border ${
                          selectedMarker.is_cloud || selectedMarker.is_datacenter || selectedMarker.connection_type === 'CLOUD'
                            ? 'bg-sky-500/20 text-sky-300 border-sky-500/40 font-bold'
                            : 'bg-workspace text-text-muted border-workspace-border'
                        }`}>
                          <span>Cloud VPS:</span>
                          {selectedMarker.is_cloud || selectedMarker.is_datacenter || selectedMarker.connection_type === 'CLOUD' ? (
                            <CheckCircle2 className="w-3 h-3 text-sky-400" />
                          ) : (
                            <XCircle className="w-3 h-3 opacity-40" />
                          )}
                        </div>

                        <div className={`px-2 py-1 rounded flex items-center justify-between border ${
                          selectedMarker.is_personal_mail || selectedMarker.connection_type === 'PERSONAL_MAIL' || selectedMarker.connection_type === 'RESIDENTIAL'
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-bold'
                            : 'bg-workspace text-text-muted border-workspace-border'
                        }`}>
                          <span>Personal:</span>
                          {selectedMarker.is_personal_mail || selectedMarker.connection_type === 'PERSONAL_MAIL' || selectedMarker.connection_type === 'RESIDENTIAL' ? (
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <XCircle className="w-3 h-3 opacity-40" />
                          )}
                        </div>
                      </div>

                      {/* Coordinates & Accuracy */}
                      <div className="grid grid-cols-2 gap-2 text-[11px] text-text-muted pt-2 border-t border-workspace-border font-mono">
                        <div>Lat: <strong className="text-text-secondary">{selectedMarker.latitude?.toFixed(4)}</strong></div>
                        <div>Lon: <strong className="text-text-secondary">{selectedMarker.longitude?.toFixed(4)}</strong></div>
                        <div>Radius: <strong className="text-text-secondary">±{selectedMarker.accuracy_radius_km || 50}km</strong></div>
                        <div>Confidence: <strong className="text-severity-safe">{Math.round((selectedMarker.confidence || 0.85) * 100)}%</strong></div>
                      </div>
                    </div>

                    <button
                      onClick={() => {
                        if (mapInstanceRef.current && selectedMarker.latitude && selectedMarker.longitude) {
                          mapInstanceRef.current.flyTo([selectedMarker.latitude, selectedMarker.longitude], 13, { duration: 1.2 });
                        }
                      }}
                      className="w-full py-1.5 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors flex items-center justify-center gap-1.5"
                    >
                      <Crosshair className="w-3.5 h-3.5" />
                      Zoom into City Street Level
                    </button>
                  </div>
                );
              })()
            ) : (
              <div className="p-4 text-center rounded-lg bg-workspace border border-dashed border-workspace-border text-xs text-text-muted space-y-1">
                <MapPin className="w-6 h-6 mx-auto text-text-muted/60 mb-1" />
                <div className="font-semibold text-text-secondary">No node selected</div>
                <p className="text-[11px]">Click on any map marker or transmission hop below to inspect classified telemetry.</p>
              </div>
            )}

            {/* List of Mapped Hops with Visual Category Badges */}
            <div className="space-y-2 pt-2">
              <div className="text-[10px] font-bold text-text-muted uppercase tracking-wide">
                Transmission Journey Nodes
              </div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {displayedMarkers.map((m, idx) => {
                  const nodeInfo = getNodeClassificationInfo(m);
                  return (
                    <div
                      key={m.id || idx}
                      onClick={() => {
                        setSelectedMarker(m);
                        if (mapInstanceRef.current && m.latitude && m.longitude) {
                          mapInstanceRef.current.flyTo([m.latitude, m.longitude], 8, { duration: 1 });
                        }
                      }}
                      className={`p-2 rounded-lg border text-xs cursor-pointer transition-colors flex items-center justify-between ${
                        selectedMarker?.id === m.id
                          ? 'bg-workspace-secondary border-brand text-text-primary shadow-sm'
                          : 'bg-workspace border-workspace-border text-text-muted hover:text-text-primary'
                      }`}
                    >
                      <div className="min-w-0 pr-2">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono font-semibold truncate text-[11px] text-text-primary">
                            {m.ip_address}
                          </span>
                          <span className={`text-[8px] font-extrabold px-1.5 py-0.2 rounded uppercase ${nodeInfo.bg} ${nodeInfo.color}`}>
                            {nodeInfo.badge}
                          </span>
                        </div>
                        <div className="text-[10px] truncate text-text-muted mt-0.5">
                          {m.provider ? `${m.provider} · ` : ''}{m.city_name ? `${m.city_name}, ` : ''}{m.country_name}
                        </div>
                      </div>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border shrink-0 font-mono ${
                        m.role === 'DEDUCED_HUMAN_ORIGIN'
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : 'bg-workspace-card text-text-muted border-workspace-border'
                      }`}>
                        {m.role === 'DEDUCED_HUMAN_ORIGIN' ? '👤 HUMAN' : m.sequence_number ? `#${m.sequence_number}` : `${idx + 1}`}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Attribution Note */}
          <div className="p-2.5 rounded-lg bg-workspace border border-workspace-border text-[10px] text-text-muted leading-relaxed">
            Observational relay coordinates reflect cloud/MTA routing hops. Personal human origin is forensically triangulated from passive .eml artifacts (Timezone offset, regional postal PIN codes, telephone prefixes, and SPF client traces) with zero social engineering.
          </div>
        </div>
      </div>
    </div>
  );
};

export default GeoIntelligenceMap;
