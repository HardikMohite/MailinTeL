import React, { useState, useEffect, useMemo, useRef } from 'react';
import L from 'leaflet';
import {
  Globe,
  MapPin,
  Search,
  RefreshCw,
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
  Building,
  Server,
  AlertTriangle,
} from 'lucide-react';
import {
  getIPGeolocation,
  getEmailGeoInfrastructure,
  GeoMarkerItem,
  GeoPathSegment,
  EmailGeoInfrastructureResponse,
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
  embedded = false,
}) => {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const markersLayerGroupRef = useRef<L.LayerGroup | null>(null);
  const pathsLayerGroupRef = useRef<L.LayerGroup | null>(null);

  const [viewMode, setViewMode] = useState<ViewMode>(
    embedded && initialEmailId ? 'email' : 'lookup'
  );
  const [activeTileType, setActiveTileType] = useState<TileLayerType>('dark');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilterType>('ALL');

  const [selectedEmailId, setSelectedEmailId] = useState<string>(initialEmailId || '');

  // Data state
  const [emailGeo, setEmailGeo] = useState<EmailGeoInfrastructureResponse | null>(null);

  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [fallbackWarning, setFallbackWarning] = useState<{
    type: 'PRIVATE_IP' | 'INVALID_SYNTAX' | 'NO_COORDS';
    title: string;
    message: string;
  } | null>(null);
  const [selectedMarker, setSelectedMarker] = useState<GeoMarkerItem | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [ipQuery, setIpQuery] = useState<string>('185.220.101.5');
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

  const isPrivateIP = (ip: string) => {
    const clean = ip.trim();
    if (clean === 'localhost' || clean === '127.0.0.1' || clean === '::1') return true;
    if (/^10\./.test(clean)) return true;
    if (/^192\.168\./.test(clean)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)) return true;
    if (/^169\.254\./.test(clean)) return true;
    return false;
  };

  const isValidIPOrHost = (val: string) => {
    const clean = val.trim();
    if (!clean) return false;
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$/;
    const domainRegex = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
    return ipv4Regex.test(clean) || ipv6Regex.test(clean) || domainRegex.test(clean) || clean === 'localhost';
  };

  const loadContext = async () => {
    try {
      if (embedded && initialEmailId) {
        setSelectedEmailId(initialEmailId);
        setViewMode('email');
        fetchEmailGeo(initialEmailId);
      } else {
        // Dedicated Threat Intelligence Geo Transmission Service
        setViewMode('lookup');
        setIpQuery('185.220.101.5');
        handleIpLookup('185.220.101.5');
      }
    } catch (err) {
      console.error('Failed to load geo context:', err);
    }
  };

  useEffect(() => {
    if (initialEmailId && initialEmailId !== selectedEmailId) {
      setSelectedEmailId(initialEmailId);
      setViewMode('email');
      fetchEmailGeo(initialEmailId);
    }
  }, [initialEmailId]);

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

  const handleIpLookup = async (overrideIp?: string) => {
    const clean = (overrideIp !== undefined ? overrideIp : ipQuery).trim();
    if (!clean) return;
    if (overrideIp !== undefined) {
      setIpQuery(overrideIp);
    }
    setFallbackWarning(null);
    setError(null);

    // 1. Validation check for malformed IP / host
    if (!isValidIPOrHost(clean)) {
      setFallbackWarning({
        type: 'INVALID_SYNTAX',
        title: 'Invalid IP Address or Hostname',
        message: `"${clean}" does not match standard IPv4 (e.g. 185.220.101.5), IPv6, or domain name syntax. Please enter a valid routable IP address or host.`,
      });
      return;
    }

    // 2. Fallback check for RFC 1918 / Private Subnet / Loopback
    if (isPrivateIP(clean)) {
      setFallbackWarning({
        type: 'PRIVATE_IP',
        title: 'RFC 1918 Private / Non-Routable IP Detected',
        message: `The address "${clean}" is reserved for private local networks or loopback interfaces. Private IP addresses exist only inside internal LANs and do not route over the public Internet, so physical geographic coordinates cannot be resolved.`,
      });
      return;
    }

    setSearchingIp(true);
    try {
      const data = await getIPGeolocation(clean);
      if (data.is_private) {
        setFallbackWarning({
          type: 'PRIVATE_IP',
          title: 'Internal / Non-Routable Gateway',
          message: `The address "${clean}" was flagged as an internal or non-routable infrastructure hop. Geographic mapping is not possible for private subnets.`,
        });
        return;
      }
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
        setFallbackWarning({
          type: 'NO_COORDS',
          title: 'Coordinates Not Available',
          message: `No physical coordinates could be resolved for "${clean}". ASN and ISP routing records may still be listed in Threat Intel.`,
        });
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || `Failed to geolocate IP: ${clean}`);
    } finally {
      setSearchingIp(false);
    }
  };

  // Extract all current markers and paths
  const allCurrentMarkers = useMemo((): GeoMarkerItem[] => {
    return emailGeo?.markers || [];
  }, [emailGeo]);

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
      const isDestination = m.role === 'DESTINATION_NODE' || m.role === 'RECIPIENT_GATEWAY';

      // Custom pulsing HTML marker with distinct category badge & icon
      const customIcon = L.divIcon({
        className: 'custom-geo-marker',
        html: `
          <div style="position: relative; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; cursor: pointer;">
            ${isDeducedOrigin ? `
              <div style="position: absolute; width: 44px; height: 44px; border-radius: 9999px; border: 2px solid #10B981; animation: pulse-ring 1.8s cubic-bezier(0.4, 0, 0.6, 1) infinite;"></div>
              <div style="position: absolute; width: 38px; height: 38px; border-radius: 9999px; border: 2px dashed #34D399; animation: spin-slow 10s linear infinite;"></div>
            ` : isOrigin ? `<div style="position: absolute; width: 36px; height: 36px; border-radius: 9999px; border: 2px dashed #EF4444; animation: spin-slow 8s linear infinite;"></div>` : isDestination ? `<div style="position: absolute; width: 36px; height: 36px; border-radius: 9999px; border: 2px solid #6366F1; opacity: 0.6;"></div>` : ''}
            <div style="position: absolute; width: 30px; height: 30px; border-radius: 9999px; background-color: ${markerColor}; opacity: 0.35; animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;"></div>
            <div style="position: relative; width: 24px; height: 24px; border-radius: 9999px; background-color: ${markerColor}; border: 2px solid #FFFFFF; box-shadow: 0 0 12px ${markerColor}; display: flex; align-items: center; justify-content: center; color: #FFFFFF; font-size: ${isDeducedOrigin ? '12px' : '10px'}; font-weight: 800; font-family: monospace;">
              ${isDeducedOrigin ? '👤' : (m.sequence_number != null ? m.sequence_number : idx + 1)}
            </div>
            <div style="position: absolute; bottom: -8px; background: #0F172A; border: 1px solid ${markerColor}; border-radius: 4px; padding: 1px 4px; font-size: 8px; font-weight: 800; color: ${markerColor}; text-transform: uppercase; white-space: nowrap; box-shadow: 0 2px 4px rgba(0,0,0,0.6);">
              ${isDestination ? 'INBOUND' : badgeLabel}
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
            ${isDeducedOrigin ? `<span style="font-size: 9px; font-weight: 800; background: #10B98133; color: #34D399; border: 1px solid #10B98166; border-radius: 4px; padding: 1px 4px;">DEDUCED SENDER</span>` : isOrigin ? (isCloudProvider ? `<span style="font-size: 9px; font-weight: 800; background: #F59E0B33; color: #FBBF24; border: 1px solid #F59E0B66; border-radius: 4px; padding: 1px 4px;">SENDER EGRESS</span>` : `<span style="font-size: 9px; font-weight: 800; background: #10B98133; color: #34D399; border: 1px solid #10B98166; border-radius: 4px; padding: 1px 4px;">SENDER ORIGIN</span>`) : isDestination ? `<span style="font-size: 9px; font-weight: 800; background: #6366F133; color: #818CF8; border: 1px solid #6366F166; border-radius: 4px; padding: 1px 4px;">RECIPIENT GATEWAY (YOU)</span>` : ''}
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
            ${m.confidence != null ? `<div>Accuracy / Confidence: <strong style="color: #34D399;">${Math.round(m.confidence > 1 ? m.confidence : m.confidence * 100)}%</strong></div>` : ''}
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
    if (m.role === 'RECIPIENT_GATEWAY' || m.role === 'DESTINATION_NODE') {
      return {
        label: 'Recipient Inbound Gateway (Your Organization / Destination)',
        badge: 'RECIPIENT GATEWAY',
        color: 'text-indigo-400',
        bg: 'bg-indigo-500/20 border-indigo-500/40',
        cardBorder: 'border-indigo-500/50',
        icon: Building,
        description: 'Destination inbound gateway where the platform user / recipient organization received the message. Final terminus of the delivery path.',
      };
    }
    if (m.role === 'ORIGIN_HOP') {
      return {
        label: 'Sender Outbound MTA / Egress Relay',
        badge: 'SENDER EGRESS',
        color: 'text-amber-400',
        bg: 'bg-amber-500/20 border-amber-500/40',
        cardBorder: 'border-amber-500/50',
        icon: Server,
        description: 'Sender mail server or intermediate cloud relay where the message was initially dispatched into the public internet.',
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

      {/* Top Header & Threat Service Banner */}
      {!embedded && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-workspace-card border border-workspace-border shadow-xs">
            <div className="flex items-center gap-3.5">
              <div className="w-11 h-11 rounded-xl bg-brand/10 border border-brand/20 text-brand flex items-center justify-center shrink-0">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-bold text-text-primary tracking-tight">
                    Geo Transmission Intelligence
                  </h1>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-brand/10 text-brand border border-brand/20">
                    Threat Intelligence Service
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-text-muted mt-0.5">
                  Resolve physical server coordinates, ASN routing boundaries, Tor/VPN anonymity shields, and egress transit points for any network indicator.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 self-start md:self-auto">
              <button
                onClick={() => handleIpLookup('185.220.101.5')}
                disabled={searchingIp || loading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-workspace border border-workspace-border text-xs text-text-muted hover:text-text-primary hover:bg-workspace-card transition-colors disabled:opacity-50"
                title="Reset to default sample indicator"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${searchingIp || loading ? 'animate-spin' : ''}`} />
                <span>Reset Map</span>
              </button>
            </div>
          </div>

          {/* Standalone IP / Indicator Search Bar with One-Click Samples */}
          <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-xs space-y-3">
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
              <div className="relative flex-1">
                <Crosshair className="w-4 h-4 text-brand absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Enter any IPv4, IPv6, or hostname (e.g. 185.220.101.5, 8.8.8.8, relay.attacker-host.net)..."
                  value={ipQuery}
                  onChange={(e) => setIpQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleIpLookup()}
                  className="w-full pl-9 pr-4 py-2 bg-workspace border border-workspace-border rounded-lg text-xs text-text-primary font-mono focus:outline-none focus:border-brand placeholder:text-text-muted placeholder:font-sans"
                />
              </div>
              <button
                onClick={() => handleIpLookup()}
                disabled={searchingIp || !ipQuery.trim()}
                className="px-5 py-2 rounded-lg bg-brand hover:bg-brand-hover text-white text-xs font-semibold transition-all disabled:opacity-50 flex items-center justify-center gap-2 shrink-0 shadow-xs"
              >
                {searchingIp ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Locating Infrastructure…</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Locate Transmission Node</span>
                  </>
                )}
              </button>
            </div>

            {/* Quick Sample Indicator Chips */}
            <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px]">
              <span className="text-text-muted font-medium mr-1">Quick Samples:</span>
              <button
                onClick={() => handleIpLookup('185.220.101.5')}
                className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30 hover:bg-purple-500/20 font-mono transition-colors"
                title="Tor Exit Relay in Frankfurt, Germany"
              >
                🧅 185.220.101.5 (Tor Exit Node)
              </button>
              <button
                onClick={() => handleIpLookup('8.8.8.8')}
                className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20 font-mono transition-colors"
                title="Google Anycast DNS in Mountain View, US"
              >
                🌐 8.8.8.8 (Google DNS)
              </button>
              <button
                onClick={() => handleIpLookup('1.1.1.1')}
                className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/30 hover:bg-sky-500/20 font-mono transition-colors"
                title="Cloudflare CDN Edge"
              >
                ⚡ 1.1.1.1 (Cloudflare Edge)
              </button>
              <button
                onClick={() => handleIpLookup('95.214.54.1')}
                className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20 font-mono transition-colors"
                title="Known Bulletproof Hosting Node"
              >
                ⚠️ 95.214.54.1 (Bulletproof Host)
              </button>
              <button
                onClick={() => handleIpLookup('192.168.1.1')}
                className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20 font-mono transition-colors"
                title="Test Private RFC 1918 Subnet Fallback"
              >
                🛡️ 192.168.1.1 (Private Fallback Test)
              </button>
            </div>
          </div>

          {/* Fallback Warning Alert Card */}
          {fallbackWarning && (
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs space-y-2 animate-fade-in shadow-xs">
              <div className="flex items-center gap-2 font-bold text-amber-200">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>{fallbackWarning.title}</span>
              </div>
              <p className="text-amber-300/90 leading-relaxed font-sans">
                {fallbackWarning.message}
              </p>
              <div className="flex items-center gap-2 pt-1">
                <span className="text-[11px] text-text-muted">Suggested test indicator:</span>
                <button
                  onClick={() => handleIpLookup('185.220.101.5')}
                  className="px-2.5 py-0.5 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 text-[11px] font-semibold border border-amber-500/40 transition-colors"
                >
                  Locate Public Tor Relay (185.220.101.5) →
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded-xl bg-severity-high-soft border border-severity-high/30 text-xs text-severity-high flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
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

      {/* Forensic Passive Origin Triangulation & Proxy Unmasking Alert Banner */}
      {viewMode === 'email' && emailGeo?.deduced_human_origin?.deduced_city && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-950/80 via-slate-900 to-slate-900 border-2 border-emerald-500/50 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-full bg-emerald-500/5 blur-2xl pointer-events-none" />
          <div className="flex items-start gap-3.5 z-10">
            <div className="relative p-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 shrink-0 mt-0.5">
              <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-400 animate-ping opacity-75" />
              <UserCheck className="w-5 h-5" />
            </div>
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-black uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/80" />
                  Deduced Physical Human Origin
                </span>
                <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                  {Math.round(
                    (emailGeo.deduced_human_origin.confidence_score || 85) > 1
                      ? (emailGeo.deduced_human_origin.confidence_score || 85)
                      : (emailGeo.deduced_human_origin.confidence_score || 0.85) * 100
                  )}% Confidence
                </span>
                {emailGeo.deduced_human_origin.is_proxy_or_cloud_relayed && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 font-semibold flex items-center gap-1">
                    <Cloud className="w-3 h-3 text-amber-400" />
                    {emailGeo.deduced_human_origin.proxy_provider_name || 'Cloud / Proxy Relayed'}
                  </span>
                )}
                {emailGeo.forwarding_analysis?.is_forwarded && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 font-semibold flex items-center gap-1">
                    <Layers className="w-3 h-3 text-purple-400" />
                    Forwarded Mail ({emailGeo.forwarding_analysis.forwarding_type})
                  </span>
                )}
                {emailGeo.deduced_human_origin.client_submission_ip && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
                    Client IP: {emailGeo.deduced_human_origin.client_submission_ip}
                  </span>
                )}
              </div>
              <div className="text-base font-bold text-white flex flex-wrap items-baseline gap-2">
                <span>Triangulated Location:</span>
                <span className="text-emerald-300 font-extrabold text-lg tracking-tight">
                  {emailGeo.deduced_human_origin.deduced_city}
                  {emailGeo.deduced_human_origin.deduced_region ? `, ${emailGeo.deduced_human_origin.deduced_region}` : ''}
                  {emailGeo.deduced_human_origin.deduced_country ? `, ${emailGeo.deduced_human_origin.deduced_country}` : ''}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
                {emailGeo.deduced_human_origin.server_infrastructure_location?.city && (
                  <div className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
                    <span>Sender Outbound Relay:</span>
                    <strong className="text-amber-300 font-semibold">
                      {emailGeo.deduced_human_origin.server_infrastructure_location.provider || 'Cloud Host'} ({emailGeo.deduced_human_origin.server_infrastructure_location.city}, {emailGeo.deduced_human_origin.server_infrastructure_location.country})
                    </strong>
                    {emailGeo.deduced_human_origin.server_infrastructure_location.ip_address && (
                      <span className="text-slate-500">[{emailGeo.deduced_human_origin.server_infrastructure_location.ip_address}]</span>
                    )}
                  </div>
                )}
                {emailGeo.deduced_human_origin.recipient_gateway_location?.city && (
                  <div className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
                    <span className="text-indigo-400">Recipient Gateway (You):</span>
                    <strong className="text-indigo-300 font-semibold">
                      {emailGeo.deduced_human_origin.recipient_gateway_location.provider || 'Inbound MX'} ({emailGeo.deduced_human_origin.recipient_gateway_location.city}, {emailGeo.deduced_human_origin.recipient_gateway_location.country})
                    </strong>
                    {emailGeo.deduced_human_origin.recipient_gateway_location.ip_address && (
                      <span className="text-slate-500">[{emailGeo.deduced_human_origin.recipient_gateway_location.ip_address}]</span>
                    )}
                  </div>
                )}
              </div>
              {emailGeo.deduced_human_origin.forensic_explanation && (
                <p className="text-xs text-slate-300 mt-1.5 leading-relaxed font-sans max-w-4xl">
                  {emailGeo.deduced_human_origin.forensic_explanation}
                </p>
              )}
            </div>
          </div>
          {emailGeo.deduced_human_origin.latitude && emailGeo.deduced_human_origin.longitude && (
            <button
              onClick={() => {
                if (mapInstanceRef.current && emailGeo.deduced_human_origin?.latitude && emailGeo.deduced_human_origin?.longitude) {
                  mapInstanceRef.current.flyTo(
                    [emailGeo.deduced_human_origin.latitude, emailGeo.deduced_human_origin.longitude],
                    11,
                    { duration: 1.2 }
                  );
                }
              }}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shrink-0 transition-all flex items-center gap-2 shadow-lg shadow-emerald-900/40 hover:scale-105 self-start md:self-center cursor-pointer z-10"
            >
              <Navigation className="w-4 h-4" />
              <span>Focus Real Origin</span>
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
              <span className="text-red-400 font-medium">Sender Beacon</span>
            </div>
            <span className="text-slate-600">·</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-indigo-500 border border-white shadow-sm shadow-indigo-500/50"></span>
              <span className="text-indigo-300 font-semibold">📥 Recipient Gateway (You)</span>
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
                        <div>Confidence: <strong className="text-severity-safe">{Math.round((selectedMarker.confidence || 0.85) > 1 ? (selectedMarker.confidence || 0.85) : (selectedMarker.confidence || 0.85) * 100)}%</strong></div>
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
