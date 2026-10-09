import { useState, useEffect, useCallback, useRef } from 'react';
import { NotificationItem, getRecentNotifications, triggerTestNotification } from './api';

const LOCAL_STORAGE_KEY = 'mailintel_soc_notifications';

export type WebSocketStatus = 'connected' | 'connecting' | 'disconnected';

export interface UseNotificationsResult {
  notifications: NotificationItem[];
  unreadCount: number;
  status: WebSocketStatus;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  clearAll: () => void;
  sendTestAlert: () => Promise<void>;
  reconnect: () => void;
}

/**
 * Custom React hook managing real-time WebSocket connection for MailinTeL SOC alert stream.
 */
export const useNotificationsWebSocket = (): UseNotificationsResult => {
  const [notifications, setNotifications] = useState<NotificationItem[]>(() => {
    try {
      const saved = localStorage.getItem(LOCAL_STORAGE_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [status, setStatus] = useState<WebSocketStatus>('connecting');
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const isMountedRef = useRef<boolean>(true);

  // Sync to local storage on change
  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(notifications.slice(0, 50)));
    } catch (e) {
      console.warn('Could not cache notifications to localStorage:', e);
    }
  }, [notifications]);

  // Connect WebSocket
  const connectWs = useCallback(() => {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    setStatus('connecting');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname || 'localhost';
    // When running Vite on 5173, backend is on 8000
    const port = window.location.port === '5173' ? '8000' : (window.location.port || '8000');
    const wsUrl = `${protocol}//${host}:${port}/ws/notifications`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        setStatus('connected');
        console.log('[MailinTeL SOC] Real-time notification WebSocket connected:', wsUrl);
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const data = JSON.parse(event.data);

          if (data.event === 'CONNECTED' && Array.isArray(data.notifications)) {
            // Merge existing with backend history, avoiding duplicate IDs
            setNotifications((prev) => {
              const existingIds = new Set(prev.map((n) => n.id));
              const newItems = data.notifications.filter((n: NotificationItem) => !existingIds.has(n.id));
              return [...newItems, ...prev];
            });
          } else if (data.event === 'NOTIFICATION' && data.notification) {
            const newNotif: NotificationItem = {
              ...data.notification,
              read: false,
            };
            setNotifications((prev) => [newNotif, ...prev.filter((n) => n.id !== newNotif.id)]);
          }
        } catch (err) {
          console.warn('[MailinTeL SOC] Error parsing WebSocket message:', err);
        }
      };

      ws.onerror = (err) => {
        console.warn('[MailinTeL SOC] WebSocket encounter:', err);
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        setStatus('disconnected');
        wsRef.current = null;
        // Exponential backoff reconnect
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          if (isMountedRef.current) {
            connectWs();
          }
        }, 3500);
      };
    } catch (e) {
      console.warn('[MailinTeL SOC] Could not establish WebSocket:', e);
      setStatus('disconnected');
    }
  }, []);

  // Initial mount & fallback fetch
  useEffect(() => {
    isMountedRef.current = true;
    connectWs();

    // Also fetch initial REST notifications if empty
    getRecentNotifications()
      .then((items) => {
        if (items && items.length > 0) {
          setNotifications((prev) => {
            const existingIds = new Set(prev.map((n) => n.id));
            const newItems = items.filter((n) => !existingIds.has(n.id));
            return [...prev, ...newItems];
          });
        }
      })
      .catch(() => {
        // quiet fallback
      });

    return () => {
      isMountedRef.current = false;
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connectWs]);

  const markAsRead = useCallback((id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  const sendTestAlert = useCallback(async () => {
    try {
      await triggerTestNotification({
        title: 'SOC Alert: Malicious Domain Homograph',
        message: 'AI Copilot detected brand spoofing domain with zero-hour credential lure.',
        severity: 'critical',
        type: 'PHISHING_ALERT',
      });
    } catch (e) {
      console.error('Failed to trigger test alert:', e);
    }
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return {
    notifications,
    unreadCount,
    status,
    markAsRead,
    markAllAsRead,
    clearAll,
    sendTestAlert,
    reconnect: connectWs,
  };
};
