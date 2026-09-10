/**
 * Minimal typed event bus used only to let the axios interceptor (a plain
 * module, outside React) notify the rest of the app about cross-cutting
 * conditions — an expired session or a fully unreachable backend — without
 * every call site having to wire that up individually.
 *
 * This deliberately does NOT replace per-call-site error handling: 4xx/5xx
 * errors are still returned to the caller (see api.ts) so views can decide
 * inline-banner vs full-page. Only the two truly app-wide conditions are
 * broadcast here.
 */

export type ApiEventName = 'unauthorized' | 'network-error';

type Listener = () => void;

const listeners: Record<ApiEventName, Set<Listener>> = {
  unauthorized: new Set(),
  'network-error': new Set(),
};

export const apiEvents = {
  on(event: ApiEventName, listener: Listener): () => void {
    listeners[event].add(listener);
    return () => listeners[event].delete(listener);
  },
  emit(event: ApiEventName): void {
    listeners[event].forEach((listener) => listener());
  },
};
