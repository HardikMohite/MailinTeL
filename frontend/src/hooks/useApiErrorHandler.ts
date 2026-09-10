import { useCallback } from 'react';
import axios, { AxiosError } from 'axios';

/**
 * Maps every backend error shape (see api docs) + network-level failures to a
 * single, UI-friendly discriminated union. This is the ONLY place that should
 * ever branch on HTTP status code — screens/components consume ParsedApiError,
 * never a raw AxiosError.
 *
 * Deliberately conservative about what it surfaces: only `error`/`message`
 * fields from the backend body are ever shown to the user. `path`, stack
 * traces, and raw response bodies are never rendered — see console.error
 * call sites (dev-only) for that instead.
 */
export type ApiErrorKind =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'too_large'
  | 'validation'
  | 'rate_limited'
  | 'server_error'
  | 'network'
  | 'unknown';

export interface PydanticErrorDetail {
  loc: (string | number)[];
  msg: string;
  type: string;
}

export interface ParsedApiError {
  kind: ApiErrorKind;
  title: string;
  message: string;
  /** Only set for 429s that carried a Retry-After header. */
  retryAfterSeconds?: number;
  /** Only set for 422s — structured, field-level validation issues. */
  details?: PydanticErrorDetail[];
  /** Raw HTTP status, if one was received (undefined for network failures). */
  status?: number;
}

const FALLBACK_MESSAGES: Record<ApiErrorKind, { title: string; message: string }> = {
  unauthorized: {
    title: 'Session expired',
    message: 'Your session has expired — please sign in again.',
  },
  forbidden: {
    title: 'Access denied',
    message: "You don't have access to this.",
  },
  not_found: {
    title: 'Not found',
    message: "We couldn't find that.",
  },
  too_large: {
    title: 'File too large',
    message: 'That file is too large to upload.',
  },
  validation: {
    title: "Let's fix a few things",
    message: 'Some of the information provided is invalid.',
  },
  rate_limited: {
    title: 'Too many attempts',
    message: 'Please wait a moment before trying again.',
  },
  server_error: {
    title: 'Something went wrong on our end',
    message: 'Please try again in a moment.',
  },
  network: {
    title: "You're offline",
    message: "We can't reach the server. Check your connection.",
  },
  unknown: {
    title: 'Unexpected error',
    message: 'Something unexpected happened. Please try again.',
  },
};

/** Only ever pull `error` / `message` / string `detail` — never dump the whole body. */
function extractSafeMessage(data: unknown): string | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const body = data as Record<string, unknown>;
  if (typeof body.message === 'string' && body.message.trim()) return body.message;
  if (typeof body.detail === 'string' && body.detail.trim()) return body.detail;
  if (typeof body.error === 'string' && body.error.trim() && body.error.length < 200) {
    return body.error;
  }
  return undefined;
}

function extractValidationDetails(data: unknown): PydanticErrorDetail[] | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const body = data as Record<string, unknown>;
  if (!Array.isArray(body.details)) return undefined;
  return body.details.filter(
    (d): d is PydanticErrorDetail =>
      !!d && typeof d === 'object' && Array.isArray((d as PydanticErrorDetail).loc) && typeof (d as PydanticErrorDetail).msg === 'string'
  );
}

function parseRetryAfter(headerValue: string | undefined): number | undefined {
  if (!headerValue) return undefined;
  const asSeconds = Number(headerValue);
  if (!Number.isNaN(asSeconds) && asSeconds >= 0) return Math.ceil(asSeconds);
  // Fallback: an HTTP-date form of Retry-After.
  const asDate = new Date(headerValue).getTime();
  if (!Number.isNaN(asDate)) {
    const seconds = Math.ceil((asDate - Date.now()) / 1000);
    return seconds > 0 ? seconds : 0;
  }
  return undefined;
}

function withFallback(kind: ApiErrorKind, message?: string): { title: string; message: string } {
  const fallback = FALLBACK_MESSAGES[kind];
  return { title: fallback.title, message: message || fallback.message };
}

/**
 * Pure function form — safe to call outside React (e.g. in the axios
 * interceptor) as well as inside components/hooks.
 */
export function parseApiError(error: unknown): ParsedApiError {
  if (!axios.isAxiosError(error)) {
    return { kind: 'unknown', ...withFallback('unknown') };
  }

  const axiosError = error as AxiosError;

  // No response received at all: offline, DNS/CORS failure, or timeout.
  if (!axiosError.response) {
    const isTimeout = axiosError.code === 'ECONNABORTED';
    return {
      kind: 'network',
      ...withFallback('network', isTimeout ? 'The request timed out. Check your connection and try again.' : undefined),
    };
  }

  const { status, data, headers } = axiosError.response;
  const safeMessage = extractSafeMessage(data);

  switch (status) {
    case 401:
      return { kind: 'unauthorized', status, ...withFallback('unauthorized') };
    case 403:
      return { kind: 'forbidden', status, ...withFallback('forbidden') };
    case 404:
      return { kind: 'not_found', status, ...withFallback('not_found') };
    case 413:
      return { kind: 'too_large', status, ...withFallback('too_large', safeMessage) };
    case 422:
      return {
        kind: 'validation',
        status,
        details: extractValidationDetails(data),
        ...withFallback('validation', safeMessage),
      };
    case 429: {
      const retryAfterSeconds = parseRetryAfter(headers?.['retry-after'] as string | undefined);
      return {
        kind: 'rate_limited',
        status,
        retryAfterSeconds,
        ...withFallback('rate_limited', safeMessage),
      };
    }
    case 500:
    case 502:
    case 503:
    case 504:
      return { kind: 'server_error', status, ...withFallback('server_error', safeMessage) };
    default:
      return { kind: 'unknown', status, ...withFallback('unknown', safeMessage) };
  }
}

/** React hook wrapper — stable identity, for use inside components/handlers. */
export function useApiErrorHandler() {
  return useCallback((error: unknown): ParsedApiError => parseApiError(error), []);
}
