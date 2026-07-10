import { API_BASE_KEY, LEGACY_AUTH_TOKEN_KEY } from '../constants.js';

const DEFAULT_TIMEOUT_MS = 15000;
let requestContextProvider = () => ({});

const createRequestId = () =>
  globalThis.crypto?.randomUUID?.() || `request-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

export const setApiRequestContextProvider = (provider) => {
  requestContextProvider = typeof provider === 'function' ? provider : () => ({});
};

export const normalizeApiBase = value => {
  const raw = String(value || '').trim();
  if (!raw) return '';
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
};
export const getApiBase = () => {
  const manualBase = normalizeApiBase(localStorage.getItem(API_BASE_KEY));
  if (manualBase) return manualBase;
  return '';
};
export const buildApiUrl = path => {
  if (/^https?:\/\//i.test(path)) return path;
  const base = getApiBase();
  return `${base}${path}`;
};
export const clearLegacyAuthToken = () => localStorage.removeItem(LEGACY_AUTH_TOKEN_KEY);

export const isRequestAbortError = (error) => Boolean(error?.isAborted);

export const apiRequest = async (path, options = {}) => {
  const {
    body,
    headers: optionHeaders,
    signal: externalSignal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    idempotencyKey,
    idempotencyRetryAttempt = 0,
    maxIdempotencyRetries = 3,
    ...fetchOptions
  } = options;
  const context = requestContextProvider() || {};
  const requestId = context.requestId || createRequestId();
  const controller = new AbortController();
  let timeoutTriggered = false;
  const abortFromExternalSignal = () => controller.abort(externalSignal?.reason || 'aborted');
  if (externalSignal?.aborted) abortFromExternalSignal();
  externalSignal?.addEventListener('abort', abortFromExternalSignal, { once: true });
  const timeout = globalThis.setTimeout(() => {
    timeoutTriggered = true;
    controller.abort('timeout');
  }, timeoutMs);
  const headers = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-Id': requestId,
    'X-Correlation-Id': context.correlationId || requestId,
    ...(Number.isInteger(context.sessionGeneration)
      ? { 'X-Session-Generation': String(context.sessionGeneration) }
      : {}),
    ...(optionHeaders || {})
  };
  const method = String(fetchOptions.method || 'GET').toUpperCase();
  const isMutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
  if (isMutation && !path.startsWith('/api/auth/') && !headers['Idempotency-Key']) {
    headers['Idempotency-Key'] = idempotencyKey || createRequestId();
  }
  let response = null;
  try {
    response = await fetch(buildApiUrl(path), {
      ...fetchOptions,
      headers,
      credentials: 'include',
      signal: controller.signal,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
  } catch (e) {
    if (controller.signal.aborted) {
      const error = new Error(timeoutTriggered ? 'Przekroczono czas oczekiwania na odpowiedź serwera.' : 'Żądanie zostało anulowane.');
      error.isAborted = !timeoutTriggered;
      error.isTimeout = timeoutTriggered;
      error.requestId = requestId;
      error.idempotencyKey = headers['Idempotency-Key'] || null;
      throw error;
    }
    const error = new Error('Brak połączenia z serwerem domowym. Sprawdź Wi-Fi i spróbuj ponownie.');
    error.isNetworkError = true;
    error.cause = e;
    error.requestId = requestId;
    error.idempotencyKey = headers['Idempotency-Key'] || null;
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
    externalSignal?.removeEventListener('abort', abortFromExternalSignal);
  }
  let data = null;
  if (response.status === 304) {
    return {
      notModified: true,
      etag: response.headers.get('ETag') || null,
    };
  }
  try {
    data = await response.json();
  } catch (e) {
    data = null;
  }
  if (!response.ok) {
    if (
      response.status === 409 &&
      data?.code === 'IDEMPOTENCY_RESULT_PENDING' &&
      idempotencyRetryAttempt < maxIdempotencyRetries &&
      !externalSignal?.aborted
    ) {
      const retryAfterSeconds = Math.max(
        1,
        Number(data?.retryAfterSeconds || response.headers.get('Retry-After') || 1),
      );
      await new Promise((resolve) => globalThis.setTimeout(resolve, retryAfterSeconds * 1000));
      return apiRequest(path, {
        ...options,
        idempotencyKey: headers['Idempotency-Key'],
        idempotencyRetryAttempt: idempotencyRetryAttempt + 1,
        maxIdempotencyRetries,
      });
    }
    const message = data?.error || `HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.data = data;
    error.requestId = requestId;
    error.idempotencyKey = headers['Idempotency-Key'] || null;
    error.isOutcomeUnknown = data?.code === 'IDEMPOTENCY_RESULT_PENDING';
    if (data?.retryAfterSeconds) {
      error.retryAfterSeconds = data.retryAfterSeconds;
    }
    throw error;
  }
  if (data && typeof data === 'object') {
    Object.defineProperty(data, '__etag', {
      value: response.headers.get('ETag') || null,
      enumerable: false,
    });
  }
  return data;
};
export const createStorageClient = () => {
  const get = async key => {
    try {
      const result = await apiRequest(`/api/storage/get/${encodeURIComponent(key)}`);
      return result?.value ?? null;
    } catch (e) {
      console.error('Storage get error:', e);
      throw e;
    }
  };
  const set = async (key, value) => {
    try {
      await apiRequest(`/api/storage/set/${encodeURIComponent(key)}`, {
        method: 'POST',
        body: {
          value
        }
      });
      return true;
    } catch (e) {
      console.error('Storage set error:', e);
      return false;
    }
  };
  const list = async prefix => {
    try {
      const result = await apiRequest(`/api/storage/list?prefix=${encodeURIComponent(prefix || '')}`);
      return result?.keys || [];
    } catch (e) {
      console.error('Storage list error:', e);
      return [];
    }
  };
  const merge = async values => {
    try {
      await apiRequest('/api/storage/merge', {
        method: 'POST',
        body: {
          values
        }
      });
      return true;
    } catch (e) {
      console.error('Storage merge error:', e);
      return false;
    }
  };
  return {
    get,
    set,
    list,
    merge
  };
};
