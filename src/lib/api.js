import { API_BASE_KEY, LEGACY_AUTH_TOKEN_KEY } from '../constants.js';

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
export const apiRequest = async (path, options = {}, withAuth = true) => {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  const response = await fetch(buildApiUrl(path), {
    ...options,
    headers,
    credentials: 'include',
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined
  });
  let data = null;
  try {
    data = await response.json();
  } catch (e) {
    data = null;
  }
  if (!response.ok) {
    const message = data?.error || `HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return data;
};
export const useStorage = () => {
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
