import { useCallback, useEffect, useRef } from 'react';

export const useAutosave = ({
  storage,
  loading,
  user,
  hasLoadedSnapshot,
  snapshot,
  setSyncing,
}) => {
  const pendingSaveSnapshotRef = useRef(null);
  const saveInFlightRef = useRef(false);
  const saveRequestedRef = useRef(false);
  const skipNextSaveRef = useRef(false);
  const skipAutoSaveUntilRef = useRef(0);

  const flushSaveQueue = useCallback(async () => {
    if (saveInFlightRef.current) {
      return;
    }
    if (!saveRequestedRef.current || !pendingSaveSnapshotRef.current) {
      return;
    }
    saveInFlightRef.current = true;
    setSyncing(true);
    try {
      while (saveRequestedRef.current && pendingSaveSnapshotRef.current) {
        saveRequestedRef.current = false;
        const queuedSnapshot = pendingSaveSnapshotRef.current;
        pendingSaveSnapshotRef.current = null;
        await storage.merge(queuedSnapshot);
      }
    } catch (e) {
      console.error('Save data error:', e);
    } finally {
      saveInFlightRef.current = false;
      setSyncing(false);
      if (saveRequestedRef.current && pendingSaveSnapshotRef.current) {
        flushSaveQueue();
      }
    }
  }, [storage, setSyncing]);

  useEffect(() => {
    if (!loading && user && hasLoadedSnapshot) {
      if (skipNextSaveRef.current) {
        skipNextSaveRef.current = false;
        return;
      }
      if (Date.now() < skipAutoSaveUntilRef.current) {
        return;
      }
      pendingSaveSnapshotRef.current = snapshot;
      saveRequestedRef.current = true;
      flushSaveQueue();
    }
  }, [loading, user, hasLoadedSnapshot, snapshot, flushSaveQueue]);

  return {
    pendingSaveSnapshotRef,
    saveInFlightRef,
    saveRequestedRef,
    skipNextSaveRef,
    skipAutoSaveUntilRef,
  };
};
