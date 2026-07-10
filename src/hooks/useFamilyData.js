import { useCallback, useRef } from 'react';
import { CHILD_SESSION_KEY } from '../constants.js';
import { apiRequest, clearLegacyAuthToken, isRequestAbortError } from '../lib/api.js';

const defaultFamilyGoal = {
  title: 'Cel rodzinny',
  target: 500,
  mode: 'points',
};

const defaultLeaderboard = {
  children: [],
  points: {},
  streaks: {},
};

export const useFamilyData = ({
  storage,
  skipNextSaveRef,
  skipAutoSaveUntilRef,
  setUser,
  setChildren,
  setChildAccessCodes,
  setTasks,
  setCompletions,
  setExtraTasks,
  setPointAdjustments,
  setPointLedger,
  setRewards,
  setStreaks,
  setPoints,
  setFamilyLeaderboard,
  setRewardUnlocks,
  setRewardUnlockHistory,
  setFamilyGoal,
  setAuditLogs,
  setDayPointGrants,
  setWeekBonusGrants,
  setTaskPointGrants,
  setParentUsers,
  setShowRewardOverlay,
  setLoading,
  setHasLoadedSnapshot,
  setView,
  setSelectedChild,
  setParentTab,
  setShowModal,
  setEditingChild,
  setEditingTask,
  setEditingReward,
  setApprovalFilterChildId,
  setApprovalFilterDate,
  setExtraTaskTitle,
  setChildApprovalNotice,
  setShowChildRewards,
  setShowPointHistory,
  setPointAdjustmentModal,
  setConnectionError,
  getSessionGeneration = () => 0,
  isSnapshotCurrent = () => true,
  onSnapshotViewer = () => {},
  onSnapshotRejected = () => {},
  onUnauthorized = () => {},
}) => {
  const activeSnapshotRef = useRef(null);
  const latestSnapshotRequestRef = useRef(0);
  const latestSnapshotVersionRef = useRef(new Map());
  const latestSnapshotEtagRef = useRef(null);
  const resetFamilyData = useCallback(() => {
    setChildren([]);
    setChildAccessCodes({});
    setTasks([]);
    setCompletions([]);
    setExtraTasks([]);
    setPointAdjustments([]);
    setPointLedger([]);
    setRewards([]);
    setStreaks({});
    setPoints({});
    setFamilyLeaderboard(defaultLeaderboard);
    setRewardUnlocks([]);
    setRewardUnlockHistory([]);
    setFamilyGoal(defaultFamilyGoal);
    setAuditLogs([]);
    setDayPointGrants({});
    setWeekBonusGrants({});
    setTaskPointGrants({});
    setParentUsers([]);
    setShowRewardOverlay(null);
    setSelectedChild(null);
    setParentTab('approvals');
    setShowModal(null);
    setEditingChild(null);
    setEditingTask(null);
    setEditingReward(null);
    setApprovalFilterChildId('ALL');
    setApprovalFilterDate('');
    setExtraTaskTitle('');
    setChildApprovalNotice(null);
    setShowChildRewards(false);
    setShowPointHistory(false);
    setPointAdjustmentModal(null);
  }, [
    setChildren,
    setChildAccessCodes,
    setTasks,
    setCompletions,
    setExtraTasks,
    setPointAdjustments,
    setPointLedger,
    setRewards,
    setStreaks,
    setPoints,
    setFamilyLeaderboard,
    setRewardUnlocks,
    setRewardUnlockHistory,
    setFamilyGoal,
    setAuditLogs,
    setDayPointGrants,
    setWeekBonusGrants,
    setTaskPointGrants,
    setParentUsers,
    setShowRewardOverlay,
    setSelectedChild,
    setParentTab,
    setShowModal,
    setEditingChild,
    setEditingTask,
    setEditingReward,
    setApprovalFilterChildId,
    setApprovalFilterDate,
    setExtraTaskTitle,
    setChildApprovalNotice,
    setShowChildRewards,
    setShowPointHistory,
    setPointAdjustmentModal,
  ]);

  const loadData = useCallback(async ({
    preserveView = false,
    silent = false,
    skipNextAutoSave = false,
  } = {}) => {
    if (!silent) {
      setLoading(true);
      setHasLoadedSnapshot(false);
    }
    try {
      const session = await apiRequest('/api/auth/me');
      setConnectionError('');
      if (session.user?.role === 'CHILD' && sessionStorage.getItem(CHILD_SESSION_KEY) !== '1') {
        try {
          await apiRequest('/api/auth/logout', {
            method: 'POST',
          }, false);
        } catch (logoutError) {
          console.warn('Child session cleanup failed:', logoutError.message);
        }
        clearLegacyAuthToken();
        setUser(null);
        resetFamilyData();
        setView('login');
        setHasLoadedSnapshot(false);
        return;
      }
      skipNextSaveRef.current = true;
      skipAutoSaveUntilRef.current = Date.now() + (skipNextAutoSave ? 2000 : 1000);
      setUser(prev => {
        const nextUser = session.user || null;
        if (
          prev &&
          nextUser &&
          prev.id === nextUser.id &&
          prev.role === nextUser.role &&
          prev.familyId === nextUser.familyId &&
          prev.childId === nextUser.childId &&
          prev.hasPinCode === nextUser.hasPinCode
        ) {
          return prev;
        }
        return nextUser;
      });
      const [
        savedChildren,
        savedTasks,
        savedCompletions,
        savedExtraTasks,
        savedPointAdjustments,
        savedRewards,
        savedStreaks,
        savedPoints,
        savedRewardUnlocks,
        savedFamilyGoal,
        savedAuditLogs,
        savedDayPointGrants,
        savedWeekBonusGrants,
        savedTaskPointGrants,
      ] = await Promise.all([
        storage.get('children'),
        storage.get('tasks'),
        storage.get('completions'),
        storage.get('extraTasks'),
        storage.get('pointAdjustments'),
        storage.get('rewards'),
        storage.get('streaks'),
        storage.get('points'),
        storage.get('rewardUnlocks'),
        storage.get('familyGoal'),
        storage.get('auditLogs'),
        storage.get('dayPointGrants'),
        storage.get('weekBonusGrants'),
        storage.get('taskPointGrants'),
      ]);
      const rawChildren = savedChildren || [];
      const loadedChildren = rawChildren.map(child => ({ ...child }));
      setChildren(loadedChildren);
      setTasks(savedTasks || []);
      setCompletions(savedCompletions || []);
      setExtraTasks(savedExtraTasks || []);
      setPointAdjustments(savedPointAdjustments || []);
      setPointLedger([]);
      setRewards(savedRewards || []);
      setStreaks(savedStreaks || {});
      setPoints(savedPoints || {});
      setRewardUnlocks(savedRewardUnlocks || []);
      setFamilyGoal(savedFamilyGoal || defaultFamilyGoal);
      setAuditLogs(savedAuditLogs || []);
      setDayPointGrants(savedDayPointGrants || {});
      setWeekBonusGrants(savedWeekBonusGrants || {});
      setTaskPointGrants(savedTaskPointGrants || {});
      try {
        const leaderboard = await apiRequest('/api/leaderboard');
        setFamilyLeaderboard({
          children: leaderboard.children || [],
          points: leaderboard.points || {},
          streaks: leaderboard.streaks || {},
        });
      } catch (leaderboardError) {
        console.warn('Could not load family leaderboard:', leaderboardError.message);
        setFamilyLeaderboard({
          children: loadedChildren.map(child => ({
            id: child.id,
            name: child.name,
            avatar: child.avatar,
          })),
          points: savedPoints || {},
          streaks: savedStreaks || {},
        });
      }
      if (session.user?.role === 'CHILD') {
        const ownChild = loadedChildren.find(c => c.id === session.user.childId && !c.archived);
        if (!ownChild) {
          throw new Error('Profil dziecka nie istnieje lub jest zarchiwizowany');
        }
        setSelectedChild(ownChild);
        setView('child');
      } else {
        if (preserveView) {
          setSelectedChild(prev => prev ? loadedChildren.find(c => c.id === prev.id) || prev : prev);
        } else {
          setSelectedChild(null);
          setView('childSelect');
        }
      }
      setHasLoadedSnapshot(true);
      if (session.user?.role === 'PARENT') {
        try {
          const [parentUsersResponse, rewardHistoryResponse] = await Promise.all([
            apiRequest('/api/auth/parents'),
            apiRequest('/api/rewards/history'),
          ]);
          setParentUsers(parentUsersResponse.users || []);
          setRewardUnlockHistory(rewardHistoryResponse.rewardUnlockHistory || []);
        } catch (parentError) {
          console.warn('Could not load parent data:', parentError.message);
          setParentUsers([]);
          setRewardUnlockHistory([]);
        }
      } else {
        setParentUsers([]);
        setRewardUnlockHistory([]);
      }
    } catch (e) {
      console.error('Load data error:', e);
      if (silent) return;
      if (e?.status === 401) {
        try {
          await apiRequest('/api/auth/logout', {
            method: 'POST',
          });
        } catch (logoutError) {
          console.warn('Expired session cleanup failed:', logoutError.message);
        }
        clearLegacyAuthToken();
        sessionStorage.removeItem(CHILD_SESSION_KEY);
        setConnectionError('');
        setUser(null);
        resetFamilyData();
        setView('login');
        setHasLoadedSnapshot(false);
        return;
      }
      setConnectionError(e?.isNetworkError
        ? e.message
        : 'Nie udało się załadować danych aplikacji. Spróbuj odświeżyć za chwilę.');
      clearLegacyAuthToken();
      setUser(null);
      resetFamilyData();
      setView('login');
      setHasLoadedSnapshot(false);
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }, [
    storage,
    skipNextSaveRef,
    skipAutoSaveUntilRef,
    resetFamilyData,
    setUser,
    setChildren,
    setTasks,
    setCompletions,
    setExtraTasks,
    setPointAdjustments,
    setPointLedger,
    setRewards,
    setStreaks,
    setPoints,
    setFamilyLeaderboard,
    setRewardUnlocks,
    setRewardUnlockHistory,
    setFamilyGoal,
    setAuditLogs,
    setDayPointGrants,
    setWeekBonusGrants,
    setTaskPointGrants,
    setParentUsers,
    setLoading,
    setHasLoadedSnapshot,
    setView,
    setSelectedChild,
    setConnectionError,
  ]);

  const loadSnapshot = useCallback(({
    preserveView = false,
    silent = false,
    skipNextAutoSave = false,
    force = false,
  } = {}) => {
    const generation = getSessionGeneration();
    const active = activeSnapshotRef.current;
    if (active && active.generation === generation && !force) {
      return active.promise;
    }
    if (active && force) {
      active.controller.abort('superseded');
    }
    const controller = new AbortController();
    const requestId = latestSnapshotRequestRef.current + 1;
    latestSnapshotRequestRef.current = requestId;
    if (!silent) {
      setLoading(true);
      setHasLoadedSnapshot(false);
    }
    const promise = (async () => {
      try {
        const snapshot = await apiRequest('/api/family-state', {
          signal: controller.signal,
          timeoutMs: 12000,
          headers: latestSnapshotEtagRef.current
            ? { 'If-None-Match': latestSnapshotEtagRef.current }
            : undefined,
        });
        if (snapshot?.notModified) return snapshot;
        if (!snapshot?.familyId || !snapshot?.viewer || !snapshot?.family) {
          return loadData({ preserveView, silent, skipNextAutoSave });
        }
        if (!isSnapshotCurrent({ generation, requestId, snapshot })) return null;
        if (onSnapshotRejected(snapshot.viewer)) return null;

        const scope = snapshot.viewer?.role === 'CHILD'
          ? `child:${snapshot.viewer.childId}`
          : `parent:${snapshot.viewer?.id}`;
        const versionKey = `${generation}:${snapshot.familyId}:${scope}`;
        const previousVersion = latestSnapshotVersionRef.current.get(versionKey);
        if (Number.isInteger(previousVersion) && Number(snapshot.version) < previousVersion) return null;
        latestSnapshotVersionRef.current.set(versionKey, Number(snapshot.version));
        latestSnapshotEtagRef.current = snapshot.__etag || null;

        const family = snapshot.family || {};
        skipNextSaveRef.current = true;
        skipAutoSaveUntilRef.current = Date.now() + (skipNextAutoSave ? 2000 : 1000);
        setConnectionError('');
        setUser(snapshot.viewer || null);
        onSnapshotViewer(snapshot.viewer || null);
        setChildren(family.children || []);
        setTasks(family.tasks || []);
        setCompletions(family.completions || []);
        setExtraTasks(family.extraTasks || []);
        setPointAdjustments(family.pointAdjustments || []);
        setPointLedger(family.pointLedger || []);
        setRewards(family.rewards || []);
        setStreaks(family.streaks || {});
        setPoints(family.points || {});
        setFamilyLeaderboard(family.familyLeaderboard || defaultLeaderboard);
        setRewardUnlocks(family.rewardUnlocks || []);
        setRewardUnlockHistory(family.rewardUnlockHistory || []);
        setFamilyGoal(family.familyGoal || defaultFamilyGoal);
        setAuditLogs(family.auditLogs || []);
        setDayPointGrants(family.dayPointGrants || {});
        setWeekBonusGrants(family.weekBonusGrants || {});
        setTaskPointGrants(family.taskPointGrants || {});
        setParentUsers(family.parentUsers || []);

        if (snapshot.viewer?.role === 'CHILD') {
          const ownChild = (family.children || []).find((child) => child.id === snapshot.viewer.childId && !child.archived);
          if (!ownChild) throw new Error('Profil dziecka nie istnieje lub jest zarchiwizowany');
          setSelectedChild(ownChild);
          setView('child');
        } else if (preserveView) {
          setSelectedChild((current) => current
            ? (family.children || []).find((child) => child.id === current.id) || current
            : current);
        } else {
          setSelectedChild(null);
          setView('childSelect');
        }
        setHasLoadedSnapshot(true);
        return snapshot;
      } catch (error) {
        if (isRequestAbortError(error)) return null;
        if (!isSnapshotCurrent({ generation, requestId, snapshot: null })) return null;
        if (error?.status === 404) {
          // Transitional compatibility only: an older backend can still serve
          // the legacy read API while the snapshot feature is rolled out.
          return loadData({ preserveView, silent, skipNextAutoSave });
        }
        if (error?.status === 401) {
          onUnauthorized(error);
          return null;
        }
        if (!silent) {
          setConnectionError(error?.isTimeout || error?.isNetworkError
            ? error.message
            : 'Nie udało się załadować danych aplikacji. Spróbuj odświeżyć za chwilę.');
        }
        return null;
      } finally {
        if (activeSnapshotRef.current?.requestId === requestId) {
          activeSnapshotRef.current = null;
        }
        if (!silent && isSnapshotCurrent({ generation, requestId, snapshot: null })) {
          setLoading(false);
        }
      }
    })();
    activeSnapshotRef.current = { generation, requestId, controller, promise };
    return promise;
  }, [
    getSessionGeneration,
    isSnapshotCurrent,
    onSnapshotViewer,
    onSnapshotRejected,
    onUnauthorized,
    loadData,
    skipNextSaveRef,
    skipAutoSaveUntilRef,
    setUser,
    setChildren,
    setTasks,
    setCompletions,
    setExtraTasks,
    setPointAdjustments,
    setPointLedger,
    setRewards,
    setStreaks,
    setPoints,
    setFamilyLeaderboard,
    setRewardUnlocks,
    setRewardUnlockHistory,
    setFamilyGoal,
    setAuditLogs,
    setDayPointGrants,
    setWeekBonusGrants,
    setTaskPointGrants,
    setParentUsers,
    setLoading,
    setHasLoadedSnapshot,
    setView,
    setSelectedChild,
    setConnectionError,
  ]);

  const abortSnapshot = useCallback((reason = 'cancelled') => {
    activeSnapshotRef.current?.controller.abort(reason);
  }, []);

  return {
    resetFamilyData,
    loadData,
    loadSnapshot,
    abortSnapshot,
  };
};
