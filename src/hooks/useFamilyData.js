import { useCallback } from 'react';
import { CHILD_SESSION_KEY } from '../constants.js';
import { apiRequest, clearLegacyAuthToken } from '../lib/api.js';
import { findAvailableChildAccessCode, isValidChildAccessCode } from '../lib/tasks.js';

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
}) => {
  const resetFamilyData = useCallback(() => {
    setChildren([]);
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
      if (skipNextAutoSave) {
        skipNextSaveRef.current = true;
        skipAutoSaveUntilRef.current = Date.now() + 2000;
      }
      setUser(session.user);
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
      const loadedChildren = rawChildren.map(child => ({
        ...child,
      }));
      loadedChildren.forEach(child => {
        if (!isValidChildAccessCode(child.accessCode)) {
          child.accessCode = findAvailableChildAccessCode(loadedChildren, null, child.id);
        }
      });
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

  return {
    resetFamilyData,
    loadData,
  };
};
