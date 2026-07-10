import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CHILD_SESSION_KEY, HISTORY_DAYS, LOGOUT_PENDING_KEY } from './constants.js';
import { apiRequest, clearLegacyAuthToken, createStorageClient, setApiRequestContextProvider } from './lib/api.js';
import { getDayNumber, getWeekStart, toDateString } from './lib/dates.js';
import { isTaskActiveForDate, isTaskScheduledForDate, normalizeTaskArchiveDays } from './lib/tasks.js';
import LoginView from './components/auth/LoginView.jsx';
import ChildSelectionView from './components/auth/ChildSelectionView.jsx';
import ChildView from './components/child/ChildView.jsx';
import ErrorBoundary from './components/common/ErrorBoundary.jsx';
import ParentPinGate from './components/auth/ParentPinGate.jsx';
import ParentPanel from './components/parent/ParentPanel.jsx';
import { useAutosave } from './hooks/useAutosave.js';
import { useFamilyData } from './hooks/useFamilyData.js';

const COMPLETION_ACTION_BATCH_DELAY_MS = 350;
const LOGOUT_PENDING_TTL_MS = 24 * 60 * 60 * 1000;

const readPendingLogout = () => {
  try {
    const value = JSON.parse(localStorage.getItem(LOGOUT_PENDING_KEY) || 'null');
    return value && typeof value === 'object' ? value : null;
  } catch {
    localStorage.removeItem(LOGOUT_PENDING_KEY);
    return null;
  }
};

const writePendingLogout = (value) => localStorage.setItem(LOGOUT_PENDING_KEY, JSON.stringify(value));

const App = () => {
  const storage = useMemo(() => createStorageClient(), []);
  const [user, setUser] = useState(null);
  const [children, setChildren] = useState([]);
  const [childAccessCodes, setChildAccessCodes] = useState({});
  const [tasks, setTasks] = useState([]);
  const [completions, setCompletions] = useState([]);
  const [extraTasks, setExtraTasks] = useState([]);
  const [pointAdjustments, setPointAdjustments] = useState([]);
  const [pointLedger, setPointLedger] = useState([]);
  const [rewards, setRewards] = useState([]);
  const [streaks, setStreaks] = useState({});
  const [points, setPoints] = useState({});
  const [familyLeaderboard, setFamilyLeaderboard] = useState({
    children: [],
    points: {},
    streaks: {}
  });
  const [rewardUnlocks, setRewardUnlocks] = useState([]);
  const [rewardUnlockHistory, setRewardUnlockHistory] = useState([]);
  const [familyGoal, setFamilyGoal] = useState({
    title: 'Cel rodzinny',
    target: 500,
    mode: 'points'
  });
  const [auditLogs, setAuditLogs] = useState([]);
  const [dayPointGrants, setDayPointGrants] = useState({});
  const [weekBonusGrants, setWeekBonusGrants] = useState({});
  const [taskPointGrants, setTaskPointGrants] = useState({});
  const [parentUsers, setParentUsers] = useState([]);
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [connectionError, setConnectionError] = useState(() => navigator.onLine ? '' : 'Brak połączenia z serwerem domowym. Sprawdź Wi-Fi i spróbuj ponownie.');
  const [syncing, setSyncing] = useState(false);
  const [showRewardOverlay, setShowRewardOverlay] = useState(null);
  const [loading, setLoading] = useState(true);
  const [hasLoadedSnapshot, setHasLoadedSnapshot] = useState(false);
  const [view, setView] = useState('login');
  const [selectedChild, setSelectedChild] = useState(null);
  const [parentTab, setParentTab] = useState('approvals');
  const [showModal, setShowModal] = useState(null);
  const [editingChild, setEditingChild] = useState(null);
  const [editingTask, setEditingTask] = useState(null);
  const [editingReward, setEditingReward] = useState(null);
  const [approvalFilterChildId, setApprovalFilterChildId] = useState('ALL');
  const [approvalFilterDate, setApprovalFilterDate] = useState('');
  const [childTaskDate, setChildTaskDate] = useState(() => toDateString(new Date()));
  const [parentTaskChildId, setParentTaskChildId] = useState('ALL');
  const [parentTaskDate, setParentTaskDate] = useState(() => toDateString(new Date()));
  const [taskListMode, setTaskListMode] = useState('active');
  const [extraTaskTitle, setExtraTaskTitle] = useState('');
  const [childApprovalNotice, setChildApprovalNotice] = useState(null);
  const [showChildRewards, setShowChildRewards] = useState(false);
  const [showPointHistory, setShowPointHistory] = useState(false);
  const [pointAdjustmentModal, setPointAdjustmentModal] = useState(null);
  const [parentPinGateOpen, setParentPinGateOpen] = useState(false);
  const [pendingCompletionActionIds, setPendingCompletionActionIds] = useState([]);
  const [pendingExtraTaskActionIds, setPendingExtraTaskActionIds] = useState([]);
  const [authState, setAuthState] = useState('active');
  const serverMutationQueueRef = useRef(Promise.resolve());
  const sessionGenerationRef = useRef(0);
  const sessionRefRef = useRef(null);
  const authStateRef = useRef('active');
  const resetFamilyDataRef = useRef(null);
  const abortSnapshotRef = useRef(() => {});
  const childCompletionMutationVersionsRef = useRef(new Map());
  const completionActionBatchRef = useRef({
    approve: new Map(),
    reject: new Map(),
    approveTimer: null,
    rejectTimer: null,
  });
  const setAuthLifecycle = useCallback((nextState) => {
    authStateRef.current = nextState;
    setAuthState(nextState);
  }, []);
  const getSessionGeneration = useCallback(() => sessionGenerationRef.current, []);
  const isSnapshotCurrent = useCallback(({ generation }) =>
    generation === sessionGenerationRef.current && authStateRef.current === 'active', []);
  const retryPendingLogout = useCallback(async (pending = readPendingLogout()) => {
    if (!pending?.sessionRef || pending.revocationState !== 'pending') return false;
    if (Number(pending.expiresAt || 0) <= Date.now()) {
      writePendingLogout({ ...pending, revocationState: 'expired' });
      return false;
    }
    try {
      await apiRequest('/api/auth/logout', { method: 'POST', timeoutMs: 5000 });
      writePendingLogout({ ...pending, revocationState: 'confirmed', confirmedAt: new Date().toISOString() });
      return true;
    } catch (error) {
      writePendingLogout({ ...pending, retryCount: Number(pending.retryCount || 0) + 1 });
      return false;
    }
  }, []);
  const discardLocalSession = useCallback((sessionRef, { revoke = true } = {}) => {
    sessionGenerationRef.current += 1;
    setAuthLifecycle('loggedOut');
    abortSnapshotRef.current('logout');
    clearLegacyAuthToken();
    sessionStorage.removeItem(CHILD_SESSION_KEY);
    sessionRefRef.current = null;
    setUser(null);
    setParentPinGateOpen(false);
    resetFamilyDataRef.current?.();
    setHasLoadedSnapshot(false);
    setLoading(false);
    setView('login');
    if (revoke && sessionRef) {
      const pending = {
        sessionRef,
        revocationState: 'pending',
        createdAt: new Date().toISOString(),
        expiresAt: Date.now() + LOGOUT_PENDING_TTL_MS,
        retryCount: 0,
      };
      writePendingLogout(pending);
      void retryPendingLogout(pending);
    }
  }, [retryPendingLogout, setAuthLifecycle]);
  const activateSession = useCallback((sessionRef) => {
    sessionGenerationRef.current += 1;
    sessionRefRef.current = sessionRef || null;
    setAuthLifecycle('active');
    const pending = readPendingLogout();
    if (pending && pending.sessionRef !== sessionRef) {
      localStorage.removeItem(LOGOUT_PENDING_KEY);
    }
  }, [setAuthLifecycle]);
  const onSnapshotRejected = useCallback((viewer) => {
    const pending = readPendingLogout();
    const pendingForThisSession = pending?.revocationState === 'pending' && pending.sessionRef === viewer?.sessionRef;
    const unexpectedChildSession = viewer?.role === 'CHILD' && sessionStorage.getItem(CHILD_SESSION_KEY) !== '1';
    if (!pendingForThisSession && !unexpectedChildSession) return false;
    discardLocalSession(viewer?.sessionRef, { revoke: true });
    return true;
  }, [discardLocalSession]);
  const onSnapshotViewer = useCallback((viewer) => {
    if (!viewer?.sessionRef) return;
    sessionRefRef.current = viewer.sessionRef;
    setAuthLifecycle('active');
  }, [setAuthLifecycle]);
  const onUnauthorized = useCallback(() => {
    discardLocalSession(sessionRefRef.current, { revoke: false });
  }, [discardLocalSession]);
  const autosaveSnapshot = useMemo(() => ({
    children,
    tasks,
    completions,
    extraTasks,
    pointAdjustments,
    pointLedger,
    rewards,
    streaks,
    points,
    rewardUnlocks,
    familyGoal,
    auditLogs,
    dayPointGrants,
    weekBonusGrants,
    taskPointGrants,
  }), [children, tasks, completions, extraTasks, pointAdjustments, pointLedger, rewards, streaks, points, rewardUnlocks, familyGoal, auditLogs, dayPointGrants, weekBonusGrants, taskPointGrants]);
  const {
    saveInFlightRef,
    saveRequestedRef,
    skipNextSaveRef,
    skipAutoSaveUntilRef,
  } = useAutosave({
    storage,
    loading,
    user,
    hasLoadedSnapshot,
    snapshot: autosaveSnapshot,
    setSyncing,
    enabled: false,
  });
  const { resetFamilyData, loadSnapshot, abortSnapshot } = useFamilyData({
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
    getSessionGeneration,
    isSnapshotCurrent,
    onSnapshotViewer,
    onSnapshotRejected,
    onUnauthorized,
  });
  useEffect(() => {
    resetFamilyDataRef.current = resetFamilyData;
    abortSnapshotRef.current = abortSnapshot;
  }, [abortSnapshot, resetFamilyData]);
  useEffect(() => {
    setApiRequestContextProvider(() => ({
      sessionGeneration: sessionGenerationRef.current,
      correlationId: sessionRefRef.current || undefined,
    }));
    return () => setApiRequestContextProvider(null);
  }, []);
  useEffect(() => {
    const goOnline = () => {
      setIsOnline(true);
      setConnectionError('');
      void retryPendingLogout();
    };
    const goOffline = () => {
      setIsOnline(false);
      setConnectionError('Brak połączenia z serwerem domowym. Sprawdź Wi-Fi i spróbuj ponownie.');
    };
    window.addEventListener('online', goOnline);
    window.addEventListener('offline', goOffline);
    return () => {
      window.removeEventListener('online', goOnline);
      window.removeEventListener('offline', goOffline);
    };
  }, [retryPendingLogout]);
  const addAuditLog = useCallback((action, entityType, entityId, details = {}) => {
    const entry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      userId: user?.id || null,
      action,
      entityType,
      entityId,
      details,
      createdAt: new Date().toISOString()
    };
    setAuditLogs(prev => [entry, ...prev].slice(0, 500));
  }, [user?.id]);
  const runServerMutation = useCallback(action => {
    if (authState !== 'active' || authStateRef.current !== 'active') {
      return Promise.reject(new Error('Sesja nie jest aktywna. Zaloguj się ponownie.'));
    }
    const queued = serverMutationQueueRef.current.catch(() => {}).then(action);
    serverMutationQueueRef.current = queued.catch(() => {});
    return queued;
  }, [authState]);
  const reloadAfterServerMutation = useCallback((options = {}) => loadSnapshot({
    preserveView: true,
    silent: true,
    skipNextAutoSave: true,
    force: true,
    ...options
  }), [loadSnapshot]);
  const addPendingCompletionActions = useCallback(ids => {
    const validIds = ids.filter(Boolean);
    if (validIds.length === 0) return;
    setPendingCompletionActionIds(prev => [...new Set([...prev, ...validIds])]);
  }, []);
  const clearPendingCompletionActions = useCallback(ids => {
    const validIds = new Set(ids.filter(Boolean));
    if (validIds.size === 0) return;
    setPendingCompletionActionIds(prev => prev.filter(id => !validIds.has(id)));
  }, []);
  const addPendingExtraTaskActions = useCallback(ids => {
    const validIds = ids.filter(Boolean);
    if (validIds.length === 0) return;
    setPendingExtraTaskActionIds(prev => [...new Set([...prev, ...validIds])]);
  }, []);
  const clearPendingExtraTaskActions = useCallback(ids => {
    const validIds = new Set(ids.filter(Boolean));
    if (validIds.size === 0) return;
    setPendingExtraTaskActionIds(prev => prev.filter(id => !validIds.has(id)));
  }, []);
  const applyServerStatePatch = useCallback(result => {
    const patch = result?.statePatch;
    if (!patch || typeof patch !== 'object') {
      return false;
    }

    skipNextSaveRef.current = true;
    skipAutoSaveUntilRef.current = Date.now() + 2000;
    setConnectionError('');

    if (Array.isArray(patch.completions)) setCompletions(patch.completions);
    if (Array.isArray(patch.extraTasks)) setExtraTasks(patch.extraTasks);
    if (patch.points && typeof patch.points === 'object') setPoints(patch.points);
    if (patch.streaks && typeof patch.streaks === 'object') setStreaks(patch.streaks);
    if (Array.isArray(patch.pointLedger)) setPointLedger(patch.pointLedger);
    if (Array.isArray(patch.rewardUnlocks)) setRewardUnlocks(patch.rewardUnlocks);
    if (Array.isArray(patch.rewardUnlockHistory)) setRewardUnlockHistory(patch.rewardUnlockHistory);
    if (patch.dayPointGrants && typeof patch.dayPointGrants === 'object') setDayPointGrants(patch.dayPointGrants);
    if (patch.weekBonusGrants && typeof patch.weekBonusGrants === 'object') setWeekBonusGrants(patch.weekBonusGrants);
    if (patch.taskPointGrants && typeof patch.taskPointGrants === 'object') setTaskPointGrants(patch.taskPointGrants);
    if (Array.isArray(patch.auditLogs)) setAuditLogs(patch.auditLogs);
    if (patch.familyLeaderboard && typeof patch.familyLeaderboard === 'object') {
      setFamilyLeaderboard({
        children: patch.familyLeaderboard.children || [],
        points: patch.familyLeaderboard.points || {},
        streaks: patch.familyLeaderboard.streaks || {},
      });
    }

    return true;
  }, [skipNextSaveRef, skipAutoSaveUntilRef]);
  const applyServerStatePatchOrReload = useCallback(async result => {
    if (applyServerStatePatch(result)) return true;
    await reloadAfterServerMutation();
    return false;
  }, [applyServerStatePatch, reloadAfterServerMutation]);
  const showConfetti = useCallback(() => {
    for (let i = 0; i < 50; i++) {
      setTimeout(() => {
        const confetti = document.createElement('div');
        confetti.className = 'confetti';
        confetti.style.left = Math.random() * 100 + '%';
        confetti.style.top = '-10px';
        confetti.style.background = ['#FF6B9D', '#FEC84B', '#12B76A', '#7C3AED', '#F97316'][Math.floor(Math.random() * 5)];
        document.body.appendChild(confetti);
        setTimeout(() => confetti.remove(), 3000);
      }, i * 30);
    }
  }, []);
  const flushCompletionActionBatch = useCallback(actionType => {
    const ref = completionActionBatchRef.current;
    const isApprove = actionType === 'approve';
    const queue = isApprove ? ref.approve : ref.reject;
    const timer = isApprove ? ref.approveTimer : ref.rejectTimer;
    if (timer) {
      window.clearTimeout(timer);
      if (isApprove) {
        ref.approveTimer = null;
      } else {
        ref.rejectTimer = null;
      }
    }

    const items = [...queue.values()];
    queue.clear();
    const ids = items.map(item => item.completion?.id).filter(Boolean);
    const shouldCelebrate = isApprove && items.some(item => item.celebrate !== false);
    if (ids.length === 0) return Promise.resolve();

    return runServerMutation(async () => {
      try {
        const result = await apiRequest(`/api/completions/${isApprove ? 'approve-bulk' : 'reject-bulk'}`, {
          method: 'POST',
          body: { ids }
        });
        await applyServerStatePatchOrReload(result);

        const changedCount = Number(isApprove ? result?.approvedCount || 0 : result?.rejectedCount || 0);
        if (changedCount === 0) {
          alert(isApprove
            ? 'Nie zatwierdzono żadnego zadania. Odświeżono listę zadań do zatwierdzenia.'
            : 'Nie odrzucono żadnego zadania. Odświeżono listę zadań do zatwierdzenia.');
          return;
        }
        if (shouldCelebrate) {
          showConfetti();
        }
      } catch (e) {
        alert(e.message || (isApprove ? 'Nie udało się zatwierdzić zadania' : 'Nie udało się odrzucić zadania'));
      } finally {
        clearPendingCompletionActions(ids);
      }
    });
  }, [runServerMutation, applyServerStatePatchOrReload, clearPendingCompletionActions, showConfetti]);
  const enqueueCompletionAction = useCallback((actionType, completion, { celebrate = true } = {}) => {
    if (!completion?.id) return Promise.resolve();
    addPendingCompletionActions([completion.id]);
    const ref = completionActionBatchRef.current;
    const isApprove = actionType === 'approve';
    const queue = isApprove ? ref.approve : ref.reject;
    const timer = isApprove ? ref.approveTimer : ref.rejectTimer;
    queue.set(completion.id, { completion, celebrate });
    if (timer) {
      window.clearTimeout(timer);
    }
    const nextTimer = window.setTimeout(() => {
      flushCompletionActionBatch(actionType);
    }, COMPLETION_ACTION_BATCH_DELAY_MS);
    if (isApprove) {
      ref.approveTimer = nextTimer;
    } else {
      ref.rejectTimer = nextTimer;
    }
    return Promise.resolve();
  }, [addPendingCompletionActions, flushCompletionActionBatch]);
  useEffect(() => () => {
    const ref = completionActionBatchRef.current;
    if (ref.approveTimer) window.clearTimeout(ref.approveTimer);
    if (ref.rejectTimer) window.clearTimeout(ref.rejectTimer);
  }, []);
  useEffect(() => {
    clearLegacyAuthToken();
    loadSnapshot();
  }, []);
  useEffect(() => {
    if (!user || !hasLoadedSnapshot || view !== 'parent' && view !== 'child') {
      return undefined;
    }
    const refreshData = () => {
      if (document.visibilityState === 'hidden') return;
      if (
        saveInFlightRef.current ||
        saveRequestedRef.current ||
        childCompletionMutationVersionsRef.current.size > 0
      ) return;
      loadSnapshot({
        preserveView: true,
        silent: true,
        force: false,
      });
    };
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') refreshData();
    };
    const interval = window.setInterval(refreshData, view === 'parent' ? 5000 : 7000);
    window.addEventListener('focus', refreshData);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener('focus', refreshData);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [user?.id, user?.role, hasLoadedSnapshot, view, parentTab, selectedChild?.id]);
  const getDateString = (date = new Date()) => toDateString(date);
  const activeChildren = children.filter(c => !c.archived);
  const claimReward = useCallback(async unlockId => runServerMutation(async () => {
    try {
      const result = await apiRequest(`/api/rewards/unlocks/${encodeURIComponent(unlockId)}/claim`, {
        method: 'POST',
      });
      await applyServerStatePatchOrReload(result);
    } catch (error) {
      alert(error.message || 'Nie udało się oznaczyć nagrody jako wydanej');
    }
  }), [applyServerStatePatchOrReload, runServerMutation]);
  const evaluateDay = (childId, date) => {
    const child = children.find(c => c.id === childId);
    if (!child) return 'NOT_ACTIVE';
    const adjustedDay = getDayNumber(date);
    if (!child.activeDays.includes(adjustedDay)) return 'NOT_ACTIVE';
    const minTasks = tasks.filter(t => t.childId === childId && t.tier === 'MIN' && isTaskActiveForDate(t, date) && isTaskScheduledForDate(t, date));
    if (minTasks.length === 0) return 'NO_REQUIRED_TASKS';
    const approvedCount = minTasks.filter(task => {
      return completions.some(c => c.taskId === task.id && c.childId === childId && c.date === date && c.approvedByParent);
    }).length;
    return approvedCount === minTasks.length ? 'PASSED' : 'FAILED';
  };
  const evaluateWeek = (childId, weekStart) => {
    let activeDays = 0;
    let passedDays = 0;
    for (let i = 0; i < 7; i++) {
      const date = new Date(weekStart);
      date.setDate(date.getDate() + i);
      const dateStr = getDateString(date);
      const status = evaluateDay(childId, dateStr);
      if (status === 'NOT_ACTIVE' || status === 'NO_REQUIRED_TASKS') continue;
      activeDays += 1;
      if (status === 'PASSED') {
        passedDays += 1;
      }
    }
    if (activeDays === 0) return 'NO_ACTIVE_DAYS';
    return passedDays === activeDays ? 'IDEAL' : 'NOT_IDEAL';
  };
  useEffect(() => {
    const next = {};
    const today = new Date();
    const minStart = new Date(today);
    minStart.setDate(today.getDate() - HISTORY_DAYS);
    children.filter(child => !child.archived).forEach(child => {
      const createdDate = child.createdAt ? new Date(child.createdAt) : minStart;
      const startDate = createdDate > minStart ? createdDate : minStart;
      let current = 0;
      let best = 0;
      let idealWeeksCount = 0;
      let idealWeeksInRow = 0;
      let rollingIdealRow = 0;
      let lastEvaluatedDate = null;
      const weekMap = {};
      const cursor = new Date(startDate);
      while (cursor <= today) {
        const dateStr = getDateString(cursor);
        const status = evaluateDay(child.id, dateStr);
        if (status === 'PASSED') {
          current += 1;
          if (current > best) best = current;
          lastEvaluatedDate = dateStr;
        } else if (status === 'FAILED') {
          current = 0;
          lastEvaluatedDate = dateStr;
        }
        const weekStart = getWeekStart(dateStr);
        if (!weekMap[weekStart]) {
          weekMap[weekStart] = evaluateWeek(child.id, weekStart);
        }
        cursor.setDate(cursor.getDate() + 1);
      }
      Object.keys(weekMap).sort().forEach(weekStart => {
        const status = weekMap[weekStart];
        if (status === 'NO_ACTIVE_DAYS') return;
        if (status === 'IDEAL') {
          idealWeeksCount += 1;
          rollingIdealRow += 1;
        } else {
          rollingIdealRow = 0;
        }
        idealWeeksInRow = rollingIdealRow;
      });
      next[child.id] = {
        current,
        best,
        lastEvaluatedDate,
        idealWeeksCount,
        idealWeeksInRow
      };
    });
    skipNextSaveRef.current = true;
    skipAutoSaveUntilRef.current = Date.now() + 500;
    setStreaks(next);
  }, [children, tasks, completions, skipAutoSaveUntilRef, skipNextSaveRef]);
  const handleLogin = async (email, password) => {
    try {
      const result = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: {
          email,
          password
        }
      }, false);
      activateSession(result?.user?.sessionRef);
      await loadSnapshot({ force: true });
      return {
        success: true
      };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nieprawidłowy email lub hasło'
      };
    }
  };
  const handleRegister = async ({
    email,
    password,
    familyName
  }) => {
    try {
      const result = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: {
          email,
          password,
          familyName
        }
      }, false);
      activateSession(result?.user?.sessionRef);
      await loadSnapshot({ force: true });
      return {
        success: true
      };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nie udało się utworzyć konta'
      };
    }
  };
  const handleChildLogin = async accessCode => {
    try {
      const result = await apiRequest('/api/auth/login-child', {
        method: 'POST',
        body: {
          accessCode
        }
      }, false);
      sessionStorage.setItem(CHILD_SESSION_KEY, '1');
      activateSession(result?.user?.sessionRef);
      await loadSnapshot({ force: true });
      return {
        success: true
      };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nieprawidłowy kod dziecka'
      };
    }
  };
  const handleForgotPassword = async email => {
    try {
      const result = await apiRequest('/api/auth/forgot-password', {
        method: 'POST',
        body: {
          email
        }
      }, false);
      return {
        success: true,
        message: result?.message || 'Jeśli konto istnieje, instrukcja resetu została wysłana.',
        debugResetToken: result?.debugResetToken || null
      };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nie udało się uruchomić resetu hasła'
      };
    }
  };
  const handleResetPasswordByToken = async (token, newPassword) => {
    try {
      await apiRequest('/api/auth/reset-password/token', {
        method: 'POST',
        body: {
          token,
          newPassword
        }
      }, false);
      return {
        success: true,
        message: 'Hasło zostało zmienione. Możesz się zalogować.'
      };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nie udało się zresetować hasła'
      };
    }
  };
  const handleLogout = async () => {
    discardLocalSession(sessionRefRef.current || user?.sessionRef, { revoke: true });
  };
  const selectChild = child => {
    if (user?.role === 'CHILD' && child.id !== user.childId) return;
    setSelectedChild(child);
    setView('child');
  };
  const enterParentMode = () => {
    if (user?.role === 'CHILD') return;
    setParentPinGateOpen(true);
  };
  const closeParentPinGate = () => {
    setParentPinGateOpen(false);
  };
  const enterParentPanelAfterPin = () => {
    setParentPinGateOpen(false);
    setSelectedChild(null);
    setView('parent');
  };
  const leaveParentMode = () => {
    setParentPinGateOpen(false);
    setView('childSelect');
  };
  const handleParentPinVerify = async pinCode => {
    try {
      await apiRequest('/api/auth/parent-pin/verify', {
        method: 'POST',
        body: { pinCode }
      });
      enterParentPanelAfterPin();
      return { success: true };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nieprawidłowy PIN rodzica',
        retryAfterSeconds: e.retryAfterSeconds || e.data?.retryAfterSeconds || null
      };
    }
  };
  const handleParentPinSetup = async ({ pinCode, currentPassword }) => {
    try {
      const response = await apiRequest('/api/auth/pin', {
        method: 'PUT',
        body: { pinCode, currentPassword }
      });
      if (response?.user) {
        setUser(response.user);
      } else {
        setUser(prev => prev ? { ...prev, hasPinCode: true } : prev);
      }
      enterParentPanelAfterPin();
      return { success: true };
    } catch (e) {
      return {
        success: false,
        error: e.message || 'Nie udało się zapisać PIN-u',
        retryAfterSeconds: e.retryAfterSeconds || e.data?.retryAfterSeconds || null
      };
    }
  };
  const toggleTask = (taskId, date = getDateString()) => {
    if (!selectedChild) return;
    const completionDate = date || getDateString();
    const childId = selectedChild.id;
    const existing = completions.find(c => c.taskId === taskId && c.date === completionDate && c.childId === childId);
    if (existing?.approvedByParent) return;

    const doneByChild = existing ? !existing.doneByChild : true;
    const mutationKey = `${childId}\u0000${taskId}\u0000${completionDate}`;
    const mutationVersion = (childCompletionMutationVersionsRef.current.get(mutationKey) || 0) + 1;
    childCompletionMutationVersionsRef.current.set(mutationKey, mutationVersion);

    const previousCompletion = existing ? { ...existing } : null;
    const optimisticCompletion = {
      ...(existing || {}),
      id: existing?.id || `optimistic-${Date.now()}-${mutationVersion}`,
      taskId,
      childId,
      date: completionDate,
      doneByChild,
      approvedByParent: false,
      approvedAt: null,
      doneAt: doneByChild ? new Date().toISOString() : existing?.doneAt || null,
      createdAt: existing?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    setCompletions(prev => {
      const matchingIndex = prev.findIndex(item =>
        item.taskId === taskId && item.date === completionDate && item.childId === childId
      );
      if (matchingIndex === -1) return [...prev, optimisticCompletion];
      return prev.map((item, index) => index === matchingIndex ? optimisticCompletion : item);
    });

    return runServerMutation(async () => {
      try {
        const result = await apiRequest('/api/completions', {
          method: 'POST',
          body: {
            taskId,
            childId,
            date: completionDate,
            doneByChild,
          },
        });
        if (childCompletionMutationVersionsRef.current.get(mutationKey) !== mutationVersion) return;
        if (result?.completion) {
          setCompletions(prev => {
            const matchingIndex = prev.findIndex(item =>
              item.taskId === taskId && item.date === completionDate && item.childId === childId
            );
            if (matchingIndex === -1) return [...prev, result.completion];
            return prev.map((item, index) => index === matchingIndex ? result.completion : item);
          });
        }
      } catch (error) {
        const isCurrentMutation = childCompletionMutationVersionsRef.current.get(mutationKey) === mutationVersion;
        if (isCurrentMutation) {
          setCompletions(prev => {
            const withoutCurrent = prev.filter(item =>
              !(item.taskId === taskId && item.date === completionDate && item.childId === childId)
            );
            return previousCompletion ? [...withoutCurrent, previousCompletion] : withoutCurrent;
          });
          alert(error.message || 'Nie udało się zapisać wykonania zadania');
        }
      } finally {
        if (childCompletionMutationVersionsRef.current.get(mutationKey) === mutationVersion) {
          childCompletionMutationVersionsRef.current.delete(mutationKey);
        }
      }
    });
  };
  const approveTask = async (completion, {
    celebrate = true
  } = {}) => {
    if (!completion || completion.approvedByParent) return;
    return enqueueCompletionAction('approve', completion, { celebrate });
  };
  const rejectTask = async completion => {
    if (!completion) return;
    return enqueueCompletionAction('reject', completion);
  };
  const reverseApproval = async completion => {
    if (!completion || !completion.approvedByParent) return;
    const task = tasks.find(item => item.id === completion.taskId);
    const child = children.find(item => item.id === completion.childId);
    const label = `${child?.name || 'Dziecko'} • ${task?.title || 'zadanie'} • ${completion.date}`;
    const ok = window.confirm(`Cofnąć zatwierdzenie?\n\n${label}\n\nSystem przeliczy punkty i passę, a korekta zostanie zapisana w historii.`);
    if (!ok) return;
    return runServerMutation(async () => {
      try {
      const result = await apiRequest(`/api/completions/${encodeURIComponent(completion.id)}/reverse-approval`, {
        method: 'POST',
        body: {
          reason: `Cofnięcie zatwierdzenia: ${task?.title || 'zadanie'}`
        }
      });
      const reversal = result?.reversal || {};
      const delta = Number(reversal.delta || 0);
      const deltaText = delta > 0 ? `+${delta}` : `${delta}`;
      window.alert(`Cofnięto zatwierdzenie.\nEfekt punktowy: ${deltaText} pkt (${reversal.previousPoints ?? '?'} → ${reversal.newPoints ?? '?'}).`);
      await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się cofnąć zatwierdzenia');
      }
    });
  };
  const completeTaskAsParent = async (task, childId, date) => {
    if (!task || !childId || !date) return;
    return runServerMutation(async () => {
      try {
      const result = await apiRequest('/api/completions', {
        method: 'POST',
        body: {
          taskId: task.id,
          childId,
          date,
          doneByChild: true
        }
      });
      const completionId = result?.completion?.id;
      if (completionId) {
        const approvalResult = await apiRequest(`/api/completions/${encodeURIComponent(completionId)}/approve`, {
          method: 'POST'
        });
        await applyServerStatePatchOrReload(approvalResult);
      } else {
        await reloadAfterServerMutation();
      }
      showConfetti();
      } catch (e) {
        alert(e.message || 'Nie udało się zaliczyć zadania');
      }
    });
  };
  const submitExtraTask = async title => {
    if (!selectedChild) return;
    const normalizedTitle = String(title || '').trim();
    if (normalizedTitle.length < 2) {
      alert('Wpisz, co udało Ci się zrobić.');
      return;
    }
    return runServerMutation(async () => {
      try {
      await apiRequest('/api/extra-tasks', {
        method: 'POST',
        body: {
          childId: selectedChild.id,
          title: normalizedTitle,
          date: getDateString()
        }
      });
      setExtraTaskTitle('');
      await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się zgłosić zadania dodatkowego');
      }
    });
  };
  const resubmitExtraTask = async task => {
    if (!task || task.status === 'PENDING') return;
    await submitExtraTask(task.title);
  };
  const approveExtraTask = async (extraTask, pointsValue) => {
    if (!extraTask || extraTask.status === 'APPROVED') return;
    const pointsToGrant = Number.parseInt(pointsValue, 10);
    if (!Number.isFinite(pointsToGrant) || pointsToGrant < 0) {
      alert('Podaj poprawną liczbę punktów.');
      return;
    }
    addPendingExtraTaskActions([extraTask.id]);
    return runServerMutation(async () => {
      try {
      const result = await apiRequest(`/api/extra-tasks/${encodeURIComponent(extraTask.id)}/approve`, {
        method: 'POST',
        body: {
          points: pointsToGrant
        }
      });
      await applyServerStatePatchOrReload(result);
      showConfetti();
      } catch (e) {
        alert(e.message || 'Nie udało się zatwierdzić zadania dodatkowego');
      } finally {
        clearPendingExtraTaskActions([extraTask.id]);
      }
    });
  };
  const rejectExtraTask = async extraTask => {
    if (!extraTask) return;
    addPendingExtraTaskActions([extraTask.id]);
    return runServerMutation(async () => {
      try {
      const result = await apiRequest(`/api/extra-tasks/${encodeURIComponent(extraTask.id)}/reject`, {
        method: 'POST'
      });
      await applyServerStatePatchOrReload(result);
      } catch (e) {
        alert(e.message || 'Nie udało się odrzucić zadania dodatkowego');
      } finally {
        clearPendingExtraTaskActions([extraTask.id]);
      }
    });
  };
  const addPointAdjustment = async (child, type) => {
    if (!child) return;
    setPointAdjustmentModal({ child, type });
  };
  const savePointAdjustment = async ({
    child,
    type,
    points,
    note
  }) => {
    if (!child) return;
    const isPenalty = type === 'PENALTY';
    const label = isPenalty ? 'karę' : 'premię';
    return runServerMutation(async () => {
      try {
      await apiRequest('/api/point-adjustments', {
        method: 'POST',
        body: {
          childId: child.id,
          type,
          points,
          note: String(note || '').trim()
        }
      });
      if (!isPenalty) {
        showConfetti();
      }
      setPointAdjustmentModal(null);
      await reloadAfterServerMutation();
      } catch (e) {
        throw new Error(e.message || `Nie udało się zapisać ${label}`);
      }
    });
  };
  const approveAllPending = async (list = null) => {
    const queue = [...(list || completions.filter(c => c.doneByChild && !c.approvedByParent))];
    if (queue.length === 0) return;
    const queueIds = queue.map(item => item.id).filter(Boolean);
    addPendingCompletionActions(queueIds);
    return runServerMutation(async () => {
      try {
      const bulkRequest = {
        ids: queueIds
      };
      if (approvalFilterChildId !== 'ALL') {
        bulkRequest.childId = approvalFilterChildId;
      }
      if (approvalFilterDate) {
        bulkRequest.date = approvalFilterDate;
      }
      const result = await apiRequest('/api/completions/approve-bulk', {
        method: 'POST',
        body: bulkRequest
      });
      const approvedCount = Number(result?.approvedCount || 0);
      await applyServerStatePatchOrReload(result);
      if (approvedCount === 0) {
        alert('Nie zatwierdzono żadnego zadania. Odświeżono listę zadań do zatwierdzenia.');
        return;
      }
      showConfetti();
      } catch (e) {
        alert(e.message || 'Nie udało się zatwierdzić zadań');
      } finally {
        clearPendingCompletionActions(queueIds);
      }
    });
  };
  const rejectAllPending = async (list = null) => {
    const queue = [...(list || completions.filter(c => c.doneByChild && !c.approvedByParent))];
    if (queue.length === 0) return;
    const queueIds = queue.map(item => item.id).filter(Boolean);
    addPendingCompletionActions(queueIds);
    return runServerMutation(async () => {
      try {
      const bulkRequest = {
        ids: queueIds
      };
      if (approvalFilterChildId !== 'ALL') {
        bulkRequest.childId = approvalFilterChildId;
      }
      if (approvalFilterDate) {
        bulkRequest.date = approvalFilterDate;
      }
      const result = await apiRequest('/api/completions/reject-bulk', {
        method: 'POST',
        body: bulkRequest
      });
      const rejectedCount = Number(result?.rejectedCount || 0);
      await applyServerStatePatchOrReload(result);
      if (rejectedCount === 0) {
        alert('Nie odrzucono żadnego zadania. Odświeżono listę zadań do zatwierdzenia.');
      }
      } catch (e) {
        alert(e.message || 'Nie udało się odrzucić zadań');
      } finally {
        clearPendingCompletionActions(queueIds);
      }
    });
  };
  useEffect(() => {
    if (view !== 'child' || user?.role !== 'CHILD' || !selectedChild) return;
    const approved = completions.filter(comp => comp.childId === selectedChild.id && comp.approvedByParent && comp.doneByChild);
    const approvedExtra = extraTasks.filter(task => task.childId === selectedChild.id && task.status === 'APPROVED');
    const childPointAdjustments = pointAdjustments.filter(adjustment => adjustment.childId === selectedChild.id);
    if (approved.length === 0 && approvedExtra.length === 0 && childPointAdjustments.length === 0) return;
    const storageKey = `fq_seen_approvals_${selectedChild.id}`;
    let seen = [];
    try {
      seen = JSON.parse(localStorage.getItem(storageKey) || '[]');
    } catch (e) {
      seen = [];
    }
    const seenSet = new Set(Array.isArray(seen) ? seen : []);
    const newApprovals = approved.filter(comp => comp.id && !seenSet.has(comp.id));
    const newExtraApprovals = approvedExtra.filter(task => task.id && !seenSet.has(task.id));
    const newPointAdjustments = childPointAdjustments.filter(adjustment => adjustment.id && !seenSet.has(adjustment.id));
    if (newApprovals.length === 0 && newExtraApprovals.length === 0 && newPointAdjustments.length === 0) return;
    const approvedTasks = newApprovals.map(comp => {
      const task = tasks.find(item => item.id === comp.taskId);
      return {
        id: comp.id,
        title: task?.title || 'Zadanie',
        points: task?.points || 0
      };
    }).concat(newExtraApprovals.map(task => ({
      id: task.id,
      title: task.title || 'Zadanie dodatkowe',
      points: Number(task.points || 0)
    })));
    const pointItems = newPointAdjustments.map(adjustment => ({
      id: adjustment.id,
      title: adjustment.note || (adjustment.type === 'PENALTY' ? 'Kara punktowa' : 'Premia punktowa'),
      points: Number(adjustment.delta || 0),
      type: adjustment.type
    }));
    const noticeItems = approvedTasks.concat(pointItems);
    const hasApprovedTasks = approvedTasks.length > 0;
    const hasBonus = pointItems.some(item => item.points > 0);
    const hasPenalty = pointItems.some(item => item.points < 0);
    const taskCountLabel = approvedTasks.length === 1 ? 'zadanie' : approvedTasks.length > 1 && approvedTasks.length < 5 ? 'zadania' : 'zadań';
    const adjustmentCountLabel = pointItems.length === 1 ? 'zmianę punktów' : pointItems.length > 1 && pointItems.length < 5 ? 'zmiany punktów' : 'zmian punktów';
    setChildApprovalNotice({
      count: noticeItems.length,
      title: hasApprovedTasks ? '🎉 Zaliczone zadania' : hasBonus && !hasPenalty ? '🎁 Premia punktowa' : hasPenalty && !hasBonus ? '⚠️ Kara punktowa' : 'Zmiana punktów',
      summary: hasApprovedTasks ? `Rodzic zatwierdził ${approvedTasks.length} ${taskCountLabel}.` : `Rodzic zapisał ${pointItems.length} ${adjustmentCountLabel}.`,
      encouragement: hasPenalty && !hasApprovedTasks && !hasBonus ? '' : 'Brawo!',
      tasks: noticeItems
    });
    if (hasApprovedTasks || hasBonus) {
      showConfetti();
    }
    localStorage.setItem(storageKey, JSON.stringify([...seenSet, ...newApprovals.map(comp => comp.id), ...newExtraApprovals.map(task => task.id), ...newPointAdjustments.map(adjustment => adjustment.id)].slice(-200)));
  }, [view, user?.role, selectedChild, completions, extraTasks, pointAdjustments, tasks, showConfetti]);
  const addChild = async (name, avatar, activeDays) => {
    return runServerMutation(async () => {
      try {
        const response = await apiRequest('/api/children', {
          method: 'POST',
          body: {
            name,
            avatar,
            activeDays
          }
        });
        if (response?.child?.id && response.child.accessCode) {
          setChildAccessCodes(prev => ({
            ...prev,
            [response.child.id]: response.child.accessCode
          }));
        }
        setShowModal(null);
        await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się dodać dziecka');
      }
    });
  };
  const addTask = async (childId, title, tier, points, description, daysOfWeek = []) => {
    const targetChildren = childId === 'ALL' ? activeChildren : activeChildren.filter(child => child.id === childId);
    if (targetChildren.length === 0) {
      alert('Wybierz dziecko albo dodaj najpierw profil dziecka.');
      return;
    }
    return runServerMutation(async () => {
      try {
        for (const child of targetChildren) {
          await apiRequest('/api/tasks', {
            method: 'POST',
            body: {
              childId: child.id,
              title: String(title || '').trim(),
              tier,
              points: Number(points || 0),
              description: String(description || '').trim(),
              daysOfWeek: normalizeTaskArchiveDays(daysOfWeek),
            },
          });
        }
        setShowModal(null);
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się dodać zadania');
      }
    });
  };
  const addReward = async (title, description, requiredPoints, requiredStreak, requiredIdealWeeks) => {
    return runServerMutation(async () => {
      try {
        await apiRequest('/api/rewards', {
          method: 'POST',
          body: { title, description, requiredPoints, requiredStreak, requiredIdealWeeks },
        });
        setShowModal(null);
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się dodać nagrody');
      }
    });
  };
  const updateReward = (rewardId, updates) => {
    return runServerMutation(async () => {
      try {
        await apiRequest(`/api/rewards/${encodeURIComponent(rewardId)}`, {
          method: 'PUT',
          body: updates,
        });
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się zaktualizować nagrody');
      }
    });
  };
  const archiveReward = rewardId => {
    return runServerMutation(async () => {
      try {
        await apiRequest(`/api/rewards/${encodeURIComponent(rewardId)}`, { method: 'DELETE' });
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się zarchiwizować nagrody');
      }
    });
  };
  const updateChild = (childId, updates) => {
    return runServerMutation(async () => {
      try {
        const response = await apiRequest(`/api/children/${encodeURIComponent(childId)}`, {
          method: 'PUT',
          body: updates
        });
        if (response?.child?.id && response.child.accessCode) {
          setChildAccessCodes(prev => ({
            ...prev,
            [response.child.id]: response.child.accessCode
          }));
        }
        await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się zaktualizować dziecka');
      }
    });
  };
  const archiveChild = childId => {
    return runServerMutation(async () => {
      try {
        await apiRequest(`/api/children/${encodeURIComponent(childId)}`, {
          method: 'DELETE'
        });
        await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się zarchiwizować dziecka');
      }
    });
  };
  const updateTask = async (taskId, updates) => {
    return runServerMutation(async () => {
      try {
        const payload = {
          ...updates,
          title: String(updates.title || '').trim(),
          description: updates.description || '',
          points: Number(updates.points || 0),
          daysOfWeek: normalizeTaskArchiveDays(updates.daysOfWeek)
        };
        const response = await apiRequest(`/api/tasks/${encodeURIComponent(taskId)}`, {
          method: 'PUT',
          body: payload
        });
        setTasks(prev => prev.map(task => task.id === taskId ? response.task || {
          ...task,
          ...payload,
          updatedAt: new Date().toISOString()
        } : task));
        await reloadAfterServerMutation();
        return response.task;
      } catch (error) {
        alert(error.message || 'Nie udało się zapisać zadania');
        throw error;
      }
    });
  };
  const archiveTask = async (taskId, {
    matching = false
  } = {}) => {
    return runServerMutation(async () => {
      try {
        await apiRequest(matching ? `/api/tasks/${encodeURIComponent(taskId)}/archive-matching` : `/api/tasks/${encodeURIComponent(taskId)}`, {
          method: matching ? 'POST' : 'DELETE'
        });
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się zarchiwizować zadania');
      }
    });
  };
  const restoreTask = async (taskId, {
    matching = false
  } = {}) => {
    return runServerMutation(async () => {
      try {
        await apiRequest(`/api/tasks/${encodeURIComponent(taskId)}/${matching ? 'restore-matching' : 'restore'}`, {
          method: 'POST'
        });
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się przywrócić zadania');
      }
    });
  };
  const updateFamilyGoal = updates => {
    return runServerMutation(async () => {
      try {
        await apiRequest('/api/family-goal', { method: 'PUT', body: updates });
        await reloadAfterServerMutation();
      } catch (error) {
        alert(error.message || 'Nie udało się zaktualizować celu rodzinnego');
      }
    });
  };
  const loadParentUsers = async () => {
    const response = await apiRequest('/api/auth/parents');
    setParentUsers(response.users || []);
  };
  const addParentUser = async ({
    email,
    password,
    pinCode
  }) => {
    await apiRequest('/api/auth/parents', {
      method: 'POST',
      body: {
        email,
        password,
        ...(pinCode ? { pinCode } : {})
      }
    });
    await loadParentUsers();
    addAuditLog('ADD_PARENT_USER', 'USER', email);
  };
  const setParentUserActive = async (userId, active) => {
    await apiRequest(`/api/auth/parents/${userId}/active`, {
      method: 'PUT',
      body: {
        active
      }
    });
    await loadParentUsers();
    addAuditLog(active ? 'ACTIVATE_USER' : 'DEACTIVATE_USER', 'USER', userId, {
      active
    });
  };
  const changeMyPassword = async (currentPassword, newPassword) => {
    await apiRequest('/api/auth/password', {
      method: 'PUT',
      body: {
        currentPassword,
        newPassword
      }
    });
    addAuditLog('CHANGE_PASSWORD', 'USER', user?.id || 'self');
  };
  const changeMyPin = async (currentPassword, pinCode) => {
    const response = await apiRequest('/api/auth/pin', {
      method: 'PUT',
      body: {
        currentPassword,
        pinCode
      }
    });
    if (response?.user) {
      setUser(response.user);
    } else {
      setUser(prev => prev ? { ...prev, hasPinCode: true } : prev);
    }
    await loadParentUsers();
    addAuditLog('CHANGE_PIN', 'USER', user?.id || 'self');
  };
  const resetParentPassword = async (userId, newPassword) => {
    await apiRequest('/api/auth/password/reset', {
      method: 'PUT',
      body: {
        userId,
        newPassword
      }
    });
    addAuditLog('RESET_PASSWORD', 'USER', userId);
  };
  const exportFamilyBackup = () => {
    const payload = {
      version: 1,
      exportedAt: new Date().toISOString(),
      data: {
        children,
        tasks,
        completions,
        extraTasks,
        pointAdjustments,
        pointLedger,
        rewards,
        streaks,
        points,
        rewardUnlocks,
        familyGoal,
        auditLogs,
        dayPointGrants,
        weekBonusGrants,
        taskPointGrants
      }
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `familyquest-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const importFamilyBackup = async jsonText => {
    const parsed = JSON.parse(jsonText);
    const data = parsed?.data || parsed;
    const childrenCount = Array.isArray(data?.children) ? data.children.length : 0;
    const tasksCount = Array.isArray(data?.tasks) ? data.tasks.length : 0;
    const ok = window.confirm(`Import backupu zastąpi aktualne dane rodziny.\n\nW pliku: ${childrenCount} dzieci, ${tasksCount} zadań.\nPo imporcie punkty i passa zostaną przeliczone przez serwer.\n\nKontynuować?`);
    if (!ok) {
      throw new Error('Import anulowany');
    }
    const result = await apiRequest('/api/storage/restore-backup', {
      method: 'POST',
      body: {
        backup: parsed
      }
    });
    if (Array.isArray(result?.childAccessCodes)) {
      setChildAccessCodes(Object.fromEntries(result.childAccessCodes.map(item => [item.childId, item.accessCode])));
    }
    await loadSnapshot({
      preserveView: true,
      silent: true,
      skipNextAutoSave: true,
      force: true,
    });
    return result;
  };
  if (loading) {
    return React.createElement("div", {
      className: "app-container"
    }, React.createElement("div", {
      className: "glass-card loading"
    }, "\uD83C\uDFC6 \u0141adowanie FamilyQuest..."));
  }
  if (view === 'login') {
    return React.createElement(LoginView, {
      onLogin: handleLogin,
      onRegister: handleRegister,
      onChildLogin: handleChildLogin,
      onForgotPassword: handleForgotPassword,
      onResetPassword: handleResetPasswordByToken,
      connectionError: connectionError
    });
  }
  if (view === 'childSelect') {
    const hasLeaderboard = familyLeaderboard.children.length > 0;
    return React.createElement(React.Fragment, null, React.createElement(ChildSelectionView, {
      children: activeChildren,
      streaks: streaks,
      points: points,
      leaderboardChildren: hasLeaderboard ? familyLeaderboard.children : activeChildren,
      leaderboardStreaks: streaks,
      leaderboardPoints: points,
      familyGoal: familyGoal,
      evaluateDay: evaluateDay,
      getDateString: getDateString,
      onSelectChild: selectChild,
      onParentMode: enterParentMode,
      onLogout: handleLogout
    }), parentPinGateOpen && React.createElement(ParentPinGate, {
      hasPinCode: Boolean(user?.hasPinCode),
      onVerify: handleParentPinVerify,
      onSetup: handleParentPinSetup,
      onCancel: closeParentPinGate
    }));
  }
  if (view === 'child' && selectedChild) {
    return React.createElement(ErrorBoundary, {
      title: "Widok dziecka wymaga odświeżenia",
      message: "Coś poszło nie tak podczas renderowania panelu dziecka.",
      onReset: () => loadSnapshot({
        preserveView: true,
        skipNextAutoSave: true,
        force: true,
      }),
      onLogout: handleLogout
    }, React.createElement(ChildView, {
      selectedChild: selectedChild,
      user: user,
      tasks: tasks,
      completions: completions,
      extraTasks: extraTasks,
      streaks: streaks,
      points: points,
      rewardUnlocks: rewardUnlocks,
      rewards: rewards,
      familyLeaderboard: familyLeaderboard,
      childTaskDate: childTaskDate,
      isOnline: isOnline,
      syncing: syncing,
      childApprovalNotice: childApprovalNotice,
      showPointHistory: showPointHistory,
      showChildRewards: showChildRewards,
      extraTaskTitle: extraTaskTitle,
      showRewardOverlay: showRewardOverlay,
      getDateString: getDateString,
      evaluateDay: evaluateDay,
      setView: setView,
      handleLogout: handleLogout,
      setChildTaskDate: setChildTaskDate,
      setChildApprovalNotice: setChildApprovalNotice,
      setShowPointHistory: setShowPointHistory,
      setShowChildRewards: setShowChildRewards,
      toggleTask: toggleTask,
      submitExtraTask: submitExtraTask,
      setExtraTaskTitle: setExtraTaskTitle,
      resubmitExtraTask: resubmitExtraTask,
      setRewardUnlocks: setRewardUnlocks,
      setShowRewardOverlay: setShowRewardOverlay
    }));
  }
  if (view === 'parent') {
    return React.createElement(ErrorBoundary, {
      title: "Panel rodzica wymaga odświeżenia",
      message: "Coś poszło nie tak podczas renderowania panelu rodzica.",
      onReset: () => loadSnapshot({
        preserveView: true,
        skipNextAutoSave: true,
        force: true,
      }),
      onLogout: handleLogout
    }, React.createElement(ParentPanel, {
      completions: completions,
      extraTasks: extraTasks,
      rewards: rewards,
      approvalFilterChildId: approvalFilterChildId,
      approvalFilterDate: approvalFilterDate,
      parentTaskDate: parentTaskDate,
      parentTaskChildId: parentTaskChildId,
      activeChildren: activeChildren,
      children: children,
      childAccessCodes: childAccessCodes,
      tasks: tasks,
      streaks: streaks,
      points: points,
      rewardUnlocks: rewardUnlocks,
      rewardUnlockHistory: rewardUnlockHistory,
      familyGoal: familyGoal,
      auditLogs: auditLogs,
      parentTab: parentTab,
      taskListMode: taskListMode,
      showModal: showModal,
      editingChild: editingChild,
      editingTask: editingTask,
      editingReward: editingReward,
      pointAdjustmentModal: pointAdjustmentModal,
      isOnline: isOnline,
      syncing: syncing,
      pendingCompletionActionIds: pendingCompletionActionIds,
      pendingExtraTaskActionIds: pendingExtraTaskActionIds,
      user: user,
      parentUsers: parentUsers,
      setView: nextView => {
        if (nextView === 'childSelect') {
          leaveParentMode();
          return;
        }
        setView(nextView);
      },
      setParentTab: setParentTab,
      setApprovalFilterChildId: setApprovalFilterChildId,
      setApprovalFilterDate: setApprovalFilterDate,
      setParentTaskChildId: setParentTaskChildId,
      setParentTaskDate: setParentTaskDate,
      setTaskListMode: setTaskListMode,
      setShowModal: setShowModal,
      setEditingChild: setEditingChild,
      setEditingTask: setEditingTask,
      setEditingReward: setEditingReward,
      setPointAdjustmentModal: setPointAdjustmentModal,
      handleLogout: handleLogout,
      approveAllPending: approveAllPending,
      rejectAllPending: rejectAllPending,
      approveTask: approveTask,
      rejectTask: rejectTask,
      approveExtraTask: approveExtraTask,
      rejectExtraTask: rejectExtraTask,
      completeTaskAsParent: completeTaskAsParent,
      reverseApproval: reverseApproval,
      evaluateDay: evaluateDay,
      getDateString: getDateString,
      archiveChild: archiveChild,
      addPointAdjustment: addPointAdjustment,
      archiveTask: archiveTask,
      restoreTask: restoreTask,
      archiveReward: archiveReward,
      claimReward: claimReward,
      loadParentUsers: loadParentUsers,
      addParentUser: addParentUser,
      setParentUserActive: setParentUserActive,
      changeMyPassword: changeMyPassword,
      changeMyPin: changeMyPin,
      resetParentPassword: resetParentPassword,
      updateFamilyGoal: updateFamilyGoal,
      exportFamilyBackup: exportFamilyBackup,
      importFamilyBackup: importFamilyBackup,
      addChild: addChild,
      updateChild: updateChild,
      addTask: addTask,
      updateTask: updateTask,
      addReward: addReward,
      updateReward: updateReward,
      savePointAdjustment: savePointAdjustment
    }));
  }
  return null;
};
export default App;
