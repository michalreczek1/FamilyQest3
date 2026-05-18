import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CHILD_SESSION_KEY, HISTORY_DAYS } from './constants.js';
import { apiRequest, clearLegacyAuthToken, useStorage } from './lib/api.js';
import { getDayNumber, getWeekStart, toDateString } from './lib/dates.js';
import { findAvailableChildAccessCode, isTaskScheduledForDate, normalizeTaskArchiveDays } from './lib/tasks.js';
import LoginView from './components/auth/LoginView.jsx';
import ChildSelectionView from './components/auth/ChildSelectionView.jsx';
import ChildView from './components/child/ChildView.jsx';
import ParentPanel from './components/parent/ParentPanel.jsx';
import { useAutosave } from './hooks/useAutosave.js';
import { useFamilyData } from './hooks/useFamilyData.js';
import { useRewardUnlocks } from './hooks/useRewardUnlocks.js';

const App = () => {
  const storage = useMemo(() => useStorage(), []);
  const [user, setUser] = useState(null);
  const [children, setChildren] = useState([]);
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
  const serverMutationQueueRef = useRef(Promise.resolve());
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
  });
  const { resetFamilyData, loadData } = useFamilyData({
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
  });
  useEffect(() => {
    const goOnline = () => setIsOnline(true);
    const goOffline = () => setIsOnline(false);
    window.addEventListener('online', goOnline);
    window.addEventListener('offline', goOffline);
    return () => {
      window.removeEventListener('online', goOnline);
      window.removeEventListener('offline', goOffline);
    };
  }, []);
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
    const queued = serverMutationQueueRef.current.catch(() => {}).then(action);
    serverMutationQueueRef.current = queued.catch(() => {});
    return queued;
  }, []);
  const reloadAfterServerMutation = useCallback((options = {}) => loadData({
    preserveView: true,
    silent: true,
    skipNextAutoSave: true,
    ...options
  }), [loadData]);
  useEffect(() => {
    clearLegacyAuthToken();
    loadData();
  }, []);
  useEffect(() => {
    if (!user || !hasLoadedSnapshot || view !== 'parent' && view !== 'child') {
      return undefined;
    }
    const refreshData = () => {
      if (document.visibilityState === 'hidden') return;
      if (saveInFlightRef.current || saveRequestedRef.current) return;
      loadData({
        preserveView: true,
        silent: true
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
  const { claimReward } = useRewardUnlocks({
    activeChildren,
    rewards,
    points,
    streaks,
    rewardUnlocks,
    setRewardUnlocks,
    setRewardUnlockHistory,
    setShowRewardOverlay,
    addAuditLog,
  });
  const evaluateDay = (childId, date) => {
    const child = children.find(c => c.id === childId);
    if (!child) return 'NOT_ACTIVE';
    const adjustedDay = getDayNumber(date);
    if (!child.activeDays.includes(adjustedDay)) return 'NOT_ACTIVE';
    const minTasks = tasks.filter(t => t.childId === childId && t.tier === 'MIN' && t.active !== false && isTaskScheduledForDate(t, date));
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
    setStreaks(next);
  }, [children, tasks, completions]);
  const handleLogin = async (email, password) => {
    try {
      await apiRequest('/api/auth/login', {
        method: 'POST',
        body: {
          email,
          password
        }
      }, false);
      await loadData();
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
      await apiRequest('/api/auth/register', {
        method: 'POST',
        body: {
          email,
          password,
          familyName
        }
      }, false);
      await loadData();
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
      await apiRequest('/api/auth/login-child', {
        method: 'POST',
        body: {
          accessCode
        }
      }, false);
      sessionStorage.setItem(CHILD_SESSION_KEY, '1');
      await loadData();
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
    try {
      await apiRequest('/api/auth/logout', {
        method: 'POST'
      }, false);
    } catch (e) {
      console.warn('Logout request failed:', e.message);
    }
    clearLegacyAuthToken();
    sessionStorage.removeItem(CHILD_SESSION_KEY);
    setUser(null);
    resetFamilyData();
    setView('login');
  };
  const selectChild = child => {
    if (user?.role === 'CHILD' && child.id !== user.childId) return;
    setSelectedChild(child);
    setView('child');
  };
  const enterParentMode = () => {
    if (user?.role === 'CHILD') return;
    setView('parent');
  };
  const toggleTask = (taskId, date = getDateString()) => {
    if (!selectedChild) return;
    const completionDate = date || getDateString();
    const existing = completions.find(c => c.taskId === taskId && c.date === completionDate && c.childId === selectedChild.id);
    if (existing) {
      if (existing.approvedByParent) return;
      existing.doneByChild = !existing.doneByChild;
      existing.updatedAt = new Date().toISOString();
      if (!existing.doneByChild) {
        existing.approvedByParent = false;
        existing.approvedAt = null;
      }
      setCompletions([...completions]);
      addAuditLog('TOGGLE_TASK', 'COMPLETION', existing.id, {
        childId: selectedChild.id,
        taskId,
        date: completionDate,
        doneByChild: existing.doneByChild
      });
    } else {
      const newCompletion = {
        id: `comp-${Date.now()}`,
        taskId,
        childId: selectedChild.id,
        date: completionDate,
        doneByChild: true,
        approvedByParent: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      setCompletions([...completions, newCompletion]);
      addAuditLog('TOGGLE_TASK', 'COMPLETION', newCompletion.id, {
        childId: selectedChild.id,
        taskId,
        date: completionDate,
        doneByChild: true
      });
    }
  };
  const approveTask = async (completion, {
    celebrate = true,
    reload = true
  } = {}) => {
    if (!completion || completion.approvedByParent) return;
    return runServerMutation(async () => {
      try {
      await apiRequest(`/api/completions/${encodeURIComponent(completion.id)}/approve`, {
        method: 'POST'
      });
      if (celebrate) showConfetti();
      if (reload) await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się zatwierdzić zadania');
      }
    });
  };
  const rejectTask = async completion => {
    if (!completion) return;
    return runServerMutation(async () => {
      try {
      await apiRequest(`/api/completions/${encodeURIComponent(completion.id)}/reject`, {
        method: 'POST'
      });
      await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się odrzucić zadania');
      }
    });
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
        await apiRequest(`/api/completions/${encodeURIComponent(completionId)}/approve`, {
          method: 'POST'
        });
      }
      showConfetti();
      await reloadAfterServerMutation();
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
    return runServerMutation(async () => {
      try {
      await apiRequest(`/api/extra-tasks/${encodeURIComponent(extraTask.id)}/approve`, {
        method: 'POST',
        body: {
          points: pointsToGrant
        }
      });
      showConfetti();
      await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się zatwierdzić zadania dodatkowego');
      }
    });
  };
  const rejectExtraTask = async extraTask => {
    if (!extraTask) return;
    return runServerMutation(async () => {
      try {
      await apiRequest(`/api/extra-tasks/${encodeURIComponent(extraTask.id)}/reject`, {
        method: 'POST'
      });
      await reloadAfterServerMutation();
      } catch (e) {
        alert(e.message || 'Nie udało się odrzucić zadania dodatkowego');
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
    return runServerMutation(async () => {
      try {
      const bulkRequest = {
        ids: queue.map(item => item.id).filter(Boolean)
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
      await reloadAfterServerMutation();
      if (approvedCount === 0) {
        alert('Nie zatwierdzono żadnego zadania. Odświeżono listę zadań do zatwierdzenia.');
        return;
      }
      showConfetti();
      } catch (e) {
        alert(e.message || 'Nie udało się zatwierdzić zadań');
      }
    });
  };
  const rejectAllPending = async (list = null) => {
    const queue = [...(list || completions.filter(c => c.doneByChild && !c.approvedByParent))];
    if (queue.length === 0) return;
    return runServerMutation(async () => {
      try {
      const bulkRequest = {
        ids: queue.map(item => item.id).filter(Boolean)
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
      await reloadAfterServerMutation();
      if (rejectedCount === 0) {
        alert('Nie odrzucono żadnego zadania. Odświeżono listę zadań do zatwierdzenia.');
      }
      } catch (e) {
        alert(e.message || 'Nie udało się odrzucić zadań');
      }
    });
  };
  const showConfetti = () => {
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
  }, [view, user?.role, selectedChild?.id, completions, extraTasks, pointAdjustments, tasks]);
  const addChild = async (name, avatar, activeDays) => {
    const accessCode = findAvailableChildAccessCode(children);
    if (!accessCode) {
      alert('Brak wolnych kodów dostępu dla dzieci');
      return;
    }
    const newChild = {
      id: `child-${Date.now()}`,
      name,
      avatar,
      activeDays,
      accessCode,
      archived: false,
      createdAt: new Date().toISOString()
    };
    setChildren([...children, newChild]);
    setStreaks({
      ...streaks,
      [newChild.id]: {
        current: 0,
        best: 0,
        idealWeeksCount: 0,
        idealWeeksInRow: 0
      }
    });
    setPoints({
      ...points,
      [newChild.id]: 0
    });
    addAuditLog('ADD_CHILD', 'CHILD', newChild.id, {
      name,
      activeDays
    });
    setShowModal(null);
  };
  const addTask = async (childId, title, tier, points, description, daysOfWeek = []) => {
    const targetChildren = childId === 'ALL' ? activeChildren : activeChildren.filter(child => child.id === childId);
    if (targetChildren.length === 0) {
      alert('Wybierz dziecko albo dodaj najpierw profil dziecka.');
      return;
    }
    const now = new Date().toISOString();
    const baseId = Date.now();
    const newTasks = targetChildren.map((child, index) => ({
      id: `task-${baseId}-${index}`,
      childId: child.id,
      title,
      tier,
      points: points || 0,
      description,
      daysOfWeek: normalizeTaskArchiveDays(daysOfWeek),
      active: true,
      createdAt: now
    }));
    setTasks(prev => [...prev, ...newTasks]);
    newTasks.forEach(task => {
      addAuditLog('ADD_TASK', 'TASK', task.id, {
        childId: task.childId,
        tier,
        points: task.points,
        bulk: childId === 'ALL'
      });
    });
    setShowModal(null);
  };
  const addReward = async (title, description, requiredPoints, requiredStreak, requiredIdealWeeks) => {
    const newReward = {
      id: `reward-${Date.now()}`,
      title,
      description,
      requiredPoints,
      requiredStreak,
      requiredIdealWeeks,
      active: true,
      createdAt: new Date().toISOString()
    };
    setRewards([...rewards, newReward]);
    addAuditLog('ADD_REWARD', 'REWARD', newReward.id, {
      requiredPoints,
      requiredStreak,
      requiredIdealWeeks
    });
    setShowModal(null);
  };
  const updateReward = (rewardId, updates) => {
    setRewards(prev => prev.map(reward => reward.id === rewardId ? {
      ...reward,
      ...updates,
      updatedAt: new Date().toISOString()
    } : reward));
    addAuditLog('UPDATE_REWARD', 'REWARD', rewardId, updates);
  };
  const archiveReward = rewardId => {
    updateReward(rewardId, {
      active: false
    });
  };
  const updateChild = (childId, updates) => {
    setChildren(prev => prev.map(child => child.id === childId ? {
      ...child,
      ...updates,
      updatedAt: new Date().toISOString()
    } : child));
    addAuditLog('UPDATE_CHILD', 'CHILD', childId, updates);
  };
  const archiveChild = childId => {
    updateChild(childId, {
      archived: true
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
        addAuditLog('UPDATE_TASK', 'TASK', taskId, payload);
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
    setFamilyGoal(prev => ({
      ...prev,
      ...updates
    }));
    addAuditLog('UPDATE_FAMILY_GOAL', 'FAMILY_GOAL', 'family-goal', updates);
  };
  const loadParentUsers = async () => {
    const response = await apiRequest('/api/auth/parents');
    setParentUsers(response.users || []);
  };
  const addParentUser = async ({
    email,
    password
  }) => {
    await apiRequest('/api/auth/parents', {
      method: 'POST',
      body: {
        email,
        password
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
    await loadData({
      preserveView: true,
      silent: true,
      skipNextAutoSave: true
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
      onResetPassword: handleResetPasswordByToken
    });
  }
  if (view === 'childSelect') {
    const hasLeaderboard = familyLeaderboard.children.length > 0;
    return React.createElement(ChildSelectionView, {
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
    });
  }
  if (view === 'child' && selectedChild) {
    return React.createElement(ChildView, {
      selectedChild: selectedChild,
      user: user,
      tasks: tasks,
      completions: completions,
      extraTasks: extraTasks,
      streaks: streaks,
      points: points,
      pointLedger: pointLedger,
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
    });
  }
  if (view === 'parent') {
    return React.createElement(ParentPanel, {
      completions: completions,
      extraTasks: extraTasks,
      rewards: rewards,
      approvalFilterChildId: approvalFilterChildId,
      approvalFilterDate: approvalFilterDate,
      parentTaskDate: parentTaskDate,
      parentTaskChildId: parentTaskChildId,
      activeChildren: activeChildren,
      children: children,
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
      user: user,
      parentUsers: parentUsers,
      setView: setView,
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
    });
  }
  return null;
};
export default App;
