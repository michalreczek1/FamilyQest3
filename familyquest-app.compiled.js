// FamilyQuest frontend source of truth.
// This file is the browser-loaded frontend used in production by index.html.
// There is currently no JSX build step; keep UI changes here until a real build pipeline replaces it.
const {
  useState,
  useEffect,
  useCallback,
  useRef,
  useMemo
} = React;
const LEGACY_AUTH_TOKEN_KEY = 'fq_auth_token';
const API_BASE_KEY = 'fq_api_base';
const CHILD_SESSION_KEY = 'fq_child_session_active';
const normalizeApiBase = value => {
  const raw = String(value || '').trim();
  if (!raw) return '';
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
};
const getApiBase = () => {
  const manualBase = normalizeApiBase(localStorage.getItem(API_BASE_KEY));
  if (manualBase) return manualBase;
  const host = window.location.hostname;
  const isLocalHost = host === 'localhost' || host === '127.0.0.1';
  if (isLocalHost && window.location.port !== '3010') {
    return 'http://localhost:3010';
  }
  return '';
};
const buildApiUrl = path => {
  if (/^https?:\/\//i.test(path)) return path;
  const base = getApiBase();
  return `${base}${path}`;
};
const clearLegacyAuthToken = () => localStorage.removeItem(LEGACY_AUTH_TOKEN_KEY);
const apiRequest = async (path, options = {}, withAuth = true) => {
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
const useStorage = () => {
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
const POINTS_PER_PASSED_DAY = 2;
const IDEAL_WEEK_BONUS = 3;
const HISTORY_DAYS = 3650;
const DAY_NAMES = ['Pon', 'Wt', 'Śr', 'Czw', 'Pt', 'Sob', 'Ndz'];
const CHILD_AVATARS = ['👧', '👦', '🧒', '👶', '🧑', '👱‍♀️', '👱‍♂️', '🧑‍🦱', '🧑‍🦰', '🧑‍🦳', '🦊', '🐼', '🦁', '🐯', '🐨', '🐸', '🐵', '🐶', '🐱', '🐰', '🦄', '🐙', '🦕', '🦖', '🦋', '⚽', '🏀', '🎮', '🎨', '🎵'];
const TASK_TEMPLATES = [{
  id: 'tpl-bed',
  title: 'Pościel łóżko',
  tier: 'MIN',
  points: 2,
  description: 'Rano po wstaniu'
}, {
  id: 'tpl-teeth',
  title: 'Umyj zęby',
  tier: 'MIN',
  points: 1,
  description: 'Rano i wieczorem'
}, {
  id: 'tpl-homework',
  title: 'Odrób lekcje',
  tier: 'MIN',
  points: 4,
  description: 'Po szkole'
}, {
  id: 'tpl-room',
  title: 'Posprzątaj pokój',
  tier: 'PLUS',
  points: 5,
  description: '15 minut porządków'
}, {
  id: 'tpl-reading',
  title: 'Czytanie 20 minut',
  tier: 'PLUS',
  points: 4,
  description: 'Dowolna książka'
}, {
  id: 'tpl-weekly-sport',
  title: 'Trening tygodniowy',
  tier: 'WEEKLY',
  points: 12,
  description: 'Min. 1 trening'
}];
const isValidChildAccessCode = value => /^\d{4}$/.test(String(value || ''));
const findAvailableChildAccessCode = (children, preferredCode = null, excludeChildId = null) => {
  const used = new Set((children || []).filter(c => c.id !== excludeChildId && isValidChildAccessCode(c.accessCode)).map(c => c.accessCode));
  if (isValidChildAccessCode(preferredCode) && !used.has(preferredCode)) return preferredCode;
  for (let i = 0; i <= 9999; i++) {
    const code = String(i).padStart(4, '0');
    if (!used.has(code)) return code;
  }
  return null;
};
const parseDateInput = dateInput => {
  if (typeof dateInput === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateInput)) {
    const [year, month, day] = dateInput.split('-').map(Number);
    return new Date(year, month - 1, day);
  }
  return new Date(dateInput);
};
const toDateString = (dateInput = new Date()) => {
  const date = parseDateInput(dateInput);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};
const getDayNumber = dateInput => {
  const day = parseDateInput(dateInput).getDay();
  return day === 0 ? 7 : day;
};
const isTaskScheduledForDate = (task, dateInput) => {
  if (!Array.isArray(task?.daysOfWeek) || task.daysOfWeek.length === 0) return true;
  return task.daysOfWeek.includes(getDayNumber(dateInput));
};
const normalizeTaskArchiveText = value => String(value || '').trim().replace(/\s+/g, ' ').toLocaleLowerCase('pl');
const normalizeTaskArchiveDays = days => Array.isArray(days) ? [...new Set(days.map(day => Number(day)).filter(day => Number.isInteger(day) && day >= 1 && day <= 7))].sort((a, b) => a - b) : [];
const getTaskArchiveFingerprint = task => JSON.stringify({
  title: normalizeTaskArchiveText(task?.title),
  tier: task?.tier || '',
  points: Number(task?.points || 0),
  description: normalizeTaskArchiveText(task?.description),
  daysOfWeek: normalizeTaskArchiveDays(task?.daysOfWeek)
});
const getWeekStart = dateInput => {
  const date = parseDateInput(dateInput);
  const day = date.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  date.setDate(date.getDate() + diff);
  return toDateString(date);
};
const getLeaderboardPoints = value => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};
const sortChildrenForLeaderboard = (children, streaks, points) => [...children].sort((a, b) => {
  const aPoints = getLeaderboardPoints(points[a.id]);
  const bPoints = getLeaderboardPoints(points[b.id]);
  if (aPoints !== bPoints) return bPoints - aPoints;
  const aStreak = streaks[a.id]?.current || 0;
  const bStreak = streaks[b.id]?.current || 0;
  if (aStreak !== bStreak) return bStreak - aStreak;
  const aIdeal = streaks[a.id]?.idealWeeksInRow || 0;
  const bIdeal = streaks[b.id]?.idealWeeksInRow || 0;
  if (aIdeal !== bIdeal) return bIdeal - aIdeal;
  return String(a.name || '').localeCompare(String(b.name || ''), 'pl');
});
const rankIcon = index => {
  if (index === 0) return '🏆';
  if (index === 1) return '🥈';
  if (index === 2) return '🥉';
  return `${index + 1}.`;
};
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
  const pendingSaveSnapshotRef = useRef(null);
  const saveInFlightRef = useRef(false);
  const saveRequestedRef = useRef(false);
  const skipNextSaveRef = useRef(false);
  const skipAutoSaveUntilRef = useRef(0);
  const resetFamilyData = () => {
    setChildren([]);
    setTasks([]);
    setCompletions([]);
    setExtraTasks([]);
    setPointAdjustments([]);
    setPointLedger([]);
    setRewards([]);
    setStreaks({});
    setPoints({});
    setFamilyLeaderboard({
      children: [],
      points: {},
      streaks: {}
    });
    setRewardUnlocks([]);
    setFamilyGoal({
      title: 'Cel rodzinny',
      target: 500,
      mode: 'points'
    });
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
  };
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
  useEffect(() => {
    clearLegacyAuthToken();
    loadData();
  }, []);
  const loadData = async ({
    preserveView = false,
    silent = false,
    skipNextAutoSave = false
  } = {}) => {
    if (!silent) {
      setLoading(true);
      setHasLoadedSnapshot(false);
    }
    try {
      const session = await apiRequest('/api/auth/me');
      if (session.user?.role === 'CHILD' && sessionStorage.getItem(CHILD_SESSION_KEY) !== '1') {
        try {
          await apiRequest('/api/auth/logout', {
            method: 'POST'
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
      const [savedChildren, savedTasks, savedCompletions, savedExtraTasks, savedPointAdjustments, savedPointLedger, savedRewards, savedStreaks, savedPoints, savedRewardUnlocks, savedFamilyGoal, savedAuditLogs, savedDayPointGrants, savedWeekBonusGrants, savedTaskPointGrants] = await Promise.all([storage.get('children'), storage.get('tasks'), storage.get('completions'), storage.get('extraTasks'), storage.get('pointAdjustments'), storage.get('pointLedger'), storage.get('rewards'), storage.get('streaks'), storage.get('points'), storage.get('rewardUnlocks'), storage.get('familyGoal'), storage.get('auditLogs'), storage.get('dayPointGrants'), storage.get('weekBonusGrants'), storage.get('taskPointGrants')]);
      const rawChildren = savedChildren || [];
      const loadedChildren = rawChildren.map(child => ({
        ...child
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
      setPointLedger(savedPointLedger || []);
      setRewards(savedRewards || []);
      setStreaks(savedStreaks || {});
      setPoints(savedPoints || {});
      setRewardUnlocks(savedRewardUnlocks || []);
      setFamilyGoal(savedFamilyGoal || {
        title: 'Cel rodzinny',
        target: 500,
        mode: 'points'
      });
      setAuditLogs(savedAuditLogs || []);
      setDayPointGrants(savedDayPointGrants || {});
      setWeekBonusGrants(savedWeekBonusGrants || {});
      setTaskPointGrants(savedTaskPointGrants || {});
      try {
        const leaderboard = await apiRequest('/api/leaderboard');
        setFamilyLeaderboard({
          children: leaderboard.children || [],
          points: leaderboard.points || {},
          streaks: leaderboard.streaks || {}
        });
      } catch (leaderboardError) {
        console.warn('Could not load family leaderboard:', leaderboardError.message);
        setFamilyLeaderboard({
          children: loadedChildren.map(child => ({
            id: child.id,
            name: child.name,
            avatar: child.avatar
          })),
          points: savedPoints || {},
          streaks: savedStreaks || {}
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
          const parentUsersResponse = await apiRequest('/api/auth/parents');
          setParentUsers(parentUsersResponse.users || []);
        } catch (parentError) {
          console.warn('Could not load parent users:', parentError.message);
          setParentUsers([]);
        }
      } else {
        setParentUsers([]);
      }
    } catch (e) {
      console.error('Load data error:', e);
      if (silent) return;
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
  };
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
        const snapshot = pendingSaveSnapshotRef.current;
        pendingSaveSnapshotRef.current = null;
        await storage.merge(snapshot);
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
  }, [storage]);
  useEffect(() => {
    if (!loading && user && hasLoadedSnapshot) {
      if (skipNextSaveRef.current) {
        skipNextSaveRef.current = false;
        return;
      }
      if (Date.now() < skipAutoSaveUntilRef.current) {
        return;
      }
      pendingSaveSnapshotRef.current = {
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
      };
      saveRequestedRef.current = true;
      flushSaveQueue();
    }
  }, [loading, user, hasLoadedSnapshot, children, tasks, completions, extraTasks, pointAdjustments, pointLedger, rewards, streaks, points, rewardUnlocks, familyGoal, auditLogs, dayPointGrants, weekBonusGrants, taskPointGrants, flushSaveQueue]);
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
  const grantPoints = (childId, amount) => {
    setPoints(prev => {
      const currentPoints = prev[childId] || 0;
      return {
        ...prev,
        [childId]: currentPoints + amount
      };
    });
  };
  const getDayPointKey = (childId, date) => `${childId}:${date}`;
  const getWeekPointKey = (childId, weekStart) => `${childId}:${weekStart}`;
  const grantDayPointsIfNeeded = (childId, date) => {
    const key = getDayPointKey(childId, date);
    if (dayPointGrants[key]) return;
    setDayPointGrants(prev => ({
      ...prev,
      [key]: true
    }));
    grantPoints(childId, POINTS_PER_PASSED_DAY);
    addAuditLog('GRANT_DAY_POINTS', 'DAY', key, {
      childId,
      date,
      points: POINTS_PER_PASSED_DAY
    });
  };
  const grantWeekBonusIfNeeded = (childId, date) => {
    const weekStart = getWeekStart(date);
    const weekStatus = evaluateWeek(childId, weekStart);
    if (weekStatus !== 'IDEAL') return;
    const key = getWeekPointKey(childId, weekStart);
    if (weekBonusGrants[key]) return;
    setWeekBonusGrants(prev => ({
      ...prev,
      [key]: true
    }));
    grantPoints(childId, IDEAL_WEEK_BONUS);
    addAuditLog('GRANT_WEEK_BONUS', 'WEEK', key, {
      childId,
      weekStart,
      points: IDEAL_WEEK_BONUS
    });
  };
  const checkRewards = childId => {
    const childPoints = points[childId] || 0;
    const childStreak = streaks[childId] || {
      current: 0,
      idealWeeksInRow: 0
    };
    const now = new Date().toISOString();
    rewards.forEach(reward => {
      if (reward.active === false) return;
      const already = rewardUnlocks.find(r => r.childId === childId && r.rewardId === reward.id);
      if (already) return;
      const pointsOk = !reward.requiredPoints || childPoints >= reward.requiredPoints;
      const streakOk = !reward.requiredStreak || childStreak.current >= reward.requiredStreak;
      const idealOk = !reward.requiredIdealWeeks || childStreak.idealWeeksInRow >= reward.requiredIdealWeeks;
      if (pointsOk && streakOk && idealOk) {
        const unlock = {
          id: `unlock-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          childId,
          rewardId: reward.id,
          unlockedAt: now,
          claimedAt: null,
          shownAt: null
        };
        setRewardUnlocks(prev => [unlock, ...prev]);
        setShowRewardOverlay({
          childId,
          reward
        });
        addAuditLog('UNLOCK_REWARD', 'REWARD', reward.id, {
          childId
        });
      }
    });
  };
  useEffect(() => {
    activeChildren.forEach(child => checkRewards(child.id));
  }, [points, streaks, rewards, children]);
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
    try {
      await apiRequest(`/api/completions/${encodeURIComponent(completion.id)}/approve`, {
        method: 'POST'
      });
      if (celebrate) showConfetti();
      if (reload) await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się zatwierdzić zadania');
    }
  };
  const rejectTask = async completion => {
    if (!completion) return;
    try {
      await apiRequest(`/api/completions/${encodeURIComponent(completion.id)}/reject`, {
        method: 'POST'
      });
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się odrzucić zadania');
    }
  };
  const reverseApproval = async completion => {
    if (!completion || !completion.approvedByParent) return;
    const task = tasks.find(item => item.id === completion.taskId);
    const child = children.find(item => item.id === completion.childId);
    const label = `${child?.name || 'Dziecko'} • ${task?.title || 'zadanie'} • ${completion.date}`;
    const ok = window.confirm(`Cofnąć zatwierdzenie?\n\n${label}\n\nSystem przeliczy punkty i passę, a korekta zostanie zapisana w historii.`);
    if (!ok) return;
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
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się cofnąć zatwierdzenia');
    }
  };
  const completeTaskAsParent = async (task, childId, date) => {
    if (!task || !childId || !date) return;
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
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się zaliczyć zadania');
    }
  };
  const submitExtraTask = async title => {
    if (!selectedChild) return;
    const normalizedTitle = String(title || '').trim();
    if (normalizedTitle.length < 2) {
      alert('Wpisz, co udało Ci się zrobić.');
      return;
    }
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
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się zgłosić zadania dodatkowego');
    }
  };
  const approveExtraTask = async (extraTask, pointsValue) => {
    if (!extraTask || extraTask.status === 'APPROVED') return;
    const pointsToGrant = Number.parseInt(pointsValue, 10);
    if (!Number.isFinite(pointsToGrant) || pointsToGrant < 0) {
      alert('Podaj poprawną liczbę punktów.');
      return;
    }
    try {
      await apiRequest(`/api/extra-tasks/${encodeURIComponent(extraTask.id)}/approve`, {
        method: 'POST',
        body: {
          points: pointsToGrant
        }
      });
      showConfetti();
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się zatwierdzić zadania dodatkowego');
    }
  };
  const rejectExtraTask = async extraTask => {
    if (!extraTask) return;
    try {
      await apiRequest(`/api/extra-tasks/${encodeURIComponent(extraTask.id)}/reject`, {
        method: 'POST'
      });
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się odrzucić zadania dodatkowego');
    }
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
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      throw new Error(e.message || `Nie udało się zapisać ${label}`);
    }
  };
  const approveAllPending = async (list = null) => {
    const queue = [...(list || completions.filter(c => c.doneByChild && !c.approvedByParent))];
    if (queue.length === 0) return;
    try {
      for (const item of queue) {
        await apiRequest(`/api/completions/${encodeURIComponent(item.id)}/approve`, {
          method: 'POST'
        });
      }
      showConfetti();
      await loadData({
        preserveView: true,
        silent: true
      });
    } catch (e) {
      alert(e.message || 'Nie udało się zatwierdzić zadań');
    }
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
      await loadData({
        preserveView: true,
        silent: true,
        skipNextAutoSave: true
      });
      addAuditLog('UPDATE_TASK', 'TASK', taskId, payload);
      return response.task;
    } catch (error) {
      alert(error.message || 'Nie udało się zapisać zadania');
      throw error;
    }
  };
  const archiveTask = async (taskId, {
    matching = false
  } = {}) => {
    try {
      await apiRequest(matching ? `/api/tasks/${encodeURIComponent(taskId)}/archive-matching` : `/api/tasks/${encodeURIComponent(taskId)}`, {
        method: matching ? 'POST' : 'DELETE'
      });
      await loadData({
        preserveView: true,
        silent: true,
        skipNextAutoSave: true
      });
    } catch (error) {
      alert(error.message || 'Nie udało się zarchiwizować zadania');
    }
  };
  const restoreTask = async taskId => {
    try {
      await apiRequest(`/api/tasks/${encodeURIComponent(taskId)}/restore`, {
        method: 'POST'
      });
      await loadData({
        preserveView: true,
        silent: true,
        skipNextAutoSave: true
      });
    } catch (error) {
      alert(error.message || 'Nie udało się przywrócić zadania');
    }
  };
  const claimReward = unlockId => {
    setRewardUnlocks(prev => prev.map(u => u.id === unlockId ? {
      ...u,
      claimedAt: new Date().toISOString()
    } : u));
    addAuditLog('CLAIM_REWARD', 'REWARD_UNLOCK', unlockId);
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
    const today = getDateString();
    const selectedTaskDate = childTaskDate || today;
    const selectedTaskDateLabel = selectedTaskDate === today ? 'dzisiaj' : selectedTaskDate;
    const childTasks = tasks.filter(t => t.childId === selectedChild.id && t.active !== false);
    const selectedDateTasks = childTasks.filter(t => isTaskScheduledForDate(t, selectedTaskDate));
    const selectedDateCompletions = completions.filter(c => c.childId === selectedChild.id && c.date === selectedTaskDate);
    const childExtraTasks = extraTasks.filter(task => task.childId === selectedChild.id).sort((a, b) => Date.parse(b.updatedAt || b.submittedAt || b.createdAt || 0) - Date.parse(a.updatedAt || a.submittedAt || a.createdAt || 0)).slice(0, 8);
    const childStreak = streaks[selectedChild.id] || {
      current: 0,
      best: 0
    };
    const childPoints = points[selectedChild.id] || 0;
    const childPointLedger = pointLedger.filter(entry => entry.childId === selectedChild.id).sort((a, b) => Date.parse(b.occurredAt || 0) - Date.parse(a.occurredAt || 0));
    const childRewardUnlocks = rewardUnlocks.filter(unlock => unlock.childId === selectedChild.id);
    const childUnlockedRewardIds = new Set(childRewardUnlocks.map(unlock => unlock.rewardId));
    const childEarnedRewards = childRewardUnlocks.map(unlock => ({
      unlock,
      reward: rewards.find(reward => reward.id === unlock.rewardId)
    })).filter(item => Boolean(item.reward)).sort((a, b) => Date.parse(b.unlock.unlockedAt || 0) - Date.parse(a.unlock.unlockedAt || 0));
    const nextPointReward = rewards.filter(reward => reward.active !== false && !childUnlockedRewardIds.has(reward.id) && Number(reward.requiredPoints || 0) > childPoints).sort((a, b) => Number(a.requiredPoints || 0) - Number(b.requiredPoints || 0))[0] || null;
    const pointsToNextReward = nextPointReward ? Math.max(0, Number(nextPointReward.requiredPoints || 0) - childPoints) : 0;
    const dayStatus = evaluateDay(selectedChild.id, selectedTaskDate);
    const last14Days = [];
    for (let i = 0; i < 14; i++) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = getDateString(date);
      const status = evaluateDay(selectedChild.id, dateStr);
      last14Days.unshift({
        date: dateStr,
        status
      });
    }
    return React.createElement(React.Fragment, null, React.createElement("div", {
      className: "app-container"
    }, React.createElement("div", {
      className: "top-status"
    }, user?.role !== 'CHILD' ? React.createElement("button", {
      className: "btn btn-secondary",
      onClick: () => setView('childSelect')
    }, "\u2190 Powr\xF3t") : React.createElement("div", null), React.createElement("div", {
      className: "network-status-group"
    }, React.createElement("div", {
      className: `network-badge ${isOnline ? '' : 'offline'}`
    }, isOnline ? '🟢 Online' : '🔴 Offline'), syncing && React.createElement("div", {
      className: "network-badge syncing"
    }, "\u23F3 Synchronizacja...")), React.createElement("button", {
      className: "btn btn-danger",
      onClick: handleLogout
    }, "Wyloguj")), React.createElement("div", {
      className: "glass-card"
    }, React.createElement("div", {
      className: "header"
    }, React.createElement("h1", {
      className: "child-hero-title"
    }, React.createElement("span", {
      className: "child-hero-avatar"
    }, selectedChild.avatar), React.createElement("span", null, selectedChild.name)), React.createElement("div", {
      className: "hero-metrics"
    }, React.createElement("button", {
      type: "button",
      className: "hero-metric points",
      onClick: () => setShowPointHistory(true),
      title: "Pokaż historię punktów"
    }, React.createElement("div", {
      className: "hero-metric-icon"
    }, "\u26A1"), React.createElement("div", null, React.createElement("div", {
      className: "hero-metric-value"
    }, childPoints), React.createElement("div", {
      className: "hero-metric-label"
    }, "punkt\xF3w"))), React.createElement("button", {
      type: "button",
      className: "hero-metric rewards",
      onClick: () => setShowChildRewards(true),
      title: "Poka\u017C moje nagrody"
    }, React.createElement("div", {
      className: "hero-metric-icon"
    }, "\uD83C\uDF81"), React.createElement("div", null, React.createElement("div", {
      className: "hero-metric-value"
    }, childEarnedRewards.length), React.createElement("div", {
      className: "hero-metric-label"
    }, "moje nagrody"))), React.createElement("div", {
      className: "hero-metric streak"
    }, React.createElement("div", {
      className: "hero-metric-icon"
    }, "\uD83D\uDD25"), React.createElement("div", null, React.createElement("div", {
      className: "hero-metric-value"
    }, childStreak.current), React.createElement("div", {
      className: "hero-metric-label"
    }, "dni passy"))))), React.createElement("div", {
      className: "glass-card",
      style: {
        marginBottom: '1rem'
      }
    }, React.createElement("h3", null, "Status dnia: ", dayStatus === 'PASSED' ? '✅ ZALICZONY' : dayStatus === 'FAILED' ? '❌ NIE ZALICZONY' : '⊘ NIE AKTYWNY'), React.createElement("p", {
      style: {
        opacity: 0.7,
        marginTop: '0.5rem'
      }
    }, "Punkty i zaliczenie wymagaj\u0105 akceptacji rodzica")), childApprovalNotice && React.createElement("div", {
      className: "modal child-approval-modal",
      style: {
        alignItems: 'flex-start',
        paddingTop: 'clamp(1rem, 7vh, 4.5rem)',
        paddingBottom: '1rem',
        overflowY: 'auto'
      },
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "child-approval-title"
    }, React.createElement("div", {
      className: "modal-content",
      style: {
        maxWidth: '520px',
        maxHeight: 'calc(100vh - 2rem)',
        borderColor: 'rgba(18, 183, 106, 0.65)',
        boxShadow: '0 24px 80px rgba(18, 183, 106, 0.25)'
      }
    }, React.createElement("h2", {
      id: "child-approval-title",
      style: {
        marginBottom: '0.75rem'
      }
    }, childApprovalNotice.title || "\uD83C\uDF89 Zaliczone zadania"), React.createElement("p", {
      style: {
        opacity: 0.88,
        marginBottom: '1rem'
      }
    }, childApprovalNotice.summary, childApprovalNotice.encouragement ? ` ${childApprovalNotice.encouragement}` : ''), React.createElement("ul", {
      style: {
        display: 'grid',
        gap: '0.75rem',
        listStyle: 'none',
        margin: '0 0 1.5rem',
        padding: 0
      }
    }, childApprovalNotice.tasks.map(task => React.createElement("li", {
      key: task.id,
      style: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
        padding: '0.85rem 1rem',
        borderRadius: '1rem',
        background: task.points < 0 ? 'rgba(249, 112, 102, 0.18)' : 'rgba(18, 183, 106, 0.18)',
        border: task.points < 0 ? '1px solid rgba(249, 112, 102, 0.4)' : '1px solid rgba(18, 183, 106, 0.36)'
      }
    }, React.createElement("strong", null, task.title), task.points !== 0 && React.createElement("span", {
      style: {
        whiteSpace: 'nowrap',
        fontWeight: 800,
        color: task.points < 0 ? '#FDA29B' : '#FEC84B'
      }
    }, task.points > 0 ? '+' : '', task.points, " pkt")))), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setChildApprovalNotice(null),
      style: {
        width: '100%'
      }
    }, childApprovalNotice.encouragement ? "Super!" : "Rozumiem"))), showPointHistory && React.createElement("div", {
      className: "modal",
      style: {
        alignItems: 'flex-start',
        paddingTop: 'clamp(1rem, 7vh, 4.5rem)',
        paddingBottom: '1rem',
        overflowY: 'auto'
      },
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "child-points-title"
    }, React.createElement("div", {
      className: "modal-content point-history-modal-content"
    }, React.createElement("div", {
      className: "point-history-header"
    }, React.createElement("h2", {
      id: "child-points-title",
      style: {
        margin: 0
      }
    }, "\u26A1 Historia punkt\xF3w"), React.createElement("button", {
      className: "btn btn-secondary",
      onClick: () => setShowPointHistory(false),
      title: "Zamknij"
    }, "\u2715")), React.createElement("div", {
      className: "glass-card point-history-summary"
    }, React.createElement("div", {
      className: "stat-value"
    }, childPoints), React.createElement("div", {
      className: "stat-label"
    }, "aktualnych punkt\xF3w")), React.createElement("div", {
      className: "point-history-list"
    }, childPointLedger.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Nie ma jeszcze historii punkt\xF3w") : childPointLedger.map(entry => {
      const delta = Number(entry.delta || 0);
      const isNegative = delta < 0;
      const when = entry.date || (entry.occurredAt ? entry.occurredAt.slice(0, 10) : '');
      const typeLabel = entry.type === 'TASK_APPROVED' ? 'Zadanie' : entry.type === 'DAY_PASSED' ? 'Dzie\u0144' : entry.type === 'WEEK_IDEAL' ? 'Tydzie\u0144' : entry.type === 'EXTRA_TASK' ? 'Extra' : entry.type === 'PENALTY' ? 'Kara' : entry.type === 'REVERSAL' ? 'Cofni\u0119cie' : 'Premia';
      return React.createElement("div", {
        key: entry.id,
        className: "point-history-entry"
      }, React.createElement("div", {
        className: `badge ${isNegative ? 'badge-min' : 'badge-points'} point-history-delta`
      }, delta > 0 ? '+' : '', delta, " pkt"), React.createElement("div", {
        className: "point-history-body"
      }, React.createElement("div", {
        className: "point-history-title"
      }, entry.title || typeLabel), React.createElement("div", {
        className: "point-history-meta"
      }, typeLabel, when ? ` • ${when}` : '', Number.isFinite(Number(entry.newPoints)) ? ` • saldo: ${entry.newPoints}` : ''), entry.note && entry.note !== entry.title && React.createElement("div", {
        className: "point-history-note"
      }, entry.note)));
    })))), showChildRewards && React.createElement("div", {
      className: "modal",
      style: {
        alignItems: 'flex-start',
        paddingTop: 'clamp(1rem, 7vh, 4.5rem)',
        paddingBottom: '1rem',
        overflowY: 'auto'
      },
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "child-rewards-title"
    }, React.createElement("div", {
      className: "modal-content child-rewards-modal",
      style: {
        maxWidth: '640px',
        maxHeight: 'calc(100vh - 2rem)'
      }
    }, React.createElement("div", {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        gap: '1rem',
        alignItems: 'center',
        marginBottom: '1rem'
      }
    }, React.createElement("h2", {
      id: "child-rewards-title",
      style: {
        margin: 0
      }
    }, "\uD83C\uDF81 Moje nagrody"), React.createElement("button", {
      className: "btn btn-secondary",
      onClick: () => setShowChildRewards(false),
      title: "Zamknij"
    }, "\u2715")), React.createElement("div", {
      className: "glass-card",
      style: {
        marginBottom: '1rem',
        background: 'rgba(254, 200, 75, 0.16)',
        borderColor: 'rgba(254, 200, 75, 0.42)'
      }
    }, nextPointReward ? React.createElement(React.Fragment, null, React.createElement("div", {
      style: {
        fontWeight: 800,
        marginBottom: '0.35rem'
      }
    }, "Najbli\u017Csza nagroda: ", nextPointReward.title), React.createElement("div", {
      style: {
        opacity: 0.85
      }
    }, "Brakuje jeszcze ", React.createElement("strong", null, pointsToNextReward, " pkt"), " do progu ", Number(nextPointReward.requiredPoints || 0), " pkt."), nextPointReward.description && React.createElement("div", {
      style: {
        opacity: 0.72,
        marginTop: '0.35rem'
      }
    }, nextPointReward.description)) : React.createElement("div", {
      style: {
        fontWeight: 700
      }
    }, "Nie ma teraz kolejnej nagrody punktowej do zdobycia.")), React.createElement("h3", {
      style: {
        marginBottom: '0.75rem'
      }
    }, "Zdobyte nagrody"), childEarnedRewards.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Nie masz jeszcze zdobytych nagr\xF3d.") : React.createElement("div", {
      style: {
        display: 'grid',
        gap: '0.75rem'
      }
    }, childEarnedRewards.map(({
      unlock,
      reward
    }) => React.createElement("div", {
      key: unlock.id,
      className: "task-item"
    }, React.createElement("div", {
      style: {
        fontSize: '2rem'
      }
    }, "\uD83C\uDFC5"), React.createElement("div", {
      style: {
        flex: 1
      }
    }, React.createElement("div", {
      style: {
        fontWeight: 700
      }
    }, reward.title), reward.description && React.createElement("div", {
      style: {
        fontSize: '0.88rem',
        opacity: 0.72
      }
    }, reward.description), React.createElement("div", {
      style: {
        fontSize: '0.82rem',
        opacity: 0.72,
        marginTop: '0.25rem'
      }
    }, "Zdobyta: ", unlock.unlockedAt?.slice(0, 10) || 'dzisiaj')), React.createElement("div", {
      className: unlock.claimedAt ? "badge badge-min" : "badge badge-pending"
    }, unlock.claimedAt ? "Odebrana" : "Do odebrania")))), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setShowChildRewards(false),
      style: {
        width: '100%',
        marginTop: '1rem'
      }
    }, "Zamknij"))), React.createElement("div", {
      className: "grid grid-2",
      style: {
        marginBottom: '1.5rem'
      }
    }, React.createElement("div", {
      className: "stat-card"
    }, React.createElement("div", {
      className: "stat-label"
    }, "Aktualna passa"), React.createElement("div", {
      className: "stat-value"
    }, childStreak.current), React.createElement("div", {
      className: "stat-label"
    }, "dni z rz\u0119du")), React.createElement("div", {
      className: "stat-card"
    }, React.createElement("div", {
      className: "stat-label"
    }, "Najlepsza passa"), React.createElement("div", {
      className: "stat-value"
    }, childStreak.best), React.createElement("div", {
      className: "stat-label"
    }, "rekord"))), React.createElement("div", {
      className: "glass-card",
      style: {
        marginBottom: '1.25rem'
      }
    }, React.createElement("label", {
      style: {
        display: 'block',
        marginBottom: '0.5rem',
        opacity: 0.82,
        fontWeight: 700
      }
    }, "Data zada\u0144"), React.createElement("input", {
      className: "input",
      type: "date",
      value: selectedTaskDate,
      max: today,
      onChange: e => setChildTaskDate(e.target.value || today)
    })), React.createElement("h2", {
      style: {
        marginBottom: '1rem'
      }
    }, "Zadania ", selectedTaskDateLabel), React.createElement("h3", {
      style: {
        marginTop: '1.5rem',
        marginBottom: '0.5rem'
      }
    }, "\uD83D\uDCCB MINIMUM (wymagane)"), selectedDateTasks.filter(t => t.tier === 'MIN').map(task => {
      const completion = selectedDateCompletions.find(c => c.taskId === task.id);
      const isDone = completion?.doneByChild;
      const isApproved = completion?.approvedByParent;
      const isPendingApproval = isDone && !isApproved;
      return React.createElement("div", {
        key: task.id,
        className: `task-item ${isDone ? 'completed' : ''} ${isApproved ? 'approved' : ''}`,
        onClick: () => toggleTask(task.id, selectedTaskDate)
      }, React.createElement("div", {
        className: "checkbox"
      }, isApproved ? '✓' : isDone ? '⏳' : ''), React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, task.title), task.description && React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, task.description), isPendingApproval && React.createElement("div", {
        className: "badge badge-pending",
        style: {
          marginTop: '0.35rem',
          width: 'fit-content'
        }
      }, "Czeka na zatwierdzenie rodzica")), task.points > 0 && React.createElement("div", {
        className: "badge badge-points"
      }, "+", task.points, " pkt"), isApproved && React.createElement("div", {
        className: "badge badge-min"
      }, "Zatwierdzone"));
    }), React.createElement("h3", {
      style: {
        marginTop: '1.5rem',
        marginBottom: '0.5rem'
      }
    }, "\u2B50 BONUS (dodatkowe punkty)"), selectedDateTasks.filter(t => t.tier === 'PLUS').map(task => {
      const completion = selectedDateCompletions.find(c => c.taskId === task.id);
      const isDone = completion?.doneByChild;
      const isApproved = completion?.approvedByParent;
      const isPendingApproval = isDone && !isApproved;
      return React.createElement("div", {
        key: task.id,
        className: `task-item ${isDone ? 'completed' : ''} ${isApproved ? 'approved' : ''}`,
        onClick: () => toggleTask(task.id, selectedTaskDate)
      }, React.createElement("div", {
        className: "checkbox"
      }, isApproved ? '✓' : isDone ? '⏳' : ''), React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, task.title), isPendingApproval && React.createElement("div", {
        className: "badge badge-pending",
        style: {
          marginTop: '0.35rem',
          width: 'fit-content'
        }
      }, "Czeka na zatwierdzenie rodzica")), task.points > 0 && React.createElement("div", {
        className: "badge badge-points"
      }, "+", task.points, " pkt"));
    }), selectedDateTasks.filter(t => t.tier === 'WEEKLY').length > 0 && React.createElement(React.Fragment, null, React.createElement("h3", {
      style: {
        marginTop: '1.5rem',
        marginBottom: '0.5rem'
      }
    }, "\uD83D\uDCC5 TYGODNIOWE"), selectedDateTasks.filter(t => t.tier === 'WEEKLY').map(task => {
      const completion = selectedDateCompletions.find(c => c.taskId === task.id);
      const isDone = completion?.doneByChild;
      const isApproved = completion?.approvedByParent;
      const isPendingApproval = isDone && !isApproved;
      return React.createElement("div", {
        key: task.id,
        className: `task-item ${isDone ? 'completed' : ''} ${isApproved ? 'approved' : ''}`,
        onClick: () => toggleTask(task.id, selectedTaskDate)
      }, React.createElement("div", {
        className: "checkbox"
      }, isApproved ? '✓' : isDone ? '⏳' : ''), React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, task.title), isPendingApproval && React.createElement("div", {
        className: "badge badge-pending",
        style: {
          marginTop: '0.35rem',
          width: 'fit-content'
        }
      }, "Czeka na zatwierdzenie rodzica")), task.points > 0 && React.createElement("div", {
        className: "badge badge-points"
      }, "+", task.points, " pkt"));
    })), React.createElement("div", {
      className: "glass-card",
      style: {
        marginTop: '1.5rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '1rem'
      }
    }, "\u2728 Zadanie dodatkowe"), React.createElement("form", {
      onSubmit: e => {
        e.preventDefault();
        submitExtraTask(extraTaskTitle);
      }
    }, React.createElement("textarea", {
      className: "input",
      value: extraTaskTitle,
      onChange: e => setExtraTaskTitle(e.target.value),
      rows: 3,
      maxLength: 240,
      placeholder: "Napisz, co dodatkowego uda\u0142o Ci si\u0119 zrobi\u0107"
    }), React.createElement("button", {
      type: "submit",
      className: "btn btn-primary",
      style: {
        width: '100%',
        marginTop: '0.75rem'
      }
    }, "Zg\u0142o\u015B rodzicowi")), childExtraTasks.length > 0 && React.createElement("div", {
      style: {
        marginTop: '1rem',
        display: 'grid',
        gap: '0.65rem'
      }
    }, childExtraTasks.map(task => React.createElement("div", {
      key: task.id,
      className: "task-item"
    }, React.createElement("div", {
      style: {
        flex: 1
      }
    }, React.createElement("div", {
      style: {
        fontWeight: 600
      }
    }, task.title), React.createElement("div", {
      style: {
        fontSize: '0.85rem',
        opacity: 0.72
      }
    }, task.date)), task.status === 'APPROVED' ? React.createElement("div", {
      className: "badge badge-points"
    }, "+", Number(task.points || 0), " pkt") : task.status === 'REJECTED' ? React.createElement("div", {
      className: "badge",
      style: {
        background: 'rgba(249, 112, 102, 0.18)',
        color: '#F97066',
        border: '1px solid #F97066'
      }
    }, "Odrzucone") : React.createElement("div", {
      className: "badge badge-pending"
    }, "Czeka"))))), React.createElement("div", {
      className: "glass-card",
      style: {
        marginTop: '1.5rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '1rem'
      }
    }, "Ostatnie 14 dni"), React.createElement("div", {
      className: "calendar"
    }, last14Days.map((day, i) => {
      const [, month, dayOfMonth] = day.date.split('-');
      const formattedDate = `${dayOfMonth}.${month}`;
      return React.createElement("div", {
        key: i,
        className: `calendar-day ${day.status.toLowerCase().replace('_', '')}`,
        title: day.date
      }, React.createElement("span", {
        className: "calendar-day-status"
      }, day.status === 'PASSED' ? '✓' : day.status === 'FAILED' ? '✗' : '−'), React.createElement("span", {
        className: "calendar-day-date"
      }, formattedDate));
    }))), React.createElement(WeeklyLeaderboardPanel, {
      children: familyLeaderboard.children.length > 0 ? familyLeaderboard.children : [{
        id: selectedChild.id,
        name: selectedChild.name,
        avatar: selectedChild.avatar
      }],
      streaks: familyLeaderboard.streaks,
      points: familyLeaderboard.points,
      title: "\uD83C\uDFC6 Tablica wynik\xF3w rodziny"
    }))), showRewardOverlay && showRewardOverlay.childId === selectedChild.id && React.createElement(RewardOverlay, {
      reward: showRewardOverlay.reward,
      onClose: () => {
        setRewardUnlocks(prev => prev.map(u => u.childId === showRewardOverlay.childId && u.rewardId === showRewardOverlay.reward.id && !u.shownAt ? {
          ...u,
          shownAt: new Date().toISOString()
        } : u));
        setShowRewardOverlay(null);
      }
    }));
  }
  if (view === 'parent') {
    const pendingApprovals = completions.filter(c => c.doneByChild && !c.approvedByParent);
    const pendingExtraTasks = extraTasks.filter(task => task.status === 'PENDING');
    const activeRewards = rewards.filter(reward => reward.active !== false);
    const filteredPendingApprovals = pendingApprovals.filter(comp => {
      const childOk = approvalFilterChildId === 'ALL' || comp.childId === approvalFilterChildId;
      const dateOk = !approvalFilterDate || comp.date === approvalFilterDate;
      return childOk && dateOk;
    });
    const filteredPendingExtraTasks = pendingExtraTasks.filter(task => {
      const childOk = approvalFilterChildId === 'ALL' || task.childId === approvalFilterChildId;
      const dateOk = !approvalFilterDate || task.date === approvalFilterDate;
      return childOk && dateOk;
    });
    const pendingApprovalCount = pendingApprovals.length + pendingExtraTasks.length;
    const filteredPendingCount = filteredPendingApprovals.length + filteredPendingExtraTasks.length;
    const today = getDateString();
    const parentTaskDateValue = parentTaskDate || today;
    const parentTaskChildren = activeChildren.filter(child => parentTaskChildId === 'ALL' || child.id === parentTaskChildId);
    return React.createElement(React.Fragment, null, React.createElement("div", {
      className: "app-container"
    }, React.createElement("div", {
      className: "top-status"
    }, React.createElement("button", {
      className: "btn btn-secondary",
      onClick: () => setView('childSelect')
    }, "\u2190 Powr\xF3t"), React.createElement("div", {
      className: "network-status-group"
    }, React.createElement("div", {
      className: `network-badge ${isOnline ? '' : 'offline'}`
    }, isOnline ? '🟢 Online' : '🔴 Offline'), syncing && React.createElement("div", {
      className: "network-badge syncing"
    }, "\u23F3 Synchronizacja...")), React.createElement("button", {
      className: "btn btn-danger",
      onClick: handleLogout
    }, "Wyloguj")), React.createElement("div", {
      className: "glass-card"
    }, React.createElement("div", {
      className: "header"
    }, React.createElement("h1", null, "\uD83D\uDD10 Panel Rodzica"), React.createElement("div", null)), React.createElement("div", {
      className: "tabs"
    }, React.createElement("button", {
      className: `tab ${parentTab === 'approvals' ? 'active' : ''}`,
      onClick: () => setParentTab('approvals')
    }, "Do zatwierdzenia (", pendingApprovalCount, ")"), React.createElement("button", {
      className: `tab ${parentTab === 'children' ? 'active' : ''}`,
      onClick: () => setParentTab('children')
    }, "Dzieci (", activeChildren.length, ")"), React.createElement("button", {
      className: `tab ${parentTab === 'tasks' ? 'active' : ''}`,
      onClick: () => setParentTab('tasks')
    }, "Zadania (", tasks.length, ")"), React.createElement("button", {
      className: `tab ${parentTab === 'rewards' ? 'active' : ''}`,
      onClick: () => setParentTab('rewards')
    }, "Nagrody (", activeRewards.length, ")"), React.createElement("button", {
      className: `tab ${parentTab === 'stats' ? 'active' : ''}`,
      onClick: () => setParentTab('stats')
    }, "Statystyki"), React.createElement("button", {
      className: `tab ${parentTab === 'settings' ? 'active' : ''}`,
      onClick: () => setParentTab('settings')
    }, "Ustawienia")), parentTab === 'approvals' && React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Zadania do zatwierdzenia"), filteredPendingApprovals.length > 0 && React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => approveAllPending(filteredPendingApprovals)
    }, "\u2705 Zatwierd\u017A wg filtra (", filteredPendingApprovals.length, ")")), React.createElement("div", {
      className: "glass-card",
      style: {
        marginBottom: '1rem'
      }
    }, React.createElement("div", {
      className: "grid grid-3"
    }, React.createElement("div", null, React.createElement("label", {
      style: {
        display: 'block',
        marginBottom: '0.4rem',
        opacity: 0.8
      }
    }, "Dziecko"), React.createElement("select", {
      className: "select",
      value: approvalFilterChildId,
      onChange: e => setApprovalFilterChildId(e.target.value)
    }, React.createElement("option", {
      value: "ALL"
    }, "Wszystkie"), activeChildren.map(child => React.createElement("option", {
      key: child.id,
      value: child.id
    }, child.avatar, " ", child.name)))), React.createElement("div", null, React.createElement("label", {
      style: {
        display: 'block',
        marginBottom: '0.4rem',
        opacity: 0.8
      }
    }, "Data"), React.createElement("input", {
      className: "input",
      type: "date",
      value: approvalFilterDate,
      onChange: e => setApprovalFilterDate(e.target.value)
    })), React.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'end'
      }
    }, React.createElement("button", {
      className: "btn btn-secondary",
      style: {
        width: '100%'
      },
      onClick: () => {
        setApprovalFilterChildId('ALL');
        setApprovalFilterDate('');
      }
    }, "Wyczy\u015B\u0107 filtry")))), filteredPendingCount === 0 ? React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\u2705"), React.createElement("p", null, pendingApprovalCount === 0 ? 'Brak zadań do zatwierdzenia' : 'Brak zadań pasujących do filtrów')) : React.createElement(React.Fragment, null, filteredPendingApprovals.map(comp => {
      const task = tasks.find(t => t.id === comp.taskId);
      const child = children.find(c => c.id === comp.childId);
      if (!task || !child) return null;
      return React.createElement("div", {
        key: comp.id,
        className: "task-item"
      }, React.createElement("div", {
        style: {
          fontSize: '2rem'
        }
      }, child.avatar), React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, task.title), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, child.name, " \u2022 ", comp.date)), React.createElement("div", {
        className: `badge badge-${task.tier.toLowerCase()}`
      }, task.tier), task.points > 0 && React.createElement("div", {
        className: "badge badge-points"
      }, "+", task.points, " pkt"), React.createElement("button", {
        className: "btn btn-success",
        onClick: () => approveTask(comp),
        title: "Zatwierd\u017A zadanie"
      }, "\u2705 Zatwierd\u017A"), React.createElement("button", {
        className: "btn btn-danger",
        onClick: () => rejectTask(comp),
        title: "Odrzu\u0107 zadanie"
      }, "\u274C Odrzu\u0107"));
    }), filteredPendingExtraTasks.length > 0 && React.createElement(React.Fragment, null, React.createElement("h3", {
      style: {
        margin: '1.2rem 0 0.75rem'
      }
    }, "\u2728 Zadania dodatkowe"), filteredPendingExtraTasks.map(extraTask => React.createElement(ExtraTaskApprovalCard, {
      key: extraTask.id,
      extraTask: extraTask,
      child: children.find(c => c.id === extraTask.childId),
      onApprove: approveExtraTask,
      onReject: rejectExtraTask
    })))), React.createElement("div", {
      className: "glass-card",
      style: {
        marginTop: '1.5rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '0.75rem'
      }
    }, "\u2705 Zalicz zadania dziecku"), React.createElement("div", {
      className: "grid grid-2",
      style: {
        marginBottom: '1rem'
      }
    }, React.createElement("div", null, React.createElement("label", {
      style: {
        display: 'block',
        marginBottom: '0.4rem',
        opacity: 0.8
      }
    }, "Dziecko"), React.createElement("select", {
      className: "select",
      value: parentTaskChildId,
      onChange: e => setParentTaskChildId(e.target.value)
    }, React.createElement("option", {
      value: "ALL"
    }, "Wszystkie"), activeChildren.map(child => React.createElement("option", {
      key: child.id,
      value: child.id
    }, child.avatar, " ", child.name)))), React.createElement("div", null, React.createElement("label", {
      style: {
        display: 'block',
        marginBottom: '0.4rem',
        opacity: 0.8
      }
    }, "Data"), React.createElement("input", {
      className: "input",
      type: "date",
      value: parentTaskDateValue,
      max: today,
      onChange: e => setParentTaskDate(e.target.value || today)
    }))), parentTaskChildren.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Brak dzieci dla wybranego filtra") : parentTaskChildren.map(child => {
      const dayTasks = tasks.filter(task => task.childId === child.id && task.active !== false && isTaskScheduledForDate(task, parentTaskDateValue));
      return React.createElement("div", {
        key: child.id,
        style: {
          marginTop: '1rem'
        }
      }, React.createElement("h4", {
        style: {
          marginBottom: '0.75rem'
        }
      }, child.avatar, " ", child.name), dayTasks.length === 0 ? React.createElement("div", {
        className: "empty-state"
      }, "Brak zada\u0144 w tym dniu") : dayTasks.map(task => {
        const completion = completions.find(item => item.childId === child.id && item.taskId === task.id && item.date === parentTaskDateValue);
        const isDone = completion?.doneByChild;
        const isApproved = completion?.approvedByParent;
        return React.createElement("div", {
          key: task.id,
          className: `task-item ${isDone ? 'completed' : ''} ${isApproved ? 'approved' : ''}`
        }, React.createElement("div", {
          className: "checkbox"
        }, isApproved ? '✓' : isDone ? '⏳' : ''), React.createElement("div", {
          style: {
            flex: 1
          }
        }, React.createElement("div", {
          style: {
            fontWeight: 700
          }
        }, task.title), task.description && React.createElement("div", {
          style: {
            fontSize: '0.86rem',
            opacity: 0.72
          }
        }, task.description)), React.createElement("div", {
          className: `badge badge-${String(task.tier || 'min').toLowerCase()}`
        }, task.tier || 'MIN'), task.points > 0 && React.createElement("div", {
        className: "badge badge-points"
      }, "+", task.points, " pkt"), React.createElement("button", {
        className: isApproved ? 'btn btn-secondary' : 'btn btn-success',
        disabled: isApproved,
        onClick: () => completeTaskAsParent(task, child.id, parentTaskDateValue)
      }, isApproved ? 'Zaliczone' : isDone ? 'Zatwierd\u017A' : 'Zalicz'), isApproved && React.createElement("button", {
        className: "btn btn-danger",
        onClick: () => reverseApproval(completion),
        title: "Cofnij zatwierdzenie i przelicz punkty"
      }, "Cofnij"));
      }));
    })), React.createElement("div", {
      style: {
        marginTop: '1.5rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '0.75rem'
      }
    }, "Historia ostatnich 7 dni"), activeChildren.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Brak dzieci") : activeChildren.map(child => {
      const days = [];
      for (let i = 0; i < 7; i++) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        const dateStr = getDateString(date);
        const status = evaluateDay(child.id, dateStr);
        const dayCompletions = completions.filter(c => c.childId === child.id && c.date === dateStr);
        const approvedCount = dayCompletions.filter(c => c.approvedByParent).length;
        const approvedTasks = dayCompletions.filter(c => c.approvedByParent).map(c => {
          const task = tasks.find(t => t.id === c.taskId);
          return task ? `${task.title}${task.points ? ` (+${task.points})` : ''}` : null;
        }).filter(Boolean);
        const dayPoints = dayCompletions.reduce((sum, comp) => {
          const task = tasks.find(t => t.id === comp.taskId);
          return sum + (comp.approvedByParent && task?.points ? task.points : 0);
        }, 0);
        days.push({
          dateStr,
          status,
          approvedCount,
          dayPoints,
          approvedTasks
        });
      }
      return React.createElement("div", {
        key: child.id,
        className: "glass-card",
        style: {
          marginBottom: '1rem'
        }
      }, React.createElement("h4", {
        style: {
          marginBottom: '0.75rem'
        }
      }, child.avatar, " ", child.name), days.map(day => React.createElement("div", {
        key: day.dateStr,
        className: "history-day"
      }, React.createElement("div", {
        style: {
          display: 'flex',
          justifyContent: 'space-between',
          gap: '1rem'
        }
      }, React.createElement("span", null, day.dateStr), React.createElement("span", null, day.status === 'PASSED' ? '✅ ZAL' : day.status === 'FAILED' ? '❌ NZ' : '⊘ N/A')), React.createElement("div", {
        style: {
          fontSize: '0.85rem',
          opacity: 0.8,
          marginTop: '0.25rem'
        }
      }, "Zatwierdzone: ", day.approvedCount, " \u2022 Punkty: ", day.dayPoints), day.approvedTasks.length > 0 && React.createElement("div", {
        style: {
          fontSize: '0.8rem',
          opacity: 0.75,
          marginTop: '0.2rem'
        }
      }, day.approvedTasks.join(' • ')))));
    }))), parentTab === 'children' && React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Zarz\u0105dzanie dzie\u0107mi"), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setShowModal('addChild')
    }, "+ Dodaj dziecko")), activeChildren.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67\u200D\uD83D\uDC66"), React.createElement("p", null, "Brak dzieci. Dodaj pierwsze dziecko!")) : React.createElement("div", {
      className: "grid grid-2"
    }, activeChildren.map(child => {
      const childStreak = streaks[child.id] || {
        current: 0,
        best: 0
      };
      const childPoints = points[child.id] || 0;
      const childTasks = tasks.filter(t => t.childId === child.id);
      return React.createElement("div", {
        key: child.id,
        className: "glass-card"
      }, React.createElement("div", {
        className: "child-avatar"
      }, child.avatar), React.createElement("h3", {
        style: {
          textAlign: 'center',
          marginBottom: '1rem'
        }
      }, child.name), React.createElement("div", {
        className: "grid grid-2",
        style: {
          marginBottom: '1rem'
        }
      }, React.createElement("div", {
        className: "stat-card"
      }, React.createElement("div", {
        className: "stat-value"
      }, childPoints), React.createElement("div", {
        className: "stat-label"
      }, "punkt\xF3w")), React.createElement("div", {
        className: "stat-card"
      }, React.createElement("div", {
        className: "stat-value"
      }, childStreak.current), React.createElement("div", {
        className: "stat-label"
      }, "passa"))), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7,
          textAlign: 'center'
        }
      }, childTasks.length, " zada\u0144 \u2022 Dni aktywne: ", child.activeDays.join(', ')), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.85,
          textAlign: 'center',
          marginTop: '0.35rem'
        }
      }, "Kod dziecka: ", React.createElement("strong", null, child.accessCode || '----')), React.createElement("div", {
        style: {
          display: 'flex',
          gap: '0.5rem',
          marginTop: '1rem'
        }
      }, React.createElement("button", {
        className: "btn btn-secondary",
        style: {
          flex: 1
        },
        onClick: () => setEditingChild(child)
      }, "\u270F\uFE0F Edytuj"), React.createElement("button", {
        className: "btn btn-danger",
        style: {
          flex: 1
        },
        onClick: () => {
          if (confirm(`Archiwizować profil ${child.name}?`)) {
            archiveChild(child.id);
          }
        }
      }, "\uD83D\uDDC3\uFE0F Archiwizuj")), React.createElement("div", {
        style: {
          display: 'flex',
          gap: '0.5rem',
          marginTop: '0.5rem'
        }
      }, React.createElement("button", {
        className: "btn btn-success",
        style: {
          flex: 1
        },
        onClick: () => addPointAdjustment(child, 'BONUS')
      }, "\uD83C\uDF81 Premia"), React.createElement("button", {
        className: "btn btn-danger",
        style: {
          flex: 1
        },
        onClick: () => addPointAdjustment(child, 'PENALTY')
      }, "\u26A0\uFE0F Kara")));
    }))), parentTab === 'tasks' && React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Zarz\u0105dzanie zadaniami"), React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.5rem',
        flexWrap: 'wrap'
      }
    }, React.createElement("button", {
      className: `btn ${taskListMode === 'active' ? 'btn-primary' : 'btn-secondary'}`,
      onClick: () => setTaskListMode('active')
    }, "Aktywne"), React.createElement("button", {
      className: `btn ${taskListMode === 'archive' ? 'btn-primary' : 'btn-secondary'}`,
      onClick: () => setTaskListMode('archive')
    }, "Archiwum (", tasks.filter(t => t.active === false).length, ")"), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setShowModal('addTask')
    }, "+ Dodaj zadanie"))), tasks.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\uD83D\uDCDD"), React.createElement("p", null, "Brak zada\u0144. Dodaj pierwsze zadanie!")) : activeChildren.map(child => {
      const childTasks = tasks.filter(t => t.childId === child.id && (taskListMode === 'archive' ? t.active === false : t.active !== false));
      if (childTasks.length === 0) return null;
      return React.createElement("div", {
        key: child.id,
        style: {
          marginBottom: '2rem'
        }
      }, React.createElement("h3", {
        style: {
          marginBottom: '1rem'
        }
      }, child.avatar, " ", child.name), childTasks.map(task => {
        const matchingActiveCount = tasks.filter(item => item.active !== false && getTaskArchiveFingerprint(item) === getTaskArchiveFingerprint(task)).length;
        return React.createElement("div", {
        key: task.id,
        className: "task-item"
      }, React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, task.title), task.description && React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, task.description), task.active === false && React.createElement("div", {
        style: {
          fontSize: '0.85rem',
          opacity: 0.75,
          marginTop: '0.25rem'
        }
      }, "Zarchiwizowano: ", (task.archivedAt || task.updatedAt || '').slice(0, 10), task.restoredAt ? ` • Przywrócono: ${String(task.restoredAt).slice(0, 10)}` : '')), React.createElement("div", {
        className: `badge badge-${task.tier.toLowerCase()}`
      }, task.tier), task.points > 0 && React.createElement("div", {
        className: "badge badge-points"
      }, "+", task.points, " pkt"), task.active !== false && React.createElement("button", {
        className: "btn btn-secondary",
        title: "Edytuj zadanie",
        onClick: () => setEditingTask(task)
      }, "\u270F\uFE0F Edytuj"), task.active !== false && React.createElement("button", {
        className: "btn btn-danger",
        title: "Archiwizuj tylko u tego dziecka",
        onClick: async () => {
          if (confirm(`Archiwizować zadanie "${task.title}" tylko u ${child.name}?`)) {
            await archiveTask(task.id);
          }
        }
      }, "\uD83D\uDDC3\uFE0F"), task.active !== false && matchingActiveCount > 1 && React.createElement("button", {
        className: "btn btn-danger",
        title: "Archiwizuj to samo zadanie u wszystkich dzieci",
        onClick: async () => {
          if (confirm(`Archiwizować zadanie "${task.title}" u wszystkich dzieci, które mają tę samą definicję? (${matchingActiveCount} zadań)`)) {
            await archiveTask(task.id, {
              matching: true
            });
          }
        }
      }, "\uD83D\uDDC3\uFE0F U wszystkich"), task.active === false && React.createElement("button", {
        className: "btn btn-success",
        title: "Przywróć zadanie",
        onClick: async () => {
          if (confirm(`Przywrócić zadanie "${task.title}" u ${child.name}?`)) {
            await restoreTask(task.id);
          }
        }
      }, "\u267B\uFE0F Przywr\xF3\u0107"));
      }));
    }).filter(Boolean), taskListMode === 'archive' && tasks.every(task => task.active !== false) && React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\uD83D\uDDC3\uFE0F"), React.createElement("p", null, "Archiwum zada\u0144 jest puste."))), parentTab === 'rewards' && React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Katalog nagr\xF3d"), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setShowModal('addReward')
    }, "+ Dodaj nagrod\u0119")), activeRewards.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\uD83C\uDF81"), React.createElement("p", null, "Brak nagr\xF3d. Dodaj pierwsz\u0105 nagrod\u0119!")) : activeRewards.map(reward => React.createElement("div", {
      key: reward.id,
      className: "task-item"
    }, React.createElement("div", {
      style: {
        fontSize: '2rem'
      }
    }, "\uD83C\uDF81"), React.createElement("div", {
      style: {
        flex: 1
      }
    }, React.createElement("div", {
      style: {
        fontWeight: 600
      }
    }, reward.title), React.createElement("div", {
      style: {
        fontSize: '0.9rem',
        opacity: 0.7
      }
    }, reward.description), React.createElement("div", {
      style: {
        marginTop: '0.5rem',
        display: 'flex',
        gap: '0.5rem'
      }
    }, reward.requiredPoints && React.createElement("div", {
      className: "badge badge-points"
    }, reward.requiredPoints, " punkt\xF3w"), reward.requiredStreak && React.createElement("div", {
      className: "badge badge-min"
    }, reward.requiredStreak, " dni passy"), reward.requiredIdealWeeks && React.createElement("div", {
      className: "badge badge-weekly"
    }, reward.requiredIdealWeeks, " idealnych tygodni"))), React.createElement("button", {
      className: "btn btn-secondary",
      onClick: () => setEditingReward(reward)
    }, "\u270F\uFE0F Edytuj"), React.createElement("button", {
      className: "btn btn-danger",
      onClick: () => {
        if (confirm(`Zarchiwizować nagrodę "${reward.title}"? Dzieci zachowają już odblokowane nagrody.`)) {
          archiveReward(reward.id);
        }
      }
    }, "\uD83D\uDDC3\uFE0F Usu\u0144"))), React.createElement("div", {
      className: "glass-card",
      style: {
        marginTop: '1rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '0.75rem'
      }
    }, "Odblokowane nagrody"), rewardUnlocks.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Brak odblokowanych nagr\xF3d") : rewardUnlocks.map(unlock => {
      const reward = rewards.find(r => r.id === unlock.rewardId);
      const child = children.find(c => c.id === unlock.childId);
      if (!reward || !child) return null;
      return React.createElement("div", {
        key: unlock.id,
        className: "task-item"
      }, React.createElement("div", {
        style: {
          fontSize: '2rem'
        }
      }, "\uD83C\uDFC5"), React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, reward.title), React.createElement("div", {
        style: {
          fontSize: '0.85rem',
          opacity: 0.8
        }
      }, child.name, " \u2022 odblokowano: ", unlock.unlockedAt?.slice(0, 10)), React.createElement("div", {
        style: {
          fontSize: '0.8rem',
          opacity: 0.7
        }
      }, unlock.claimedAt ? `Wydano: ${unlock.claimedAt.slice(0, 10)}` : 'Oczekuje na wydanie')), !unlock.claimedAt && React.createElement("button", {
        className: "btn btn-success",
        onClick: () => claimReward(unlock.id)
      }, "\u2705 Wydano"));
    }))), parentTab === 'stats' && React.createElement(React.Fragment, null, React.createElement("h2", {
      style: {
        marginBottom: '1rem'
      }
    }, "Statystyki rodziny"), React.createElement("div", {
      className: "grid grid-3"
    }, activeChildren.map(child => {
      const childStreak = streaks[child.id] || {
        current: 0,
        best: 0,
        idealWeeksCount: 0,
        idealWeeksInRow: 0
      };
      const childPoints = points[child.id] || 0;
      const today = getDateString();
      const status = evaluateDay(child.id, today);
      return React.createElement("div", {
        key: child.id,
        className: "glass-card"
      }, React.createElement("div", {
        className: "child-avatar",
        style: {
          fontSize: '3rem'
        }
      }, child.avatar), React.createElement("h3", {
        style: {
          textAlign: 'center',
          marginBottom: '1rem'
        }
      }, child.name), React.createElement("div", {
        style: {
          marginBottom: '0.5rem'
        }
      }, React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Status dzisiaj"), React.createElement("div", {
        style: {
          fontSize: '1.2rem',
          fontWeight: 600
        }
      }, status === 'PASSED' ? '✅ Zaliczony' : status === 'FAILED' ? '❌ Niezaliczony' : '⊘ Nieaktywny')), React.createElement("div", {
        style: {
          marginBottom: '0.5rem'
        }
      }, React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Punkty"), React.createElement("div", {
        style: {
          fontSize: '2rem',
          fontWeight: 700
        }
      }, childPoints)), React.createElement("div", null, React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Passa"), React.createElement("div", {
        style: {
          fontSize: '2rem',
          fontWeight: 700
        }
      }, childStreak.current, " dni"), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Rekord: ", childStreak.best), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Idealne tygodnie: ", childStreak.idealWeeksCount || 0)));
    })), React.createElement(WeeklyLeaderboardPanel, {
      children: activeChildren,
      streaks: streaks,
      points: points
    })), parentTab === 'settings' && React.createElement(React.Fragment, null, React.createElement("h2", {
      style: {
        marginBottom: '1rem'
      }
    }, "Ustawienia rodzica"), React.createElement("div", {
      className: "settings-grid"
    }, React.createElement(SettingsSecurityPanel, {
      user: user,
      parentUsers: parentUsers,
      onRefreshParents: loadParentUsers,
      onAddParent: addParentUser,
      onToggleParent: setParentUserActive,
      onChangePassword: changeMyPassword,
      onResetPassword: resetParentPassword
    }), React.createElement(SettingsBackupPanel, {
      familyGoal: familyGoal,
      onFamilyGoalChange: updateFamilyGoal,
      onExport: exportFamilyBackup,
      onImport: importFamilyBackup
    })), React.createElement("div", {
      className: "glass-card",
      style: {
        marginTop: '1rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '0.75rem'
      }
    }, "Audit log (ostatnie zmiany)"), auditLogs.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Brak wpis\xF3w audytu") : auditLogs.slice(0, 25).map(log => React.createElement("div", {
      key: log.id,
      className: "history-day"
    }, React.createElement("div", {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        gap: '1rem'
      }
    }, React.createElement("strong", null, log.action), React.createElement("span", {
      style: {
        opacity: 0.8
      }
    }, (log.createdAt || '').replace('T', ' ').slice(0, 16))), React.createElement("div", {
      style: {
        fontSize: '0.85rem',
        opacity: 0.8
      }
    }, log.entityType, " \u2022 ", log.entityId))))))), showModal === 'addChild' && React.createElement(AddChildModal, {
      onAdd: addChild,
      onClose: () => setShowModal(null)
    }), editingChild && React.createElement(EditChildModal, {
      child: editingChild,
      siblings: children,
      onSave: updates => {
        updateChild(editingChild.id, updates);
        setEditingChild(null);
      },
      onClose: () => setEditingChild(null)
    }), showModal === 'addTask' && React.createElement(AddTaskModal, {
      children: activeChildren,
      onAdd: addTask,
      onClose: () => setShowModal(null)
    }), editingTask && React.createElement(EditTaskModal, {
      task: editingTask,
      children: activeChildren,
      onSave: async updates => {
        await updateTask(editingTask.id, updates);
        setEditingTask(null);
      },
      onClose: () => setEditingTask(null)
    }), showModal === 'addReward' && React.createElement(AddRewardModal, {
      onAdd: addReward,
      onClose: () => setShowModal(null)
    }), editingReward && React.createElement(AddRewardModal, {
      reward: editingReward,
      onSave: updates => {
        updateReward(editingReward.id, updates);
        setEditingReward(null);
      },
      onClose: () => setEditingReward(null)
    }), pointAdjustmentModal && React.createElement(PointAdjustmentModal, {
      draft: pointAdjustmentModal,
      onSave: savePointAdjustment,
      onClose: () => setPointAdjustmentModal(null)
    }));
  }
  return null;
};
const PointAdjustmentModal = ({
  draft,
  onSave,
  onClose
}) => {
  const child = draft?.child;
  const type = draft?.type || 'BONUS';
  const isPenalty = type === 'PENALTY';
  const [pointsValue, setPointsValue] = useState('5');
  const [note, setNote] = useState(isPenalty ? 'Kara punktowa' : 'Premia punktowa');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  if (!child) return null;
  const submit = async event => {
    event.preventDefault();
    setError('');
    const points = Number.parseInt(pointsValue, 10);
    if (!Number.isFinite(points) || points <= 0) {
      setError('Podaj dodatnią liczbę punktów.');
      return;
    }
    setSaving(true);
    try {
      await onSave({
        child,
        type,
        points,
        note
      });
    } catch (e) {
      setError(e.message || 'Nie udało się zapisać zmiany punktów.');
    } finally {
      setSaving(false);
    }
  };
  return React.createElement("div", {
    className: "modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-labelledby": "point-adjustment-title"
  }, React.createElement("div", {
    className: "modal-content",
    style: {
      maxWidth: '520px'
    }
  }, React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '1rem',
      alignItems: 'center',
      marginBottom: '1rem'
    }
  }, React.createElement("h2", {
    id: "point-adjustment-title",
    style: {
      margin: 0
    }
  }, isPenalty ? "\u26A0\uFE0F Kara punktowa" : "\uD83C\uDF81 Premia punktowa"), React.createElement("button", {
    className: "btn btn-secondary",
    type: "button",
    onClick: onClose,
    title: "Zamknij"
  }, "\u2715")), React.createElement("div", {
    className: "task-item",
    style: {
      marginBottom: '1rem',
      cursor: 'default'
    }
  }, React.createElement("div", {
    style: {
      fontSize: '2.2rem'
    }
  }, child.avatar || "\uD83D\uDC64"), React.createElement("div", {
    style: {
      flex: 1
    }
  }, React.createElement("div", {
    style: {
      fontWeight: 800
    }
  }, child.name), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.75
    }
  }, isPenalty ? "Punkty zostan\u0105 odj\u0119te po zapisaniu." : "Punkty zostan\u0105 dodane po zapisaniu."))), React.createElement("form", {
    onSubmit: submit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.4rem',
      fontWeight: 700
    }
  }, "Liczba punkt\xF3w"), React.createElement("input", {
    className: "input",
    type: "number",
    min: "1",
    max: "1000",
    value: pointsValue,
    onChange: e => setPointsValue(e.target.value),
    autoFocus: true
  }), React.createElement("label", {
    style: {
      display: 'block',
      margin: '1rem 0 0.4rem',
      fontWeight: 700
    }
  }, "Informacja dla dziecka"), React.createElement("textarea", {
    className: "input",
    rows: 3,
    maxLength: 180,
    value: note,
    onChange: e => setNote(e.target.value),
    placeholder: isPenalty ? "Za co odejmujemy punkty?" : "Za co przyznajemy premi\u0119?"
  }), error && React.createElement("div", {
    className: "badge",
    style: {
      marginTop: '0.75rem',
      background: 'rgba(249, 112, 102, 0.18)',
      color: '#FDA29B',
      border: '1px solid rgba(249, 112, 102, 0.45)'
    }
  }, error), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginTop: '1.25rem'
    }
  }, React.createElement("button", {
    className: "btn btn-secondary",
    type: "button",
    onClick: onClose,
    disabled: saving,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    className: isPenalty ? "btn btn-danger" : "btn btn-success",
    type: "submit",
    disabled: saving,
    style: {
      flex: 1
    }
  }, saving ? "Zapisywanie..." : isPenalty ? "Odejmij punkty" : "Dodaj premi\u0119")))));
};
const RewardOverlay = ({
  reward,
  onClose
}) => {
  if (!reward) return null;
  return React.createElement("div", {
    className: "reward-overlay",
    onClick: onClose
  }, React.createElement("div", {
    className: "reward-overlay-content",
    onClick: e => e.stopPropagation()
  }, React.createElement("div", {
    style: {
      fontSize: '4rem',
      marginBottom: '0.5rem'
    }
  }, "\uD83C\uDF89"), React.createElement("h2", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Nowa nagroda odblokowana!"), React.createElement("h3", {
    style: {
      marginBottom: '0.5rem'
    }
  }, reward.title), React.createElement("p", {
    style: {
      opacity: 0.9,
      marginBottom: '1rem'
    }
  }, reward.description), React.createElement("button", {
    className: "btn btn-primary",
    onClick: onClose
  }, "Super! \uD83D\uDE80")));
};
const FamilyGoalWidget = ({
  familyGoal,
  children,
  points,
  evaluateDay,
  getDateString
}) => {
  const today = getDateString();
  const totalPoints = children.reduce((sum, child) => sum + (points[child.id] || 0), 0);
  const totalPassedDays = children.reduce((sum, child) => {
    let passed = 0;
    for (let i = 0; i < HISTORY_DAYS; i++) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const status = evaluateDay(child.id, getDateString(date));
      if (status === 'PASSED') passed += 1;
    }
    return sum + passed;
  }, 0);
  const mode = familyGoal?.mode || 'points';
  const currentValue = mode === 'passedDays' ? totalPassedDays : totalPoints;
  const target = Number(familyGoal?.target || 1);
  const progress = Math.max(0, Math.min(100, Math.round(currentValue / Math.max(target, 1) * 100)));
  return React.createElement("div", {
    className: "glass-card"
  }, React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      marginBottom: '0.45rem'
    }
  }, React.createElement("span", {
    className: "goal-icon",
    style: {
      fontSize: '1.2rem'
    },
    "aria-hidden": "true"
  }, "\uD83C\uDFC6"), React.createElement("div", {
    style: {
      fontWeight: 700
    }
  }, familyGoal?.title || 'Cel rodzinny')), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.8
    }
  }, mode === 'passedDays' ? 'Tryb: liczba zaliczonych dni' : 'Tryb: suma punktów rodziny'), React.createElement("div", {
    style: {
      marginTop: '0.5rem',
      fontWeight: 600
    }
  }, currentValue, " / ", target), React.createElement("div", {
    className: "progress-bar"
  }, React.createElement("div", {
    className: "progress-fill",
    style: {
      width: `${progress}%`
    }
  })));
};
const WeeklyLeaderboardPanel = ({
  children,
  streaks,
  points,
  title = '📊 Ranking tygodniowy'
}) => {
  const rankedChildren = sortChildrenForLeaderboard(children, streaks, points);
  return React.createElement("div", {
    className: "glass-card",
    style: {
      marginTop: '1.25rem'
    }
  }, React.createElement("h3", {
    style: {
      marginBottom: '1rem'
    }
  }, title), rankedChildren.length === 0 ? React.createElement("div", {
    className: "empty-state"
  }, "Brak dzieci") : rankedChildren.map((child, index) => {
    const childStreak = streaks[child.id] || {
      current: 0,
      idealWeeksInRow: 0
    };
    const childPoints = getLeaderboardPoints(points[child.id]);
    return React.createElement("div", {
      key: child.id,
      className: "task-item"
    }, React.createElement("div", {
      style: {
        fontSize: '2rem',
        fontWeight: 700,
        width: '50px',
        textAlign: 'center'
      }
    }, rankIcon(index)), React.createElement("div", {
      style: {
        fontSize: '2rem'
      }
    }, child.avatar), React.createElement("div", {
      style: {
        flex: 1
      }
    }, React.createElement("div", {
      style: {
        fontWeight: 600
      }
    }, child.name), React.createElement("div", {
      style: {
        fontSize: '0.9rem',
        opacity: 0.78
      }
    }, "Idealne tyg.: ", childStreak.idealWeeksInRow || 0, " \u2022 Passa: ", childStreak.current || 0, " \u2022 ", childPoints, " pkt")));
  }));
};
const ExtraTaskApprovalCard = ({
  extraTask,
  child,
  onApprove,
  onReject
}) => {
  const [pointsValue, setPointsValue] = useState('3');
  if (!extraTask || !child) return null;
  return React.createElement("div", {
    className: "task-item"
  }, React.createElement("div", {
    style: {
      fontSize: '2rem'
    }
  }, child.avatar), React.createElement("div", {
    style: {
      flex: 1
    }
  }, React.createElement("div", {
    style: {
      fontWeight: 700
    }
  }, extraTask.title), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.7
    }
  }, child.name, " \u2022 ", extraTask.date, " \u2022 zadanie dodatkowe")), React.createElement("input", {
    className: "input",
    type: "number",
    min: "0",
    max: "1000",
    value: pointsValue,
    onChange: e => setPointsValue(e.target.value),
    style: {
      width: '92px'
    },
    "aria-label": "Punkty za zadanie dodatkowe"
  }), React.createElement("button", {
    className: "btn btn-success",
    onClick: () => onApprove(extraTask, pointsValue),
    title: "Zatwierd\u017A zadanie dodatkowe"
  }, "\u2705 Zatwierd\u017A"), React.createElement("button", {
    className: "btn btn-danger",
    onClick: () => onReject(extraTask),
    title: "Odrzu\u0107 zadanie dodatkowe"
  }, "\u274C Odrzu\u0107"));
};
const SettingsSecurityPanel = ({
  user,
  parentUsers,
  onRefreshParents,
  onAddParent,
  onToggleParent,
  onChangePassword,
  onResetPassword
}) => {
  const [newParentEmail, setNewParentEmail] = useState('');
  const [newParentPassword, setNewParentPassword] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [resetPasswordValue, setResetPasswordValue] = useState('');
  const [resetTarget, setResetTarget] = useState('');
  const [message, setMessage] = useState('');
  useEffect(() => {
    onRefreshParents();
  }, []);
  return React.createElement("div", {
    className: "glass-card"
  }, React.createElement("h3", {
    style: {
      marginBottom: '0.75rem'
    }
  }, "\uD83D\uDD10 Konta i bezpiecze\u0144stwo"), message && React.createElement("div", {
    className: "success"
  }, message), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Dodaj konto rodzica (nieaktywne)"), React.createElement("input", {
    className: "input",
    placeholder: "Email",
    value: newParentEmail,
    onChange: e => setNewParentEmail(e.target.value)
  }), React.createElement("input", {
    className: "input",
    placeholder: "Has\u0142o tymczasowe",
    type: "password",
    value: newParentPassword,
    onChange: e => setNewParentPassword(e.target.value)
  }), React.createElement("button", {
    className: "btn btn-primary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: async () => {
      try {
        await onAddParent({
          email: newParentEmail,
          password: newParentPassword
        });
        setMessage('Dodano konto rodzica. Czeka na aktywację.');
        setNewParentEmail('');
        setNewParentPassword('');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "+ Dodaj rodzica"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "U\u017Cytkownicy rodzice"), parentUsers.map(parent => React.createElement("div", {
    key: parent.id,
    className: "history-day"
  }, React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '1rem',
      alignItems: 'center'
    }
  }, React.createElement("div", null, React.createElement("div", {
    style: {
      fontWeight: 600
    }
  }, parent.email), React.createElement("div", {
    style: {
      fontSize: '0.8rem',
      opacity: 0.8
    }
  }, parent.active ? 'Aktywne' : 'Nieaktywne', " \u2022 ", (parent.createdAt || '').slice(0, 10), parent.id === user?.id ? ' • Twoje konto' : '')), React.createElement("button", {
    className: parent.active ? 'btn btn-danger' : 'btn btn-success',
    onClick: () => onToggleParent(parent.id, !parent.active)
  }, parent.active ? 'Dezaktywuj' : 'Aktywuj')))), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Zmie\u0144 has\u0142o"), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Aktualne has\u0142o",
    value: currentPassword,
    onChange: e => setCurrentPassword(e.target.value)
  }), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Nowe has\u0142o",
    value: newPassword,
    onChange: e => setNewPassword(e.target.value)
  }), React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: async () => {
      try {
        await onChangePassword(currentPassword, newPassword);
        setCurrentPassword('');
        setNewPassword('');
        setMessage('Hasło zostało zmienione.');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "Zmie\u0144 has\u0142o"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Reset has\u0142a u\u017Cytkownika"), React.createElement("select", {
    className: "select",
    value: resetTarget,
    onChange: e => setResetTarget(e.target.value)
  }, React.createElement("option", {
    value: ""
  }, "Wybierz konto"), parentUsers.map(parent => React.createElement("option", {
    key: parent.id,
    value: parent.id
  }, parent.email))), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Nowe has\u0142o dla wybranego konta",
    value: resetPasswordValue,
    onChange: e => setResetPasswordValue(e.target.value)
  }), React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      width: '100%'
    },
    onClick: async () => {
      try {
        if (!resetTarget) throw new Error('Wybierz konto do resetu');
        await onResetPassword(resetTarget, resetPasswordValue);
        setResetPasswordValue('');
        setMessage('Hasło użytkownika zostało zresetowane.');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "Resetuj has\u0142o"));
};
const SettingsBackupPanel = ({
  familyGoal,
  onFamilyGoalChange,
  onExport,
  onImport
}) => {
  const [title, setTitle] = useState(familyGoal?.title || 'Cel rodzinny');
  const [target, setTarget] = useState(String(familyGoal?.target || 500));
  const [mode, setMode] = useState(familyGoal?.mode || 'points');
  const [message, setMessage] = useState('');
  return React.createElement("div", {
    className: "glass-card"
  }, React.createElement("h3", {
    style: {
      marginBottom: '0.75rem'
    }
  }, "\uD83E\uDDF0 Backup i cel rodzinny"), message && React.createElement("div", {
    className: "success"
  }, message), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Cel rodzinny"), React.createElement("input", {
    className: "input",
    placeholder: "Nazwa celu",
    value: title,
    onChange: e => setTitle(e.target.value)
  }), React.createElement("input", {
    className: "input",
    type: "number",
    min: "1",
    placeholder: "Pr\xF3g",
    value: target,
    onChange: e => setTarget(e.target.value)
  }), React.createElement("select", {
    className: "select",
    value: mode,
    onChange: e => setMode(e.target.value)
  }, React.createElement("option", {
    value: "points"
  }, "Suma punkt\xF3w rodziny"), React.createElement("option", {
    value: "passedDays"
  }, "Liczba zaliczonych dni rodziny")), React.createElement("button", {
    className: "btn btn-primary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: () => {
      onFamilyGoalChange({
        title: title.trim() || 'Cel rodzinny',
        target: Math.max(1, parseInt(target || '1', 10)),
        mode
      });
      setMessage('Cel rodzinny został zapisany.');
    }
  }, "Zapisz cel"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Backup"), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem'
    }
  }, React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      flex: 1
    },
    onClick: onExport
  }, "Eksport JSON"), React.createElement("label", {
    className: "btn btn-secondary",
    style: {
      flex: 1,
      textAlign: 'center'
    }
  }, "Import JSON", React.createElement("input", {
    type: "file",
    accept: "application/json",
    style: {
      display: 'none'
    },
    onChange: async e => {
      const file = e.target.files?.[0];
      if (!file) return;
      const text = await file.text();
      try {
        const result = await onImport(text);
        const restored = result?.restored || {};
        setMessage(`Backup został odtworzony. Dzieci: ${restored.children ?? '?'}, zadania: ${restored.tasks ?? '?'}.`);
      } catch (err) {
        setMessage('Import nieudany: ' + err.message);
      }
      e.target.value = '';
    }
  }))));
};
const LoginView = ({
  onLogin,
  onRegister,
  onChildLogin,
  onForgotPassword,
  onResetPassword
}) => {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [familyName, setFamilyName] = useState('');
  const [childCode, setChildCode] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const switchMode = nextMode => {
    setMode(nextMode);
    setError('');
    setSuccess('');
  };
  const getSubtitle = () => {
    if (mode === 'register') return 'Załóż konto rodzica';
    if (mode === 'child') return 'Zaloguj dziecko kodem dostępu';
    if (mode === 'forgot') return 'Reset hasła rodzica';
    if (mode === 'reset') return 'Ustaw nowe hasło';
    return 'Zaloguj się do konta rodzica';
  };
  const getSubmitLabel = () => {
    if (mode === 'register') return 'Utwórz konto';
    if (mode === 'child') return 'Zaloguj dziecko';
    if (mode === 'forgot') return 'Wyślij reset';
    if (mode === 'reset') return 'Zmień hasło';
    return 'Zaloguj się';
  };
  const handleSubmit = async e => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSubmitting(true);
    let result = null;
    if (mode === 'login') {
      result = await onLogin(email, password);
    } else if (mode === 'register') {
      result = await onRegister({
        email,
        password,
        familyName
      });
    } else if (mode === 'child') {
      result = await onChildLogin(childCode);
    } else if (mode === 'forgot') {
      result = await onForgotPassword(email);
    } else {
      result = await onResetPassword(resetToken, password);
    }
    if (!result?.success) {
      setError(result?.error || 'Operacja nie powiodła się');
      setSubmitting(false);
      return;
    }
    if (mode === 'forgot') {
      const debugTokenText = result.debugResetToken ? ` Token testowy: ${result.debugResetToken}` : '';
      setSuccess((result.message || 'Wysłano instrukcję resetu.') + debugTokenText);
      if (result.debugResetToken) setResetToken(result.debugResetToken);
      setMode('reset');
    } else if (mode === 'reset') {
      setSuccess(result.message || 'Hasło zostało zmienione.');
      setPassword('');
      setResetToken('');
      setMode('login');
    }
    setSubmitting(false);
  };
  return React.createElement("div", {
    className: "app-container"
  }, React.createElement("div", {
    className: "glass-card",
    style: {
      maxWidth: '560px',
      margin: '5rem auto'
    }
  }, React.createElement("div", {
    style: {
      textAlign: 'center',
      marginBottom: '1.2rem'
    }
  }, React.createElement("div", {
    style: {
      fontSize: '5rem'
    }
  }, "\uD83C\uDFC6"), React.createElement("h1", null, "FamilyQuest"), React.createElement("p", {
    style: {
      opacity: 0.8
    }
  }, getSubtitle())), React.createElement("div", {
    className: "tabs",
    style: {
      justifyContent: 'center',
      marginBottom: '1rem'
    }
  }, React.createElement("button", {
    className: `tab ${mode === 'login' ? 'active' : ''}`,
    onClick: () => switchMode('login')
  }, "Rodzic"), React.createElement("button", {
    className: `tab ${mode === 'register' ? 'active' : ''}`,
    onClick: () => switchMode('register')
  }, "Rejestracja"), React.createElement("button", {
    className: `tab ${mode === 'child' ? 'active' : ''}`,
    onClick: () => switchMode('child')
  }, "Dziecko"), React.createElement("button", {
    className: `tab ${mode === 'forgot' ? 'active' : ''}`,
    onClick: () => switchMode('forgot')
  }, "Reset")), React.createElement("form", {
    onSubmit: handleSubmit
  }, error && React.createElement("div", {
    className: "error"
  }, error), success && React.createElement("div", {
    className: "success"
  }, success), (mode === 'login' || mode === 'register' || mode === 'forgot') && React.createElement("input", {
    type: "email",
    className: "input",
    placeholder: "Email rodzica",
    value: email,
    onChange: e => setEmail(e.target.value),
    required: true
  }), (mode === 'login' || mode === 'register' || mode === 'reset') && React.createElement("input", {
    type: "password",
    className: "input",
    placeholder: mode === 'reset' ? 'Nowe hasło' : 'Hasło',
    value: password,
    onChange: e => setPassword(e.target.value),
    required: true
  }), mode === 'register' && React.createElement(React.Fragment, null, React.createElement("input", {
    type: "text",
    className: "input",
    placeholder: "Nazwa rodziny (np. Rodzina Kowalskich)",
    value: familyName,
    onChange: e => setFamilyName(e.target.value)
  })), mode === 'child' && React.createElement("input", {
    type: "password",
    className: "input",
    placeholder: "Kod dziecka (4 cyfry)",
    value: childCode,
    onChange: e => setChildCode(e.target.value.replace(/\D/g, '').slice(0, 4)),
    inputMode: "numeric",
    autoComplete: "one-time-code",
    maxLength: 4,
    required: true
  }), mode === 'reset' && React.createElement("input", {
    type: "text",
    className: "input",
    placeholder: "Token resetu",
    value: resetToken,
    onChange: e => setResetToken(e.target.value),
    required: true
  }), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      width: '100%'
    },
    disabled: submitting
  }, submitting ? 'Przetwarzanie...' : getSubmitLabel()))));
};
const ChildSelectionView = ({
  children,
  streaks,
  points,
  leaderboardChildren = null,
  leaderboardStreaks = null,
  leaderboardPoints = null,
  familyGoal,
  evaluateDay,
  getDateString,
  onSelectChild,
  onParentMode,
  onLogout
}) => {
  return React.createElement("div", {
    className: "app-container"
  }, React.createElement("div", {
    className: "glass-card"
  }, React.createElement("div", {
    className: "header"
  }, React.createElement("button", {
    className: "btn btn-danger",
    onClick: onLogout
  }, "Wyloguj"), React.createElement("h1", null, "Wybierz profil"), React.createElement("button", {
    className: "btn btn-secondary",
    onClick: onParentMode
  }, "\uD83D\uDD10 Panel rodzica")), children.length === 0 ? React.createElement("div", {
    className: "empty-state"
  }, React.createElement("div", {
    style: {
      fontSize: '5rem'
    }
  }, "\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67\u200D\uD83D\uDC66"), React.createElement("p", null, "Brak dzieci. Przejd\u017A do panelu rodzica, aby doda\u0107 pierwsze dziecko.")) : React.createElement(React.Fragment, null, React.createElement("div", {
    className: "grid grid-3"
  }, children.map(child => React.createElement("div", {
    key: child.id,
    className: "glass-card child-card",
    onClick: () => onSelectChild(child)
  }, React.createElement("div", {
    className: "child-avatar"
  }, child.avatar), React.createElement("h2", {
    style: {
      textAlign: 'center'
    }
  }, child.name)))), React.createElement(WeeklyLeaderboardPanel, {
    children: leaderboardChildren || children,
    streaks: leaderboardStreaks || streaks,
    points: leaderboardPoints || points,
    title: "\uD83C\uDFC6 Ranking rodzinny"
  }), React.createElement("div", {
    style: {
      marginTop: '1.25rem'
    }
  }, React.createElement("h3", {
    style: {
      marginBottom: '1rem'
    }
  }, "\uD83C\uDFAF Cel rodzinny"), React.createElement(FamilyGoalWidget, {
    familyGoal: familyGoal,
    children: children,
    points: points,
    evaluateDay: evaluateDay,
    getDateString: getDateString
  })))));
};
const AddChildModal = ({
  onAdd,
  onClose
}) => {
  const [name, setName] = useState('');
  const [avatar, setAvatar] = useState('👧');
  const [customAvatar, setCustomAvatar] = useState('');
  const [activeDays, setActiveDays] = useState([1, 2, 3, 4, 5]);
  const [error, setError] = useState('');
  const toggleDay = day => {
    if (activeDays.includes(day)) {
      setActiveDays(activeDays.filter(d => d !== day));
    } else {
      setActiveDays([...activeDays, day].sort((a, b) => a - b));
    }
  };
  const handleSubmit = e => {
    e.preventDefault();
    setError('');
    const normalizedName = name.trim();
    const normalizedAvatar = (customAvatar.trim() || avatar || '').trim();
    if (!normalizedName) {
      setError('Imię dziecka jest wymagane.');
      return;
    }
    if (!normalizedAvatar) {
      setError('Wybierz avatar dziecka.');
      return;
    }
    if (activeDays.length === 0) {
      setError('Wybierz co najmniej 1 dzień aktywny.');
      return;
    }
    onAdd(normalizedName, normalizedAvatar, activeDays);
  };
  return React.createElement("div", {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Dodaj dziecko"), React.createElement("form", {
    onSubmit: handleSubmit
  }, error && React.createElement("div", {
    className: "error"
  }, error), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Imi\u0119"), React.createElement("input", {
    type: "text",
    className: "input",
    value: name,
    onChange: e => setName(e.target.value),
    required: true,
    placeholder: "Wpisz imi\u0119 dziecka"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wybierz avatar"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(6, 1fr)',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, CHILD_AVATARS.map(av => React.createElement("button", {
    key: av,
    type: "button",
    onClick: () => {
      setAvatar(av);
      setCustomAvatar('');
    },
    style: {
      fontSize: '2rem',
      padding: '0.5rem',
      background: customAvatar ? 'rgba(255, 255, 255, 0.1)' : avatar === av ? 'rgba(254, 200, 75, 0.3)' : 'rgba(255, 255, 255, 0.1)',
      border: customAvatar ? '2px solid transparent' : avatar === av ? '2px solid #FEC84B' : '2px solid transparent',
      borderRadius: '1rem',
      cursor: 'pointer'
    }
  }, av))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "W\u0142asny avatar (emoji)"), React.createElement("input", {
    type: "text",
    className: "input",
    value: customAvatar,
    onChange: e => setCustomAvatar(e.target.value),
    placeholder: "np. \uD83E\uDD16"
  }), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.85,
      marginBottom: '1rem'
    }
  }, "Wybrany avatar: ", React.createElement("strong", null, customAvatar.trim() || avatar)), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dni aktywne"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(7, 1fr)',
      gap: '0.5rem',
      marginBottom: '1.5rem'
    }
  }, DAY_NAMES.map((day, index) => {
    const dayNum = index + 1;
    return React.createElement("button", {
      key: dayNum,
      type: "button",
      onClick: () => toggleDay(dayNum),
      style: {
        padding: '0.75rem 0.5rem',
        background: activeDays.includes(dayNum) ? 'rgba(18, 183, 106, 0.3)' : 'rgba(255, 255, 255, 0.1)',
        border: activeDays.includes(dayNum) ? '2px solid #12B76A' : '2px solid transparent',
        borderRadius: '0.5rem',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: 600,
        color: 'white'
      }
    }, day);
  })), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      flex: 1
    }
  }, "Dodaj dziecko")))));
};
const EditChildModal = ({
  child,
  siblings,
  onSave,
  onClose
}) => {
  const [name, setName] = useState(child?.name || '');
  const [avatar, setAvatar] = useState(child?.avatar || '👧');
  const [customAvatar, setCustomAvatar] = useState('');
  const [activeDays, setActiveDays] = useState(Array.isArray(child?.activeDays) ? child.activeDays : [1, 2, 3, 4, 5]);
  const [accessCode, setAccessCode] = useState(child?.accessCode || '');
  const [error, setError] = useState('');
  const toggleDay = day => {
    if (activeDays.includes(day)) {
      setActiveDays(activeDays.filter(d => d !== day));
    } else {
      setActiveDays([...activeDays, day].sort((a, b) => a - b));
    }
  };
  const handleSubmit = e => {
    e.preventDefault();
    setError('');
    const normalizedName = name.trim();
    const normalizedAvatar = (customAvatar.trim() || avatar || '').trim();
    const normalizedCode = accessCode.replace(/\D/g, '').slice(0, 4);
    if (!normalizedName) {
      setError('Imię dziecka jest wymagane.');
      return;
    }
    if (!normalizedAvatar) {
      setError('Wybierz avatar dziecka.');
      return;
    }
    if (activeDays.length === 0) {
      setError('Wybierz co najmniej 1 dzień aktywny.');
      return;
    }
    if (!isValidChildAccessCode(normalizedCode)) {
      setError('Kod dziecka musi mieć dokładnie 4 cyfry.');
      return;
    }
    const uniqueCode = findAvailableChildAccessCode(siblings, normalizedCode, child.id);
    if (!uniqueCode) {
      setError('Nie udało się ustawić unikalnego kodu dziecka.');
      return;
    }
    onSave({
      name: normalizedName,
      avatar: normalizedAvatar,
      activeDays: [...new Set(activeDays)].sort((a, b) => a - b),
      accessCode: uniqueCode
    });
  };
  return React.createElement("div", {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Edytuj profil dziecka"), React.createElement("form", {
    onSubmit: handleSubmit
  }, error && React.createElement("div", {
    className: "error"
  }, error), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Imi\u0119"), React.createElement("input", {
    type: "text",
    className: "input",
    value: name,
    onChange: e => setName(e.target.value),
    required: true
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wybierz avatar"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(6, 1fr)',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, CHILD_AVATARS.map(av => React.createElement("button", {
    key: av,
    type: "button",
    onClick: () => {
      setAvatar(av);
      setCustomAvatar('');
    },
    style: {
      fontSize: '2rem',
      padding: '0.5rem',
      background: customAvatar ? 'rgba(255, 255, 255, 0.1)' : avatar === av ? 'rgba(254, 200, 75, 0.3)' : 'rgba(255, 255, 255, 0.1)',
      border: customAvatar ? '2px solid transparent' : avatar === av ? '2px solid #FEC84B' : '2px solid transparent',
      borderRadius: '1rem',
      cursor: 'pointer'
    }
  }, av))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "W\u0142asny avatar (emoji)"), React.createElement("input", {
    type: "text",
    className: "input",
    value: customAvatar,
    onChange: e => setCustomAvatar(e.target.value),
    placeholder: "np. \uD83E\uDD16"
  }), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.85,
      marginBottom: '1rem'
    }
  }, "Wybrany avatar: ", React.createElement("strong", null, customAvatar.trim() || avatar)), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Kod dziecka (4 cyfry)"), React.createElement("input", {
    type: "text",
    className: "input",
    value: accessCode,
    onChange: e => setAccessCode(e.target.value.replace(/\D/g, '').slice(0, 4)),
    inputMode: "numeric",
    maxLength: 4,
    required: true
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dni aktywne"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(7, 1fr)',
      gap: '0.5rem',
      marginBottom: '1.5rem'
    }
  }, DAY_NAMES.map((day, index) => {
    const dayNum = index + 1;
    return React.createElement("button", {
      key: dayNum,
      type: "button",
      onClick: () => toggleDay(dayNum),
      style: {
        padding: '0.75rem 0.5rem',
        background: activeDays.includes(dayNum) ? 'rgba(18, 183, 106, 0.3)' : 'rgba(255, 255, 255, 0.1)',
        border: activeDays.includes(dayNum) ? '2px solid #12B76A' : '2px solid transparent',
        borderRadius: '0.5rem',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: 600,
        color: 'white'
      }
    }, day);
  })), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      flex: 1
    }
  }, "Zapisz zmiany")))));
};
const AddTaskModal = ({
  children,
  onAdd,
  onClose
}) => {
  const [childId, setChildId] = useState(children.length > 1 ? 'ALL' : children[0]?.id || '');
  const [title, setTitle] = useState('');
  const [tier, setTier] = useState('MIN');
  const [points, setPoints] = useState(0);
  const [description, setDescription] = useState('');
  const [daysOfWeek, setDaysOfWeek] = useState([1, 2, 3, 4, 5, 6, 7]);
  const [templateId, setTemplateId] = useState('');
  const templatesForTier = TASK_TEMPLATES.filter(t => t.tier === tier);
  const applyTemplate = id => {
    const template = TASK_TEMPLATES.find(t => t.id === id);
    if (!template) return;
    setTemplateId(template.id);
    setTier(template.tier);
    setTitle(template.title);
    setPoints(template.points);
    setDescription(template.description || '');
  };
  const toggleDay = dayNum => {
    setDaysOfWeek(prev => prev.includes(dayNum) ? prev.filter(day => day !== dayNum) : [...prev, dayNum].sort((a, b) => a - b));
  };
  const handleSubmit = e => {
    e.preventDefault();
    if (!childId) return;
    onAdd(childId, title, tier, points, description, daysOfWeek);
  };
  return React.createElement("div", {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Dodaj zadanie"), React.createElement("form", {
    onSubmit: handleSubmit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dziecko"), React.createElement("select", {
    className: "select",
    value: childId,
    onChange: e => setChildId(e.target.value),
    required: true
  }, children.length > 1 && React.createElement("option", {
    value: "ALL"
  }, "Wszystkie dzieci"), children.map(child => React.createElement("option", {
    key: child.id,
    value: child.id
  }, child.avatar, " ", child.name))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Tytu\u0142 zadania"), React.createElement("input", {
    type: "text",
    className: "input",
    value: title,
    onChange: e => setTitle(e.target.value),
    required: true,
    placeholder: "np. Po\u015Bciel \u0142\xF3\u017Cko"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dni tygodnia"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(7, minmax(0, 1fr))',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, DAY_NAMES.map((day, index) => {
    const dayNum = index + 1;
    const active = daysOfWeek.includes(dayNum);
    return React.createElement("button", {
      key: dayNum,
      type: "button",
      onClick: () => toggleDay(dayNum),
      style: {
        padding: '0.75rem 0.45rem',
        background: active ? 'rgba(18, 183, 106, 0.3)' : 'rgba(255, 255, 255, 0.1)',
        border: active ? '2px solid #12B76A' : '2px solid rgba(255, 255, 255, 0.2)',
        borderRadius: '0.5rem',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: 600,
        color: 'white'
      }
    }, day);
  })), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Typ zadania"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, ['MIN', 'PLUS', 'WEEKLY'].map(t => React.createElement("button", {
    key: t,
    type: "button",
    onClick: () => {
      setTier(t);
      setTemplateId('');
    },
    className: `badge badge-${t.toLowerCase()}`,
    style: {
      padding: '1rem',
      opacity: tier === t ? 1 : 0.5,
      border: tier === t ? '2px solid white' : '2px solid transparent',
      cursor: 'pointer'
    }
  }, t === 'MIN' ? '📋 MINIMUM' : t === 'PLUS' ? '⭐ BONUS' : '📅 TYGODNIOWE'))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Szablon (opcjonalnie)"), React.createElement("select", {
    className: "select",
    value: templateId,
    onChange: e => applyTemplate(e.target.value)
  }, React.createElement("option", {
    value: ""
  }, "W\u0142asne zadanie"), templatesForTier.map(template => React.createElement("option", {
    key: template.id,
    value: template.id
  }, template.title, " (+", template.points, " pkt)"))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Punkty (opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: points,
    onChange: e => setPoints(parseInt(e.target.value) || 0),
    min: "0",
    placeholder: "0"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Opis (opcjonalny)"), React.createElement("textarea", {
    className: "textarea",
    value: description,
    onChange: e => setDescription(e.target.value),
    placeholder: "np. Zaraz po wstaniu",
    rows: "2"
  }), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      flex: 1
    }
  }, "Dodaj zadanie")))));
};
const EditTaskModal = ({
  task,
  children,
  onSave,
  onClose
}) => {
  const [childId, setChildId] = useState(task?.childId || '');
  const [title, setTitle] = useState(task?.title || '');
  const [tier, setTier] = useState(task?.tier || 'MIN');
  const [points, setPoints] = useState(Number(task?.points || 0));
  const [description, setDescription] = useState(task?.description || '');
  const [daysOfWeek, setDaysOfWeek] = useState(normalizeTaskArchiveDays(task?.daysOfWeek).length > 0 ? normalizeTaskArchiveDays(task?.daysOfWeek) : [1, 2, 3, 4, 5, 6, 7]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const toggleDay = dayNum => {
    setDaysOfWeek(prev => prev.includes(dayNum) ? prev.filter(day => day !== dayNum) : [...prev, dayNum].sort((a, b) => a - b));
  };
  const handleSubmit = async e => {
    e.preventDefault();
    const cleanTitle = title.trim();
    if (!cleanTitle) {
      setError('Podaj nazwę zadania.');
      return;
    }
    if (!childId) {
      setError('Wybierz dziecko.');
      return;
    }
    if (daysOfWeek.length === 0) {
      setError('Wybierz przynajmniej jeden dzień tygodnia.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      await onSave({
        childId,
        title: cleanTitle,
        tier,
        points: Number(points || 0),
        description: description.trim(),
        daysOfWeek
      });
    } catch (saveError) {
      setError(saveError.message || 'Nie udało się zapisać zadania.');
      setSaving(false);
    }
  };
  return React.createElement("div", {
    className: "modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-label": "Edytuj zadanie"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Edytuj zadanie"), error && React.createElement("div", {
    className: "error"
  }, error), React.createElement("form", {
    onSubmit: handleSubmit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dziecko"), React.createElement("select", {
    className: "select",
    value: childId,
    onChange: e => setChildId(e.target.value),
    required: true
  }, children.map(child => React.createElement("option", {
    key: child.id,
    value: child.id
  }, child.avatar, " ", child.name))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Nazwa zadania"), React.createElement("input", {
    type: "text",
    className: "input",
    value: title,
    onChange: e => setTitle(e.target.value),
    required: true,
    placeholder: "np. Pościel łóżko"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Typ zadania"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, ['MIN', 'PLUS', 'WEEKLY'].map(t => React.createElement("button", {
    key: t,
    type: "button",
    onClick: () => setTier(t),
    className: `badge badge-${t.toLowerCase()}`,
    style: {
      padding: '1rem 0.55rem',
      opacity: tier === t ? 1 : 0.55,
      border: tier === t ? '2px solid white' : '2px solid transparent',
      cursor: 'pointer',
      whiteSpace: 'normal',
      lineHeight: 1.15
    }
  }, t === 'MIN' ? '📋 Podstawowe' : t === 'PLUS' ? '⭐ Bonus' : '📅 Tygodniowe'))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Punkty"), React.createElement("input", {
    type: "number",
    className: "input",
    value: points,
    onChange: e => setPoints(parseInt(e.target.value || '0', 10) || 0),
    min: "0",
    max: "10000",
    placeholder: "0"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dni tygodnia"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(7, minmax(0, 1fr))',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, DAY_NAMES.map((day, index) => {
    const dayNum = index + 1;
    const active = daysOfWeek.includes(dayNum);
    return React.createElement("button", {
      key: dayNum,
      type: "button",
      onClick: () => toggleDay(dayNum),
      style: {
        padding: '0.75rem 0.45rem',
        background: active ? 'rgba(18, 183, 106, 0.3)' : 'rgba(255, 255, 255, 0.1)',
        border: active ? '2px solid #12B76A' : '2px solid rgba(255, 255, 255, 0.2)',
        borderRadius: '0.5rem',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: 600,
        color: 'white'
      }
    }, day);
  })), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Opis"), React.createElement("textarea", {
    className: "textarea",
    value: description,
    onChange: e => setDescription(e.target.value),
    placeholder: "np. Zaraz po wstaniu",
    rows: "3"
  }), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    disabled: saving,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    disabled: saving,
    style: {
      flex: 1
    }
  }, saving ? 'Zapisywanie...' : 'Zapisz zmiany')))));
};
const AddRewardModal = ({
  onAdd,
  onSave,
  reward = null,
  onClose
}) => {
  const isEditing = Boolean(reward);
  const [title, setTitle] = useState(reward?.title || '');
  const [description, setDescription] = useState(reward?.description || '');
  const [requiredPoints, setRequiredPoints] = useState(reward?.requiredPoints ? String(reward.requiredPoints) : '');
  const [requiredStreak, setRequiredStreak] = useState(reward?.requiredStreak ? String(reward.requiredStreak) : '');
  const [requiredIdealWeeks, setRequiredIdealWeeks] = useState(reward?.requiredIdealWeeks ? String(reward.requiredIdealWeeks) : '');
  const handleSubmit = e => {
    e.preventDefault();
    const payload = {
      title: title.trim(),
      description: description.trim(),
      requiredPoints: requiredPoints ? parseInt(requiredPoints, 10) : null,
      requiredStreak: requiredStreak ? parseInt(requiredStreak, 10) : null,
      requiredIdealWeeks: requiredIdealWeeks ? parseInt(requiredIdealWeeks, 10) : null
    };
    if (isEditing) {
      onSave(payload);
    } else {
      onAdd(payload.title, payload.description, payload.requiredPoints, payload.requiredStreak, payload.requiredIdealWeeks);
    }
  };
  return React.createElement("div", {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, isEditing ? "Edytuj nagrod\u0119" : "Dodaj nagrod\u0119"), React.createElement("form", {
    onSubmit: handleSubmit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Nazwa nagrody"), React.createElement("input", {
    type: "text",
    className: "input",
    value: title,
    onChange: e => setTitle(e.target.value),
    required: true,
    placeholder: "np. 30 minut gier"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Opis"), React.createElement("textarea", {
    className: "textarea",
    value: description,
    onChange: e => setDescription(e.target.value),
    placeholder: "np. Dodatkowy czas na granie",
    rows: "2"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wymagane punkty (opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: requiredPoints,
    onChange: e => setRequiredPoints(e.target.value),
    min: "0",
    placeholder: "np. 50"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wymagana passa (dni z rz\u0119du, opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: requiredStreak,
    onChange: e => setRequiredStreak(e.target.value),
    min: "0",
    placeholder: "np. 7"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wymagane idealne tygodnie z rz\u0119du (opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: requiredIdealWeeks,
    onChange: e => setRequiredIdealWeeks(e.target.value),
    min: "0",
    placeholder: "np. 2"
  }), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      flex: 1
    }
  }, isEditing ? "Zapisz" : "Dodaj nagrod\u0119")))));
};
ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App, null));
let deferredInstallPrompt = null;
const installButton = document.getElementById('install-app-btn');
const hideInstallButton = () => {
  installButton.style.display = 'none';
  installButton.disabled = false;
};
const showInstallButton = () => {
  installButton.style.display = 'block';
};
installButton.addEventListener('click', async () => {
  if (!deferredInstallPrompt) return;
  installButton.disabled = true;
  deferredInstallPrompt.prompt();
  const choiceResult = await deferredInstallPrompt.userChoice;
  if (choiceResult.outcome !== 'accepted') {
    installButton.disabled = false;
  }
  deferredInstallPrompt = null;
  hideInstallButton();
});
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  deferredInstallPrompt = event;
  showInstallButton();
});
window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  hideInstallButton();
});
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.getRegistrations().then(registrations => {
      registrations.forEach(registration => registration.unregister());
    }).catch(err => {
      console.warn('Service worker cleanup failed:', err);
    });
  });
}
console.log('🏆 FamilyQuest - Pełna wersja produkcyjna');
console.log('✨ Funkcje: konto rodzica, Postgres, zarządzanie dziećmi i zadaniami, passa, punkty, ranking, nagrody');
