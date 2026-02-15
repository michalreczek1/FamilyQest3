import React, { useState, useEffect, useCallback } from 'react';
import { AlertCircle, Check, X, Star, Trophy, Calendar, Users, Settings, LogOut, Lock, Plus, Edit2, Trash2, Award, TrendingUp, Gift, Target, Zap, Moon, Sun, CheckCircle, XCircle, Minus } from 'lucide-react';

// ============================================================================
// STORAGE & DATA LAYER with PostgreSQL Schema
// ============================================================================

const STORAGE_KEYS = {
  USERS: 'fq_users',
  FAMILIES: 'fq_families',
  CHILDREN: 'fq_children',
  TASKS: 'fq_tasks',
  COMPLETIONS: 'fq_completions',
  DAYS: 'fq_days',
  STREAKS: 'fq_streaks',
  POINTS: 'fq_points',
  REWARDS: 'fq_rewards',
  FAMILY_GOAL: 'fq_family_goal',
  AUDIT_LOG: 'fq_audit_log',
  CURRENT_USER: 'fq_current_user',
  CURRENT_CHILD: 'fq_current_child'
};

const DEMO_PARENT_EMAIL = 'demo.parent@example.com';
const DEMO_PARENT_PASSWORD = 'Demo-Change-This-Password';

// PostgreSQL Schema Reference (Prisma)
const POSTGRES_SCHEMA = `
-- User accounts
model User {
  id          String   @id @default(uuid())
  email       String   @unique
  password    String   // hashed
  role        String   // PARENT, CHILD
  familyId    String
  active      Boolean  @default(false)
  pinCode     String?  // for parent access
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}

-- Families
model Family {
  id          String   @id @default(uuid())
  name        String
  createdAt   DateTime @default(now())
  children    Child[]
  tasks       Task[]
  rewards     Reward[]
  familyGoal  FamilyGoal?
}

-- Children profiles
model Child {
  id          String   @id @default(uuid())
  familyId    String
  name        String
  avatar      String   // icon/emoji
  activeDays  Int[]    // [1,2,3,4,5] = Mon-Fri
  createdAt   DateTime @default(now())
  archived    Boolean  @default(false)
  tasks       Task[]
  completions TaskCompletion[]
  days        DayEvaluation[]
  streak      Streak?
  points      Points?
}

-- Tasks
model Task {
  id          String   @id @default(uuid())
  childId     String
  title       String
  description String?
  tier        String   // MIN, PLUS, WEEKLY
  points      Int      @default(0)
  active      Boolean  @default(true)
  createdAt   DateTime @default(now())
  completions TaskCompletion[]
}

-- Task completions
model TaskCompletion {
  id              String   @id @default(uuid())
  taskId          String
  childId         String
  date            String   // YYYY-MM-DD
  doneByChild     Boolean  @default(false)
  approvedByParent Boolean @default(false)
  approvedAt      DateTime?
  approvedBy      String?  // userId
  createdAt       DateTime @default(now())
}

-- Day evaluations
model DayEvaluation {
  id          String   @id @default(uuid())
  childId     String
  date        String   // YYYY-MM-DD
  status      String   // PASSED, FAILED, NOT_ACTIVE
  pointsAwarded Int    @default(0)
  evaluatedAt DateTime
}

-- Streaks
model Streak {
  id              String   @id @default(uuid())
  childId         String   @unique
  current         Int      @default(0)
  best            Int      @default(0)
  lastEvaluatedDate String?
  idealWeeksCount Int      @default(0)
  idealWeeksInRow Int      @default(0)
  updatedAt       DateTime @updatedAt
}

-- Points
model Points {
  id          String   @id @default(uuid())
  childId     String   @unique
  total       Int      @default(0)
  updatedAt   DateTime @updatedAt
}

-- Rewards
model Reward {
  id              String   @id @default(uuid())
  familyId        String
  title           String
  description     String?
  requiredPoints  Int?
  requiredStreak  Int?
  requiredIdealWeeks Int?
  unlockMode      String   // AND, OR
  active          Boolean  @default(true)
  unlockedBy      RewardUnlock[]
}

-- Reward unlocks
model RewardUnlock {
  id          String   @id @default(uuid())
  rewardId    String
  childId     String
  unlockedAt  DateTime @default(now())
  claimedAt   DateTime?
  shown       Boolean  @default(false)
}

-- Family goal
model FamilyGoal {
  id          String   @id @default(uuid())
  familyId    String   @unique
  title       String
  targetValue Int
  mode        String   // POINTS, DAYS
  currentValue Int     @default(0)
  updatedAt   DateTime @updatedAt
}

-- Audit log
model AuditLog {
  id          String   @id @default(uuid())
  userId      String
  action      String
  entityType  String
  entityId    String
  details     Json
  createdAt   DateTime @default(now())
}
`;

// Storage utilities
const storage = {
  get: (key, defaultValue = null) => {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultValue;
    } catch (e) {
      console.error('Storage get error:', e);
      return defaultValue;
    }
  },
  set: (key, value) => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (e) {
      console.error('Storage set error:', e);
      return false;
    }
  },
  remove: (key) => {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (e) {
      console.error('Storage remove error:', e);
      return false;
    }
  }
};

// Initialize demo data
const initializeData = () => {
  if (!storage.get(STORAGE_KEYS.FAMILIES)) {
    const familyId = 'family-1';
    const parentId = 'user-1';
    
    // Users
    storage.set(STORAGE_KEYS.USERS, [{
      id: parentId,
      email: DEMO_PARENT_EMAIL,
      password: DEMO_PARENT_PASSWORD, // In production: bcrypt hash
      role: 'PARENT',
      familyId,
      active: true,
      pinCode: '1234',
      createdAt: new Date().toISOString()
    }]);
    
    // Families
    storage.set(STORAGE_KEYS.FAMILIES, [{
      id: familyId,
      name: 'Rodzina Kowalskich',
      createdAt: new Date().toISOString()
    }]);
    
    // Children
    storage.set(STORAGE_KEYS.CHILDREN, [{
      id: 'child-1',
      familyId,
      name: 'Asia',
      avatar: '👧',
      activeDays: [1, 2, 3, 4, 5], // Mon-Fri
      archived: false,
      createdAt: new Date().toISOString()
    }, {
      id: 'child-2',
      familyId,
      name: 'Tomek',
      avatar: '👦',
      activeDays: [1, 2, 3, 4, 5],
      archived: false,
      createdAt: new Date().toISOString()
    }]);
    
    // Tasks
    storage.set(STORAGE_KEYS.TASKS, [{
      id: 'task-1',
      childId: 'child-1',
      title: 'Pościel łóżko',
      description: 'Zaraz po wstaniu',
      tier: 'MIN',
      points: 0,
      active: true
    }, {
      id: 'task-2',
      childId: 'child-1',
      title: 'Umyj zęby',
      tier: 'MIN',
      points: 0,
      active: true
    }, {
      id: 'task-3',
      childId: 'child-1',
      title: 'Odłóż naczynia',
      tier: 'PLUS',
      points: 5,
      active: true
    }, {
      id: 'task-4',
      childId: 'child-1',
      title: 'Sprzątanie pokoju',
      tier: 'WEEKLY',
      points: 10,
      active: true
    }]);
    
    // Streaks
    storage.set(STORAGE_KEYS.STREAKS, [{
      id: 'streak-1',
      childId: 'child-1',
      current: 0,
      best: 0,
      idealWeeksCount: 0,
      idealWeeksInRow: 0,
      lastEvaluatedDate: null
    }, {
      id: 'streak-2',
      childId: 'child-2',
      current: 0,
      best: 0,
      idealWeeksCount: 0,
      idealWeeksInRow: 0,
      lastEvaluatedDate: null
    }]);
    
    // Points
    storage.set(STORAGE_KEYS.POINTS, [{
      id: 'points-1',
      childId: 'child-1',
      total: 0
    }, {
      id: 'points-2',
      childId: 'child-2',
      total: 0
    }]);
    
    // Rewards
    storage.set(STORAGE_KEYS.REWARDS, [{
      id: 'reward-1',
      familyId,
      title: '30 minut gier',
      description: 'Dodatkowy czas na granie',
      requiredPoints: 50,
      requiredStreak: null,
      requiredIdealWeeks: null,
      unlockMode: 'AND',
      active: true
    }, {
      id: 'reward-2',
      familyId,
      title: 'Kino z rodzicami',
      description: 'Wybierz film!',
      requiredPoints: 100,
      requiredStreak: 7,
      requiredIdealWeeks: null,
      unlockMode: 'AND',
      active: true
    }, {
      id: 'reward-3',
      familyId,
      title: 'Pizza party',
      description: 'Zamówimy Twoją ulubioną pizzę',
      requiredPoints: null,
      requiredStreak: null,
      requiredIdealWeeks: 2,
      unlockMode: 'AND',
      active: true
    }]);
    
    // Family Goal
    storage.set(STORAGE_KEYS.FAMILY_GOAL, {
      id: 'goal-1',
      familyId,
      title: 'Wycieczka nad morze',
      targetValue: 500,
      mode: 'POINTS',
      currentValue: 0
    });
    
    // Initialize empty arrays
    storage.set(STORAGE_KEYS.COMPLETIONS, []);
    storage.set(STORAGE_KEYS.DAYS, []);
    storage.set(STORAGE_KEYS.AUDIT_LOG, []);
  }
};

// Business Logic Functions
const BusinessLogic = {
  // Get date string YYYY-MM-DD
  getDateString: (date = new Date()) => {
    return date.toISOString().split('T')[0];
  },
  
  // Get day of week (1=Mon, 7=Sun)
  getDayOfWeek: (dateString) => {
    const date = new Date(dateString + 'T00:00:00');
    const day = date.getDay();
    return day === 0 ? 7 : day;
  },
  
  // Check if day is active for child
  isDayActive: (child, dateString) => {
    const dayOfWeek = BusinessLogic.getDayOfWeek(dateString);
    return child.activeDays.includes(dayOfWeek);
  },
  
  // Evaluate day status
  evaluateDay: (childId, dateString) => {
    const children = storage.get(STORAGE_KEYS.CHILDREN, []);
    const child = children.find(c => c.id === childId);
    if (!child) return 'NOT_ACTIVE';
    
    // Check if day is active
    if (!BusinessLogic.isDayActive(child, dateString)) {
      return 'NOT_ACTIVE';
    }
    
    // Get MIN tasks for child
    const tasks = storage.get(STORAGE_KEYS.TASKS, []);
    const minTasks = tasks.filter(t => t.childId === childId && t.tier === 'MIN' && t.active);
    
    if (minTasks.length === 0) {
      return 'PASSED'; // No MIN tasks = automatically passed
    }
    
    // Check completions
    const completions = storage.get(STORAGE_KEYS.COMPLETIONS, []);
    const approvedCount = minTasks.filter(task => {
      const completion = completions.find(c => 
        c.taskId === task.id && 
        c.date === dateString && 
        c.approvedByParent
      );
      return !!completion;
    }).length;
    
    return approvedCount === minTasks.length ? 'PASSED' : 'FAILED';
  },
  
  // Update streak
  updateStreak: (childId, dateString, status) => {
    const streaks = storage.get(STORAGE_KEYS.STREAKS, []);
    let streak = streaks.find(s => s.childId === childId);
    
    if (!streak) {
      streak = {
        id: `streak-${childId}`,
        childId,
        current: 0,
        best: 0,
        idealWeeksCount: 0,
        idealWeeksInRow: 0,
        lastEvaluatedDate: null
      };
      streaks.push(streak);
    }
    
    if (status === 'PASSED') {
      streak.current += 1;
      if (streak.current > streak.best) {
        streak.best = streak.current;
      }
    } else if (status === 'FAILED') {
      streak.current = 0;
    }
    // NOT_ACTIVE doesn't affect streak
    
    streak.lastEvaluatedDate = dateString;
    storage.set(STORAGE_KEYS.STREAKS, streaks);
    return streak;
  },
  
  // Grant day points
  grantDayPoints: (childId, dateString, status) => {
    if (status !== 'PASSED') return;
    
    // Check if points already granted
    const days = storage.get(STORAGE_KEYS.DAYS, []);
    const existingDay = days.find(d => d.childId === childId && d.date === dateString);
    if (existingDay && existingDay.pointsAwarded > 0) return; // Already granted
    
    const POINTS_PER_DAY = 10;
    const pointsRecords = storage.get(STORAGE_KEYS.POINTS, []);
    let pointsRecord = pointsRecords.find(p => p.childId === childId);
    
    if (!pointsRecord) {
      pointsRecord = {
        id: `points-${childId}`,
        childId,
        total: 0
      };
      pointsRecords.push(pointsRecord);
    }
    
    pointsRecord.total += POINTS_PER_DAY;
    storage.set(STORAGE_KEYS.POINTS, pointsRecords);
    
    // Record points awarded
    if (existingDay) {
      existingDay.pointsAwarded = POINTS_PER_DAY;
    }
  },
  
  // Grant task points (for PLUS tasks)
  grantTaskPoints: (childId, taskId, points) => {
    if (points <= 0) return;
    
    const pointsRecords = storage.get(STORAGE_KEYS.POINTS, []);
    let pointsRecord = pointsRecords.find(p => p.childId === childId);
    
    if (!pointsRecord) {
      pointsRecord = {
        id: `points-${childId}`,
        childId,
        total: 0
      };
      pointsRecords.push(pointsRecord);
    }
    
    pointsRecord.total += points;
    storage.set(STORAGE_KEYS.POINTS, pointsRecords);
  },
  
  // Evaluate week
  evaluateWeek: (childId, weekStart) => {
    const children = storage.get(STORAGE_KEYS.CHILDREN, []);
    const child = children.find(c => c.id === childId);
    if (!child) return false;
    
    const days = storage.get(STORAGE_KEYS.DAYS, []);
    let allPassed = true;
    
    for (let i = 0; i < 7; i++) {
      const date = new Date(weekStart);
      date.setDate(date.getDate() + i);
      const dateString = BusinessLogic.getDateString(date);
      
      if (BusinessLogic.isDayActive(child, dateString)) {
        const dayEval = days.find(d => d.childId === childId && d.date === dateString);
        if (!dayEval || dayEval.status !== 'PASSED') {
          allPassed = false;
          break;
        }
      }
    }
    
    if (allPassed) {
      const streaks = storage.get(STORAGE_KEYS.STREAKS, []);
      const streak = streaks.find(s => s.childId === childId);
      if (streak) {
        streak.idealWeeksCount += 1;
        streak.idealWeeksInRow += 1;
        storage.set(STORAGE_KEYS.STREAKS, streaks);
      }
    } else {
      const streaks = storage.get(STORAGE_KEYS.STREAKS, []);
      const streak = streaks.find(s => s.childId === childId);
      if (streak) {
        streak.idealWeeksInRow = 0;
        storage.set(STORAGE_KEYS.STREAKS, streaks);
      }
    }
    
    return allPassed;
  },
  
  // Check and unlock rewards
  checkRewards: (childId) => {
    const points = storage.get(STORAGE_KEYS.POINTS, []).find(p => p.childId === childId);
    const streak = storage.get(STORAGE_KEYS.STREAKS, []).find(s => s.childId === childId);
    const rewards = storage.get(STORAGE_KEYS.REWARDS, []).filter(r => r.active);
    const unlocks = storage.get('fq_reward_unlocks', []);
    
    const newUnlocks = [];
    
    rewards.forEach(reward => {
      // Check if already unlocked
      const alreadyUnlocked = unlocks.find(u => u.rewardId === reward.id && u.childId === childId);
      if (alreadyUnlocked) return;
      
      // Check conditions
      let meetsConditions = true;
      
      if (reward.requiredPoints && (!points || points.total < reward.requiredPoints)) {
        meetsConditions = false;
      }
      
      if (reward.requiredStreak && (!streak || streak.current < reward.requiredStreak)) {
        meetsConditions = false;
      }
      
      if (reward.requiredIdealWeeks && (!streak || streak.idealWeeksInRow < reward.requiredIdealWeeks)) {
        meetsConditions = false;
      }
      
      if (meetsConditions) {
        const unlock = {
          id: `unlock-${Date.now()}-${Math.random()}`,
          rewardId: reward.id,
          childId,
          unlockedAt: new Date().toISOString(),
          claimedAt: null,
          shown: false
        };
        unlocks.push(unlock);
        newUnlocks.push({ ...unlock, reward });
      }
    });
    
    storage.set('fq_reward_unlocks', unlocks);
    return newUnlocks;
  },
  
  // Audit log
  addAuditLog: (userId, action, entityType, entityId, details) => {
    const logs = storage.get(STORAGE_KEYS.AUDIT_LOG, []);
    logs.push({
      id: `log-${Date.now()}`,
      userId,
      action,
      entityType,
      entityId,
      details,
      createdAt: new Date().toISOString()
    });
    storage.set(STORAGE_KEYS.AUDIT_LOG, logs);
  }
};

// ============================================================================
// COMPONENTS
// ============================================================================

// Confetti effect
const Confetti = ({ show, onComplete }) => {
  useEffect(() => {
    if (show) {
      const timer = setTimeout(onComplete, 3000);
      return () => clearTimeout(timer);
    }
  }, [show, onComplete]);
  
  if (!show) return null;
  
  return (
    <div className="confetti-container">
      {[...Array(50)].map((_, i) => (
        <div
          key={i}
          className="confetti"
          style={{
            left: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 0.5}s`,
            backgroundColor: ['#FF6B9D', '#FEC84B', '#12B76A', '#7C3AED', '#F97316'][Math.floor(Math.random() * 5)]
          }}
        />
      ))}
    </div>
  );
};

// Reward overlay
const RewardOverlay = ({ reward, onClose }) => {
  if (!reward) return null;
  
  return (
    <div className="reward-overlay">
      <div className="reward-content">
        <Gift size={80} className="reward-icon" />
        <h1>🎉 Gratulacje! 🎉</h1>
        <h2>{reward.title}</h2>
        <p>{reward.description}</p>
        <button onClick={onClose} className="btn btn-primary btn-large">
          Wow! Dziękuję! 🎊
        </button>
      </div>
    </div>
  );
};

// Login Screen
const LoginScreen = ({ onLogin }) => {
  const [email, setEmail] = useState(DEMO_PARENT_EMAIL);
  const [password, setPassword] = useState(DEMO_PARENT_PASSWORD);
  const [error, setError] = useState('');
  
  const handleLogin = () => {
    const users = storage.get(STORAGE_KEYS.USERS, []);
    const user = users.find(u => u.email === email && u.password === password);
    
    if (!user) {
      setError('Nieprawidłowy email lub hasło');
      return;
    }
    
    if (!user.active) {
      setError('Konto nieaktywne - czeka na aktywację przez admina');
      return;
    }
    
    storage.set(STORAGE_KEYS.CURRENT_USER, user);
    onLogin(user);
  };
  
  return (
    <div className="login-screen">
      <div className="login-card">
        <div style={{
          background: 'rgba(254, 200, 75, 0.2)',
          border: '2px solid rgba(254, 200, 75, 0.5)',
          borderRadius: '1rem',
          padding: '0.75rem',
          marginBottom: '1.5rem',
          textAlign: 'center',
          fontSize: '0.9rem'
        }}>
          🎮 <strong>Tryb DEMO</strong> - Dane lokalne w przeglądarce
        </div>
        
        <div className="login-header">
          <Trophy size={60} className="login-icon" />
          <h1>FamilyQuest</h1>
          <p>Rodzinna przygoda z zadaniami</p>
        </div>
        
        <div className="login-form">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input"
          />
          <input
            type="password"
            placeholder="Hasło"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
          />
          
          {error && (
            <div className="error-message">
              <AlertCircle size={16} />
              {error}
            </div>
          )}
          
          <button onClick={handleLogin} className="btn btn-primary btn-large">
            Zaloguj się
          </button>
          
          <div className="login-links">
            <a href="#reset">Zapomniałeś hasła?</a>
            <a href="#register">Utwórz nowe konto</a>
          </div>
          
          <button 
            onClick={() => {
              if (confirm('Czy na pewno chcesz zresetować wszystkie dane demo?')) {
                localStorage.clear();
                window.location.reload();
              }
            }}
            style={{
              marginTop: '1rem',
              padding: '0.5rem',
              background: 'rgba(249, 112, 102, 0.2)',
              border: '1px solid rgba(249, 112, 102, 0.5)',
              borderRadius: '0.5rem',
              color: 'var(--text-secondary)',
              fontSize: '0.85rem',
              cursor: 'pointer'
            }}
          >
            🔄 Reset danych demo
          </button>
        </div>
      </div>
    </div>
  );
};

// PIN Screen for Parent Access
const PinScreen = ({ onSuccess, onCancel }) => {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  
  const handlePin = (digit) => {
    const newPin = pin + digit;
    setPin(newPin);
    
    if (newPin.length === 4) {
      const user = storage.get(STORAGE_KEYS.CURRENT_USER);
      if (user && user.pinCode === newPin) {
        setError('');
        onSuccess();
      } else {
        setError('Nieprawidłowy PIN');
        setPin('');
      }
    }
  };
  
  const handleBackspace = () => {
    setPin(pin.slice(0, -1));
    setError('');
  };
  
  return (
    <div className="pin-screen">
      <div className="pin-card">
        <Lock size={48} className="pin-icon" />
        <h2>Wprowadź PIN rodzica</h2>
        
        <div className="pin-display">
          {[0, 1, 2, 3].map(i => (
            <div key={i} className={`pin-dot ${i < pin.length ? 'filled' : ''}`} />
          ))}
        </div>
        
        {error && <div className="error-message">{error}</div>}
        
        <div className="pin-pad">
          {[1, 2, 3, 4, 5, 6, 7, 8, 9].map(num => (
            <button key={num} onClick={() => handlePin(num.toString())} className="pin-button">
              {num}
            </button>
          ))}
          <button onClick={onCancel} className="pin-button">✕</button>
          <button onClick={() => handlePin('0')} className="pin-button">0</button>
          <button onClick={handleBackspace} className="pin-button">⌫</button>
        </div>
      </div>
    </div>
  );
};

// Child Selection Screen
const ChildSelectionScreen = ({ onSelectChild }) => {
  const children = storage.get(STORAGE_KEYS.CHILDREN, []).filter(c => !c.archived);
  const [showPin, setShowPin] = useState(false);
  
  if (showPin) {
    return <PinScreen onSuccess={() => onSelectChild(null)} onCancel={() => setShowPin(false)} />;
  }
  
  return (
    <div className="child-selection-screen">
      <div className="child-selection-header">
        <Trophy size={48} />
        <h1>Wybierz swój profil</h1>
        <button onClick={() => setShowPin(true)} className="btn btn-secondary">
          <Lock size={18} />
          Panel rodzica
        </button>
      </div>
      
      <div className="child-grid">
        {children.map(child => (
          <button
            key={child.id}
            onClick={() => onSelectChild(child)}
            className="child-card"
          >
            <div className="child-avatar">{child.avatar}</div>
            <div className="child-name">{child.name}</div>
          </button>
        ))}
      </div>
    </div>
  );
};

// Child Dashboard
const ChildDashboard = ({ child, onBack }) => {
  const [tasks, setTasks] = useState([]);
  const [weeklyTasks, setWeeklyTasks] = useState([]);
  const [completions, setCompletions] = useState([]);
  const [dayStatus, setDayStatus] = useState('FAILED');
  const [streak, setStreak] = useState(null);
  const [points, setPoints] = useState(0);
  const [showConfetti, setShowConfetti] = useState(false);
  const [recentDays, setRecentDays] = useState([]);
  const [showReward, setShowReward] = useState(null);
  
  const today = BusinessLogic.getDateString();
  
  useEffect(() => {
    loadData();
  }, [child.id]);
  
  const loadData = () => {
    const allTasks = storage.get(STORAGE_KEYS.TASKS, []);
    const childTasks = allTasks.filter(t => t.childId === child.id && t.active);
    setTasks(childTasks.filter(t => t.tier !== 'WEEKLY'));
    setWeeklyTasks(childTasks.filter(t => t.tier === 'WEEKLY'));
    
    const allCompletions = storage.get(STORAGE_KEYS.COMPLETIONS, []);
    const todayCompletions = allCompletions.filter(c => c.childId === child.id && c.date === today);
    setCompletions(todayCompletions);
    
    const status = BusinessLogic.evaluateDay(child.id, today);
    setDayStatus(status);
    
    const streakData = storage.get(STORAGE_KEYS.STREAKS, []).find(s => s.childId === child.id);
    setStreak(streakData);
    
    const pointsData = storage.get(STORAGE_KEYS.POINTS, []).find(p => p.childId === child.id);
    setPoints(pointsData?.total || 0);
    
    // Load recent days
    const days = storage.get(STORAGE_KEYS.DAYS, []);
    const recent = [];
    for (let i = 0; i < 14; i++) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateString = BusinessLogic.getDateString(date);
      const dayEval = days.find(d => d.childId === child.id && d.date === dateString);
      const isActive = BusinessLogic.isDayActive(child, dateString);
      recent.push({
        date: dateString,
        status: dayEval?.status || (isActive ? 'FAILED' : 'NOT_ACTIVE')
      });
    }
    setRecentDays(recent);
  };
  
  const handleTaskToggle = (task) => {
    const allCompletions = storage.get(STORAGE_KEYS.COMPLETIONS, []);
    const existing = allCompletions.find(c => 
      c.taskId === task.id && c.date === today && c.childId === child.id
    );
    
    if (existing) {
      existing.doneByChild = !existing.doneByChild;
    } else {
      allCompletions.push({
        id: `completion-${Date.now()}-${Math.random()}`,
        taskId: task.id,
        childId: child.id,
        date: today,
        doneByChild: true,
        approvedByParent: false,
        createdAt: new Date().toISOString()
      });
    }
    
    storage.set(STORAGE_KEYS.COMPLETIONS, allCompletions);
    loadData();
  };
  
  const isTaskCompleted = (task) => {
    return completions.some(c => c.taskId === task.id && c.doneByChild);
  };
  
  const isTaskApproved = (task) => {
    return completions.some(c => c.taskId === task.id && c.approvedByParent);
  };
  
  const getStatusIcon = () => {
    if (dayStatus === 'NOT_ACTIVE') return { icon: Minus, color: '#94A3B8', text: 'Dzień nieaktywny' };
    if (dayStatus === 'PASSED') return { icon: CheckCircle, color: '#12B76A', text: 'Dzień zaliczony!' };
    return { icon: XCircle, color: '#F97316', text: 'Dzień niezaliczony' };
  };
  
  const statusInfo = getStatusIcon();
  
  return (
    <div className="child-dashboard">
      <Confetti show={showConfetti} onComplete={() => setShowConfetti(false)} />
      <RewardOverlay reward={showReward} onClose={() => setShowReward(null)} />
      
      <div className="dashboard-header">
        <button onClick={onBack} className="btn-back">←</button>
        <div className="child-info">
          <span className="child-avatar-small">{child.avatar}</span>
          <h2>{child.name}</h2>
        </div>
        <div className="header-stats">
          <div className="stat">
            <Zap size={20} />
            <span>{points}</span>
          </div>
          <div className="stat">
            <Trophy size={20} />
            <span>{streak?.current || 0}</span>
          </div>
        </div>
      </div>
      
      <div className="day-status-card">
        <statusInfo.icon size={32} color={statusInfo.color} />
        <h3>{statusInfo.text}</h3>
        <p className="status-note">Punkty i zaliczenie wymagają akceptacji rodzica</p>
      </div>
      
      <div className="streak-card">
        <div className="streak-item">
          <Trophy size={24} />
          <div>
            <div className="streak-label">Aktualna passa</div>
            <div className="streak-value">{streak?.current || 0} dni</div>
          </div>
        </div>
        <div className="streak-item">
          <Star size={24} />
          <div>
            <div className="streak-label">Najlepsza passa</div>
            <div className="streak-value">{streak?.best || 0} dni</div>
          </div>
        </div>
      </div>
      
      <div className="calendar-mini">
        {recentDays.map((day, i) => (
          <div
            key={i}
            className={`calendar-day ${day.status.toLowerCase()}`}
            title={day.date}
          >
            {day.status === 'PASSED' ? '✓' : day.status === 'NOT_ACTIVE' ? '−' : '✗'}
          </div>
        ))}
      </div>
      
      <div className="tasks-section">
        <h3 className="section-title">
          <CheckCircle size={20} />
          Zadania MINIMUM
        </h3>
        {tasks.filter(t => t.tier === 'MIN').map(task => (
          <button
            key={task.id}
            onClick={() => handleTaskToggle(task)}
            className={`task-item ${isTaskCompleted(task) ? 'completed' : ''} ${isTaskApproved(task) ? 'approved' : ''}`}
          >
            <div className="task-checkbox">
              {isTaskApproved(task) ? <Check size={20} /> : isTaskCompleted(task) ? '⏳' : ''}
            </div>
            <div className="task-content">
              <div className="task-title">{task.title}</div>
              {task.description && <div className="task-desc">{task.description}</div>}
            </div>
            {isTaskApproved(task) && <span className="task-badge approved">✓ Zatwierdzone</span>}
          </button>
        ))}
        
        <h3 className="section-title" style={{marginTop: '2rem'}}>
          <Plus size={20} />
          Zadania BONUS
        </h3>
        {tasks.filter(t => t.tier === 'PLUS').map(task => (
          <button
            key={task.id}
            onClick={() => handleTaskToggle(task)}
            className={`task-item ${isTaskCompleted(task) ? 'completed' : ''} ${isTaskApproved(task) ? 'approved' : ''}`}
          >
            <div className="task-checkbox">
              {isTaskApproved(task) ? <Check size={20} /> : isTaskCompleted(task) ? '⏳' : ''}
            </div>
            <div className="task-content">
              <div className="task-title">{task.title}</div>
              {task.description && <div className="task-desc">{task.description}</div>}
            </div>
            {task.points > 0 && <span className="task-badge points">+{task.points}</span>}
          </button>
        ))}
        
        {weeklyTasks.length > 0 && (
          <>
            <h3 className="section-title" style={{marginTop: '2rem'}}>
              <Calendar size={20} />
              Zadania TYGODNIOWE
            </h3>
            {weeklyTasks.map(task => (
              <button
                key={task.id}
                onClick={() => handleTaskToggle(task)}
                className={`task-item weekly ${isTaskCompleted(task) ? 'completed' : ''} ${isTaskApproved(task) ? 'approved' : ''}`}
              >
                <div className="task-checkbox">
                  {isTaskApproved(task) ? <Check size={20} /> : isTaskCompleted(task) ? '⏳' : ''}
                </div>
                <div className="task-content">
                  <div className="task-title">{task.title}</div>
                  {task.description && <div className="task-desc">{task.description}</div>}
                </div>
                {task.points > 0 && <span className="task-badge points">+{task.points}</span>}
              </button>
            ))}
          </>
        )}
      </div>
    </div>
  );
};

// Parent Dashboard
const ParentDashboard = ({ onBack }) => {
  const [view, setView] = useState('approvals'); // approvals, children, tasks, rewards, settings
  const [children, setChildren] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [showConfetti, setShowConfetti] = useState(false);
  
  useEffect(() => {
    loadData();
  }, []);
  
  const loadData = () => {
    const allChildren = storage.get(STORAGE_KEYS.CHILDREN, []).filter(c => !c.archived);
    setChildren(allChildren);
    
    const completions = storage.get(STORAGE_KEYS.COMPLETIONS, []);
    const pending = completions.filter(c => c.doneByChild && !c.approvedByParent);
    
    // Enrich with task and child info
    const tasks = storage.get(STORAGE_KEYS.TASKS, []);
    const enriched = pending.map(c => {
      const task = tasks.find(t => t.id === c.taskId);
      const child = allChildren.find(ch => ch.id === c.childId);
      return { ...c, task, child };
    }).filter(c => c.task && c.child);
    
    setPendingApprovals(enriched);
  };
  
  const handleApprove = (completion) => {
    const completions = storage.get(STORAGE_KEYS.COMPLETIONS, []);
    const index = completions.findIndex(c => c.id === completion.id);
    if (index !== -1) {
      completions[index].approvedByParent = true;
      completions[index].approvedAt = new Date().toISOString();
      completions[index].approvedBy = storage.get(STORAGE_KEYS.CURRENT_USER)?.id;
      storage.set(STORAGE_KEYS.COMPLETIONS, completions);
      
      // Grant task points if PLUS
      if (completion.task.tier === 'PLUS' && completion.task.points > 0) {
        BusinessLogic.grantTaskPoints(completion.childId, completion.taskId, completion.task.points);
      }
      
      // Evaluate day
      const status = BusinessLogic.evaluateDay(completion.childId, completion.date);
      
      // Save day evaluation
      const days = storage.get(STORAGE_KEYS.DAYS, []);
      const existingDay = days.find(d => d.childId === completion.childId && d.date === completion.date);
      if (existingDay) {
        existingDay.status = status;
        existingDay.evaluatedAt = new Date().toISOString();
      } else {
        days.push({
          id: `day-${Date.now()}-${Math.random()}`,
          childId: completion.childId,
          date: completion.date,
          status,
          pointsAwarded: 0,
          evaluatedAt: new Date().toISOString()
        });
      }
      storage.set(STORAGE_KEYS.DAYS, days);
      
      // Update streak
      BusinessLogic.updateStreak(completion.childId, completion.date, status);
      
      // Grant day points if passed
      if (status === 'PASSED') {
        BusinessLogic.grantDayPoints(completion.childId, completion.date, status);
        setShowConfetti(true);
      }
      
      // Check rewards
      const newRewards = BusinessLogic.checkRewards(completion.childId);
      
      // Audit log
      BusinessLogic.addAuditLog(
        storage.get(STORAGE_KEYS.CURRENT_USER)?.id,
        'APPROVE_TASK',
        'TaskCompletion',
        completion.id,
        { taskTitle: completion.task.title, childName: completion.child.name }
      );
      
      loadData();
    }
  };
  
  const handleReject = (completion) => {
    const completions = storage.get(STORAGE_KEYS.COMPLETIONS, []);
    const index = completions.findIndex(c => c.id === completion.id);
    if (index !== -1) {
      completions[index].doneByChild = false;
      storage.set(STORAGE_KEYS.COMPLETIONS, completions);
      
      BusinessLogic.addAuditLog(
        storage.get(STORAGE_KEYS.CURRENT_USER)?.id,
        'REJECT_TASK',
        'TaskCompletion',
        completion.id,
        { taskTitle: completion.task.title, childName: completion.child.name }
      );
      
      loadData();
    }
  };
  
  const handleApproveAll = () => {
    pendingApprovals.forEach(approval => handleApprove(approval));
  };
  
  return (
    <div className="parent-dashboard">
      <Confetti show={showConfetti} onComplete={() => setShowConfetti(false)} />
      
      <div className="dashboard-header">
        <button onClick={onBack} className="btn-back">←</button>
        <h2>Panel rodzica</h2>
        <button onClick={onBack} className="btn btn-secondary">
          <LogOut size={18} />
          Wyjdź
        </button>
      </div>
      
      <div className="parent-tabs">
        <button
          onClick={() => setView('approvals')}
          className={`tab ${view === 'approvals' ? 'active' : ''}`}
        >
          <Check size={20} />
          Do zatwierdzenia
          {pendingApprovals.length > 0 && <span className="badge">{pendingApprovals.length}</span>}
        </button>
        <button
          onClick={() => setView('children')}
          className={`tab ${view === 'children' ? 'active' : ''}`}
        >
          <Users size={20} />
          Dzieci
        </button>
        <button
          onClick={() => setView('tasks')}
          className={`tab ${view === 'tasks' ? 'active' : ''}`}
        >
          <CheckCircle size={20} />
          Zadania
        </button>
        <button
          onClick={() => setView('rewards')}
          className={`tab ${view === 'rewards' ? 'active' : ''}`}
        >
          <Gift size={20} />
          Nagrody
        </button>
        <button
          onClick={() => setView('settings')}
          className={`tab ${view === 'settings' ? 'active' : ''}`}
        >
          <Settings size={20} />
          Ustawienia
        </button>
      </div>
      
      <div className="parent-content">
        {view === 'approvals' && (
          <div className="approvals-view">
            <div className="view-header">
              <h3>Zadania do zatwierdzenia</h3>
              {pendingApprovals.length > 0 && (
                <button onClick={handleApproveAll} className="btn btn-primary">
                  Zatwierdź wszystko
                </button>
              )}
            </div>
            
            {pendingApprovals.length === 0 ? (
              <div className="empty-state">
                <CheckCircle size={48} />
                <p>Brak zadań do zatwierdzenia</p>
              </div>
            ) : (
              <div className="approval-list">
                {pendingApprovals.map(approval => (
                  <div key={approval.id} className="approval-item">
                    <div className="approval-child">
                      <span className="child-avatar-small">{approval.child.avatar}</span>
                      <span>{approval.child.name}</span>
                    </div>
                    <div className="approval-task">
                      <div className="task-title">{approval.task.title}</div>
                      <div className="task-meta">
                        <span className={`tier-badge ${approval.task.tier.toLowerCase()}`}>
                          {approval.task.tier}
                        </span>
                        {approval.task.points > 0 && (
                          <span className="points-badge">+{approval.task.points} pkt</span>
                        )}
                        <span className="date-badge">{approval.date}</span>
                      </div>
                    </div>
                    <div className="approval-actions">
                      <button
                        onClick={() => handleApprove(approval)}
                        className="btn btn-success btn-sm"
                      >
                        <Check size={18} />
                        Zatwierdź
                      </button>
                      <button
                        onClick={() => handleReject(approval)}
                        className="btn btn-danger btn-sm"
                      >
                        <X size={18} />
                        Odrzuć
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        
        {view === 'children' && (
          <div className="children-view">
            <div className="view-header">
              <h3>Zarządzaj dziećmi</h3>
              <button className="btn btn-primary">
                <Plus size={18} />
                Dodaj dziecko
              </button>
            </div>
            
            <div className="children-list">
              {children.map(child => {
                const streak = storage.get(STORAGE_KEYS.STREAKS, []).find(s => s.childId === child.id);
                const points = storage.get(STORAGE_KEYS.POINTS, []).find(p => p.childId === child.id);
                
                return (
                  <div key={child.id} className="child-card-parent">
                    <div className="child-header">
                      <span className="child-avatar-large">{child.avatar}</span>
                      <div>
                        <h4>{child.name}</h4>
                        <div className="child-stats-small">
                          <span><Zap size={14} /> {points?.total || 0} pkt</span>
                          <span><Trophy size={14} /> {streak?.current || 0} dni</span>
                        </div>
                      </div>
                    </div>
                    <div className="child-actions">
                      <button className="btn btn-secondary btn-sm">
                        <Edit2 size={16} />
                        Edytuj
                      </button>
                      <button className="btn btn-secondary btn-sm">
                        <Trash2 size={16} />
                        Usuń
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        
        {view === 'tasks' && (
          <div className="tasks-view">
            <div className="view-header">
              <h3>Zarządzaj zadaniami</h3>
              <button className="btn btn-primary">
                <Plus size={18} />
                Dodaj zadanie
              </button>
            </div>
            
            <p className="info-text">Panel zarządzania zadaniami - tutaj możesz dodawać, edytować i usuwać zadania dla każdego dziecka.</p>
          </div>
        )}
        
        {view === 'rewards' && (
          <div className="rewards-view">
            <div className="view-header">
              <h3>Katalog nagród</h3>
              <button className="btn btn-primary">
                <Plus size={18} />
                Dodaj nagrodę
              </button>
            </div>
            
            <div className="rewards-list">
              {storage.get(STORAGE_KEYS.REWARDS, []).map(reward => (
                <div key={reward.id} className="reward-card">
                  <Gift size={32} />
                  <div className="reward-info">
                    <h4>{reward.title}</h4>
                    <p>{reward.description}</p>
                    <div className="reward-requirements">
                      {reward.requiredPoints && <span>🔸 {reward.requiredPoints} pkt</span>}
                      {reward.requiredStreak && <span>🔥 {reward.requiredStreak} dni passy</span>}
                      {reward.requiredIdealWeeks && <span>⭐ {reward.requiredIdealWeeks} idealne tygodnie</span>}
                    </div>
                  </div>
                  <button className="btn btn-secondary btn-sm">
                    <Edit2 size={16} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {view === 'settings' && (
          <div className="settings-view">
            <h3>Ustawienia</h3>
            
            <div className="settings-section">
              <h4>Bezpieczeństwo</h4>
              <button className="btn btn-secondary">
                <Lock size={18} />
                Zmień kod PIN
              </button>
              <button className="btn btn-secondary">
                Zmień hasło
              </button>
            </div>
            
            <div className="settings-section">
              <h4>Użytkownicy</h4>
              <button className="btn btn-secondary">
                <Plus size={18} />
                Dodaj rodzica
              </button>
            </div>
            
            <div className="settings-section">
              <h4>Dane</h4>
              <button className="btn btn-secondary">
                Eksportuj dane rodziny
              </button>
              <button className="btn btn-secondary">
                Importuj backup
              </button>
            </div>
          </div>
        )}
      </div>
      
      <FamilyGoalWidget />
    </div>
  );
};

// Family Goal Widget
const FamilyGoalWidget = () => {
  const goal = storage.get(STORAGE_KEYS.FAMILY_GOAL);
  if (!goal) return null;
  
  const progress = Math.min(100, (goal.currentValue / goal.targetValue) * 100);
  
  return (
    <div className="family-goal-widget">
      <div className="goal-header">
        <Target size={24} />
        <div>
          <div className="goal-title">{goal.title}</div>
          <div className="goal-progress-text">
            {goal.currentValue} / {goal.targetValue} {goal.mode === 'POINTS' ? 'punktów' : 'dni'}
          </div>
        </div>
      </div>
      <div className="goal-progress-bar">
        <div className="goal-progress-fill" style={{ width: `${progress}%` }} />
      </div>
    </div>
  );
};

// Network Status Component
const NetworkStatus = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  
  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);
  
  if (isOnline) return null;
  
  return (
    <div style={{
      position: 'fixed',
      bottom: '1rem',
      left: '50%',
      transform: 'translateX(-50%)',
      background: 'rgba(249, 112, 102, 0.95)',
      color: 'white',
      padding: '0.75rem 1.5rem',
      borderRadius: '2rem',
      fontWeight: '600',
      zIndex: 10001,
      boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
      animation: 'slideUp 0.3s ease'
    }}>
      🔌 Tryb offline - zmiany będą zsynchronizowane
    </div>
  );
};

// Main App
const FamilyQuestApp = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [currentChild, setCurrentChild] = useState(null);
  const [isParentMode, setIsParentMode] = useState(false);
  
  useEffect(() => {
    initializeData();
    const user = storage.get(STORAGE_KEYS.CURRENT_USER);
    if (user) {
      setCurrentUser(user);
      if (user.role === 'PARENT') {
        const child = storage.get(STORAGE_KEYS.CURRENT_CHILD);
        setCurrentChild(child);
      }
    }
    
    // Log demo mode info
    console.log('🎮 FamilyQuest uruchomiony w trybie DEMO');
    console.log('📝 Dane przechowywane lokalnie w przeglądarce');
    console.log('🔐 Domyślne dane logowania:');
    console.log(`   Email: ${DEMO_PARENT_EMAIL}`);
    console.log(`   Hasło: ${DEMO_PARENT_PASSWORD}`);
    console.log('   PIN: 1234');
  }, []);
  
  const handleLogin = (user) => {
    setCurrentUser(user);
    if (user.role === 'PARENT') {
      setIsParentMode(false);
    }
  };
  
  const handleSelectChild = (child) => {
    if (child === null) {
      setIsParentMode(true);
    } else {
      setCurrentChild(child);
      storage.set(STORAGE_KEYS.CURRENT_CHILD, child);
    }
  };
  
  const handleBack = () => {
    if (isParentMode) {
      setIsParentMode(false);
      setCurrentChild(null);
      storage.remove(STORAGE_KEYS.CURRENT_CHILD);
    } else if (currentChild) {
      setCurrentChild(null);
      storage.remove(STORAGE_KEYS.CURRENT_CHILD);
    }
  };
  
  const handleLogout = () => {
    storage.remove(STORAGE_KEYS.CURRENT_USER);
    storage.remove(STORAGE_KEYS.CURRENT_CHILD);
    setCurrentUser(null);
    setCurrentChild(null);
    setIsParentMode(false);
  };
  
  if (!currentUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }
  
  if (currentUser.role === 'PARENT') {
    if (isParentMode) {
      return (
        <>
          <NetworkStatus />
          <ParentDashboard onBack={handleBack} />
        </>
      );
    }
    
    if (currentChild) {
      return (
        <>
          <NetworkStatus />
          <ChildDashboard child={currentChild} onBack={handleBack} />
        </>
      );
    }
    
    return (
      <>
        <NetworkStatus />
        <ChildSelectionScreen onSelectChild={handleSelectChild} />
      </>
    );
  }
  
  return <div>Child role not fully implemented</div>;
};

// Export
export default FamilyQuestApp;
