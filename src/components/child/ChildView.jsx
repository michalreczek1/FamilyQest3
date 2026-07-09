import React, { useCallback, useEffect, useState } from 'react';
import { apiRequest } from '../../lib/api.js';
import { isTaskActiveForDate, isTaskScheduledForDate } from '../../lib/tasks.js';
import ModalOverlay from '../common/ModalOverlay.jsx';
import WeeklyLeaderboardPanel from '../leaderboard/WeeklyLeaderboardPanel.jsx';
import RewardOverlay from '../rewards/RewardOverlay.jsx';

const POINT_LEDGER_PAGE_LIMIT = 20;

const getCalendarDayClassName = (status) => {
  if (status === 'PASSED') return 'passed';
  if (status === 'FAILED') return 'failed';
  return 'na';
};

const ChildView = ({
  selectedChild,
  user,
  tasks,
  completions,
  extraTasks,
  streaks,
  points,
  rewardUnlocks,
  rewards,
  familyLeaderboard,
  childTaskDate,
  isOnline,
  syncing,
  childApprovalNotice,
  showPointHistory,
  showChildRewards,
  extraTaskTitle,
  showRewardOverlay,
  getDateString,
  evaluateDay,
  setView,
  handleLogout,
  setChildTaskDate,
  setChildApprovalNotice,
  setShowPointHistory,
  setShowChildRewards,
  toggleTask,
  submitExtraTask,
  setExtraTaskTitle,
  resubmitExtraTask,
  setRewardUnlocks,
  setShowRewardOverlay,
}) => {
    const today = getDateString();
    const selectedTaskDate = childTaskDate || today;
    const selectedTaskDateLabel = selectedTaskDate === today ? 'dzisiaj' : selectedTaskDate;
    const childTasks = tasks.filter(t => t.childId === selectedChild.id && isTaskActiveForDate(t, selectedTaskDate));
    const selectedDateTasks = childTasks.filter(t => isTaskScheduledForDate(t, selectedTaskDate));
    const selectedDateCompletions = completions.filter(c => c.childId === selectedChild.id && c.date === selectedTaskDate);
    const childExtraTasks = extraTasks.filter(task => task.childId === selectedChild.id).sort((a, b) => Date.parse(b.updatedAt || b.submittedAt || b.createdAt || 0) - Date.parse(a.updatedAt || a.submittedAt || a.createdAt || 0)).slice(0, 8);
    const childStreak = streaks[selectedChild.id] || {
      current: 0,
      best: 0
    };
    const childPoints = points[selectedChild.id] || 0;
    const [pointHistoryEntries, setPointHistoryEntries] = useState([]);
    const [pointHistoryNextCursor, setPointHistoryNextCursor] = useState(null);
    const [pointHistoryLoading, setPointHistoryLoading] = useState(false);
    const [pointHistoryError, setPointHistoryError] = useState('');
    const childRewardUnlocks = rewardUnlocks.filter(unlock => unlock.childId === selectedChild.id && !unlock.revokedAt);
    const childUnlockedRewardIds = new Set(childRewardUnlocks.map(unlock => unlock.rewardId));
    const childEarnedRewards = childRewardUnlocks.map(unlock => ({
      unlock,
      reward: rewards.find(reward => reward.id === unlock.rewardId)
    })).filter(item => Boolean(item.reward)).sort((a, b) => Date.parse(b.unlock.unlockedAt || 0) - Date.parse(a.unlock.unlockedAt || 0));
    const nextPointReward = rewards.filter(reward => reward.active !== false && !childUnlockedRewardIds.has(reward.id) && Number(reward.requiredPoints || 0) > childPoints).sort((a, b) => Number(a.requiredPoints || 0) - Number(b.requiredPoints || 0))[0] || null;
    const pointsToNextReward = nextPointReward ? Math.max(0, Number(nextPointReward.requiredPoints || 0) - childPoints) : 0;
    const dayStatus = evaluateDay(selectedChild.id, selectedTaskDate);
    const loadPointHistoryPage = useCallback(async ({
      cursor = 0,
      reset = false
    } = {}) => {
      if (!selectedChild?.id) return;
      setPointHistoryLoading(true);
      setPointHistoryError('');
      try {
        const params = new URLSearchParams({
          childId: selectedChild.id,
          limit: String(POINT_LEDGER_PAGE_LIMIT),
          cursor: String(cursor)
        });
        const result = await apiRequest(`/api/point-ledger?${params.toString()}`);
        const entries = Array.isArray(result?.entries) ? result.entries : [];
        setPointHistoryEntries(prev => reset ? entries : [...prev, ...entries]);
        setPointHistoryNextCursor(result?.nextCursor ?? null);
      } catch (error) {
        setPointHistoryError(error.message || 'Nie udało się pobrać historii punktów');
      } finally {
        setPointHistoryLoading(false);
      }
    }, [selectedChild?.id]);
    useEffect(() => {
      if (!showPointHistory) return;
      setPointHistoryEntries([]);
      setPointHistoryNextCursor(null);
      loadPointHistoryPage({
        cursor: 0,
        reset: true
      });
    }, [loadPointHistoryPage, selectedChild?.id, showPointHistory]);
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
    }, "Punkty i zaliczenie wymagaj\u0105 akceptacji rodzica")), childApprovalNotice && React.createElement(ModalOverlay, {
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
    }, childApprovalNotice.encouragement ? "Super!" : "Rozumiem"))), showPointHistory && React.createElement(ModalOverlay, {
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
    }, pointHistoryError && React.createElement("div", {
      className: "error"
    }, pointHistoryError), pointHistoryLoading && pointHistoryEntries.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "\u0141adowanie historii punkt\xF3w...") : pointHistoryEntries.length === 0 && !pointHistoryError ? React.createElement("div", {
      className: "empty-state"
    }, "Nie ma jeszcze historii punkt\xF3w") : pointHistoryEntries.map(entry => {
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
    }), pointHistoryNextCursor !== null && React.createElement("div", {
      className: "point-history-footer"
    }, React.createElement("button", {
      type: "button",
      className: "btn btn-secondary",
      disabled: pointHistoryLoading,
      onClick: () => loadPointHistoryPage({
        cursor: pointHistoryNextCursor,
        reset: false
      })
    }, pointHistoryLoading ? "\u0141adowanie..." : "Poka\u017C starsze wpisy"))))), showChildRewards && React.createElement(ModalOverlay, {
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
      className: "extra-task-history-list",
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
    }, "Czeka"), task.status !== 'PENDING' && React.createElement("button", {
      type: "button",
      className: "btn btn-secondary extra-task-resubmit-btn",
      onClick: () => resubmitExtraTask(task),
      title: `Zg\u0142o\u015B ponownie: ${task.title}`
    }, "\u21BB Zg\u0142o\u015B ponownie"))))), React.createElement("div", {
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
    }, last14Days.map((day) => {
      const [, month, dayOfMonth] = day.date.split('-');
      const formattedDate = `${dayOfMonth}.${month}`;
      return React.createElement("div", {
        key: day.date,
        className: `calendar-day ${getCalendarDayClassName(day.status)}`,
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

};

export default ChildView;
