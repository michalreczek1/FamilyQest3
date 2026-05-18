import React from 'react';
import { getTaskArchiveFingerprint, isTaskScheduledForDate } from '../../lib/tasks.js';
import WeeklyLeaderboardPanel from '../leaderboard/WeeklyLeaderboardPanel.jsx';
import ExtraTaskApprovalCard from './ExtraTaskApprovalCard.jsx';
import RewardHistoryPanel from '../rewards/RewardHistoryPanel.jsx';
import SettingsSecurityPanel from '../settings/SettingsSecurityPanel.jsx';
import SettingsBackupPanel from '../settings/SettingsBackupPanel.jsx';
import AddChildModal from '../modals/AddChildModal.jsx';
import EditChildModal from '../modals/EditChildModal.jsx';
import AddTaskModal from '../modals/AddTaskModal.jsx';
import EditTaskModal from '../modals/EditTaskModal.jsx';
import AddRewardModal from '../modals/AddRewardModal.jsx';
import PointAdjustmentModal from '../modals/PointAdjustmentModal.jsx';

const ParentPanel = ({
  completions,
  extraTasks,
  rewards,
  approvalFilterChildId,
  approvalFilterDate,
  parentTaskDate,
  parentTaskChildId,
  activeChildren,
  children,
  tasks,
  streaks,
  points,
  rewardUnlocks,
  rewardUnlockHistory,
  familyGoal,
  auditLogs,
  parentTab,
  taskListMode,
  showModal,
  editingChild,
  editingTask,
  editingReward,
  pointAdjustmentModal,
  isOnline,
  syncing,
  user,
  parentUsers,
  setView,
  setParentTab,
  setApprovalFilterChildId,
  setApprovalFilterDate,
  setParentTaskChildId,
  setParentTaskDate,
  setTaskListMode,
  setShowModal,
  setEditingChild,
  setEditingTask,
  setEditingReward,
  setPointAdjustmentModal,
  handleLogout,
  approveAllPending,
  approveTask,
  rejectTask,
  approveExtraTask,
  rejectExtraTask,
  completeTaskAsParent,
  reverseApproval,
  evaluateDay,
  getDateString,
  archiveChild,
  addPointAdjustment,
  archiveTask,
  restoreTask,
  archiveReward,
  claimReward,
  loadParentUsers,
  addParentUser,
  setParentUserActive,
  changeMyPassword,
  resetParentPassword,
  updateFamilyGoal,
  exportFamilyBackup,
  importFamilyBackup,
  addChild,
  updateChild,
  addTask,
  updateTask,
  addReward,
  updateReward,
  savePointAdjustment,
}) => {
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
        className: "child-admin-actions"
      }, React.createElement("button", {
        className: "btn btn-secondary",
        onClick: () => setEditingChild(child)
      }, "\u270F\uFE0F Edytuj"), React.createElement("button", {
        className: "btn btn-danger",
        onClick: () => {
          if (confirm(`Archiwizować profil ${child.name}?`)) {
            archiveChild(child.id);
          }
        }
      }, "\uD83D\uDDC3\uFE0F Archiwizuj")), React.createElement("div", {
        className: "child-admin-actions"
      }, React.createElement("button", {
        className: "btn btn-success",
        onClick: () => addPointAdjustment(child, 'BONUS')
      }, "\uD83C\uDF81 Premia"), React.createElement("button", {
        className: "btn btn-danger",
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
        const matchingArchivedCount = tasks.filter(item => item.active === false && getTaskArchiveFingerprint(item) === getTaskArchiveFingerprint(task)).length;
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
      }, "\u267B\uFE0F Przywr\xF3\u0107"), task.active === false && matchingArchivedCount > 1 && React.createElement("button", {
        className: "btn btn-success",
        title: "Przywróć to samo zadanie u wszystkich dzieci",
        onClick: async () => {
          if (confirm(`Przywrócić zadanie "${task.title}" u wszystkich dzieci, które mają tę samą definicję? (${matchingArchivedCount} zadań)`)) {
            await restoreTask(task.id, {
              matching: true
            });
          }
        }
      }, "\u267B\uFE0F U wszystkich"));
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
    }, "Odblokowane nagrody"), rewardUnlocks.filter(unlock => !unlock.revokedAt).length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Brak odblokowanych nagr\xF3d") : rewardUnlocks.filter(unlock => !unlock.revokedAt).map(unlock => {
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
    }))), React.createElement(RewardHistoryPanel, {
      history: rewardUnlockHistory
    }), parentTab === 'stats' && React.createElement(React.Fragment, null, React.createElement("h2", {
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

};

export default ParentPanel;
