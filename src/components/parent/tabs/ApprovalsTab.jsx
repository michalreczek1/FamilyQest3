import React from 'react';
import { isTaskScheduledForDate } from '../../../lib/tasks.js';
import ExtraTaskApprovalCard from '../ExtraTaskApprovalCard.jsx';

const ApprovalsTab = ({
  activeChildren,
  children,
  tasks,
  completions,
  approvalFilterChildId,
  approvalFilterDate,
  parentTaskChildId,
  filteredPendingApprovals,
  filteredPendingExtraTasks,
  pendingApprovalCount,
  filteredPendingCount,
  today,
  parentTaskDateValue,
  parentTaskChildren,
  setApprovalFilterChildId,
  setApprovalFilterDate,
  setParentTaskChildId,
  setParentTaskDate,
  approveAllPending,
  rejectAllPending,
  approveTask,
  rejectTask,
  approveExtraTask,
  rejectExtraTask,
  completeTaskAsParent,
  reverseApproval,
  getDateString,
  evaluateDay,
}) => {
  return React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Zadania do zatwierdzenia"), filteredPendingApprovals.length > 0 && React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.6rem',
        flexWrap: 'wrap'
      }
    }, React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => approveAllPending(filteredPendingApprovals)
    }, "\u2705 Zatwierd\u017A wg filtra (", filteredPendingApprovals.length, ")"), React.createElement("button", {
      className: "btn btn-danger",
      onClick: () => rejectAllPending(filteredPendingApprovals)
    }, "\u274C Odrzu\u0107 wg filtra (", filteredPendingApprovals.length, ")"))), React.createElement("div", {
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
    })));
};

export default ApprovalsTab;
