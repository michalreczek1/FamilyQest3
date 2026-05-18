import React from 'react';
import { getTaskArchiveFingerprint } from '../../../lib/tasks.js';

const TasksTab = ({
  activeChildren,
  tasks,
  taskListMode,
  setShowModal,
  setTaskListMode,
  setEditingTask,
  archiveTask,
  restoreTask,
}) => {
  return React.createElement(React.Fragment, null, React.createElement("div", {
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
    }, "\uD83D\uDDC3\uFE0F"), React.createElement("p", null, "Archiwum zada\u0144 jest puste.")));
};

export default TasksTab;
