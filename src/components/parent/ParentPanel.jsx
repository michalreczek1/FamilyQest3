import React from 'react';
import ApprovalsTab from './tabs/ApprovalsTab.jsx';
import ChildrenTab from './tabs/ChildrenTab.jsx';
import TasksTab from './tabs/TasksTab.jsx';
import RewardsTab from './tabs/RewardsTab.jsx';
import StatsTab from './tabs/StatsTab.jsx';
import SettingsTab from './tabs/SettingsTab.jsx';
import RewardHistoryPanel from '../rewards/RewardHistoryPanel.jsx';
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
  childAccessCodes,
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
  pendingCompletionActionIds = [],
  pendingExtraTaskActionIds = [],
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
  rejectAllPending,
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
  changeMyPin,
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
    const pendingCompletionActionIdSet = new Set(pendingCompletionActionIds);
    const pendingExtraTaskActionIdSet = new Set(pendingExtraTaskActionIds);
    const pendingApprovals = completions.filter(c => c.doneByChild && !c.approvedByParent && !pendingCompletionActionIdSet.has(c.id));
    const pendingExtraTasks = extraTasks.filter(task => task.status === 'PENDING' && !pendingExtraTaskActionIdSet.has(task.id));
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
    }, "Ustawienia")), parentTab === 'approvals' && React.createElement(ApprovalsTab, { activeChildren: activeChildren, children: children, tasks: tasks, completions: completions, rewards: rewards, rewardUnlocks: rewardUnlocks, rewardUnlockHistory: rewardUnlockHistory, streaks: streaks, points: points, auditLogs: auditLogs, user: user, parentUsers: parentUsers, familyGoal: familyGoal, approvalFilterChildId: approvalFilterChildId, approvalFilterDate: approvalFilterDate, parentTaskChildId: parentTaskChildId, parentTaskDate: parentTaskDate, taskListMode: taskListMode, pendingApprovals: pendingApprovals, pendingExtraTasks: pendingExtraTasks, activeRewards: activeRewards, filteredPendingApprovals: filteredPendingApprovals, filteredPendingExtraTasks: filteredPendingExtraTasks, pendingApprovalCount: pendingApprovalCount, filteredPendingCount: filteredPendingCount, today: today, parentTaskDateValue: parentTaskDateValue, parentTaskChildren: parentTaskChildren, setApprovalFilterChildId: setApprovalFilterChildId, setApprovalFilterDate: setApprovalFilterDate, setParentTaskChildId: setParentTaskChildId, setParentTaskDate: setParentTaskDate, setShowModal: setShowModal, setEditingChild: setEditingChild, setTaskListMode: setTaskListMode, setEditingTask: setEditingTask, setEditingReward: setEditingReward, approveAllPending: approveAllPending, rejectAllPending: rejectAllPending, approveTask: approveTask, rejectTask: rejectTask, approveExtraTask: approveExtraTask, rejectExtraTask: rejectExtraTask, completeTaskAsParent: completeTaskAsParent, reverseApproval: reverseApproval, getDateString: getDateString, evaluateDay: evaluateDay, archiveChild: archiveChild, addPointAdjustment: addPointAdjustment, archiveTask: archiveTask, restoreTask: restoreTask, archiveReward: archiveReward, claimReward: claimReward, loadParentUsers: loadParentUsers, addParentUser: addParentUser, setParentUserActive: setParentUserActive, changeMyPassword: changeMyPassword, changeMyPin: changeMyPin, resetParentPassword: resetParentPassword, updateFamilyGoal: updateFamilyGoal, exportFamilyBackup: exportFamilyBackup, importFamilyBackup: importFamilyBackup }), parentTab === 'children' && React.createElement(ChildrenTab, { activeChildren: activeChildren, childAccessCodes: childAccessCodes, children: children, tasks: tasks, completions: completions, rewards: rewards, rewardUnlocks: rewardUnlocks, rewardUnlockHistory: rewardUnlockHistory, streaks: streaks, points: points, auditLogs: auditLogs, user: user, parentUsers: parentUsers, familyGoal: familyGoal, approvalFilterChildId: approvalFilterChildId, approvalFilterDate: approvalFilterDate, parentTaskChildId: parentTaskChildId, parentTaskDate: parentTaskDate, taskListMode: taskListMode, pendingApprovals: pendingApprovals, pendingExtraTasks: pendingExtraTasks, activeRewards: activeRewards, filteredPendingApprovals: filteredPendingApprovals, filteredPendingExtraTasks: filteredPendingExtraTasks, pendingApprovalCount: pendingApprovalCount, filteredPendingCount: filteredPendingCount, today: today, parentTaskDateValue: parentTaskDateValue, parentTaskChildren: parentTaskChildren, setApprovalFilterChildId: setApprovalFilterChildId, setApprovalFilterDate: setApprovalFilterDate, setParentTaskChildId: setParentTaskChildId, setParentTaskDate: setParentTaskDate, setShowModal: setShowModal, setEditingChild: setEditingChild, setTaskListMode: setTaskListMode, setEditingTask: setEditingTask, setEditingReward: setEditingReward, approveAllPending: approveAllPending, approveTask: approveTask, rejectTask: rejectTask, approveExtraTask: approveExtraTask, rejectExtraTask: rejectExtraTask, completeTaskAsParent: completeTaskAsParent, reverseApproval: reverseApproval, getDateString: getDateString, evaluateDay: evaluateDay, archiveChild: archiveChild, addPointAdjustment: addPointAdjustment, archiveTask: archiveTask, restoreTask: restoreTask, archiveReward: archiveReward, claimReward: claimReward, loadParentUsers: loadParentUsers, addParentUser: addParentUser, setParentUserActive: setParentUserActive, changeMyPassword: changeMyPassword, changeMyPin: changeMyPin, resetParentPassword: resetParentPassword, updateFamilyGoal: updateFamilyGoal, exportFamilyBackup: exportFamilyBackup, importFamilyBackup: importFamilyBackup }), parentTab === 'tasks' && React.createElement(TasksTab, { activeChildren: activeChildren, children: children, tasks: tasks, completions: completions, rewards: rewards, rewardUnlocks: rewardUnlocks, rewardUnlockHistory: rewardUnlockHistory, streaks: streaks, points: points, auditLogs: auditLogs, user: user, parentUsers: parentUsers, familyGoal: familyGoal, approvalFilterChildId: approvalFilterChildId, approvalFilterDate: approvalFilterDate, parentTaskChildId: parentTaskChildId, parentTaskDate: parentTaskDate, taskListMode: taskListMode, pendingApprovals: pendingApprovals, pendingExtraTasks: pendingExtraTasks, activeRewards: activeRewards, filteredPendingApprovals: filteredPendingApprovals, filteredPendingExtraTasks: filteredPendingExtraTasks, pendingApprovalCount: pendingApprovalCount, filteredPendingCount: filteredPendingCount, today: today, parentTaskDateValue: parentTaskDateValue, parentTaskChildren: parentTaskChildren, setApprovalFilterChildId: setApprovalFilterChildId, setApprovalFilterDate: setApprovalFilterDate, setParentTaskChildId: setParentTaskChildId, setParentTaskDate: setParentTaskDate, setShowModal: setShowModal, setEditingChild: setEditingChild, setTaskListMode: setTaskListMode, setEditingTask: setEditingTask, setEditingReward: setEditingReward, approveAllPending: approveAllPending, approveTask: approveTask, rejectTask: rejectTask, approveExtraTask: approveExtraTask, rejectExtraTask: rejectExtraTask, completeTaskAsParent: completeTaskAsParent, reverseApproval: reverseApproval, getDateString: getDateString, evaluateDay: evaluateDay, archiveChild: archiveChild, addPointAdjustment: addPointAdjustment, archiveTask: archiveTask, restoreTask: restoreTask, archiveReward: archiveReward, claimReward: claimReward, loadParentUsers: loadParentUsers, addParentUser: addParentUser, setParentUserActive: setParentUserActive, changeMyPassword: changeMyPassword, changeMyPin: changeMyPin, resetParentPassword: resetParentPassword, updateFamilyGoal: updateFamilyGoal, exportFamilyBackup: exportFamilyBackup, importFamilyBackup: importFamilyBackup }), parentTab === 'rewards' && React.createElement(RewardsTab, { activeChildren: activeChildren, children: children, tasks: tasks, completions: completions, rewards: rewards, rewardUnlocks: rewardUnlocks, rewardUnlockHistory: rewardUnlockHistory, streaks: streaks, points: points, auditLogs: auditLogs, user: user, parentUsers: parentUsers, familyGoal: familyGoal, approvalFilterChildId: approvalFilterChildId, approvalFilterDate: approvalFilterDate, parentTaskChildId: parentTaskChildId, parentTaskDate: parentTaskDate, taskListMode: taskListMode, pendingApprovals: pendingApprovals, pendingExtraTasks: pendingExtraTasks, activeRewards: activeRewards, filteredPendingApprovals: filteredPendingApprovals, filteredPendingExtraTasks: filteredPendingExtraTasks, pendingApprovalCount: pendingApprovalCount, filteredPendingCount: filteredPendingCount, today: today, parentTaskDateValue: parentTaskDateValue, parentTaskChildren: parentTaskChildren, setApprovalFilterChildId: setApprovalFilterChildId, setApprovalFilterDate: setApprovalFilterDate, setParentTaskChildId: setParentTaskChildId, setParentTaskDate: setParentTaskDate, setShowModal: setShowModal, setEditingChild: setEditingChild, setTaskListMode: setTaskListMode, setEditingTask: setEditingTask, setEditingReward: setEditingReward, approveAllPending: approveAllPending, approveTask: approveTask, rejectTask: rejectTask, approveExtraTask: approveExtraTask, rejectExtraTask: rejectExtraTask, completeTaskAsParent: completeTaskAsParent, reverseApproval: reverseApproval, getDateString: getDateString, evaluateDay: evaluateDay, archiveChild: archiveChild, addPointAdjustment: addPointAdjustment, archiveTask: archiveTask, restoreTask: restoreTask, archiveReward: archiveReward, claimReward: claimReward, loadParentUsers: loadParentUsers, addParentUser: addParentUser, setParentUserActive: setParentUserActive, changeMyPassword: changeMyPassword, changeMyPin: changeMyPin, resetParentPassword: resetParentPassword, updateFamilyGoal: updateFamilyGoal, exportFamilyBackup: exportFamilyBackup, importFamilyBackup: importFamilyBackup }), React.createElement(RewardHistoryPanel, {
      history: rewardUnlockHistory
    }), parentTab === 'stats' && React.createElement(StatsTab, { activeChildren: activeChildren, children: children, tasks: tasks, completions: completions, rewards: rewards, rewardUnlocks: rewardUnlocks, rewardUnlockHistory: rewardUnlockHistory, streaks: streaks, points: points, auditLogs: auditLogs, user: user, parentUsers: parentUsers, familyGoal: familyGoal, approvalFilterChildId: approvalFilterChildId, approvalFilterDate: approvalFilterDate, parentTaskChildId: parentTaskChildId, parentTaskDate: parentTaskDate, taskListMode: taskListMode, pendingApprovals: pendingApprovals, pendingExtraTasks: pendingExtraTasks, activeRewards: activeRewards, filteredPendingApprovals: filteredPendingApprovals, filteredPendingExtraTasks: filteredPendingExtraTasks, pendingApprovalCount: pendingApprovalCount, filteredPendingCount: filteredPendingCount, today: today, parentTaskDateValue: parentTaskDateValue, parentTaskChildren: parentTaskChildren, setApprovalFilterChildId: setApprovalFilterChildId, setApprovalFilterDate: setApprovalFilterDate, setParentTaskChildId: setParentTaskChildId, setParentTaskDate: setParentTaskDate, setShowModal: setShowModal, setEditingChild: setEditingChild, setTaskListMode: setTaskListMode, setEditingTask: setEditingTask, setEditingReward: setEditingReward, approveAllPending: approveAllPending, approveTask: approveTask, rejectTask: rejectTask, approveExtraTask: approveExtraTask, rejectExtraTask: rejectExtraTask, completeTaskAsParent: completeTaskAsParent, reverseApproval: reverseApproval, getDateString: getDateString, evaluateDay: evaluateDay, archiveChild: archiveChild, addPointAdjustment: addPointAdjustment, archiveTask: archiveTask, restoreTask: restoreTask, archiveReward: archiveReward, claimReward: claimReward, loadParentUsers: loadParentUsers, addParentUser: addParentUser, setParentUserActive: setParentUserActive, changeMyPassword: changeMyPassword, changeMyPin: changeMyPin, resetParentPassword: resetParentPassword, updateFamilyGoal: updateFamilyGoal, exportFamilyBackup: exportFamilyBackup, importFamilyBackup: importFamilyBackup }), parentTab === 'settings' && React.createElement(SettingsTab, { activeChildren: activeChildren, children: children, tasks: tasks, completions: completions, rewards: rewards, rewardUnlocks: rewardUnlocks, rewardUnlockHistory: rewardUnlockHistory, streaks: streaks, points: points, auditLogs: auditLogs, user: user, parentUsers: parentUsers, familyGoal: familyGoal, approvalFilterChildId: approvalFilterChildId, approvalFilterDate: approvalFilterDate, parentTaskChildId: parentTaskChildId, parentTaskDate: parentTaskDate, taskListMode: taskListMode, pendingApprovals: pendingApprovals, pendingExtraTasks: pendingExtraTasks, activeRewards: activeRewards, filteredPendingApprovals: filteredPendingApprovals, filteredPendingExtraTasks: filteredPendingExtraTasks, pendingApprovalCount: pendingApprovalCount, filteredPendingCount: filteredPendingCount, today: today, parentTaskDateValue: parentTaskDateValue, parentTaskChildren: parentTaskChildren, setApprovalFilterChildId: setApprovalFilterChildId, setApprovalFilterDate: setApprovalFilterDate, setParentTaskChildId: setParentTaskChildId, setParentTaskDate: setParentTaskDate, setShowModal: setShowModal, setEditingChild: setEditingChild, setTaskListMode: setTaskListMode, setEditingTask: setEditingTask, setEditingReward: setEditingReward, approveAllPending: approveAllPending, approveTask: approveTask, rejectTask: rejectTask, approveExtraTask: approveExtraTask, rejectExtraTask: rejectExtraTask, completeTaskAsParent: completeTaskAsParent, reverseApproval: reverseApproval, getDateString: getDateString, evaluateDay: evaluateDay, archiveChild: archiveChild, addPointAdjustment: addPointAdjustment, archiveTask: archiveTask, restoreTask: restoreTask, archiveReward: archiveReward, claimReward: claimReward, loadParentUsers: loadParentUsers, addParentUser: addParentUser, setParentUserActive: setParentUserActive, changeMyPassword: changeMyPassword, changeMyPin: changeMyPin, resetParentPassword: resetParentPassword, updateFamilyGoal: updateFamilyGoal, exportFamilyBackup: exportFamilyBackup, importFamilyBackup: importFamilyBackup }))), showModal === 'addChild' && React.createElement(AddChildModal, {
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
