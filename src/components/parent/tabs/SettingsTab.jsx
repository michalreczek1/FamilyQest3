import React from 'react';
import SettingsSecurityPanel from '../../settings/SettingsSecurityPanel.jsx';
import SettingsBackupPanel from '../../settings/SettingsBackupPanel.jsx';

const SettingsTab = ({
  auditLogs,
  user,
  parentUsers,
  familyGoal,
  loadParentUsers,
  addParentUser,
  setParentUserActive,
  changeMyPassword,
  resetParentPassword,
  updateFamilyGoal,
  exportFamilyBackup,
  importFamilyBackup,
}) => {
  return React.createElement(React.Fragment, null, React.createElement("h2", {
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
    }, log.entityType, " \u2022 ", log.entityId)))));
};

export default SettingsTab;
