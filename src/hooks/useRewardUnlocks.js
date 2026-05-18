import { useCallback, useEffect } from 'react';

export const useRewardUnlocks = ({
  activeChildren,
  rewards,
  points,
  streaks,
  rewardUnlocks,
  setRewardUnlocks,
  setRewardUnlockHistory,
  setShowRewardOverlay,
  addAuditLog,
}) => {
  const checkRewards = useCallback(childId => {
    const childPoints = points[childId] || 0;
    const childStreak = streaks[childId] || {
      current: 0,
      idealWeeksInRow: 0,
    };
    const now = new Date().toISOString();
    rewards.forEach(reward => {
      if (reward.active === false) return;
      const pointsOk = !reward.requiredPoints || childPoints >= reward.requiredPoints;
      const streakOk = !reward.requiredStreak || childStreak.current >= reward.requiredStreak;
      const idealOk = !reward.requiredIdealWeeks || childStreak.idealWeeksInRow >= reward.requiredIdealWeeks;
      const activeUnlock = rewardUnlocks.find(r => r.childId === childId && r.rewardId === reward.id && !r.revokedAt);
      const revokedUnlock = rewardUnlocks.find(r => r.childId === childId && r.rewardId === reward.id && r.revokedAt && !r.claimedAt);
      if (!pointsOk) {
        if (activeUnlock && !activeUnlock.claimedAt && Number(reward.requiredPoints || 0) > 0) {
          setRewardUnlocks(prev => prev.map(unlock => unlock.id === activeUnlock.id ? {
            ...unlock,
            revokedAt: now,
            revokedReason: 'POINTS_BELOW_THRESHOLD',
            updatedAt: now,
          } : unlock));
        }
        return;
      }
      if (activeUnlock) return;
      if (pointsOk && streakOk && idealOk) {
        if (revokedUnlock) {
          setRewardUnlocks(prev => prev.map(unlock => unlock.id === revokedUnlock.id ? {
            ...unlock,
            revokedAt: null,
            revokedReason: null,
            restoredAt: now,
            updatedAt: now,
          } : unlock));
          return;
        }
        const unlock = {
          id: `unlock-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          childId,
          rewardId: reward.id,
          unlockedAt: now,
          claimedAt: null,
          shownAt: null,
          revokedAt: null,
          revokedReason: null,
          restoredAt: null,
          updatedAt: now,
        };
        setRewardUnlocks(prev => [unlock, ...prev]);
        setShowRewardOverlay({
          childId,
          reward,
        });
        addAuditLog('UNLOCK_REWARD', 'REWARD', reward.id, {
          childId,
        });
      }
    });
  }, [points, streaks, rewards, rewardUnlocks, setRewardUnlocks, setShowRewardOverlay, addAuditLog]);

  useEffect(() => {
    activeChildren.forEach(child => checkRewards(child.id));
  }, [activeChildren, checkRewards]);

  const claimReward = useCallback(unlockId => {
    const now = new Date().toISOString();
    setRewardUnlocks(prev => prev.map(u => u.id === unlockId ? {
      ...u,
      claimedAt: now,
      updatedAt: now,
    } : u));
    setRewardUnlockHistory(prev => prev.map(entry => entry.id === unlockId ? {
      ...entry,
      status: 'CLAIMED',
      claimedAt: now,
      latestAt: now,
      events: [...(entry.events || []), {
        type: 'CLAIMED',
        at: now,
        source: 'local',
      }],
    } : entry));
    addAuditLog('CLAIM_REWARD', 'REWARD_UNLOCK', unlockId);
  }, [setRewardUnlocks, setRewardUnlockHistory, addAuditLog]);

  return {
    claimReward,
  };
};
