-- FamilyQuest PostgreSQL Database Schema
-- Migration: Initial schema v1.0

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- USERS & AUTHENTICATION
-- =============================================================================

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL, -- bcrypt hashed
  role VARCHAR(20) NOT NULL CHECK (role IN ('PARENT', 'CHILD')),
  family_id UUID NOT NULL,
  active BOOLEAN DEFAULT FALSE,
  pin_code VARCHAR(10),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_family ON users(family_id);
CREATE INDEX idx_users_email ON users(email);

-- =============================================================================
-- FAMILIES
-- =============================================================================

CREATE TABLE families (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- CHILDREN PROFILES
-- =============================================================================

CREATE TABLE children (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  avatar VARCHAR(10) NOT NULL, -- emoji or icon
  active_days INTEGER[] NOT NULL DEFAULT '{1,2,3,4,5}', -- [1=Mon, 2=Tue, ..., 7=Sun]
  archived BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_children_family ON children(family_id);
CREATE INDEX idx_children_archived ON children(archived);

-- =============================================================================
-- TASKS
-- =============================================================================

CREATE TABLE tasks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  tier VARCHAR(20) NOT NULL CHECK (tier IN ('MIN', 'PLUS', 'WEEKLY')),
  points INTEGER DEFAULT 0,
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tasks_child ON tasks(child_id);
CREATE INDEX idx_tasks_tier ON tasks(tier);
CREATE INDEX idx_tasks_active ON tasks(active);

-- =============================================================================
-- TASK COMPLETIONS
-- =============================================================================

CREATE TABLE task_completions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  done_by_child BOOLEAN DEFAULT FALSE,
  approved_by_parent BOOLEAN DEFAULT FALSE,
  approved_at TIMESTAMP,
  approved_by UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_completions_task ON task_completions(task_id);
CREATE INDEX idx_completions_child_date ON task_completions(child_id, date);
CREATE INDEX idx_completions_approval ON task_completions(approved_by_parent);
CREATE UNIQUE INDEX idx_completions_unique ON task_completions(task_id, child_id, date);

-- =============================================================================
-- DAY EVALUATIONS
-- =============================================================================

CREATE TABLE day_evaluations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  status VARCHAR(20) NOT NULL CHECK (status IN ('PASSED', 'FAILED', 'NOT_ACTIVE')),
  points_awarded INTEGER DEFAULT 0,
  evaluated_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_evaluations_child_date ON day_evaluations(child_id, date);
CREATE UNIQUE INDEX idx_evaluations_unique ON day_evaluations(child_id, date);

-- =============================================================================
-- STREAKS
-- =============================================================================

CREATE TABLE streaks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  child_id UUID UNIQUE NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  current INTEGER DEFAULT 0,
  best INTEGER DEFAULT 0,
  last_evaluated_date DATE,
  ideal_weeks_count INTEGER DEFAULT 0,
  ideal_weeks_in_row INTEGER DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_streaks_child ON streaks(child_id);

-- =============================================================================
-- POINTS
-- =============================================================================

CREATE TABLE points (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  child_id UUID UNIQUE NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  total INTEGER DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_points_child ON points(child_id);

-- =============================================================================
-- REWARDS
-- =============================================================================

CREATE TABLE rewards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  required_points INTEGER,
  required_streak INTEGER,
  required_ideal_weeks INTEGER,
  unlock_mode VARCHAR(10) NOT NULL DEFAULT 'AND' CHECK (unlock_mode IN ('AND', 'OR')),
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rewards_family ON rewards(family_id);
CREATE INDEX idx_rewards_active ON rewards(active);

-- =============================================================================
-- REWARD UNLOCKS
-- =============================================================================

CREATE TABLE reward_unlocks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  reward_id UUID NOT NULL REFERENCES rewards(id) ON DELETE CASCADE,
  child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  claimed_at TIMESTAMP,
  shown BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_unlocks_reward ON reward_unlocks(reward_id);
CREATE INDEX idx_unlocks_child ON reward_unlocks(child_id);
CREATE INDEX idx_unlocks_claimed ON reward_unlocks(claimed_at);
CREATE UNIQUE INDEX idx_unlocks_unique ON reward_unlocks(reward_id, child_id);

-- =============================================================================
-- FAMILY GOALS
-- =============================================================================

CREATE TABLE family_goals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  family_id UUID UNIQUE NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  target_value INTEGER NOT NULL,
  mode VARCHAR(20) NOT NULL CHECK (mode IN ('POINTS', 'DAYS')),
  current_value INTEGER DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_goals_family ON family_goals(family_id);

-- =============================================================================
-- AUDIT LOGS
-- =============================================================================

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id),
  action VARCHAR(100) NOT NULL,
  entity_type VARCHAR(50) NOT NULL,
  entity_id UUID NOT NULL,
  details JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_audit_entity ON audit_logs(entity_type, entity_id);

-- =============================================================================
-- TRIGGERS FOR UPDATED_AT
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_families_updated_at BEFORE UPDATE ON families
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_children_updated_at BEFORE UPDATE ON children
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON tasks
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_streaks_updated_at BEFORE UPDATE ON streaks
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_points_updated_at BEFORE UPDATE ON points
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_rewards_updated_at BEFORE UPDATE ON rewards
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_family_goals_updated_at BEFORE UPDATE ON family_goals
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- SEED DATA (Demo family)
-- =============================================================================

-- Insert demo family
INSERT INTO families (id, name) VALUES 
  ('11111111-1111-1111-1111-111111111111', 'Rodzina Kowalskich');

-- Insert demo parent (password: haslo123, pin: 1234)
INSERT INTO users (id, email, password, role, family_id, active, pin_code) VALUES 
  ('22222222-2222-2222-2222-222222222222', 'rodzic@familyquest.pl', 
   '$2b$10$YourBcryptHashHere', 'PARENT', 
   '11111111-1111-1111-1111-111111111111', TRUE, '1234');

-- Insert demo children
INSERT INTO children (id, family_id, name, avatar, active_days) VALUES 
  ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111', 
   'Asia', '👧', '{1,2,3,4,5}'),
  ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111', 
   'Tomek', '👦', '{1,2,3,4,5}');

-- Insert demo tasks for Asia
INSERT INTO tasks (child_id, title, description, tier, points) VALUES 
  ('33333333-3333-3333-3333-333333333333', 'Pościel łóżko', 'Zaraz po wstaniu', 'MIN', 0),
  ('33333333-3333-3333-3333-333333333333', 'Umyj zęby', NULL, 'MIN', 0),
  ('33333333-3333-3333-3333-333333333333', 'Odłóż naczynia', NULL, 'PLUS', 5),
  ('33333333-3333-3333-3333-333333333333', 'Sprzątanie pokoju', NULL, 'WEEKLY', 10);

-- Insert demo tasks for Tomek
INSERT INTO tasks (child_id, title, description, tier, points) VALUES 
  ('44444444-4444-4444-4444-444444444444', 'Pościel łóżko', 'Zaraz po wstaniu', 'MIN', 0),
  ('44444444-4444-4444-4444-444444444444', 'Umyj zęby', NULL, 'MIN', 0),
  ('44444444-4444-4444-4444-444444444444', 'Wynieś śmieci', NULL, 'PLUS', 5);

-- Initialize streaks
INSERT INTO streaks (child_id, current, best) VALUES 
  ('33333333-3333-3333-3333-333333333333', 0, 0),
  ('44444444-4444-4444-4444-444444444444', 0, 0);

-- Initialize points
INSERT INTO points (child_id, total) VALUES 
  ('33333333-3333-3333-3333-333333333333', 0),
  ('44444444-4444-4444-4444-444444444444', 0);

-- Insert demo rewards
INSERT INTO rewards (family_id, title, description, required_points, required_streak, unlock_mode) VALUES 
  ('11111111-1111-1111-1111-111111111111', '30 minut gier', 
   'Dodatkowy czas na granie', 50, NULL, 'AND'),
  ('11111111-1111-1111-1111-111111111111', 'Kino z rodzicami', 
   'Wybierz film!', 100, 7, 'AND'),
  ('11111111-1111-1111-1111-111111111111', 'Pizza party', 
   'Zamówimy Twoją ulubioną pizzę', NULL, NULL, 'AND');

-- Set required_ideal_weeks for pizza reward
UPDATE rewards 
SET required_ideal_weeks = 2 
WHERE title = 'Pizza party';

-- Insert family goal
INSERT INTO family_goals (family_id, title, target_value, mode) VALUES 
  ('11111111-1111-1111-1111-111111111111', 'Wycieczka nad morze', 500, 'POINTS');

-- =============================================================================
-- FUNCTIONS & PROCEDURES
-- =============================================================================

-- Function to evaluate day status
CREATE OR REPLACE FUNCTION evaluate_day_status(p_child_id UUID, p_date DATE)
RETURNS VARCHAR AS $$
DECLARE
  v_active_days INTEGER[];
  v_day_of_week INTEGER;
  v_min_tasks_count INTEGER;
  v_approved_tasks_count INTEGER;
BEGIN
  -- Get child's active days
  SELECT active_days INTO v_active_days 
  FROM children WHERE id = p_child_id;
  
  -- Get day of week (1=Monday, 7=Sunday)
  v_day_of_week := EXTRACT(ISODOW FROM p_date);
  
  -- Check if day is active
  IF NOT (v_day_of_week = ANY(v_active_days)) THEN
    RETURN 'NOT_ACTIVE';
  END IF;
  
  -- Count MIN tasks
  SELECT COUNT(*) INTO v_min_tasks_count
  FROM tasks
  WHERE child_id = p_child_id AND tier = 'MIN' AND active = TRUE;
  
  -- Count approved MIN tasks
  SELECT COUNT(*) INTO v_approved_tasks_count
  FROM task_completions tc
  JOIN tasks t ON tc.task_id = t.id
  WHERE tc.child_id = p_child_id 
    AND tc.date = p_date
    AND tc.approved_by_parent = TRUE
    AND t.tier = 'MIN'
    AND t.active = TRUE;
  
  -- Evaluate
  IF v_approved_tasks_count >= v_min_tasks_count THEN
    RETURN 'PASSED';
  ELSE
    RETURN 'FAILED';
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to update streak
CREATE OR REPLACE FUNCTION update_streak(p_child_id UUID, p_date DATE, p_status VARCHAR)
RETURNS VOID AS $$
DECLARE
  v_current_streak INTEGER;
  v_best_streak INTEGER;
BEGIN
  -- Get current streak
  SELECT current, best INTO v_current_streak, v_best_streak
  FROM streaks WHERE child_id = p_child_id;
  
  IF p_status = 'PASSED' THEN
    v_current_streak := v_current_streak + 1;
    IF v_current_streak > v_best_streak THEN
      v_best_streak := v_current_streak;
    END IF;
  ELSIF p_status = 'FAILED' THEN
    v_current_streak := 0;
  END IF;
  
  -- Update streak
  UPDATE streaks 
  SET current = v_current_streak,
      best = v_best_streak,
      last_evaluated_date = p_date
  WHERE child_id = p_child_id;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- VIEWS FOR COMMON QUERIES
-- =============================================================================

-- View: Pending approvals
CREATE VIEW pending_approvals AS
SELECT 
  tc.*,
  t.title as task_title,
  t.tier as task_tier,
  t.points as task_points,
  c.name as child_name,
  c.avatar as child_avatar
FROM task_completions tc
JOIN tasks t ON tc.task_id = t.id
JOIN children c ON tc.child_id = c.id
WHERE tc.done_by_child = TRUE 
  AND tc.approved_by_parent = FALSE
ORDER BY tc.created_at DESC;

-- View: Child statistics
CREATE VIEW child_statistics AS
SELECT 
  c.id as child_id,
  c.name,
  c.avatar,
  COALESCE(s.current, 0) as current_streak,
  COALESCE(s.best, 0) as best_streak,
  COALESCE(s.ideal_weeks_count, 0) as ideal_weeks_count,
  COALESCE(s.ideal_weeks_in_row, 0) as ideal_weeks_in_row,
  COALESCE(p.total, 0) as total_points
FROM children c
LEFT JOIN streaks s ON c.id = s.child_id
LEFT JOIN points p ON c.id = p.child_id
WHERE c.archived = FALSE;

-- View: Weekly leaderboard
CREATE VIEW weekly_leaderboard AS
SELECT 
  cs.*,
  COUNT(CASE WHEN de.status = 'PASSED' THEN 1 END) as passed_days_this_week
FROM child_statistics cs
LEFT JOIN day_evaluations de ON cs.child_id = de.child_id 
  AND de.date >= DATE_TRUNC('week', CURRENT_DATE)
GROUP BY cs.child_id, cs.name, cs.avatar, cs.current_streak, 
         cs.best_streak, cs.ideal_weeks_count, cs.ideal_weeks_in_row, cs.total_points
ORDER BY cs.ideal_weeks_in_row DESC, cs.current_streak DESC, cs.total_points DESC;

-- =============================================================================
-- PERMISSIONS (Adjust for your setup)
-- =============================================================================

-- Create roles
CREATE ROLE familyquest_app WITH LOGIN PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE familyquest TO familyquest_app;
GRANT USAGE ON SCHEMA public TO familyquest_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO familyquest_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO familyquest_app;

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================

-- Additional performance indexes
CREATE INDEX idx_completions_date ON task_completions(date);
CREATE INDEX idx_evaluations_date ON day_evaluations(date);
CREATE INDEX idx_audit_created_desc ON audit_logs(created_at DESC);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE users IS 'User accounts - parents and children';
COMMENT ON TABLE families IS 'Family units';
COMMENT ON TABLE children IS 'Child profiles within families';
COMMENT ON TABLE tasks IS 'Tasks assigned to children (MIN/PLUS/WEEKLY)';
COMMENT ON TABLE task_completions IS 'Task completion records with approval status';
COMMENT ON TABLE day_evaluations IS 'Daily evaluation results (PASSED/FAILED/NOT_ACTIVE)';
COMMENT ON TABLE streaks IS 'Streak counters and ideal weeks tracking';
COMMENT ON TABLE points IS 'Point totals per child';
COMMENT ON TABLE rewards IS 'Reward definitions with unlock conditions';
COMMENT ON TABLE reward_unlocks IS 'Unlocked rewards per child';
COMMENT ON TABLE family_goals IS 'Shared family goals';
COMMENT ON TABLE audit_logs IS 'Audit trail for all important actions';

-- =============================================================================
-- COMPLETE
-- =============================================================================

COMMIT;
