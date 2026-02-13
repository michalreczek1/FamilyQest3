/* eslint-disable no-console */

const baseUrl = process.env.SMOKE_BASE_URL || `http://127.0.0.1:${process.env.PORT || 3010}`;

const requestJson = async (path, { method = 'GET', body, token } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  let data = null;
  try {
    data = await response.json();
  } catch (error) {
    data = null;
  }

  return {
    ok: response.ok,
    status: response.status,
    data,
  };
};

const assertOk = (condition, message, payload = null) => {
  if (!condition) {
    const extra = payload ? ` | payload=${JSON.stringify(payload)}` : '';
    throw new Error(`${message}${extra}`);
  }
};

const run = async () => {
  const suffix = Date.now();
  const parentEmail = `smoke.parent.${suffix}@familyquest.local`;
  const parentPassword = 'SmokeHaslo123!';
  const today = new Date().toISOString().slice(0, 10);

  const health = await requestJson('/health');
  assertOk(health.status === 200, 'Health endpoint failed', health);

  const register = await requestJson('/api/auth/register', {
    method: 'POST',
    body: {
      email: parentEmail,
      password: parentPassword,
      pinCode: '1234',
      familyName: 'Smoke Family',
    },
  });
  assertOk(register.status === 201, 'Parent register failed', register);
  const parentToken = register.data?.token;
  assertOk(Boolean(parentToken), 'Missing parent token', register.data);

  const childCreate = await requestJson('/api/children', {
    method: 'POST',
    token: parentToken,
    body: {
      name: `Smoke-${suffix}`,
      avatar: '🐼',
      activeDays: [1, 2, 3, 4, 5, 6, 7],
    },
  });
  assertOk(childCreate.status === 201, 'Child create failed', childCreate);
  const childId = childCreate.data?.child?.id;
  assertOk(Boolean(childId), 'Invalid child response', childCreate.data);

  let childCode = null;
  for (let i = 0; i < 50; i += 1) {
    const candidate = String(((suffix + i) % 9000) + 1000);
    const setCode = await requestJson(`/api/children/${childId}`, {
      method: 'PUT',
      token: parentToken,
      body: { accessCode: candidate },
    });
    if (setCode.status === 200) {
      childCode = setCode.data?.child?.accessCode || candidate;
      break;
    }
    if (setCode.status !== 409) {
      throw new Error(`Unexpected status while setting child code: ${setCode.status}`);
    }
  }
  assertOk(Boolean(childCode) && /^\d{4}$/.test(childCode), 'Cannot set unique child code');

  const taskCreate = await requestJson('/api/tasks', {
    method: 'POST',
    token: parentToken,
    body: {
      childId,
      title: 'Pościel łóżko',
      tier: 'MIN',
      points: 2,
      description: 'Rano po wstaniu',
    },
  });
  assertOk(taskCreate.status === 201, 'Task create failed', taskCreate);
  const taskId = taskCreate.data?.task?.id;
  assertOk(Boolean(taskId), 'Missing task id', taskCreate.data);

  const childLogin = await requestJson('/api/auth/login-child', {
    method: 'POST',
    body: { accessCode: childCode },
  });
  assertOk(childLogin.status === 200, 'Child login failed', childLogin);
  const childToken = childLogin.data?.token;
  assertOk(Boolean(childToken), 'Missing child token', childLogin.data);

  const complete = await requestJson('/api/completions', {
    method: 'POST',
    token: childToken,
    body: {
      taskId,
      childId,
      date: today,
      doneByChild: true,
    },
  });
  assertOk([200, 201].includes(complete.status), 'Task completion failed', complete);

  const approve = await requestJson('/api/completions/approve-bulk', {
    method: 'POST',
    token: parentToken,
    body: { childId, date: today },
  });
  assertOk(approve.status === 200, 'Bulk approve failed', approve);
  assertOk((approve.data?.approvedCount || 0) >= 1, 'Bulk approve returned 0', approve.data);

  const forgot = await requestJson('/api/auth/forgot-password', {
    method: 'POST',
    body: { email: parentEmail },
  });
  assertOk(forgot.status === 200 && forgot.data?.debugResetToken, 'Forgot password failed', forgot);

  const reset = await requestJson('/api/auth/reset-password/token', {
    method: 'POST',
    body: {
      token: forgot.data.debugResetToken,
      newPassword: 'SmokeHaslo999!',
    },
  });
  assertOk(reset.status === 200, 'Reset password by token failed', reset);

  const loginAfterReset = await requestJson('/api/auth/login', {
    method: 'POST',
    body: {
      email: parentEmail,
      password: 'SmokeHaslo999!',
    },
  });
  assertOk(loginAfterReset.status === 200, 'Login after reset failed', loginAfterReset);

  console.log(
    JSON.stringify(
      {
        result: 'PASS',
        baseUrl,
        parentEmail,
        childId,
        childCode,
        taskId,
      },
      null,
      2,
    ),
  );
};

run().catch((error) => {
  console.error('SMOKE_RESULT: FAIL');
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
