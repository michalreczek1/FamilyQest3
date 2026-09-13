import React, { useEffect, useMemo, useRef, useState } from 'react';
import { normalizeVoiceText, parseParentVoiceCommand } from '../../lib/parentVoiceCommands.js';
import { isTaskScheduledForDate } from '../../lib/tasks.js';
import ModalOverlay from '../common/ModalOverlay.jsx';

const SpeechRecognitionCtor = () => window.SpeechRecognition || window.webkitSpeechRecognition || null;

const formatDate = (date) => date ? new Date(`${date}T12:00:00`).toLocaleDateString('pl-PL') : 'wszystkie daty';

const ParentVoiceCommand = ({ children, tasks, completions, extraTasks, getDateString, approveAllPending, rejectAllPending, approveExtraTask, rejectExtraTask, completeTaskAsParent, savePointAdjustment, mainScreen = false }) => {
  const recognitionRef = useRef(null);
  const [transcript, setTranscript] = useState('');
  const [listening, setListening] = useState(false);
  const [feedback, setFeedback] = useState('');
  const [plan, setPlan] = useState(null);
  const [executing, setExecuting] = useState(false);
  const supported = useMemo(() => Boolean(SpeechRecognitionCtor()), []);

  useEffect(() => () => {
    recognitionRef.current?.stop?.();
  }, []);

  const prepare = (value = transcript) => {
    const parsed = parseParentVoiceCommand({ transcript: value, children, today: getDateString() });
    if (parsed.error) {
      setPlan(null);
      setFeedback(parsed.error);
      return;
    }
    if (parsed.type === 'APPROVE_PENDING' || parsed.type === 'REJECT_PENDING') {
      const pending = completions.filter((completion) =>
        completion.childId === parsed.child.id &&
        completion.doneByChild &&
        !completion.approvedByParent &&
        (!parsed.date || completion.date === parsed.date),
      );
      if (pending.length === 0) {
        setPlan(null);
        setFeedback(`Nie ma zadań ${parsed.date ? `z datą ${formatDate(parsed.date)}` : ''} oczekujących na zatwierdzenie dla ${parsed.child.name}.`);
        return;
      }
      setPlan({ ...parsed, completions: pending });
      setFeedback('');
      return;
    }
    if (parsed.type === 'APPROVE_EXTRA_TASKS' || parsed.type === 'REJECT_EXTRA_TASKS') {
      const pendingExtraTasks = extraTasks.filter((task) => task.childId === parsed.child.id && task.status === 'PENDING' && (!parsed.date || task.date === parsed.date));
      if (pendingExtraTasks.length === 0) {
        setPlan(null);
        setFeedback(`Nie ma zadań dodatkowych oczekujących na decyzję dla ${parsed.child.name}.`);
        return;
      }
      setPlan({ ...parsed, extraTasks: pendingExtraTasks });
      setFeedback('');
      return;
    }
    if (parsed.type === 'COMPLETE_TASK') {
      const queryTokens = normalizeVoiceText(parsed.taskQuery).split(' ').filter(Boolean);
      const matches = tasks.filter((task) => task.childId === parsed.child.id && task.active !== false && isTaskScheduledForDate(task, parsed.date) && (queryTokens.length === 0 || queryTokens.every((token) => normalizeVoiceText(task.title).includes(token))));
      if (matches.length !== 1) {
        setPlan(null);
        setFeedback(matches.length === 0 ? `Nie znalazłem pasującego zadania dla ${parsed.child.name} w dniu ${formatDate(parsed.date)}.` : 'Znalazłem kilka pasujących zadań. Wypowiedz ich nazwę dokładniej.');
        return;
      }
      setPlan({ ...parsed, task: matches[0] });
      setFeedback('');
      return;
    }
    setPlan(parsed);
    setFeedback('');
  };

  const toggleListening = () => {
    const Recognition = SpeechRecognitionCtor();
    if (!Recognition) {
      setFeedback('Dyktowanie nie jest dostępne w tej przeglądarce. Nadal możesz wpisać polecenie.');
      return;
    }
    if (recognitionRef.current) {
      recognitionRef.current.stop();
      return;
    }
    const recognition = new Recognition();
    recognitionRef.current = recognition;
    recognition.lang = 'pl-PL';
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.maxAlternatives = 1;
    let finalTranscript = '';
    recognition.onstart = () => {
      setListening(true);
      setFeedback('Słucham polecenia…');
    };
    recognition.onresult = (event) => {
      let interimTranscript = '';
      for (let index = event.resultIndex || 0; index < event.results.length; index += 1) {
        const next = String(event.results[index][0]?.transcript || '').trim();
        if (event.results[index].isFinal) finalTranscript = `${finalTranscript} ${next}`.trim();
        else interimTranscript = `${interimTranscript} ${next}`.trim();
      }
      setTranscript((finalTranscript || interimTranscript).trim());
    };
    recognition.onerror = (event) => {
      setFeedback(event?.error === 'not-allowed' ? 'Brak zgody na mikrofon.' : 'Nie udało się rozpoznać głosu. Spróbuj ponownie lub wpisz polecenie.');
    };
    recognition.onend = () => {
      recognitionRef.current = null;
      setListening(false);
      if (finalTranscript) prepare(finalTranscript);
    };
    try {
      recognition.start();
    } catch {
      recognitionRef.current = null;
      setListening(false);
      setFeedback('Nie udało się uruchomić mikrofonu.');
    }
  };

  const execute = async () => {
    if (!plan) return;
    setExecuting(true);
    try {
      if (plan.type === 'APPROVE_PENDING') {
        const result = await approveAllPending(plan.completions);
        if (result?.success !== true) throw new Error('Nie udało się zatwierdzić zadań. Sprawdź komunikat aplikacji i spróbuj ponownie.');
        const approvedCount = Number(result.approvedCount);
        setFeedback(`Zatwierdzono ${approvedCount} zadań dla ${plan.child.name}.`);
      } else if (plan.type === 'REJECT_PENDING') {
        const result = await rejectAllPending(plan.completions);
        if (result?.success !== true) throw new Error('Nie udało się odrzucić zadań. Sprawdź komunikat aplikacji i spróbuj ponownie.');
        setFeedback(`Odrzucono ${result.rejectedCount} zadań dla ${plan.child.name}.`);
      } else if (plan.type === 'APPROVE_EXTRA_TASKS') {
        for (const extraTask of plan.extraTasks) {
          const result = await approveExtraTask(extraTask, plan.points);
          if (result?.success !== true) throw new Error('Nie udało się zatwierdzić wszystkich zadań dodatkowych. Sprawdź listę zadań przed ponowieniem.');
        }
        setFeedback(`Zatwierdzono ${plan.extraTasks.length} zadań dodatkowych dla ${plan.child.name}.`);
      } else if (plan.type === 'REJECT_EXTRA_TASKS') {
        for (const extraTask of plan.extraTasks) {
          const result = await rejectExtraTask(extraTask);
          if (result?.success !== true) throw new Error('Nie udało się odrzucić wszystkich zadań dodatkowych. Sprawdź listę zadań przed ponowieniem.');
        }
        setFeedback(`Odrzucono ${plan.extraTasks.length} zadań dodatkowych dla ${plan.child.name}.`);
      } else if (plan.type === 'COMPLETE_TASK') {
        const result = await completeTaskAsParent(plan.task, plan.child.id, plan.date);
        if (result?.success !== true) throw new Error('Nie udało się zaliczyć zadania. Sprawdź komunikat aplikacji i spróbuj ponownie.');
        setFeedback(`Zaliczono „${plan.task.title}” dla ${plan.child.name}.`);
      } else {
        const result = await savePointAdjustment({
          child: plan.child,
          type: plan.adjustmentType,
          points: plan.points,
          note: plan.note,
          sourceDate: plan.date,
        });
        if (result?.success !== true) throw new Error('Nie udało się potwierdzić zapisu punktów. Sprawdź historię przed ponowieniem.');
        setFeedback(`${plan.adjustmentType === 'PENALTY' ? 'Odjęto' : 'Dodano'} ${plan.points} pkt dla ${plan.child.name}.`);
      }
      setPlan(null);
      setTranscript('');
    } catch (error) {
      setPlan(null);
      setFeedback(error?.message || 'Nie udało się wykonać polecenia. Spróbuj ponownie.');
    } finally {
      setExecuting(false);
    }
  };

  const planText = plan?.type === 'APPROVE_PENDING'
    ? `Zatwierdzić ${plan.completions.length} zadań dla ${plan.child.name}${plan.date ? ` z ${formatDate(plan.date)}` : ''}?`
    : plan?.type === 'REJECT_PENDING'
      ? `Odrzucić ${plan.completions.length} zadań dla ${plan.child.name}?`
      : plan?.type === 'APPROVE_EXTRA_TASKS'
        ? `Zatwierdzić ${plan.extraTasks.length} zadań dodatkowych dla ${plan.child.name}, po ${plan.points} pkt?`
        : plan?.type === 'REJECT_EXTRA_TASKS'
          ? `Odrzucić ${plan.extraTasks.length} zadań dodatkowych dla ${plan.child.name}?`
          : plan?.type === 'COMPLETE_TASK'
            ? `Zaliczyć „${plan.task.title}” dla ${plan.child.name} z ${formatDate(plan.date)}?`
            : plan ? `${plan.adjustmentType === 'PENALTY' ? 'Odjąć' : 'Dodać'} ${plan.points} pkt dla ${plan.child.name}: „${plan.note}”?` : '';

  return React.createElement(React.Fragment, null,
    React.createElement('section', { className: `voice-command-card${mainScreen ? ' voice-command-card-main' : ''}`, 'aria-label': 'Polecenia głosowe' },
      React.createElement('div', { className: 'voice-command-heading' },
        React.createElement('div', null,
          React.createElement('h2', null, '🎙️ Polecenie dla rodzica'),
          React.createElement('p', null, 'Powiedz lub wpisz, co zrobić. Przed zmianą zawsze pokażemy potwierdzenie.'),
        ),
        React.createElement('button', {
          type: 'button',
          className: `voice-mic-button ${listening ? 'listening' : ''} ${supported ? '' : 'unsupported'}`,
          onClick: toggleListening,
          'aria-label': listening ? 'Zatrzymaj nasłuchiwanie' : 'Wydaj polecenie głosowe',
          'aria-pressed': listening ? 'true' : 'false',
          title: listening ? 'Zatrzymaj nasłuchiwanie' : 'Wydaj polecenie głosowe',
        }, '🎙️'),
      ),
      React.createElement('form', { className: 'voice-command-form', onSubmit: (event) => { event.preventDefault(); prepare(); } },
        React.createElement('input', {
          className: 'input',
          value: transcript,
          onChange: (event) => setTranscript(event.target.value),
          placeholder: 'Np. dodaj dwa punkty Filipowi za zmywarkę dzisiaj',
          'aria-label': 'Polecenie dla rodzica',
        }),
        React.createElement('button', { className: 'btn btn-primary', type: 'submit', disabled: !transcript.trim() }, 'Przygotuj'),
      ),
      React.createElement('div', { className: 'voice-command-examples' }, 'Dla każdego dodanego dziecka: premie/kary, zatwierdzanie i odrzucanie zadań, zadania dodatkowe oraz zaliczanie. Daty: dziś, wczoraj, 12.09.2026 lub 12 września.'),
      feedback && React.createElement('div', { className: 'voice-command-feedback', role: 'status' }, feedback),
    ),
    plan && React.createElement(ModalOverlay, {
      className: 'modal',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': 'voice-command-confirm-title',
    }, React.createElement('div', { className: 'modal-content voice-command-confirm' },
      React.createElement('h2', { id: 'voice-command-confirm-title' }, 'Potwierdź polecenie'),
      React.createElement('p', null, planText),
      React.createElement('p', { className: 'voice-command-transcript' }, `Rozpoznano: „${plan.transcript}”`),
      React.createElement('div', { className: 'voice-command-confirm-actions' },
        React.createElement('button', { type: 'button', className: 'btn btn-secondary', onClick: () => setPlan(null), disabled: executing }, 'Anuluj'),
        React.createElement('button', { type: 'button', className: 'btn btn-success', onClick: execute, disabled: executing }, executing ? 'Wykonuję…' : 'Potwierdź i wykonaj'),
      ),
    )),
  );
};

export default ParentVoiceCommand;
