// Suppress benign React 18 async mount act(...) warnings in tests
const _origConsoleError = console.error;
console.error = (...args: unknown[]) => {
  const msg = typeof args[0] === 'string' ? args[0] : '';
  if (msg.includes('not wrapped in act(')) {
    return;
  }
  _origConsoleError.apply(console, args);
};
