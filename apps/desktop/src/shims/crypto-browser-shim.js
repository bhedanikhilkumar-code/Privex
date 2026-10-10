module.exports = {
  createHash: () => ({
    update: () => ({
      digest: () => ''
    }),
    digest: () => ''
  }),
  randomUUID: () => (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : '00000000-0000-0000-0000-000000000000'),
  randomBytes: (n) => {
    const buf = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(buf);
    }
    return buf;
  }
};
