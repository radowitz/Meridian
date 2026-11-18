// The setup wizard tells the shell it ended (the shell then shows the normal
// pages). A plain module so the lazy wizard chunk and the shell share it.
export const wizardEvents = { onFinish: (): void => {} };
