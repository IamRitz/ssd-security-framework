// Lambda handlers. Both functions ship the same bundle and differ by handler:
//   break-glass-ci            -> server/break-glass/lambda/index.ciHandler
//   break-glass-interactions  -> server/break-glass/lambda/index.interactionsHandler
import { createCiHandler, createInteractionsHandler } from './handlers.mjs';
import { enqueueSelf, getBroker } from './runtime.mjs';

// The CI broker reads its secrets lazily (only when it posts); the interaction
// function reads them at start-up (runtime.mjs).
export const ciHandler = createCiHandler({ getBroker: () => getBroker(process.env, { role: 'ci' }) });
export const interactionsHandler = createInteractionsHandler({
  getBroker: () => getBroker(process.env, { role: 'interactions' }),
  enqueue: (job) => enqueueSelf(job)
});
