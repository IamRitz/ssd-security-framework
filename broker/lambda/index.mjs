// Lambda handlers. Both functions ship the same bundle and differ by handler:
//   break-glass-ci            -> server/break-glass/lambda/index.ciHandler
//   break-glass-interactions  -> server/break-glass/lambda/index.interactionsHandler
import { createCiHandler, createInteractionsHandler } from './handlers.mjs';
import { enqueueSelf, getBroker } from './runtime.mjs';

export const ciHandler = createCiHandler({ getBroker: () => getBroker() });
export const interactionsHandler = createInteractionsHandler({
  getBroker: () => getBroker(),
  enqueue: (job) => enqueueSelf(job)
});
