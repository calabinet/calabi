// How often the console re-reads GET /v1/update.
//
// Two different questions hide behind one number, and they want opposite
// answers:
//
//   nothing is happening   the daemon checks on its own every six hours, and
//                          this query only re-reads what it already knows.
//                          Once a minute is already generous.
//   something IS happening the page renders its spinners from `state`, so how
//                          fast it notices the end IS the spinner's length.
//
// Using the idle number for both is how a check that finished in 200ms could
// still spin: the snapshot the page holds can be a stale "checking" — a GET
// that was already in flight when the check finished and resolved AFTER the
// fresh snapshot was written into the cache — and then nothing asks again for
// the rest of the minute. The daemon is right; the page is 60 seconds behind
// it, and the user is looking at the page.
//
// Polling faster while an operation is believed to be running bounds that to
// two seconds, and costs nothing the rest of the time (which is almost always).
// It is not a substitute for the daemon telling the truth — see
// selfupdate.Agent.finish and manifestFetchTimeout, both of which exist because
// it once did not — it is what keeps a single stale answer from lasting a
// minute.
export const UPDATE_POLL_IDLE_MS = 60_000;
export const UPDATE_POLL_ACTIVE_MS = 2_000;

// updatePollInterval: anything it does not recognise is treated as at rest.
// A newer daemon may answer with a state this page predates, and guessing
// "busy" would leave an old console hammering localhost forever with no way
// out; guessing "idle" costs at most one slow-looking button.
export function updatePollInterval(info?: { state?: string } | null): number {
  switch (info?.state) {
    case "checking":
    case "updating":
      return UPDATE_POLL_ACTIVE_MS;
    default:
      return UPDATE_POLL_IDLE_MS;
  }
}
