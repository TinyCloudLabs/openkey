/**
 * The review model with the requester's name read from the live requester. The model is built once and kept while the
 * owner narrows the request; a name frozen into it would stay on screen after a later message stops being named.
 */
export function withLiveRequester<T extends { requester: { displayName: string } }>(model: T | null, requester: { displayName: string } | null): T | null {
  return model && { ...model, requester: { ...model.requester, displayName: requester?.displayName ?? '' } };
}
