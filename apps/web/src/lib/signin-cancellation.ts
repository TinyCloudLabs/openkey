import { listenForApprovalCancellation } from './approval-cancellation';
export type SignInCancellation = { token: string; requestId: string; origin: string; keyId: string; chainId: number };

/** The app cannot call the cookie-authenticated cancellation API itself. */
export function listenForSignInCancellation(
  current: () => SignInCancellation | undefined,
  beforeCancel: () => void = () => {},
): () => void {
  return listenForApprovalCancellation('tinycloud-signin', current, beforeCancel);
}
