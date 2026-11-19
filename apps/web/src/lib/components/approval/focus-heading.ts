/**
 * Moves focus to an element when it appears, so a screen reader announces the new end state.
 * The element is focusable by script only; it never joins the tab order.
 */
export function focusHeading(node: HTMLElement): void {
  node.tabIndex = -1;
  node.focus({ preventScroll: true });
}
