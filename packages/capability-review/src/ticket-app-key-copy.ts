import { TICKET_APP_KEY_ROW_COPY } from "./copy.js";

/** Copy for the command-line app key approval screen. The warning, receipt and refusals wrap as paragraphs. */
export const TICKET_APP_KEY_COPY = {
  ...TICKET_APP_KEY_ROW_COPY,
  receipt: `${TICKET_APP_KEY_ROW_COPY.toolName} can use the key {keyName} for {host} until {time}.`,
  warning:
    `This request comes from ${TICKET_APP_KEY_ROW_COPY.toolName}, a command-line tool, not from {host}. Approve it only if you started it on your own device.`,
  longerNote: "TinyCloud CLI keeps this access for the time you choose.",
  refusals: {
    missing:
      "OpenKey can't approve this request: {host} doesn't list keys that command-line tools can ask for. Nothing was approved.",
    invalid:
      "OpenKey can't approve this request: {host}'s list of keys for command-line tools can't be read. Nothing was approved.",
    notListed:
      "OpenKey can't approve this request: {host} doesn't let command-line tools ask for the key `{keyName}`. Nothing was approved.",
    unavailable:
      "OpenKey couldn't check {host}'s list of keys for command-line tools. Nothing was approved. Try again.",
    fetchBusy:
      "OpenKey is busy and couldn't check {host}'s list of keys for command-line tools. Nothing was approved. Try again in a minute.",
    request_invalid: "OpenKey can't read the app key in this request. Nothing was approved.",
    ticket_required: "App keys can be requested only through a command-line sign-in link. Nothing was approved.",
    app_id: "This app id isn't a website address written in reverse, such as xyz.tinycloud.share. Nothing was approved.",
    recap: "This request asks for more than the one app key it names. Nothing was approved.",
    account: "This request was made for a different account. Nothing was approved.",
    expiry: "This request lasts longer than 7 days. Nothing was approved.",
  },
} as const;
