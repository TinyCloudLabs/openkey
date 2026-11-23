import {
  INBOX_MAIL_STATEMENT,
  INBOX_MEDIA_STATEMENT,
  INBOX_TRIAGE_STATEMENT,
} from "./copy.js";

const MESSAGES_SPACE = /^tinycloud:pkh:eip155:\d+:0x[a-fA-F0-9]{40}:messages$/;
const MEDIA_PATH = "xyz.tinycloud.inbox/media/";
const MAIL_PATH = "xyz.tinycloud.inbox/db/";
const TRIAGE_PATH = "xyz.tinycloud.inbox/triage";

/** Name the Inbox data reached by a read of one exact resource. */
export function inboxMessagesStatement(
  entry: {
    service: string;
    space: string;
    path: string;
    actions: readonly string[];
    resourceService?: string | null;
  },
  isOwnSpace: boolean,
): string | null {
  const { service, space, path, actions, resourceService } = entry;
  if (!isOwnSpace || !MESSAGES_SPACE.test(space) || actions.length !== 1) {
    return null;
  }
  if (
    service === "tinycloud.kv" &&
    (resourceService === undefined || resourceService === "kv") &&
    actions[0] === "tinycloud.kv/get" &&
    path === MEDIA_PATH
  ) {
    return INBOX_MEDIA_STATEMENT;
  }
  if (
    service === "tinycloud.sql" &&
    (resourceService === undefined || resourceService === "sql") &&
    actions[0] === "tinycloud.sql/read"
  ) {
    if (path === MAIL_PATH) return INBOX_MAIL_STATEMENT;
    if (path === TRIAGE_PATH) return INBOX_TRIAGE_STATEMENT;
  }
  return null;
}
