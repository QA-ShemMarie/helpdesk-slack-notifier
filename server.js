import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";

const {
  PORT = 3000,
  GITHUB_WEBHOOK_SECRET,
  GITHUB_TOKEN, // needed for titles, descriptions, and comment filtering
  PROJECT_NUMBER, // only notify for this project (e.g. 68)
  SNIPPET_LENGTH = 10000, // max characters of description/comment shown in Slack
  SLACK_BOT_TOKEN, // enables threading (one message per issue, updates as replies)
  SLACK_CHANNEL_ID, // channel ID (looks like C0123ABCD) for the bot to post in
  SLACK_WEBHOOK_URL, // fallback without threading
  THREADS_FILE = "threads.json", // remembers which Slack message belongs to which issue
} = process.env;

if (!GITHUB_WEBHOOK_SECRET) {
  console.error("Missing GITHUB_WEBHOOK_SECRET");
  process.exit(1);
}
if (SLACK_BOT_TOKEN && !SLACK_CHANNEL_ID) {
  console.error("SLACK_BOT_TOKEN is set but SLACK_CHANNEL_ID is missing");
  process.exit(1);
}
if (!SLACK_BOT_TOKEN && !SLACK_WEBHOOK_URL) {
  console.error("Set SLACK_BOT_TOKEN + SLACK_CHANNEL_ID (threads) or SLACK_WEBHOOK_URL (no threads)");
  process.exit(1);
}
if (!SLACK_BOT_TOKEN) console.warn("No SLACK_BOT_TOKEN: using the webhook, so messages will NOT be threaded.");
if (!GITHUB_TOKEN) console.warn("GITHUB_TOKEN is not set: no titles/descriptions, no project filtering, comments are skipped.");

// ---------- Thread storage (issue -> Slack message timestamp) ----------

let threads = {};
try {
  threads = JSON.parse(fs.readFileSync(THREADS_FILE, "utf8"));
} catch {
  // first run or unreadable file: start empty
}
function saveThreads() {
  try {
    fs.writeFileSync(THREADS_FILE, JSON.stringify(threads));
  } catch (err) {
    console.error("Could not save threads file:", err.message);
  }
}

// ---------- Web server ----------

const app = express();

// Raw body is required to verify GitHub's HMAC signature.
app.post("/webhook", express.raw({ type: "application/json", limit: "5mb" }), (req, res) => {
  if (!verifySignature(req)) return res.status(401).send("Invalid signature");

  const event = req.get("x-github-event");
  if (event === "ping") return res.status(200).send("pong");
  if (event !== "projects_v2_item" && event !== "issue_comment") return res.status(204).end();

  // Acknowledge fast; GitHub times out webhook deliveries after ~10s.
  res.status(202).end();

  const payload = JSON.parse(req.body.toString("utf8"));
  const run = event === "issue_comment" ? handleCommentEvent : handleItemEvent;
  run(payload).catch((err) => console.error("Handler error:", err));
});

app.get("/", (_req, res) => res.send("ok"));

app.listen(PORT, () => console.log(`Listening on :${PORT}`));

function verifySignature(req) {
  const received = Buffer.from(req.get("x-hub-signature-256") || "");
  const expected = Buffer.from(
    "sha256=" +
      crypto.createHmac("sha256", GITHUB_WEBHOOK_SECRET).update(req.body).digest("hex")
  );
  return received.length === expected.length && crypto.timingSafeEqual(received, expected);
}

// ---------- Project item events (cards added, moved, edited...) ----------

async function handleItemEvent(payload) {
  const { action, projects_v2_item: item, sender, changes } = payload;
  if (action === "reordered") return; // too noisy

  const info = GITHUB_TOKEN ? await lookup(item.content_node_id, item.project_node_id) : null;

  if (PROJECT_NUMBER && info?.project && String(info.project.number) !== String(PROJECT_NUMBER)) {
    return; // different project
  }

  const title = info?.item?.title ?? `${item.content_type ?? "Item"}`;
  const itemText = info?.item?.url ? `<${info.item.url}|${escapeSlack(title)}>` : `*${escapeSlack(title)}*`;
  const projectText = info?.project
    ? `<${info.project.url}|${escapeSlack(info.project.title)}>`
    : "a project";
  const who = userLink(sender);

  // First message for this issue: title, project and description
  let parentText = `:ticket: ${itemText} in ${projectText}`;
  const desc = snippet(info?.item?.body);
  if (desc) parentText += `\n${desc}`;

  // Replies in the thread
  let replyText;
  switch (action) {
    case "created":
      replyText = `:heavy_plus_sign: ${who} added this to ${projectText}`;
      break;
    case "deleted":
      replyText = `:wastebasket: ${who} removed this from ${projectText}`;
      break;
    case "archived":
      replyText = `:file_cabinet: ${who} archived this`;
      break;
    case "restored":
      replyText = `:recycle: ${who} restored this`;
      break;
    case "converted":
      replyText = `:arrows_counterclockwise: ${who} converted this`;
      break;
    case "edited": {
      const fv = changes?.field_value;
      if (fv && (fv.field_type === "assignees" || fv.field_name === "Assignees") && info?.item) {
        // GitHub doesn't include the people in the event, so we show the current list.
        const people = (info.item.assignees?.nodes ?? []).map(
          (n) => `<https://github.com/${n.login}|${n.login}>`
        );
        replyText = `:bust_in_silhouette: ${who} changed *Assignees*: now ${people.length ? people.join(", ") : "_none_"}`;
      } else if (fv && (fv.field_type === "labels" || fv.field_name === "Labels") && info?.item) {
        const labels = (info.item.labels?.nodes ?? []).map((n) => `\`${escapeSlack(n.name)}\``);
        replyText = `:label: ${who} changed *Labels*: now ${labels.length ? labels.join(" ") : "_none_"}`;
      } else if (fv) {
        replyText = `:pencil2: ${who} changed *${escapeSlack(fv.field_name)}*: ${fmt(fv.from)} → ${fmt(fv.to)}`;
      } else {
        replyText = `:pencil2: ${who} edited this`;
      }
      break;
    }
    default:
      replyText = `${who} ${action} this`;
  }

  await notify({
    key: item.content_node_id ?? item.node_id,
    parentText,
    replyText,
    // If this event itself created the thread (e.g. "added to project"), the parent already says it.
    skipReplyIfNew: action === "created",
  });
}

// ---------- Comment events ----------

async function handleCommentEvent(payload) {
  if (payload.action !== "created") return; // new comments only
  if (!GITHUB_TOKEN) return; // can't tell which project the issue belongs to

  const { issue, comment, sender } = payload;
  const project = await findProjectForIssue(issue.node_id);
  if (!project) return; // issue isn't on the project we care about

  let parentText = `:ticket: <${issue.html_url}|${escapeSlack(issue.title)}> in <${project.url}|${escapeSlack(project.title)}>`;
  const desc = snippet(issue.body);
  if (desc) parentText += `\n${desc}`;

  const replyText =
    `:speech_balloon: ${userLink(sender)} <${comment.html_url}|commented>:\n` + snippet(comment.body);

  await notify({ key: issue.node_id, parentText, replyText });
}

async function findProjectForIssue(nodeId) {
  const query = `
    query($id: ID!) {
      node(id: $id) {
        ... on Issue { projectItems(first: 50) { nodes { project { title number url } } } }
        ... on PullRequest { projectItems(first: 50) { nodes { project { title number url } } } }
      }
    }`;
  const data = await graphql(query, { id: nodeId });
  const nodes = data?.node?.projectItems?.nodes ?? [];
  const projects = nodes.map((n) => n.project).filter(Boolean);
  if (PROJECT_NUMBER) return projects.find((p) => String(p.number) === String(PROJECT_NUMBER));
  return projects[0];
}

// ---------- Slack posting with threads ----------

// Events for the same issue are handled one at a time so we never create two parent messages.
const locks = new Map();
function withLock(key, fn) {
  const prev = locks.get(key) ?? Promise.resolve();
  const next = prev.then(fn, fn);
  locks.set(key, next.catch(() => {}));
  return next;
}

async function notify({ key, parentText, replyText, skipReplyIfNew }) {
  if (!SLACK_BOT_TOKEN) {
    // Webhook fallback: no threading possible
    const text = [replyText, parentText].filter(Boolean).join("\n");
    return postWebhook(text);
  }

  return withLock(key, async () => {
    let ts = threads[key];
    let isNew = false;

    if (!ts) {
      ts = await slackPost(parentText);
      threads[key] = ts;
      saveThreads();
      isNew = true;
    }

    if (!replyText || (isNew && skipReplyIfNew)) return;

    try {
      await slackPost(replyText, ts);
    } catch (err) {
      // The original message was deleted: start a fresh thread
      if (["thread_not_found", "message_not_found"].includes(err.slackError)) {
        ts = await slackPost(parentText);
        threads[key] = ts;
        saveThreads();
        await slackPost(replyText, ts);
      } else {
        throw err;
      }
    }
  });
}

async function slackPost(text, thread_ts) {
  const r = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      channel: SLACK_CHANNEL_ID,
      text,
      thread_ts,
      unfurl_links: false,
      unfurl_media: false,
    }),
  });
  const json = await r.json();
  if (!json.ok) {
    if (json.error === "not_in_channel") {
      console.error("Slack: the bot is not in the channel. Run /invite @YourBotName in that channel.");
    }
    throw Object.assign(new Error(`Slack error: ${json.error}`), { slackError: json.error });
  }
  return json.ts;
}

async function postWebhook(text) {
  const r = await fetch(SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!r.ok) console.error("Slack error:", r.status, await r.text());
}

// ---------- GitHub helpers ----------

async function graphql(query, variables) {
  try {
    const r = await fetch("https://api.github.com/graphql", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ query, variables }),
    });
    const json = await r.json();
    if (json.errors) console.warn("GraphQL warnings:", JSON.stringify(json.errors));
    return json.data ?? null;
  } catch (err) {
    console.error("GraphQL request failed:", err);
    return null;
  }
}

// Resolve titles and descriptions from the node IDs in the webhook payload.
async function lookup(itemId, projectId) {
  const query = `
    query($item: ID!, $project: ID!) {
      item: node(id: $item) {
        __typename
        ... on Issue { title url body assignees(first: 10) { nodes { login } } labels(first: 20) { nodes { name } } }
        ... on PullRequest { title url body assignees(first: 10) { nodes { login } } labels(first: 20) { nodes { name } } }
        ... on DraftIssue { title body assignees(first: 10) { nodes { login } } }
      }
      project: node(id: $project) {
        ... on ProjectV2 { title number url }
      }
    }`;
  return graphql(query, { item: itemId ?? "", project: projectId });
}

// ---------- Formatting helpers ----------

// Turn markdown text into a short, quoted Slack snippet.
function snippet(text) {
  if (!text || !text.trim()) return "";
  const max = Number(SNIPPET_LENGTH);
  let t = text.replace(/\r\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  if (t.length > max) t = t.slice(0, max).trimEnd() + "…";
  return escapeSlack(t)
    .split("\n")
    .map((line) => `> ${line}`)
    .join("\n");
}

function userLink(sender) {
  return sender?.login ? `<https://github.com/${sender.login}|${sender.login}>` : "Someone";
}

function fmt(v) {
  if (v == null) return "_none_";
  if (typeof v === "object") return escapeSlack(v.name ?? v.title ?? v.text ?? JSON.stringify(v));
  return escapeSlack(String(v));
}

function escapeSlack(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
