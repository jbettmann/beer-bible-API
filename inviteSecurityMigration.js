const mongoose = require("mongoose");

const { normalizeEmail } = require("./emailNormalization.js");

const APPLY_FLAG = "--apply";
const CONFIRM_PRODUCTION_FLAG = "--confirm-production";
const LEGACY_COMPOUND_INDEX_NAME = "brewery_1_recipientEmail_1_expiresAt_1";
const INDEX_NAMES = {
  inviteToken: "invite_token_unique",
  inviteExpiresAt: "invite_expires_at_ttl",
  inviteBreweryRecipient: "invite_brewery_recipient_unique",
  userEmail: "user_email_unique",
};

class MigrationAbortError extends Error {
  constructor(message) {
    super(message);
    this.name = "MigrationAbortError";
  }
}

function compareByCreatedAtAndId(left, right) {
  const leftCreatedAt = new Date(left.createdAt || 0).getTime();
  const rightCreatedAt = new Date(right.createdAt || 0).getTime();

  if (leftCreatedAt !== rightCreatedAt) {
    return leftCreatedAt - rightCreatedAt;
  }

  return String(left._id).localeCompare(String(right._id));
}

function redactMongoUri(uri) {
  try {
    const parsed = new URL(uri);
    const databaseName = parsed.pathname.replace(/^\/+/, "") || "(default)";
    const host = parsed.host || "(unknown-host)";
    const querySuffix = parsed.search ? "?[redacted]" : "";
    return `${parsed.protocol}//${host}/${databaseName}${querySuffix}`;
  } catch (error) {
    return "[unparseable-mongo-uri-redacted]";
  }
}

function assertNonProductionMigrationTarget({
  isApply = false,
  hasConfirmProduction = false,
  nodeEnv = process.env.NODE_ENV,
} = {}) {
  if (nodeEnv === "production" && isApply && !hasConfirmProduction) {
    throw new MigrationAbortError(
      `Refusing to apply invite security migration against production without ${APPLY_FLAG} and ${CONFIRM_PRODUCTION_FLAG}.`
    );
  }
}

function isIndexKey(index, expectedKey) {
  const actualEntries = Object.entries(index?.key || {});
  const expectedEntries = Object.entries(expectedKey);

  if (actualEntries.length !== expectedEntries.length) {
    return false;
  }

  return expectedEntries.every(([key, value]) => index.key[key] === value);
}

function formatIds(records) {
  return records.map((record) => String(record._id));
}

function buildUserEmailAudit(users) {
  const duplicateGroups = [];
  const normalizeOnly = [];
  const invalid = [];
  const groups = new Map();

  for (const user of users) {
    const normalizedEmail = normalizeEmail(user.email);

    if (!normalizedEmail) {
      invalid.push({ _id: String(user._id), email: user.email ?? null });
      continue;
    }

    if (user.email !== normalizedEmail) {
      normalizeOnly.push({
        _id: String(user._id),
        from: user.email,
        to: normalizedEmail,
      });
    }

    const group = groups.get(normalizedEmail) || [];
    group.push({
      _id: String(user._id),
      email: user.email,
      normalizedEmail,
    });
    groups.set(normalizedEmail, group);
  }

  for (const [email, group] of groups.entries()) {
    if (group.length > 1) {
      duplicateGroups.push({
        email,
        userIds: group.map((user) => user._id),
      });
    }
  }

  return {
    duplicateGroups,
    invalid,
    normalizeOnly,
    totalUsers: users.length,
  };
}

function buildInviteAudit(invites, now) {
  const duplicateOutstandingGroups = [];
  const duplicateOutstandingDeleted = [];
  const duplicateTokenGroups = [];
  const expired = [];
  const legacyEmailUnbound = [];
  const normalizeOnly = [];
  const outstandingGroups = new Map();
  const tokenGroups = new Map();

  for (const invite of invites) {
    if (typeof invite.token === "string" && invite.token.length > 0) {
      const tokenGroup = tokenGroups.get(invite.token) || [];
      tokenGroup.push(invite);
      tokenGroups.set(invite.token, tokenGroup);
    }

    const normalizedEmail = normalizeEmail(invite.recipientEmail);
    const isExpired =
      invite.expiresAt && new Date(invite.expiresAt).getTime() <= now.getTime();

    if (!normalizedEmail) {
      legacyEmailUnbound.push(String(invite._id));
      continue;
    }

    if (isExpired) {
      expired.push(String(invite._id));
      continue;
    }

    if (invite.recipientEmail !== normalizedEmail) {
      normalizeOnly.push({
        _id: String(invite._id),
        from: invite.recipientEmail,
        to: normalizedEmail,
      });
    }

    const groupKey = `${String(invite.brewery)}::${normalizedEmail}`;
    const group = outstandingGroups.get(groupKey) || [];
    group.push({
      ...invite,
      recipientEmail: normalizedEmail,
    });
    outstandingGroups.set(groupKey, group);
  }

  for (const [groupKey, group] of outstandingGroups.entries()) {
    if (group.length <= 1) {
      continue;
    }

    group.sort(compareByCreatedAtAndId);
    duplicateOutstandingGroups.push({
      groupKey,
      inviteIds: formatIds(group),
    });
    duplicateOutstandingDeleted.push(...formatIds(group));
  }

  for (const [token, group] of tokenGroups.entries()) {
    if (group.length > 1) {
      duplicateTokenGroups.push({
        token,
        inviteIds: formatIds(group),
      });
    }
  }

  return {
    duplicateOutstandingDeleted,
    duplicateOutstandingGroups,
    duplicateTokenGroups,
    expired,
    legacyEmailUnbound,
    normalizeOnly,
    totalInvites: invites.length,
  };
}

function buildIndexAudit({ inviteIndexes, userIndexes }) {
  const inviteIndexDropsPlanned = [];
  const inviteIndexCreatesPlanned = [];
  const userIndexDropsPlanned = [];
  const userIndexCreatesPlanned = [];

  const inviteByName = new Map(inviteIndexes.map((index) => [index.name, index]));
  const userByName = new Map(userIndexes.map((index) => [index.name, index]));

  const legacyInviteIndexes = inviteIndexes.filter((index) => {
    return (
      index.name === LEGACY_COMPOUND_INDEX_NAME ||
      isIndexKey(index, { brewery: 1, recipientEmail: 1, expiresAt: 1 })
    );
  });

  for (const index of legacyInviteIndexes) {
    if (!inviteIndexDropsPlanned.includes(index.name)) {
      inviteIndexDropsPlanned.push(index.name);
    }
  }

  const emailIndexes = userIndexes.filter((index) => isIndexKey(index, { email: 1 }));
  for (const index of emailIndexes) {
    if (
      index.name !== INDEX_NAMES.userEmail ||
      index.unique !== true
    ) {
      userIndexDropsPlanned.push(index.name);
    }
  }

  if (
    !inviteByName.has(INDEX_NAMES.inviteToken) ||
    inviteByName.get(INDEX_NAMES.inviteToken).unique !== true
  ) {
    inviteIndexCreatesPlanned.push(INDEX_NAMES.inviteToken);
  }

  if (
    !inviteByName.has(INDEX_NAMES.inviteExpiresAt) ||
    !isIndexKey(inviteByName.get(INDEX_NAMES.inviteExpiresAt), { expiresAt: 1 })
  ) {
    inviteIndexCreatesPlanned.push(INDEX_NAMES.inviteExpiresAt);
  }

  if (
    !inviteByName.has(INDEX_NAMES.inviteBreweryRecipient) ||
    inviteByName.get(INDEX_NAMES.inviteBreweryRecipient).unique !== true ||
    !isIndexKey(inviteByName.get(INDEX_NAMES.inviteBreweryRecipient), {
      brewery: 1,
      recipientEmail: 1,
    })
  ) {
    inviteIndexCreatesPlanned.push(INDEX_NAMES.inviteBreweryRecipient);
  }

  if (
    !userByName.has(INDEX_NAMES.userEmail) ||
    userByName.get(INDEX_NAMES.userEmail).unique !== true ||
    !isIndexKey(userByName.get(INDEX_NAMES.userEmail), { email: 1 })
  ) {
    userIndexCreatesPlanned.push(INDEX_NAMES.userEmail);
  }

  return {
    inviteIndexCreatesPlanned,
    inviteIndexDropsPlanned,
    userIndexCreatesPlanned,
    userIndexDropsPlanned,
  };
}

function buildMigrationAudit({
  inviteIndexes,
  invites,
  now = new Date(),
  userIndexes,
  users,
}) {
  const userEmailAudit = buildUserEmailAudit(users);
  const inviteAudit = buildInviteAudit(invites, now);
  const indexAudit = buildIndexAudit({ inviteIndexes, userIndexes });

  return {
    ...indexAudit,
    inviteAudit,
    userEmailAudit,
  };
}

function getManualResolutionReasons(audit) {
  const reasons = [];

  if (audit.userEmailAudit.invalid.length > 0) {
    reasons.push("invalid user emails");
  }

  if (audit.userEmailAudit.duplicateGroups.length > 0) {
    reasons.push("duplicate canonical user email groups");
  }

  if (audit.inviteAudit.duplicateTokenGroups.length > 0) {
    reasons.push("duplicate invite token groups");
  }

  return reasons;
}

function assertApplyReady(audit) {
  const reasons = getManualResolutionReasons(audit);

  if (reasons.length > 0) {
    throw new MigrationAbortError(
      `Manual resolution required before apply: ${reasons.join(", ")}.`
    );
  }
}

function buildObjectIds(ids) {
  return ids.map((id) => new mongoose.Types.ObjectId(id));
}

async function applyMigration({
  audit,
  invitesCollection,
  usersCollection,
}) {
  assertApplyReady(audit);

  let normalizedInviteUpdatesApplied = 0;
  let normalizedUserUpdatesApplied = 0;
  let revokedInviteCount = 0;

  for (const item of audit.userEmailAudit.normalizeOnly) {
    const result = await usersCollection.updateOne(
      { _id: new mongoose.Types.ObjectId(item._id) },
      { $set: { email: item.to } }
    );
    normalizedUserUpdatesApplied += result.modifiedCount ?? result.nModified ?? 0;
  }

  for (const item of audit.inviteAudit.normalizeOnly) {
    const result = await invitesCollection.updateOne(
      { _id: new mongoose.Types.ObjectId(item._id) },
      { $set: { recipientEmail: item.to } }
    );
    normalizedInviteUpdatesApplied += result.modifiedCount ?? result.nModified ?? 0;
  }

  const deletedIds = [
    ...audit.inviteAudit.legacyEmailUnbound,
    ...audit.inviteAudit.expired,
    ...audit.inviteAudit.duplicateOutstandingDeleted,
  ];

  if (deletedIds.length > 0) {
    const deleteResult = await invitesCollection.deleteMany({
      _id: { $in: buildObjectIds(deletedIds) },
    });
    revokedInviteCount = deleteResult.deletedCount ?? 0;
  }

  for (const indexName of audit.inviteIndexDropsPlanned) {
    try {
      await invitesCollection.dropIndex(indexName);
    } catch (error) {
      if (error.codeName !== "IndexNotFound") {
        throw error;
      }
    }
  }

  for (const indexName of audit.userIndexDropsPlanned) {
    try {
      await usersCollection.dropIndex(indexName);
    } catch (error) {
      if (error.codeName !== "IndexNotFound") {
        throw error;
      }
    }
  }

  if (audit.inviteIndexCreatesPlanned.includes(INDEX_NAMES.inviteToken)) {
    await invitesCollection.createIndex(
      { token: 1 },
      { unique: true, name: INDEX_NAMES.inviteToken }
    );
  }

  if (audit.inviteIndexCreatesPlanned.includes(INDEX_NAMES.inviteExpiresAt)) {
    await invitesCollection.createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, name: INDEX_NAMES.inviteExpiresAt }
    );
  }

  if (
    audit.inviteIndexCreatesPlanned.includes(INDEX_NAMES.inviteBreweryRecipient)
  ) {
    await invitesCollection.createIndex(
      { brewery: 1, recipientEmail: 1 },
      { unique: true, name: INDEX_NAMES.inviteBreweryRecipient }
    );
  }

  if (audit.userIndexCreatesPlanned.includes(INDEX_NAMES.userEmail)) {
    await usersCollection.createIndex(
      { email: 1 },
      { unique: true, name: INDEX_NAMES.userEmail }
    );
  }

  return {
    normalizedInviteUpdatesApplied,
    normalizedUserUpdatesApplied,
    revokedInviteCount,
  };
}

module.exports = {
  APPLY_FLAG,
  CONFIRM_PRODUCTION_FLAG,
  INDEX_NAMES,
  LEGACY_COMPOUND_INDEX_NAME,
  MigrationAbortError,
  applyMigration,
  assertApplyReady,
  assertNonProductionMigrationTarget,
  buildMigrationAudit,
  getManualResolutionReasons,
  redactMongoUri,
};
