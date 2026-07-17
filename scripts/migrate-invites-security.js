#!/usr/bin/env node

const mongoose = require("mongoose");
const {
  DEFAULT_MONGO_OPTIONS,
  DEFAULT_MONGO_URI,
} = require("../mongo.js");
const {
  APPLY_FLAG,
  CONFIRM_PRODUCTION_FLAG,
  MigrationAbortError,
  applyMigration,
  assertNonProductionMigrationTarget,
  buildMigrationAudit,
  redactMongoUri,
} = require("../inviteSecurityMigration.js");

async function main() {
  const isApply = process.argv.includes(APPLY_FLAG);
  const hasConfirmProduction = process.argv.includes(CONFIRM_PRODUCTION_FLAG);
  const mode = isApply ? "APPLY" : "DRY-RUN";
  const now = new Date();
  const safeMongoTarget = redactMongoUri(DEFAULT_MONGO_URI);

  console.log(`[${mode}] Invite security remediation migration`);
  console.log(`[${mode}] Mongo target: ${safeMongoTarget}`);
  console.log(`[${mode}] Current time: ${now.toISOString()}`);
  console.log(`[${mode}] Writes require ${APPLY_FLAG}.`);
  if (process.env.NODE_ENV === "production") {
    console.log(
      `[${mode}] Production apply also requires ${CONFIRM_PRODUCTION_FLAG}.`
    );
  }

  assertNonProductionMigrationTarget({
    isApply,
    hasConfirmProduction,
  });

  await mongoose.connect(DEFAULT_MONGO_URI, DEFAULT_MONGO_OPTIONS);

  try {
    const invitesCollection = mongoose.connection.collection("invites");
    const usersCollection = mongoose.connection.collection("users");
    const invites = await invitesCollection.find({}).toArray();
    const users = await usersCollection.find({}).toArray();
    const inviteIndexes = await invitesCollection.indexes();
    const userIndexes = await usersCollection.indexes();
    const audit = buildMigrationAudit({
      invites,
      inviteIndexes,
      now,
      userIndexes,
      users,
    });

    console.log(`Audit total users: ${audit.userEmailAudit.totalUsers}`);
    console.log(`Audit invalid user emails: ${audit.userEmailAudit.invalid.length}`);
    console.log(
      `Audit user email normalization-only records: ${audit.userEmailAudit.normalizeOnly.length}`
    );
    console.log(
      `Audit duplicate canonical user email groups: ${audit.userEmailAudit.duplicateGroups.length}`
    );
    console.log(`Audit total invites: ${audit.inviteAudit.totalInvites}`);
    console.log(
      `Audit legacy email-unbound invites: ${audit.inviteAudit.legacyEmailUnbound.length}`
    );
    console.log(`Audit expired invites: ${audit.inviteAudit.expired.length}`);
    console.log(
      `Audit invite normalization-only records: ${audit.inviteAudit.normalizeOnly.length}`
    );
    console.log(
      `Audit duplicate outstanding invite groups: ${audit.inviteAudit.duplicateOutstandingGroups.length}`
    );
    console.log(
      `Audit duplicate outstanding invites to revoke: ${audit.inviteAudit.duplicateOutstandingDeleted.length}`
    );
    console.log(
      `Audit duplicate invite token groups: ${audit.inviteAudit.duplicateTokenGroups.length}`
    );
    console.log(
      `Audit invite index drops planned: ${audit.inviteIndexDropsPlanned.length}`
    );
    console.log(
      `Audit invite index creates planned: ${audit.inviteIndexCreatesPlanned.length}`
    );
    console.log(
      `Audit user index drops planned: ${audit.userIndexDropsPlanned.length}`
    );
    console.log(
      `Audit user index creates planned: ${audit.userIndexCreatesPlanned.length}`
    );

    if (!isApply) {
      console.log("Dry run only. No writes applied.");
      return;
    }

    const applyResult = await applyMigration({
      audit,
      invitesCollection,
      usersCollection,
    });

    console.log(
      `Applied normalized user email updates: ${applyResult.normalizedUserUpdatesApplied}`
    );
    console.log(
      `Applied normalized invite email updates: ${applyResult.normalizedInviteUpdatesApplied}`
    );
    console.log(
      `Applied invite revocations/deletions: ${applyResult.revokedInviteCount}`
    );
    console.log("Migration apply completed.");
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((error) => {
  if (error instanceof MigrationAbortError) {
    console.error("Invite security remediation migration aborted:", error.message);
    process.exitCode = 1;
    return;
  }
  console.error(
    "Invite security remediation migration failed:",
    error && error.message ? error.message : String(error)
  );
  process.exitCode = 1;
});
