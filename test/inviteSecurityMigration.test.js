const test = require("node:test");
const assert = require("node:assert/strict");

const {
  APPLY_FLAG,
  CONFIRM_PRODUCTION_FLAG,
  INDEX_NAMES,
  MigrationAbortError,
  applyMigration,
  assertNonProductionMigrationTarget,
  buildMigrationAudit,
  redactMongoUri,
} = require("../inviteSecurityMigration.js");

function buildNoopCollection(state) {
  return {
    async updateOne() {
      state.updateCalls += 1;
      return { modifiedCount: 1 };
    },
    async deleteMany() {
      state.deleteCalls += 1;
      return { deletedCount: 1 };
    },
    async dropIndex() {
      state.dropCalls += 1;
    },
    async createIndex() {
      state.createCalls += 1;
    },
  };
}

test("redactMongoUri never exposes credentials", () => {
  assert.equal(
    redactMongoUri("mongodb://user:secret@example.com:27017/BeerBibleDB?retryWrites=true"),
    "mongodb://example.com:27017/BeerBibleDB?[redacted]"
  );
});

test("assertNonProductionMigrationTarget allows dry-run against production", () => {
  assert.doesNotThrow(() =>
    assertNonProductionMigrationTarget({ nodeEnv: "production" })
  );
});

test("assertNonProductionMigrationTarget blocks production apply without explicit confirmation", () => {
  assert.throws(
    () =>
      assertNonProductionMigrationTarget({
        nodeEnv: "production",
        isApply: true,
      }),
    (error) =>
      error instanceof MigrationAbortError &&
      error.message.includes(APPLY_FLAG) &&
      error.message.includes(CONFIRM_PRODUCTION_FLAG)
  );
});

test("assertNonProductionMigrationTarget allows production apply with explicit confirmation", () => {
  assert.doesNotThrow(() =>
    assertNonProductionMigrationTarget({
      nodeEnv: "production",
      hasConfirmProduction: true,
      isApply: true,
    })
  );
});

test("buildMigrationAudit revokes all conflicting outstanding invites and audits user collisions", () => {
  const now = new Date("2026-07-17T00:00:00.000Z");
  const audit = buildMigrationAudit({
    users: [
      { _id: "507f1f77bcf86cd799439011", email: "User@Example.com" },
      { _id: "507f1f77bcf86cd799439012", email: "user@example.com" },
    ],
    userIndexes: [{ name: "_id_", key: { _id: 1 } }],
    invites: [
      {
        _id: "507f1f77bcf86cd799439013",
        brewery: "507f1f77bcf86cd799439099",
        recipientEmail: "Member@Example.com",
        token: "a".repeat(64),
        createdAt: "2026-07-15T00:00:00.000Z",
        expiresAt: "2026-07-18T00:00:00.000Z",
      },
      {
        _id: "507f1f77bcf86cd799439014",
        brewery: "507f1f77bcf86cd799439099",
        recipientEmail: "member@example.com",
        token: "b".repeat(64),
        createdAt: "2026-07-16T00:00:00.000Z",
        expiresAt: "2026-07-18T00:00:00.000Z",
      },
    ],
    inviteIndexes: [{ name: "_id_", key: { _id: 1 } }],
    now,
  });

  assert.equal(audit.userEmailAudit.duplicateGroups.length, 1);
  assert.deepEqual(audit.inviteAudit.duplicateOutstandingDeleted, [
    "507f1f77bcf86cd799439013",
    "507f1f77bcf86cd799439014",
  ]);
  assert.deepEqual(audit.userIndexCreatesPlanned, [INDEX_NAMES.userEmail]);
});

test("applyMigration aborts before writes when manual user-email resolution is required", async () => {
  const state = {
    createCalls: 0,
    deleteCalls: 0,
    dropCalls: 0,
    updateCalls: 0,
  };
  const audit = buildMigrationAudit({
    users: [
      { _id: "507f1f77bcf86cd799439011", email: "User@Example.com" },
      { _id: "507f1f77bcf86cd799439012", email: "user@example.com" },
    ],
    userIndexes: [{ name: "_id_", key: { _id: 1 } }],
    invites: [],
    inviteIndexes: [{ name: "_id_", key: { _id: 1 } }],
    now: new Date("2026-07-17T00:00:00.000Z"),
  });

  await assert.rejects(
    applyMigration({
      audit,
      invitesCollection: buildNoopCollection(state),
      usersCollection: buildNoopCollection(state),
    }),
    (error) =>
      error instanceof MigrationAbortError &&
      /duplicate canonical user email groups/.test(error.message)
  );

  assert.deepEqual(state, {
    createCalls: 0,
    deleteCalls: 0,
    dropCalls: 0,
    updateCalls: 0,
  });
});
