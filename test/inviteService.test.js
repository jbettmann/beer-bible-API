const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ServiceError,
  buildAdminGrantFilter,
  buildAdminRevokeFilter,
  buildInviteUrl,
  createInviteEmailContent,
  createInviteService,
  ensureAdminGrantPreconditions,
  isDuplicateKeyError,
  normalizeEmail,
  wasRecipientAccepted,
  validateInviteToken,
} = require("../inviteService.js");

function createQuery(result) {
  return {
    populate() {
      return this;
    },
    session() {
      return this;
    },
    then(resolve, reject) {
      return Promise.resolve(result).then(resolve, reject);
    },
    catch(reject) {
      return Promise.resolve(result).catch(reject);
    },
  };
}

function createSessionTracker() {
  return {
    started: false,
    committed: false,
    aborted: false,
    ended: false,
    startTransaction() {
      this.started = true;
    },
    async commitTransaction() {
      this.committed = true;
    },
    async abortTransaction() {
      this.aborted = true;
    },
    async withTransaction(work) {
      this.startTransaction();
      try {
        const result = await work();
        await this.commitTransaction();
        return result;
      } catch (error) {
        await this.abortTransaction();
        throw error;
      }
    },
    endSession() {
      this.ended = true;
    },
  };
}

test("normalizeEmail trims and lowercases valid emails", () => {
  assert.equal(normalizeEmail("  USER@Example.COM "), "user@example.com");
  assert.equal(normalizeEmail("bad-email"), null);
  assert.equal(normalizeEmail(null), null);
});

test("buildInviteUrl uses encoded token and safe fallback origin", () => {
  assert.equal(
    buildInviteUrl("https://frontend.example/path", "abc/123"),
    "https://frontend.example/invite/abc%2F123"
  );
  assert.equal(
    buildInviteUrl("not-a-url", "token"),
    "https://beer-flow.vercel.app/invite/token"
  );
});

test("invite email uses product branding and escapes brewery HTML", () => {
  const content = createInviteEmailContent({
    breweryName: "<Brew & Co>",
    inviteUrl: "https://frontend.example/invite/token",
  });
  assert.match(content.subject, /Beer Flow/);
  assert.doesNotMatch(content.subject, /Brett/);
  assert.match(content.html, /&lt;Brew &amp; Co&gt;/);
  assert.doesNotMatch(content.html, /<Brew & Co>/);
});

test("validateInviteToken requires the expected random token format", () => {
  assert.equal(validateInviteToken("f".repeat(64)), true);
  assert.equal(validateInviteToken("short"), false);
  assert.equal(validateInviteToken("f".repeat(65)), false);
  assert.equal(validateInviteToken("z".repeat(64)), false);
});

test("isDuplicateKeyError detects Mongo duplicate-key responses", () => {
  assert.equal(isDuplicateKeyError({ code: 11000 }), true);
  assert.equal(isDuplicateKeyError({ code: 11001 }), true);
  assert.equal(isDuplicateKeyError({ code: 42 }), false);
});

test("wasRecipientAccepted requires confirmation for the intended recipient", () => {
  assert.equal(
    wasRecipientAccepted({ accepted: ["User@Example.com"] }, "user@example.com"),
    true
  );
  assert.equal(
    wasRecipientAccepted(
      { accepted: [], rejected: ["user@example.com"] },
      "user@example.com"
    ),
    false
  );
  assert.equal(wasRecipientAccepted(undefined, "user@example.com"), false);
  assert.equal(
    wasRecipientAccepted(
      { accepted: [{ name: "User", address: "User@Example.com" }] },
      "user@example.com"
    ),
    true
  );
});

test("createInvitation rejects an invalid breweryId before brewery lookup", async () => {
  let breweryFindByIdCalls = 0;
  const service = createInviteService({
    Breweries: {
      findById: () => {
        breweryFindByIdCalls += 1;
        return createQuery(null);
      },
    },
    Invites: class {},
    Users: { findOne: async () => null },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: "not-an-object-id",
      authUserId: "507f1f77bcf86cd799439012",
      email: "member@example.com",
      isAdmin: false,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 400 &&
      error.message === "Invalid brewery ID format."
  );

  assert.equal(breweryFindByIdCalls, 0);
});

test("createInvitation requires a normalized email and boolean isAdmin", async () => {
  const service = createInviteService({
    Breweries: { findById: () => createQuery(null) },
    Invites: class {},
    Users: { findOne: async () => null },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: "507f1f77bcf86cd799439011",
      authUserId: "507f1f77bcf86cd799439012",
      email: "not-an-email",
      isAdmin: false,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 400 &&
      error.message === "A valid email is required."
  );

  await assert.rejects(
    service.createInvitation({
      breweryId: "507f1f77bcf86cd799439011",
      authUserId: "507f1f77bcf86cd799439012",
      email: "member@example.com",
      isAdmin: "true",
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 400 &&
      error.message === "isAdmin must be a boolean."
  );
});

test("createInvitation rejects existing members and duplicate active invites", async () => {
  const brewery = {
    _id: "507f1f77bcf86cd799439011",
    companyName: "Brewery",
    owner: "507f1f77bcf86cd799439012",
    admin: [],
    staff: ["507f1f77bcf86cd799439013"],
  };

  let inviteLookupCount = 0;
  const service = createInviteService({
    Breweries: { findById: () => createQuery(brewery) },
    Invites: class {
      static async findOne() {
        inviteLookupCount += 1;
        return inviteLookupCount === 1
          ? null
          : {
              _id: "invite-1",
              recipientEmail: "person@example.com",
            };
      }
    },
    Users: {
      async findOne() {
        return { _id: "507f1f77bcf86cd799439013", email: "person@example.com" };
      },
    },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: brewery._id,
      authUserId: brewery.owner,
      email: "Person@Example.com",
      isAdmin: false,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 400 &&
      /already a member/.test(error.message)
  );
});

test("createInvitation rejects duplicate active invites for the same brewery email", async () => {
  const brewery = {
    _id: "507f1f77bcf86cd799439011",
    companyName: "Brewery",
    owner: "507f1f77bcf86cd799439012",
    admin: [],
    staff: [],
  };

  const service = createInviteService({
    Breweries: { findById: () => createQuery(brewery) },
    Invites: class {
      static async findOne() {
        return {
          _id: "invite-1",
          recipientEmail: "person@example.com",
        };
      }
    },
    Users: { findOne: async () => null },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: brewery._id,
      authUserId: brewery.owner,
      email: "Person@Example.com",
      isAdmin: false,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 409 &&
      /active invite already exists/.test(error.message)
  );
});

test("createInvitation persists normalized email and removes invite if provider rejects delivery", async () => {
  const state = {
    savedInvite: null,
    deleteFilter: null,
  };

  class FakeInviteModel {
    constructor(doc) {
      Object.assign(this, doc);
      this._id = "invite-1";
    }

    async save() {
      state.savedInvite = this;
      return this;
    }

    static async findOne() {
      return null;
    }

    static async deleteOne(filter) {
      state.deleteFilter = filter;
      return { deletedCount: 1 };
    }
  }

  const service = createInviteService({
    Breweries: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439011",
          companyName: "<Safe Brewery>",
          owner: "507f1f77bcf86cd799439012",
          admin: [],
          staff: [],
        }),
    },
    Invites: FakeInviteModel,
    Users: { findOne: async () => null },
    frontendBaseUrl: "https://frontend.example/app",
    inviteFrom: "test@example.com",
    sendMail: async () => ({ accepted: [], rejected: ["user@example.com"] }),
    tokenGenerator: () => "a".repeat(64),
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: "507f1f77bcf86cd799439011",
      authUserId: "507f1f77bcf86cd799439012",
      email: " User@Example.com ",
      isAdmin: true,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 502 &&
      /Failed to deliver invite email/.test(error.message)
  );

  assert.equal(state.savedInvite.recipientEmail, "user@example.com");
  assert.equal(state.savedInvite.token, "a".repeat(64));
  assert.deepEqual(state.deleteFilter, { _id: "invite-1" });
});

test("createInvitation keeps a generic 502 and logs sanitized delivery metadata", async () => {
  let loggedFailure;
  class FakeInviteModel {
    constructor(doc) {
      Object.assign(this, doc, { _id: "invite-1" });
    }
    async save() {
      return this;
    }
    static async findOne() {
      return null;
    }
    static async deleteOne(filter) {
      if (filter._id) throw new Error("cleanup leaked detail");
      return { deletedCount: 0 };
    }
  }

  const service = createInviteService({
    Breweries: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439011",
          companyName: "Brewery",
          owner: "507f1f77bcf86cd799439012",
          admin: [],
          staff: [],
        }),
    },
    Invites: FakeInviteModel,
    Users: { findOne: async () => null },
    inviteFrom: "sender@example.com",
    logDeliveryFailure: (details) => {
      loggedFailure = details;
    },
    sendMail: async () => {
      throw new Error("provider leaked detail");
    },
    tokenGenerator: () => "b".repeat(64),
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: "507f1f77bcf86cd799439011",
      authUserId: "507f1f77bcf86cd799439012",
      email: "user@example.com",
      isAdmin: false,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 502 &&
      error.message === "Failed to deliver invite email. Please try again later."
  );
  assert.deepEqual(loggedFailure, {
    cleanupFailed: true,
    providerCode: undefined,
    providerResponseCode: undefined,
  });
  assert.equal(JSON.stringify(loggedFailure).includes("provider leaked detail"), false);
});

test("createInvitation returns success only after provider acceptance", async () => {
  let sentMessage;
  class FakeInviteModel {
    constructor(doc) {
      Object.assign(this, doc, { _id: "invite-1" });
    }
    async save() {
      return this;
    }
    static async findOne() {
      return null;
    }
    static async deleteOne() {
      return { deletedCount: 0 };
    }
  }

  const from = { name: "Beer Flow", address: "sender@example.com" };
  const service = createInviteService({
    Breweries: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439011",
          companyName: "Brewery",
          owner: "507f1f77bcf86cd799439012",
          admin: [],
          staff: [],
        }),
    },
    Invites: FakeInviteModel,
    Users: { findOne: async () => null },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: from,
    sendMail: async (message) => {
      sentMessage = message;
      return { accepted: [message.to], rejected: [] };
    },
    tokenGenerator: () => "c".repeat(64),
  });

  const result = await service.createInvitation({
    breweryId: "507f1f77bcf86cd799439011",
    authUserId: "507f1f77bcf86cd799439012",
    email: " User@Example.com ",
    isAdmin: false,
  });

  assert.equal(result.message, "Invitation sent to user@example.com");
  assert.deepEqual(sentMessage.from, from);
  assert.equal(sentMessage.to, "user@example.com");
  assert.equal(result.message.includes("c".repeat(64)), false);
  assert.equal(Object.hasOwn(result, "invite"), false);
});

test("createInvitation maps unique-index duplicate races to HTTP 409", async () => {
  class FakeInviteModel {
    constructor(doc) {
      Object.assign(this, doc);
    }

    async save() {
      const error = new Error("duplicate key");
      error.code = 11000;
      throw error;
    }

    static async findOne() {
      return null;
    }

    static async deleteOne() {
      return { deletedCount: 0 };
    }
  }

  const service = createInviteService({
    Breweries: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439011",
          companyName: "Brewery",
          owner: "507f1f77bcf86cd799439012",
          admin: [],
          staff: [],
        }),
    },
    Invites: FakeInviteModel,
    Users: { findOne: async () => null },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
    tokenGenerator: () => "a".repeat(64),
  });

  await assert.rejects(
    service.createInvitation({
      breweryId: "507f1f77bcf86cd799439011",
      authUserId: "507f1f77bcf86cd799439012",
      email: "user@example.com",
      isAdmin: false,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 409 &&
      /active invite already exists/.test(error.message)
  );
});

test("acceptInvitation rejects legacy invites that do not persist recipientEmail", async () => {
  const session = createSessionTracker();
  const service = createInviteService({
    Breweries: { findById: () => createQuery(null) },
    Invites: {
      findOne: () =>
        createQuery({
          _id: "invite-1",
          token: "a".repeat(64),
        }),
      findOneAndDelete: () => createQuery(null),
    },
    Users: { findById: () => createQuery(null), updateOne: async () => ({}) },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
    startSession: async () => session,
  });

  await assert.rejects(
    service.acceptInvitation({
      authUserId: "507f1f77bcf86cd799439012",
      token: "a".repeat(64),
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 400 &&
      error.message === "Invalid or expired invite token."
  );

  assert.equal(session.aborted, true);
  assert.equal(session.committed, false);
});

test("acceptInvitation binds invite to authenticated user email without consuming on mismatch", async () => {
  const state = {
    deleted: false,
  };
  const session = createSessionTracker();
  const invite = {
    _id: "invite-1",
    token: "a".repeat(64),
    brewery: "507f1f77bcf86cd799439011",
    recipientEmail: "member@example.com",
    isAdmin: false,
    expiresAt: new Date(Date.now() + 60_000),
  };

  const service = createInviteService({
    Breweries: { findById: () => createQuery({ _id: invite.brewery }) },
    Invites: {
      findOne: () => createQuery(invite),
      findOneAndDelete: () => {
        state.deleted = true;
        return createQuery(invite);
      },
    },
    Users: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439012",
          email: "other@example.com",
        }),
      updateOne: async () => ({ acknowledged: true }),
    },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
    startSession: async () => session,
  });

  await assert.rejects(
    service.acceptInvitation({
      authUserId: "507f1f77bcf86cd799439012",
      token: invite.token,
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 403 &&
      error.message === "This invite belongs to a different account."
  );

  assert.equal(state.deleted, false);
  assert.equal(session.aborted, true);
});

test("acceptInvitation updates staff, admin, and user breweries once under replay/concurrency", async () => {
  const state = {
    invite: {
      _id: "invite-1",
      token: "a".repeat(64),
      brewery: "507f1f77bcf86cd799439011",
      recipientEmail: "member@example.com",
      isAdmin: true,
      expiresAt: new Date(Date.now() + 60_000),
    },
    brewery: {
      _id: "507f1f77bcf86cd799439011",
      companyName: "Brewery",
      owner: "507f1f77bcf86cd799439099",
      admin: [],
      staff: [],
      categories: [],
    },
    user: {
      _id: "507f1f77bcf86cd799439012",
      email: "Member@Example.com",
      breweries: [],
    },
  };

  const sessions = [];
  const service = createInviteService({
    Breweries: {
      findById(id) {
        const result =
          id === state.brewery._id
            ? {
                ...state.brewery,
                admin: [...state.brewery.admin],
                staff: [...state.brewery.staff],
              }
            : null;
        return createQuery(result);
      },
      async updateOne(filter, update) {
        if (filter._id !== state.brewery._id) {
          return { acknowledged: false, matchedCount: 0 };
        }

        for (const field of Object.keys(update.$addToSet)) {
          const value = update.$addToSet[field];
          if (!state.brewery[field].includes(value)) {
            state.brewery[field].push(value);
          }
        }

        return { acknowledged: true, matchedCount: 1 };
      },
    },
    Invites: {
      findOne: () => createQuery(state.invite ? { ...state.invite } : null),
      findOneAndDelete(filter) {
        if (state.invite && state.invite._id === filter._id) {
          const claimedInvite = { ...state.invite };
          state.invite = null;
          return createQuery(claimedInvite);
        }

        return createQuery(null);
      },
    },
    Users: {
      findById: () => createQuery({ ...state.user, breweries: [...state.user.breweries] }),
      async updateOne(filter, update) {
        if (filter._id !== state.user._id) {
          return { acknowledged: false, matchedCount: 0 };
        }

        const breweryId = update.$addToSet.breweries;
        if (!state.user.breweries.includes(breweryId)) {
          state.user.breweries.push(breweryId);
        }

        return { acknowledged: true, matchedCount: 1 };
      },
    },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
    startSession: async () => {
      const session = createSessionTracker();
      sessions.push(session);
      return session;
    },
  });

  const [first, second] = await Promise.allSettled([
    service.acceptInvitation({
      authUserId: state.user._id,
      token: "a".repeat(64),
    }),
    service.acceptInvitation({
      authUserId: state.user._id,
      token: "a".repeat(64),
    }),
  ]);

  assert.equal(first.status, "fulfilled");
  assert.equal(first.value.message, "Admin invitation accepted.");
  assert.equal(second.status, "rejected");
  assert.equal(second.reason.statusCode, 409);
  assert.deepEqual(state.brewery.staff, [state.user._id]);
  assert.deepEqual(state.brewery.admin, [state.user._id]);
  assert.deepEqual(state.user.breweries, [state.brewery._id]);
  assert.equal(sessions.some((session) => session.committed), true);
  assert.equal(sessions.some((session) => session.aborted), true);
});

test("acceptInvitation verifies update matched counts before success", async () => {
  const session = createSessionTracker();
  const service = createInviteService({
    Breweries: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439011",
          companyName: "Brewery",
          owner: "507f1f77bcf86cd799439099",
          admin: [],
          staff: [],
          categories: [],
        }),
      async updateOne() {
        return { acknowledged: true, matchedCount: 0 };
      },
    },
    Invites: {
      findOne: () =>
        createQuery({
          _id: "invite-1",
          token: "a".repeat(64),
          brewery: "507f1f77bcf86cd799439011",
          recipientEmail: "member@example.com",
          isAdmin: false,
          expiresAt: new Date(Date.now() + 60_000),
        }),
      findOneAndDelete: () =>
        createQuery({
          _id: "invite-1",
          token: "a".repeat(64),
          brewery: "507f1f77bcf86cd799439011",
          recipientEmail: "member@example.com",
          isAdmin: false,
        }),
    },
    Users: {
      findById: () =>
        createQuery({
          _id: "507f1f77bcf86cd799439012",
          email: "member@example.com",
          breweries: [],
        }),
      async updateOne() {
        return { acknowledged: true, matchedCount: 1 };
      },
    },
    frontendBaseUrl: "https://frontend.example",
    inviteFrom: "test@example.com",
    sendMail: async () => {},
    startSession: async () => session,
  });

  await assert.rejects(
    service.acceptInvitation({
      authUserId: "507f1f77bcf86cd799439012",
      token: "a".repeat(64),
    }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 404 &&
      error.message === "Brewery not found."
  );

  assert.equal(session.aborted, true);
  assert.equal(session.committed, false);
});

test("ensureAdminGrantPreconditions requires owner/admin caller and existing staff membership", () => {
  const brewery = {
    owner: "507f1f77bcf86cd799439011",
    admin: ["507f1f77bcf86cd799439012"],
    staff: ["507f1f77bcf86cd799439013"],
  };

  assert.throws(
    () =>
      ensureAdminGrantPreconditions({
        brewery,
        authUserId: "507f1f77bcf86cd799439014",
        targetUser: { _id: "507f1f77bcf86cd799439013" },
      }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 403 &&
      /grant admin access/.test(error.message)
  );

  assert.throws(
    () =>
      ensureAdminGrantPreconditions({
        brewery,
        authUserId: "507f1f77bcf86cd799439011",
        targetUser: { _id: "507f1f77bcf86cd799439015" },
      }),
    (error) =>
      error instanceof ServiceError &&
      error.statusCode === 400 &&
      /must already be a brewery staff member/.test(error.message)
  );
});

test("admin update filters keep caller authorization and target constraints in the write query", () => {
  assert.deepEqual(
    buildAdminGrantFilter({
      breweryId: "brewery-1",
      authUserId: "caller-1",
      targetUserId: "target-1",
    }),
    {
      _id: "brewery-1",
      staff: "target-1",
      admin: { $ne: "target-1" },
      $or: [{ owner: "caller-1" }, { admin: "caller-1" }],
    }
  );

  assert.deepEqual(
    buildAdminRevokeFilter({
      breweryId: "brewery-1",
      authUserId: "caller-1",
      targetUserId: "target-1",
    }),
    {
      _id: "brewery-1",
      owner: { $ne: "target-1" },
      admin: "target-1",
      $or: [{ owner: "caller-1" }, { admin: "caller-1" }],
    }
  );
});
