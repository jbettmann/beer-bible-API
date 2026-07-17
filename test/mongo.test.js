const test = require("node:test");
const assert = require("node:assert/strict");

const {
  DEFAULT_MONGO_OPTIONS,
  createMongoConnectionManager,
  isValidObjectIdArray,
} = require("../mongo.js");

test("DEFAULT_MONGO_OPTIONS disables automatic index creation", () => {
  assert.equal(DEFAULT_MONGO_OPTIONS.autoIndex, false);
});

test("isValidObjectIdArray accepts only non-empty valid ObjectId arrays", () => {
  assert.equal(
    isValidObjectIdArray([
      "507f1f77bcf86cd799439011",
      "507f1f77bcf86cd799439012",
    ]),
    true
  );
  assert.equal(isValidObjectIdArray([]), false);
  assert.equal(isValidObjectIdArray(["not-an-object-id"]), false);
  assert.equal(isValidObjectIdArray("507f1f77bcf86cd799439011"), false);
});

test("ensureMongoConnection reuses an in-flight connection attempt", async () => {
  let connectCalls = 0;
  const fakeMongoose = {
    connection: { readyState: 0 },
    connect: () => {
      connectCalls += 1;
      fakeMongoose.connection.readyState = 1;
      return Promise.resolve(fakeMongoose.connection);
    },
  };

  const { ensureMongoConnection } = createMongoConnectionManager({
    mongooseInstance: fakeMongoose,
    uri: "mongodb://example.invalid/test",
    options: {},
    logger: { error() {} },
  });

  await Promise.all([ensureMongoConnection(), ensureMongoConnection()]);

  assert.equal(connectCalls, 1);
});

test("ensureMongoConnection reconnects after a later disconnect", async () => {
  let connectCalls = 0;
  const fakeMongoose = {
    connection: { readyState: 0 },
    connect: () => {
      connectCalls += 1;
      fakeMongoose.connection.readyState = 1;
      return Promise.resolve(fakeMongoose.connection);
    },
  };

  const { ensureMongoConnection } = createMongoConnectionManager({
    mongooseInstance: fakeMongoose,
    uri: "mongodb://example.invalid/test",
    options: {},
    logger: { error() {} },
  });

  await ensureMongoConnection();
  fakeMongoose.connection.readyState = 0;
  await ensureMongoConnection();

  assert.equal(connectCalls, 2);
});

test("mongoReadinessMiddleware returns JSON when the connection fails", async () => {
  const fakeMongoose = {
    connection: { readyState: 0 },
    connect: () => Promise.reject(new Error("boom")),
  };

  const { mongoReadinessMiddleware } = createMongoConnectionManager({
    mongooseInstance: fakeMongoose,
    uri: "mongodb://example.invalid/test",
    options: {},
    logger: { error() {} },
  });

  let nextCalled = false;
  const res = {
    statusCode: null,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };

  await mongoReadinessMiddleware({}, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.payload, { error: "Database unavailable" });
});
