const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildBreweryAccessQuery,
  validateBreweryAccessIds,
} = require("../breweryAccess.js");

test("buildBreweryAccessQuery authorizes owner, admin, and staff", () => {
  const query = buildBreweryAccessQuery({
    breweryId: "507f1f77bcf86cd799439011",
    authUser: "507f1f77bcf86cd799439012",
  });

  assert.deepEqual(query, {
    _id: "507f1f77bcf86cd799439011",
    $or: [
      { staff: "507f1f77bcf86cd799439012" },
      { admin: "507f1f77bcf86cd799439012" },
      { owner: "507f1f77bcf86cd799439012" },
    ],
  });
});

test("validateBreweryAccessIds rejects malformed brewery IDs first", () => {
  assert.deepEqual(
    validateBreweryAccessIds({
      breweryId: "not-an-id",
      authUser: "507f1f77bcf86cd799439012",
    }),
    { error: "Invalid brewery ID format." }
  );
});

test("validateBreweryAccessIds rejects malformed user IDs", () => {
  assert.deepEqual(
    validateBreweryAccessIds({
      breweryId: "507f1f77bcf86cd799439011",
      authUser: "not-an-id",
    }),
    { error: "Invalid user ID format." }
  );
});

test("validateBreweryAccessIds accepts valid ObjectIds", () => {
  assert.equal(
    validateBreweryAccessIds({
      breweryId: "507f1f77bcf86cd799439011",
      authUser: "507f1f77bcf86cd799439012",
    }),
    null
  );
});
