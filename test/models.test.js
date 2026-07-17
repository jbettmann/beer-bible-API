const test = require("node:test");
const assert = require("node:assert/strict");

const { User } = require("../models.js");

test("user email schema enforces lowercase trim and unique index", () => {
  const emailPath = User.schema.path("email");
  const userIndexes = User.schema.indexes();

  assert.equal(emailPath.options.lowercase, true);
  assert.equal(emailPath.options.trim, true);
  assert.equal(emailPath.options.required, true);
  assert.equal(
    userIndexes.some(([key, options]) => {
      return key.email === 1 && options.unique === true && options.name === "user_email_unique";
    }),
    true
  );
});
