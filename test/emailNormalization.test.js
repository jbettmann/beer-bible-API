const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildCaseInsensitiveEmailFilter,
  normalizeEmail,
} = require("../emailNormalization.js");

test("normalizeEmail lowercases and trims user emails", () => {
  assert.equal(normalizeEmail(" User@Example.com "), "user@example.com");
  assert.equal(normalizeEmail("not-an-email"), null);
});

test("buildCaseInsensitiveEmailFilter anchors normalized emails", () => {
  assert.deepEqual(buildCaseInsensitiveEmailFilter(" User@Example.com "), {
    $regex: "^user@example\\.com$",
    $options: "i",
  });
  assert.equal(buildCaseInsensitiveEmailFilter("not-an-email"), null);
});
