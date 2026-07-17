const test = require("node:test");
const assert = require("node:assert/strict");

const {
  assertGmailConfig,
  buildInviteSender,
  getMissingGmailConfig,
} = require("../mailConfig.js");

const validConfig = {
  GMAIL_EMAIL: "sender@example.com",
  GMAIL_CLIENT: "client",
  GMAIL_SECRET: "secret",
  GMAIL_OAUTH_REFRESH: "refresh",
};

test("mail configuration reports missing values without exposing values", () => {
  assert.deepEqual(getMissingGmailConfig({ GMAIL_EMAIL: " " }), [
    "GMAIL_EMAIL",
    "GMAIL_CLIENT",
    "GMAIL_SECRET",
    "GMAIL_OAUTH_REFRESH",
  ]);
  assert.throws(
    () => assertGmailConfig({ ...validConfig, GMAIL_SECRET: "" }),
    (error) =>
      error.message === "Missing required Gmail configuration: GMAIL_SECRET" &&
      !error.message.includes(validConfig.GMAIL_OAUTH_REFRESH)
  );
});

test("invite sender uses the authenticated mailbox and product display name", () => {
  assert.deepEqual(buildInviteSender(validConfig), {
    name: "Beer Flow",
    address: "sender@example.com",
  });
});
