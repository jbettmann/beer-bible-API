const REQUIRED_GMAIL_ENV = [
  "GMAIL_EMAIL",
  "GMAIL_CLIENT",
  "GMAIL_SECRET",
  "GMAIL_OAUTH_REFRESH",
];

function getMissingGmailConfig(env = process.env) {
  return REQUIRED_GMAIL_ENV.filter(
    (name) => typeof env[name] !== "string" || env[name].trim() === ""
  );
}

function assertGmailConfig(env = process.env) {
  const missing = getMissingGmailConfig(env);
  if (missing.length > 0) {
    throw new Error(`Missing required Gmail configuration: ${missing.join(", ")}`);
  }
}

function buildInviteSender(env = process.env) {
  assertGmailConfig(env);
  return { name: "Beer Flow", address: env.GMAIL_EMAIL.trim() };
}

module.exports = {
  REQUIRED_GMAIL_ENV,
  assertGmailConfig,
  buildInviteSender,
  getMissingGmailConfig,
};
