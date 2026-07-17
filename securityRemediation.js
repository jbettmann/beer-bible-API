const USER_PROFILE_ALLOWED_FIELDS = ["fullName", "image", "notifications"];
const BREWERY_PROFILE_ALLOWED_FIELDS = ["companyName", "image"];

function getBodyKeys(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return [];
  }

  return Object.keys(body);
}

function findDisallowedFields(body, allowedFields) {
  const allowed = new Set(allowedFields);
  return getBodyKeys(body).filter((field) => !allowed.has(field));
}

function pickAllowedFields(body, allowedFields) {
  const update = {};

  for (const field of allowedFields) {
    if (
      body &&
      typeof body === "object" &&
      !Array.isArray(body) &&
      Object.prototype.hasOwnProperty.call(body, field) &&
      typeof body[field] !== "undefined"
    ) {
      update[field] = body[field];
    }
  }

  return update;
}

function validateNotificationsPayload(notifications) {
  if (!notifications || typeof notifications !== "object" || Array.isArray(notifications)) {
    return "Missing notifications object.";
  }

  if (typeof notifications.allow !== "boolean") {
    return "Missing or invalid allow in notifications.";
  }

  const expectedKeys = ["newBeerRelease", "beerUpdate"];

  for (const key of expectedKeys) {
    if (!notifications[key] || typeof notifications[key] !== "object") {
      return `Missing ${key} in notifications.`;
    }

    if (
      typeof notifications[key].email !== "boolean" ||
      typeof notifications[key].push !== "boolean"
    ) {
      return `Invalid values for ${key}.`;
    }
  }

  return null;
}

module.exports = {
  BREWERY_PROFILE_ALLOWED_FIELDS,
  findDisallowedFields,
  pickAllowedFields,
  USER_PROFILE_ALLOWED_FIELDS,
  validateNotificationsPayload,
};
