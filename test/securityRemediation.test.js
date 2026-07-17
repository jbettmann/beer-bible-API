const test = require("node:test");
const assert = require("node:assert/strict");

const {
  BREWERY_PROFILE_ALLOWED_FIELDS,
  findDisallowedFields,
  pickAllowedFields,
  USER_PROFILE_ALLOWED_FIELDS,
  validateNotificationsPayload,
} = require("../securityRemediation.js");

test("findDisallowedFields and pickAllowedFields enforce allowlists", () => {
  const payload = {
    fullName: "Brewer",
    image: "https://example.com/user.png",
    email: "blocked@example.com",
    breweries: ["507f1f77bcf86cd799439011"],
  };

  assert.deepEqual(findDisallowedFields(payload, ["fullName", "image"]), [
    "email",
    "breweries",
  ]);
  assert.deepEqual(pickAllowedFields(payload, ["fullName", "image"]), {
    fullName: "Brewer",
    image: "https://example.com/user.png",
  });
});

test("validateNotificationsPayload requires allow plus known boolean channels", () => {
  assert.equal(
    validateNotificationsPayload({
      allow: true,
      newBeerRelease: { email: true, push: false },
      beerUpdate: { email: false, push: true },
    }),
    null
  );

  assert.equal(
    validateNotificationsPayload({
      newBeerRelease: { email: true, push: false },
      beerUpdate: { email: false, push: true },
    }),
    "Missing or invalid allow in notifications."
  );

  assert.equal(
    validateNotificationsPayload({
      allow: true,
      newBeerRelease: { email: true, push: "nope" },
      beerUpdate: { email: false, push: true },
    }),
    "Invalid values for newBeerRelease."
  );
});

test("generic profile allowlists exclude canonical email changes", () => {
  assert.equal(USER_PROFILE_ALLOWED_FIELDS.includes("email"), false);
  assert.equal(BREWERY_PROFILE_ALLOWED_FIELDS.includes("email"), false);
});
