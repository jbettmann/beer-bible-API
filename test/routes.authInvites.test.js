const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");

process.env.NEXTAUTH_SECRET = "test-nextauth-secret";

const Models = require("../models.js");
const app = require("../index.js");

function buildAuthToken(userId) {
  return jwt.sign({ id: userId }, process.env.NEXTAUTH_SECRET);
}

function getRouteHandlers({ method, path }) {
  const layer = app._router.stack.find(
    (item) => item.route && item.route.path === path && item.route.methods[method]
  );

  if (!layer) {
    throw new Error(`Route not found: ${method.toUpperCase()} ${path}`);
  }

  return layer.route.stack.map((routeLayer) => routeLayer.handle);
}

function createResponse() {
  return {
    statusCode: 200,
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
}

async function invokeHandlers(handlers, req, res) {
  let index = 0;

  async function next(error) {
    if (error) {
      throw error;
    }

    const handler = handlers[index];
    index += 1;

    if (!handler) {
      return;
    }

    await handler(req, res, next);
  }

  await next();
}

test("GET /accept-invite returns 400 when legacy query token is missing", async () => {
  const handlers = getRouteHandlers({ method: "get", path: "/accept-invite" });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
    query: {},
  };
  const res = createResponse();

  await invokeHandlers(handlers, req, res);

  assert.equal(res.statusCode, 400);
  assert.deepEqual(res.payload, { message: "Invite token query is required." });
});

test("GET /accept-invite returns 400 when legacy query token is malformed", async () => {
  const handlers = getRouteHandlers({ method: "get", path: "/accept-invite" });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
    query: {
      token: "not-32-hex",
    },
  };
  const res = createResponse();

  await invokeHandlers(handlers, req, res);

  assert.equal(res.statusCode, 400);
  assert.deepEqual(res.payload, { message: "Malformed legacy invite token." });
});

test("GET /accept-invite returns 410 tombstone for 32-hex legacy query token without invite lookup", async () => {
  const originalInviteFindOne = Models.Invite.findOne;
  let inviteFindOneCalls = 0;
  Models.Invite.findOne = async () => {
    inviteFindOneCalls += 1;
    return null;
  };

  const handlers = getRouteHandlers({ method: "get", path: "/accept-invite" });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
    query: {
      token: "a".repeat(32),
    },
  };
  const res = createResponse();

  try {
    await invokeHandlers(handlers, req, res);

    assert.equal(res.statusCode, 410);
    assert.deepEqual(res.payload, {
      message:
        "This legacy invite was revoked by the security upgrade. Ask the brewery manager to resend your invite.",
    });
    assert.equal(inviteFindOneCalls, 0);
  } finally {
    Models.Invite.findOne = originalInviteFindOne;
  }
});

test("GET /users/me returns 400 when authenticated user id is invalid", async () => {
  const originalUserFindById = Models.User.findById;
  let findByIdCalls = 0;
  Models.User.findById = async () => {
    findByIdCalls += 1;
    return null;
  };

  const handlers = getRouteHandlers({ method: "get", path: "/users/me" });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("not-an-object-id")}`,
    },
  };
  const res = createResponse();

  try {
    await invokeHandlers(handlers, req, res);

    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.payload, { error: "Invalid authenticated user ID." });
    assert.equal(findByIdCalls, 0);
  } finally {
    Models.User.findById = originalUserFindById;
  }
});

test("GET /users/me returns 404 when authenticated user is missing", async () => {
  const originalUserFindById = Models.User.findById;
  Models.User.findById = async () => null;

  const handlers = getRouteHandlers({ method: "get", path: "/users/me" });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
  };
  const res = createResponse();

  try {
    await invokeHandlers(handlers, req, res);

    assert.equal(res.statusCode, 404);
    assert.deepEqual(res.payload, { error: "User not found" });
  } finally {
    Models.User.findById = originalUserFindById;
  }
});

test("GET /users/me returns the authenticated user without password", async () => {
  const originalUserFindById = Models.User.findById;
  Models.User.findById = async (userId) => ({
    toObject() {
      return {
        _id: userId,
        fullName: "Brew User",
        email: "brew@example.com",
        breweries: ["507f1f77bcf86cd799439011"],
        image: "https://example.com/user.png",
        notifications: {
          allow: true,
          newBeerRelease: { email: true, push: false },
          beerUpdate: { email: false, push: true },
        },
        password: "hashed-secret",
      };
    },
  });

  const handlers = getRouteHandlers({ method: "get", path: "/users/me" });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
  };
  const res = createResponse();

  try {
    await invokeHandlers(handlers, req, res);

    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.payload, {
      _id: "507f1f77bcf86cd799439099",
      fullName: "Brew User",
      email: "brew@example.com",
      breweries: ["507f1f77bcf86cd799439011"],
      image: "https://example.com/user.png",
      notifications: {
        allow: true,
        newBeerRelease: { email: true, push: false },
        beerUpdate: { email: false, push: true },
      },
    });
    assert.equal(Object.prototype.hasOwnProperty.call(res.payload, "password"), false);
  } finally {
    Models.User.findById = originalUserFindById;
  }
});
