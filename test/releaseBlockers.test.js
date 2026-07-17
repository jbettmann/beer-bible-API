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

test("PATCH /breweries/:breweryId/admins/:userId rejects invalid breweryId before DB lookup", async () => {
  const originalBreweryFindById = Models.Brewery.findById;
  const originalUserFindById = Models.User.findById;
  let breweryFindByIdCalls = 0;
  let userFindByIdCalls = 0;

  Models.Brewery.findById = async () => {
    breweryFindByIdCalls += 1;
    return null;
  };
  Models.User.findById = async () => {
    userFindByIdCalls += 1;
    return null;
  };

  const handlers = getRouteHandlers({
    method: "patch",
    path: "/breweries/:breweryId/admins/:userId",
  });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
    params: {
      breweryId: "not-an-object-id",
      userId: "507f1f77bcf86cd799439011",
    },
    body: { action: "add" },
  };
  const res = createResponse();

  try {
    await invokeHandlers(handlers, req, res);
    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.payload, { error: "Invalid brewery ID format." });
    assert.equal(breweryFindByIdCalls, 0);
    assert.equal(userFindByIdCalls, 0);
  } finally {
    Models.Brewery.findById = originalBreweryFindById;
    Models.User.findById = originalUserFindById;
  }
});

test("PATCH /breweries/:breweryId/admins/:userId rejects invalid userId before DB lookup", async () => {
  const originalBreweryFindById = Models.Brewery.findById;
  const originalUserFindById = Models.User.findById;
  let breweryFindByIdCalls = 0;
  let userFindByIdCalls = 0;

  Models.Brewery.findById = async () => {
    breweryFindByIdCalls += 1;
    return null;
  };
  Models.User.findById = async () => {
    userFindByIdCalls += 1;
    return null;
  };

  const handlers = getRouteHandlers({
    method: "patch",
    path: "/breweries/:breweryId/admins/:userId",
  });
  const req = {
    headers: {
      authorization: `Bearer ${buildAuthToken("507f1f77bcf86cd799439099")}`,
    },
    params: {
      breweryId: "507f1f77bcf86cd799439010",
      userId: "not-an-object-id",
    },
    body: { action: "add" },
  };
  const res = createResponse();

  try {
    await invokeHandlers(handlers, req, res);
    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.payload, { error: "Invalid user ID format." });
    assert.equal(breweryFindByIdCalls, 0);
    assert.equal(userFindByIdCalls, 0);
  } finally {
    Models.Brewery.findById = originalBreweryFindById;
    Models.User.findById = originalUserFindById;
  }
});
