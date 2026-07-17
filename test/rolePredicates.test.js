const test = require("node:test");
const assert = require("node:assert/strict");

const {
  arrayHasObjectId,
  canManageBreweryInvites,
  canReadBreweryMembership,
  isBreweryAdmin,
  isBreweryOwner,
  isBreweryStaff,
  objectIdsEqual,
} = require("../rolePredicates.js");

const ownerId = "507f1f77bcf86cd799439011";
const adminId = "507f1f77bcf86cd799439012";
const staffId = "507f1f77bcf86cd799439013";
const outsiderId = "507f1f77bcf86cd799439014";

test("objectIdsEqual handles strings and populated documents safely", () => {
  assert.equal(objectIdsEqual(ownerId, { _id: ownerId }), true);
  assert.equal(objectIdsEqual(ownerId, adminId), false);
  assert.equal(objectIdsEqual("not-an-id", ownerId), false);
});

test("arrayHasObjectId matches ObjectIds without relying on array.includes", () => {
  assert.equal(arrayHasObjectId([{ _id: adminId }], adminId), true);
  assert.equal(arrayHasObjectId([staffId], adminId), false);
});

test("brewery role predicates allow owner, admin, and staff reads only", () => {
  const brewery = {
    owner: { _id: ownerId },
    admin: [{ _id: adminId }],
    staff: [{ _id: staffId }],
  };

  assert.equal(isBreweryOwner(brewery, ownerId), true);
  assert.equal(isBreweryAdmin(brewery, adminId), true);
  assert.equal(isBreweryStaff(brewery, staffId), true);
  assert.equal(canReadBreweryMembership(brewery, ownerId), true);
  assert.equal(canReadBreweryMembership(brewery, adminId), true);
  assert.equal(canReadBreweryMembership(brewery, staffId), true);
  assert.equal(canReadBreweryMembership(brewery, outsiderId), false);
});

test("invite management remains limited to owner or admin", () => {
  const brewery = {
    owner: ownerId,
    admin: [adminId],
    staff: [staffId],
  };

  assert.equal(canManageBreweryInvites(brewery, ownerId), true);
  assert.equal(canManageBreweryInvites(brewery, adminId), true);
  assert.equal(canManageBreweryInvites(brewery, staffId), false);
});
