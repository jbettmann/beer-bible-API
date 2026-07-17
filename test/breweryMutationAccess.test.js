const test = require("node:test");
const assert = require("node:assert/strict");

const {
  breweryHasCategories,
  buildBeerWithinBreweryFilter,
  buildContainingBreweryCategoryFilter,
  buildOwnerAdminBreweryFilter,
  validateObjectId,
  validateObjectIdArray,
  validateOptionalObjectIdArray,
} = require("../breweryMutationAccess.js");

const breweryId = "507f1f77bcf86cd799439011";
const ownerId = "507f1f77bcf86cd799439012";
const categoryId = "507f1f77bcf86cd799439013";
const categoryIdTwo = "507f1f77bcf86cd799439014";
const beerId = "507f1f77bcf86cd799439015";

test("owner admin brewery filters exclude staff-only authorization", () => {
  assert.deepEqual(buildOwnerAdminBreweryFilter({ breweryId, authUserId: ownerId }), {
    _id: breweryId,
    $or: [{ owner: ownerId }, { admin: ownerId }],
  });
  assert.deepEqual(
    buildContainingBreweryCategoryFilter({
      categoryId,
      authUserId: ownerId,
    }),
    {
      categories: categoryId,
      $or: [{ owner: ownerId }, { admin: ownerId }],
    }
  );
});

test("buildBeerWithinBreweryFilter scopes beer mutations to the brewery", () => {
  assert.deepEqual(buildBeerWithinBreweryFilter({ breweryId, beerId }), {
    _id: beerId,
    companyId: breweryId,
  });
});

test("breweryHasCategories requires every category to belong to the brewery", () => {
  const brewery = {
    categories: [{ _id: categoryId }, categoryIdTwo],
  };

  assert.equal(breweryHasCategories(brewery, [categoryId, categoryIdTwo]), true);
  assert.equal(breweryHasCategories(brewery, [categoryId, beerId]), false);
});

test("ID validators reject malformed mutation identifiers", () => {
  assert.equal(validateObjectId(breweryId, "bad"), null);
  assert.equal(validateObjectId("bad-id", "bad"), "bad");
  assert.equal(validateObjectIdArray([categoryId, categoryIdTwo], "bad"), null);
  assert.equal(validateObjectIdArray(["bad-id"], "bad"), "bad");
  assert.equal(validateOptionalObjectIdArray(undefined, "bad"), null);
  assert.equal(
    validateOptionalObjectIdArray([categoryId, categoryIdTwo], "bad"),
    null
  );
  assert.equal(validateOptionalObjectIdArray(["bad-id"], "bad"), "bad");
});
