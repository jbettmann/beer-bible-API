const mongoose = require("mongoose");

const { arrayHasObjectId } = require("./rolePredicates.js");

function buildOwnerAdminBreweryFilter({ breweryId, authUserId }) {
  return {
    _id: breweryId,
    $or: [{ owner: authUserId }, { admin: authUserId }],
  };
}

function buildContainingBreweryCategoryFilter({ categoryId, authUserId }) {
  return {
    categories: categoryId,
    $or: [{ owner: authUserId }, { admin: authUserId }],
  };
}

function buildBeerWithinBreweryFilter({ breweryId, beerId }) {
  return {
    _id: beerId,
    companyId: breweryId,
  };
}

function validateObjectId(value, message) {
  if (!mongoose.isValidObjectId(value)) {
    return message;
  }

  return null;
}

function validateObjectIdArray(values, message) {
  if (!Array.isArray(values) || values.length < 1) {
    return message;
  }

  for (const value of values) {
    if (!mongoose.isValidObjectId(value)) {
      return message;
    }
  }

  return null;
}

function validateOptionalObjectIdArray(values, message) {
  if (typeof values === "undefined") {
    return null;
  }

  return validateObjectIdArray(values, message);
}

function breweryHasCategories(brewery, categoryIds) {
  return (
    Boolean(brewery) &&
    Array.isArray(categoryIds) &&
    categoryIds.every((categoryId) => arrayHasObjectId(brewery.categories, categoryId))
  );
}

module.exports = {
  breweryHasCategories,
  buildBeerWithinBreweryFilter,
  buildContainingBreweryCategoryFilter,
  buildOwnerAdminBreweryFilter,
  validateObjectId,
  validateObjectIdArray,
  validateOptionalObjectIdArray,
};
