const mongoose = require("mongoose");

function getObjectIdValue(value) {
  if (value && typeof value === "object" && value._id) {
    return value._id;
  }

  return value;
}

function objectIdToString(value) {
  const normalizedValue = getObjectIdValue(value);

  if (!mongoose.isValidObjectId(normalizedValue)) {
    return null;
  }

  return normalizedValue.toString();
}

function objectIdsEqual(left, right) {
  const leftId = objectIdToString(left);
  const rightId = objectIdToString(right);

  return Boolean(leftId && rightId && leftId === rightId);
}

function arrayHasObjectId(values, target) {
  return Array.isArray(values) && values.some((value) => objectIdsEqual(value, target));
}

function isBreweryOwner(brewery, userId) {
  return Boolean(brewery) && objectIdsEqual(brewery.owner, userId);
}

function isBreweryAdmin(brewery, userId) {
  return Boolean(brewery) && arrayHasObjectId(brewery.admin, userId);
}

function isBreweryStaff(brewery, userId) {
  return Boolean(brewery) && arrayHasObjectId(brewery.staff, userId);
}

function canReadBreweryMembership(brewery, userId) {
  return (
    isBreweryOwner(brewery, userId) ||
    isBreweryAdmin(brewery, userId) ||
    isBreweryStaff(brewery, userId)
  );
}

function canManageBreweryInvites(brewery, userId) {
  return isBreweryOwner(brewery, userId) || isBreweryAdmin(brewery, userId);
}

module.exports = {
  arrayHasObjectId,
  canManageBreweryInvites,
  canReadBreweryMembership,
  getObjectIdValue,
  isBreweryAdmin,
  isBreweryOwner,
  isBreweryStaff,
  objectIdsEqual,
  objectIdToString,
};
