const mongoose = require("mongoose");

function validateBreweryAccessIds({ breweryId, authUser }) {
  if (!mongoose.isValidObjectId(breweryId)) {
    return { error: "Invalid brewery ID format." };
  }

  if (!mongoose.isValidObjectId(authUser)) {
    return { error: "Invalid user ID format." };
  }

  return null;
}

function buildBreweryAccessQuery({ breweryId, authUser }) {
  return {
    _id: breweryId,
    $or: [{ staff: authUser }, { admin: authUser }, { owner: authUser }],
  };
}

module.exports = {
  buildBreweryAccessQuery,
  validateBreweryAccessIds,
};
