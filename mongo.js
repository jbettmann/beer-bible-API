const mongoose = require("mongoose");

const DEFAULT_MONGO_URI =
  process.env.CONNECTION_URI || "mongodb://localhost:27017/BeerBibleDB";

const DEFAULT_MONGO_OPTIONS = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  connectTimeoutMS: 5000,
  maxPoolSize: 5,
  autoIndex: false,
};

function createMongoConnectionManager({
  mongooseInstance = mongoose,
  uri = DEFAULT_MONGO_URI,
  options = DEFAULT_MONGO_OPTIONS,
  logger = console,
} = {}) {
  let connectionPromise = null;

  async function ensureMongoConnection() {
    if (mongooseInstance.connection.readyState === 1) {
      return mongooseInstance.connection;
    }

    if (!connectionPromise) {
      connectionPromise = mongooseInstance
        .connect(uri, options)
        .then(() => {
          connectionPromise = null;
          return mongooseInstance.connection;
        })
        .catch((error) => {
          connectionPromise = null;
          throw error;
        });
    }

    return connectionPromise;
  }

  async function mongoReadinessMiddleware(req, res, next) {
    try {
      await ensureMongoConnection();
      return next();
    } catch (error) {
      logger.error("Mongo connection unavailable:", error);
      return res.status(503).json({ error: "Database unavailable" });
    }
  }

  return {
    ensureMongoConnection,
    mongoReadinessMiddleware,
  };
}

function isValidObjectIdArray(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((id) => mongoose.isValidObjectId(id))
  );
}

module.exports = {
  DEFAULT_MONGO_OPTIONS,
  DEFAULT_MONGO_URI,
  createMongoConnectionManager,
  isValidObjectIdArray,
};
