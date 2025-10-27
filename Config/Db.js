/**
 * Establishes a connection to the MongoDB database using Mongoose.
 * 
 * Attempts to connect using the connection string specified in the MONGO_URI environment variable.
 * Logs a success message upon successful connection.
 * If the connection fails, logs the error message and exits the process with a failure code.
 * 
 * @async
 * @function connectDB
 * @throws Will exit the process if the connection fails.
 */
const seedAdmin = require ('./seedAdmin');
const logger = require('../util/Logger');
const mongoose = require('mongoose');



const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
  maxPoolSize: 50,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 20000,
  connectTimeoutMS: 5000,

      // retryWrites: true,                // Retry transient write errors
    });


    await seedAdmin();
  logger.info('-----MongoDB connected successfully-----');

} catch (err) {
  logger.error('DB failed to connect ', { message: err.message, stack: err.stack });
  }
};

module.exports = connectDB;