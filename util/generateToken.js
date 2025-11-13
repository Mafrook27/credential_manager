const Session = require("../models/Session");
const { generateAccessToken, generateRefreshToken } = require("./jwtUtil");
const logger = require("../util/Logger");

// Get refresh token max time from env (default 4 hours)
const getRefreshMaxTime = () => {
  const time = process.env.REFRESH_MAXTIME || "4h";
  // Convert to milliseconds
  if (time.endsWith('d')) {
    return parseInt(time) * 24 * 60 * 60 * 1000;
  } else if (time.endsWith('h')) {
    return parseInt(time) * 60 * 60 * 1000;
  } else if (time.endsWith('m')) {
    return parseInt(time) * 60 * 1000;
  }
  return 4 * 60 * 60 * 1000; // default 4 hours
};

const createSession = async (payload, userAgent = null, ipAddress = null) => {

  const updateResult = await Session.updateMany(
    { userId: payload.id, active: true },
    { $set: { active: false } }
  );

  if (updateResult.modifiedCount > 0) {
    logger.info(`🔄 Marked ${updateResult.modifiedCount} previous session(s) as inactive for user ${payload.id} (Single session enforcement)`);
  }

  // Clean up old expired sessions
  const now = new Date();
  const deleteResult = await Session.deleteMany({
    userId: payload.id,
    expiresAt: { $lt: now }
  });

  if (deleteResult.deletedCount > 0) {
    logger.info(`🧹 Cleaned up ${deleteResult.deletedCount} expired session(s) for user ${payload.id}`);
  }

  const refreshToken = generateRefreshToken(payload);
  const expiresAt = new Date(Date.now() + getRefreshMaxTime());

  const session = await Session.create({
    userId: payload.id,
    refreshToken,
    expiresAt,
    refreshCount: 0,
    userAgent,
    ipAddress,
    active: true
  });

  logger.info(`✅ Created new active session for user ${payload.id} (Session ID: ${session._id})`);

  const accessToken = generateAccessToken(payload);
  return { accessToken, refreshToken, session };
};

// Legacy function for backward compatibility
const generateToken = (payload) => {
  return generateAccessToken(payload);
};

module.exports = {
  createSession,
  generateToken
};
