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
  // ✅ Mark old sessions as inactive instead of deleting
  await Session.updateMany(
    { userId: payload.id },
    { active: false }
  );

  logger.info(`Marked previous sessions as inactive for user ${payload.id}`);

  const refreshToken = generateRefreshToken(payload);
  const expiresAt = new Date(Date.now() + getRefreshMaxTime());

  const session = await Session.create({
    userId: payload.id,
    refreshToken,
    expiresAt,
    refreshCount: 0,
    userAgent,
    ipAddress,
    active: true  // ✅ New session is active
  });

  logger.info(`Created new active session for user ${payload.id}`);

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
