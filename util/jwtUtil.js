// const jwt = require("jsonwebtoken");

// /**
//  * Generates a JSON Web Token (JWT) for a given user ID.
//  *
//  * @param {string|number} userId - The unique identifier of the user for whom the token is generated.
//  * @returns {string} The signed JWT token as a string.
//  */
// const generateToken = (payload) => {
//   return jwt.sign({ payload }, process.env.JWT_SECRET, { expiresIn: "1h" });
// };

// module.exports = { generateToken };

const jwt = require("jsonwebtoken");

const ACCESS_SECRET = process.env.ACCESS_SECRET || process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || process.env.JWT_SECRET;
const ACCESS_TIME = process.env.ACCESS_TIME || "5m";
const REFRESH_TIME = process.env.REFRESH_TIME || "30m";

const generateAccessToken = (payload) => {
  return jwt.sign({ payload }, ACCESS_SECRET, { expiresIn: ACCESS_TIME });
};

const generateRefreshToken = (payload) => {
  return jwt.sign({ payload }, REFRESH_SECRET, { expiresIn: REFRESH_TIME });
};

const verifyAccessToken = (token) => jwt.verify(token, ACCESS_SECRET);
const verifyRefreshToken = (token) => jwt.verify(token, REFRESH_SECRET);

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken
};

















































































































































































































