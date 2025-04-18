const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { redisClient } = require("../config/redis");
const RedisKeys = require("../utils/redisKeys");
const User = require("../models/User");
const { generateAccessToken } = require("../utils/tokens");
const { setAccessTokenCookie } = require("../utils/cookies");
const { COOKIE_KEY_NAMES } = require("../utils/constants");

dotenv.config();

const validateAccessToken = ({ userId, token }) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    if (decoded.id !== userId) {
      throw new Error("Access token doesn't match the user session.");
    }
    return decoded;
  } catch (err) {
    if (err.name === "TokenExpiredError") return null;
    throw new Error("Invalid access token.");
  }
};

const validateRefreshToken = async ({ userId, refreshId }) => {
  const key = RedisKeys.REFRESH_TOKEN_ID({ userId, refreshId });
  const session = await redisClient.get(key);

  if (!session) {
    throw new Error("Session expired or invalid. Please log in again.");
  }

  const { refresh } = JSON.parse(session);

  try {
    return jwt.verify(refresh, process.env.JWT_REFRESH_SECRET);
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      await redisClient.del(key); // Clear expired session
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Invalid refresh token.");
  }
};

// --- Middleware ---
const verifyAccessToken = async (req, res, next) => {
  const cookies = req.cookies;
  const userId = cookies[COOKIE_KEY_NAMES.USER_ID];
  const accessToken = cookies[COOKIE_KEY_NAMES.ACCESS_TOKEN];
  const refreshId = cookies[COOKIE_KEY_NAMES.REFRESH_TOKEN_ID];

  if (!userId || !refreshId) {
    return res.status(401).json({ message: "Session missing. Please log in." });
  }

  try {
    if (accessToken) {
      const decoded = validateAccessToken({
        userId,
        token: accessToken,
      });
      if (decoded) {
        req.user = decoded;

        return next();
      }
    }
  } catch (err) {
    return res.status(403).json({ message: err.message });
  }

  try {
    const [user, decodedRefresh] = await Promise.all([
      User.findByPk(userId),
      validateRefreshToken({ userId, refreshId }),
    ]);

    if (!user) {
      return res
        .status(404)
        .json({ message: "User not found. Please log in." });
    }

    const newAccessToken = generateAccessToken({ id: userId });
    setAccessTokenCookie(res, newAccessToken);

    req.user = decodedRefresh;
    return next();
  } catch (err) {
    return res.status(403).json({ message: err.message });
  }
};

module.exports = verifyAccessToken;
